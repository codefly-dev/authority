package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// The edge is the auth gateway's role: the one origin a browser talks to. A
// person signs in here and holds a session cookie; every call to a module is
// routed by its path, and the edge asks the authority for the person's Work
// Context at that module and sends the call on to the module's own HTTP face,
// which dials the hop in front of the module. The hop checks the method and
// stamps the call; the edge decides nothing about what a call may do, and the
// frontend holds no token.

// SessionKey is the cookie the session bearer travels in.
const SessionKey = "edge_session"

// WorkContextKey is the header a Work Context travels in to a module.
const WorkContextKey = "x-codefly-work-context"

// Sessions is the authority's session interface.
type Sessions interface {
	SignIn(ctx context.Context, in *sessionv1.SignInRequest, opts ...grpc.CallOption) (*sessionv1.Session, error)
	Current(ctx context.Context, in *sessionv1.CurrentRequest, opts ...grpc.CallOption) (*sessionv1.Session, error)
}

// Issuer is the authority interface's Issue.
type Issuer interface {
	Issue(ctx context.Context, in *authorityv1.IssueRequest, opts ...grpc.CallOption) (*authorityv1.IssueResponse, error)
}

// Module is one module the edge routes to: REST under /v1/<name>/, Connect
// for the services it serves.
type Module struct {
	Name     string
	REST     *url.URL
	Connect  *url.URL
	Services []string
}

// Edge serves the browser.
type Edge struct {
	Sessions  Sessions
	Authority Issuer
	Modules   map[string]Module
	// Frontend serves every path no module claims; nil serves none.
	Frontend *url.URL
	Now      func() time.Time

	mu   sync.Mutex
	held map[[32]byte]held
}

type held struct {
	token string
	renew time.Time
}

func (e *Edge) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/auth/sign-in":
		e.signIn(w, r)
		return
	case "/auth/session":
		e.session(w, r)
		return
	case "/auth/sign-out":
		http.SetCookie(w, &http.Cookie{Name: SessionKey, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if module, target, ok := e.route(r.URL.Path); ok {
		e.toModule(w, r, module, target)
		return
	}
	if e.Frontend == nil {
		refuse(w, http.StatusNotFound, "no module serves "+r.URL.Path)
		return
	}
	proxy(e.Frontend, "", w, r)
}

// route is the module a path is for and the face that serves it.
func (e *Edge) route(path string) (Module, *url.URL, bool) {
	if rest, ok := strings.CutPrefix(path, "/v1/"); ok {
		name, _, _ := strings.Cut(rest, "/")
		if m, ok := e.Modules[name]; ok && m.REST != nil {
			return m, m.REST, true
		}
		return Module{}, nil, false
	}
	service, _, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	for _, m := range e.Modules {
		for _, s := range m.Services {
			if s == service && m.Connect != nil {
				return m, m.Connect, true
			}
		}
	}
	return Module{}, nil, false
}

func (e *Edge) toModule(w http.ResponseWriter, r *http.Request, module Module, target *url.URL) {
	bearer, fromCookie := bearerOf(r)
	if bearer == "" {
		refuse(w, http.StatusUnauthorized, "no session: sign in at /auth/sign-in")
		return
	}
	// A cookie rides every request the browser makes to this origin, including
	// one another site causes; a write authenticated by it must say it comes
	// from this origin. A caller presenting its bearer itself is not a browser
	// being steered.
	if fromCookie && r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r) {
		refuse(w, http.StatusForbidden, "a write must come from this origin")
		return
	}
	token, err := e.workContext(r.Context(), bearer, module.Name)
	if err != nil {
		code := http.StatusForbidden
		if status.Code(err) == codes.Unauthenticated {
			code = http.StatusUnauthorized
		}
		refuse(w, code, "the authority refused this person at "+module.Name+": "+status.Convert(err).Message())
		return
	}
	proxy(target, token, w, r)
}

// workContext is the person's Work Context at module, issued by the authority
// for everything the person holds there and held until shortly before it
// lapses. The hop narrows each call to what its method requires.
func (e *Edge) workContext(ctx context.Context, bearer, module string) (string, error) {
	key := sha256.Sum256([]byte(bearer + "\x00" + module))
	e.mu.Lock()
	if h, ok := e.held[key]; ok && e.now().Before(h.renew) {
		e.mu.Unlock()
		return h.token, nil
	}
	e.mu.Unlock()
	ctx, cancel := context.WithTimeout(metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+bearer), 10*time.Second)
	defer cancel()
	issued, err := e.Authority.Issue(ctx, &authorityv1.IssueRequest{
		As:       &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}},
		Audience: module,
	})
	if err != nil {
		return "", err
	}
	if issued.GetToken() == "" {
		return "", status.Error(codes.Internal, "the authority issued no Work Context")
	}
	expires := time.Unix(issued.GetExpiresAtUnix(), 0)
	lead := expires.Sub(e.now()) / 2
	if lead > 30*time.Second {
		lead = 30 * time.Second
	}
	e.mu.Lock()
	if e.held == nil {
		e.held = map[[32]byte]held{}
	}
	e.held[key] = held{token: issued.GetToken(), renew: expires.Add(-lead)}
	e.mu.Unlock()
	return issued.GetToken(), nil
}

func (e *Edge) signIn(w http.ResponseWriter, r *http.Request) {
	fixture := r.URL.Query().Get("fixture")
	if r.Method == http.MethodPost {
		var in struct {
			FixtureToken string `json:"fixtureToken"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
			refuse(w, http.StatusBadRequest, "a sign-in names a fixture token")
			return
		}
		fixture = in.FixtureToken
	}
	if fixture == "" {
		refuse(w, http.StatusBadRequest, "a sign-in names a fixture token")
		return
	}
	sess, err := e.Sessions.SignIn(r.Context(), &sessionv1.SignInRequest{FixtureToken: fixture})
	if err != nil {
		refuse(w, http.StatusUnauthorized, "the authority refused the sign-in: "+status.Convert(err).Message())
		return
	}
	http.SetCookie(w, &http.Cookie{Name: SessionKey, Value: sess.GetBearer(), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"personId": sess.GetPersonId(), "organizationId": sess.GetOrganizationId()})
}

func (e *Edge) session(w http.ResponseWriter, r *http.Request) {
	bearer, _ := bearerOf(r)
	if bearer == "" {
		refuse(w, http.StatusUnauthorized, "no session: sign in at /auth/sign-in")
		return
	}
	sess, err := e.Sessions.Current(metadata.AppendToOutgoingContext(r.Context(), "authorization", "Bearer "+bearer), &sessionv1.CurrentRequest{})
	if err != nil {
		refuse(w, http.StatusUnauthorized, "the authority knows no session for this bearer")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"personId": sess.GetPersonId(), "organizationId": sess.GetOrganizationId(), "roles": sess.GetRoles()})
}

// bearerOf is the session the request presents: its cookie, or a bearer a
// non-browser caller presents itself.
func bearerOf(r *http.Request) (string, bool) {
	if c, err := r.Cookie(SessionKey); err == nil && c.Value != "" {
		return c.Value, true
	}
	if b, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && b != "" {
		return b, false
	}
	return "", false
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host
}

// proxy sends r on to target, with the Work Context the edge holds for it and
// nothing a caller said about who it is: no Authorization, no Cookie and no
// x-codefly-* header leaves the edge unless the edge set it.
func proxy(target *url.URL, token string, w http.ResponseWriter, r *http.Request) {
	(&httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Cookie")
			for name := range pr.Out.Header {
				if strings.HasPrefix(strings.ToLower(name), "x-codefly-") {
					pr.Out.Header.Del(name)
				}
			}
			if token != "" {
				pr.Out.Header.Set(WorkContextKey, token)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			refuse(w, http.StatusBadGateway, "the module did not answer: "+err.Error())
		},
	}).ServeHTTP(w, r)
}

func refuse(w http.ResponseWriter, code int, reason string) {
	writeJSON(w, code, map[string]string{"error": reason})
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
