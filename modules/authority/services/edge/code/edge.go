package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	installationv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/installation/v1"
	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/host"
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
	ListFixturePeople(ctx context.Context, in *sessionv1.ListFixturePeopleRequest, opts ...grpc.CallOption) (*sessionv1.ListFixturePeopleResponse, error)
}

// Installations is the installation interface's List: an administrator's read
// of what one organisation has installed, which a host refuses a member. The
// edge never decides from it who may use an installation (that is Issue, see
// session); it reads from it only the namespace an installation's authored
// content belongs to, which no member's read carries yet.
type Installations interface {
	List(ctx context.Context, in *installationv1.ListRequest, opts ...grpc.CallOption) (*installationv1.ListResponse, error)
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
	SignInChoices []signInChoice
	Sessions      Sessions
	Authority     Issuer
	Installations Installations
	Modules       map[string]Module
	// Frontend serves every path no module claims; nil serves none.
	Frontend *url.URL
	Now      func() time.Time

	mu              sync.Mutex
	held            map[[32]byte]held
	cacheGeneration uint64
}

type held struct {
	bearer [32]byte
	token  string
	// installation is the installation the authority sealed the context to.
	installation string
	renew        time.Time
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
		e.signOut(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/auth/assets/") {
		e.signInAsset(w, r)
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
	wc, err := e.workContext(r.Context(), bearer, module.Name)
	if err != nil {
		code := http.StatusForbidden
		if status.Code(err) == codes.Unauthenticated {
			code = http.StatusUnauthorized
		}
		refuse(w, code, "the authority refused this person at "+module.Name+": "+status.Convert(err).Message())
		return
	}
	proxy(target, wc.token, w, r)
}

// workContext is the person's Work Context at module, issued by the authority
// for everything the person holds there and held until shortly before it
// lapses. The hop narrows each call to what its method requires.
func (e *Edge) workContext(ctx context.Context, bearer, module string) (held, error) {
	key := sha256.Sum256([]byte(bearer + "\x00" + module))
	e.mu.Lock()
	for key, h := range e.held {
		if !e.now().Before(h.renew) {
			delete(e.held, key)
		}
	}
	generation := e.cacheGeneration
	if h, ok := e.held[key]; ok && e.now().Before(h.renew) {
		e.mu.Unlock()
		return h, nil
	}
	e.mu.Unlock()
	ctx, cancel := context.WithTimeout(metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+bearer), 10*time.Second)
	defer cancel()
	issued, err := e.Authority.Issue(ctx, &authorityv1.IssueRequest{
		As:       &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}},
		Audience: module,
	})
	if err != nil {
		return held{}, err
	}
	if issued.GetToken() == "" {
		return held{}, status.Error(codes.Internal, "the authority issued no Work Context")
	}
	expires := time.Unix(issued.GetExpiresAtUnix(), 0)
	lead := expires.Sub(e.now()) / 2
	if lead > 30*time.Second {
		lead = 30 * time.Second
	}
	h := held{bearer: sha256.Sum256([]byte(bearer)), token: issued.GetToken(), installation: issued.GetContext().GetSeal().GetInstallationId(), renew: expires.Add(-lead)}
	e.mu.Lock()
	if e.held == nil {
		e.held = map[[32]byte]held{}
	}
	if generation == e.cacheGeneration && e.now().Before(h.renew) {
		e.held[key] = h
	}
	e.mu.Unlock()
	return h, nil
}

func (e *Edge) signIn(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		e.signInPage(w, r)
		return
	}
	if r.Method != http.MethodPost {
		refuse(w, http.StatusMethodNotAllowed, "sign in with GET for the page or POST for a session")
		return
	}
	// Signing a browser in is a write: another site must not sign it in as
	// someone else.
	if !sameOrigin(r) {
		refuse(w, http.StatusForbidden, "a sign-in must come from this origin")
		return
	}
	form := !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
	var fixture, back string
	if form {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil {
			refuse(w, http.StatusBadRequest, "a sign-in names a fixture token")
			return
		}
		fixture, back = r.PostForm.Get("fixtureToken"), r.PostForm.Get("return")
	} else {
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
	if form {
		http.Redirect(w, r, localPath(back), http.StatusSeeOther)
		return
	}
	// A caller that is not a browser (a CLI applying an agent bundle) presents
	// the bearer itself on each call, so the JSON answer hands it back as the
	// session interface does; the cookie above carries the same value.
	writeJSON(w, http.StatusOK, map[string]string{"personId": sess.GetPersonId(), "organizationId": sess.GetOrganizationId(), "bearer": sess.GetBearer()})
}

// signOut ends the browser's session here; it is a write, so it must come
// from this origin.
func (e *Edge) signOut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		refuse(w, http.StatusMethodNotAllowed, "sign out with POST")
		return
	}
	if !sameOrigin(r) {
		refuse(w, http.StatusForbidden, "a sign-out must come from this origin")
		return
	}
	bearer, _ := bearerOf(r)
	e.evict(bearer)
	http.SetCookie(w, &http.Cookie{Name: SessionKey, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

// localPath is where a sign-in returns the browser: a path on this origin,
// never another site; anything else returns to the root.
func localPath(back string) string {
	if !strings.HasPrefix(back, "/") || strings.HasPrefix(back, "//") || strings.HasPrefix(back, "/\\") {
		return "/"
	}
	return back
}

func (e *Edge) session(w http.ResponseWriter, r *http.Request) {
	bearer, _ := bearerOf(r)
	if bearer == "" {
		refuse(w, http.StatusUnauthorized, "no session: sign in at /auth/sign-in")
		return
	}
	sess, err := e.Sessions.Current(metadata.AppendToOutgoingContext(r.Context(), "authorization", "Bearer "+bearer), &sessionv1.CurrentRequest{})
	if err != nil {
		if status.Code(err) == codes.Unauthenticated {
			e.evict(bearer)
			refuse(w, http.StatusUnauthorized, status.Convert(err).Message())
		} else {
			refuse(w, http.StatusServiceUnavailable, "the authority could not answer Current: "+status.Convert(err).Message())
		}
		return
	}
	usable, refused := e.usable(r.Context(), bearer)
	e.namespaces(r.Context(), bearer, sess.GetOrganizationId(), usable)
	writeJSON(w, http.StatusOK, map[string]any{
		"personId": sess.GetPersonId(), "organizationId": sess.GetOrganizationId(), "roles": sess.GetRoles(),
		"personDisplayName": sess.GetPersonDisplayName(), "organizationDisplayName": sess.GetOrganizationDisplayName(),
		"installations": usable, "refused": refused,
	})
}

// evict drops this bearer's cached authority and fences in-flight cache writes.
func (e *Edge) evict(bearer string) {
	digest := sha256.Sum256([]byte(bearer))
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cacheGeneration++
	for key, h := range e.held {
		if h.bearer == digest || !e.now().Before(h.renew) {
			delete(e.held, key)
		}
	}
}

// usable asks each target independently. Every failure retains its named reason
// without hiding the session or waiting serially for each target's timeout.
func (e *Edge) usable(ctx context.Context, bearer string) ([]installation, map[string]string) {
	type result struct {
		name string
		wc   held
		err  error
	}
	results := make(chan result, len(e.Modules))
	for name := range e.Modules {
		go func() { wc, err := e.workContext(ctx, bearer, name); results <- result{name, wc, err} }()
	}
	usable, refused := []installation{}, map[string]string{}
	for range e.Modules {
		r := <-results
		if r.err != nil {
			refused[r.name] = status.Convert(r.err).Message()
			continue
		}
		if r.wc.installation == "" {
			refused[r.name] = "the authority sealed the person's Work Context at " + r.name + " to no installation"
			continue
		}
		usable = append(usable, installation{ID: r.wc.installation, Target: r.name})
	}
	sort.Slice(usable, func(i, j int) bool { return usable[i].Target < usable[j].Target })
	return usable, refused
}

// namespaces names the namespace of each usable installation from List, the
// one read that carries it. List is an administrator's read, so for anyone a
// host refuses it to the namespace stays unnamed, and a frontend that needs one
// says so rather than guess it. Nothing about who may use an installation is
// read here. A stopgap until a member's read carries the namespace.
func (e *Edge) namespaces(ctx context.Context, bearer, organization string, usable []installation) {
	if e.Installations == nil || len(usable) == 0 {
		return
	}
	listed, err := e.Installations.List(metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+bearer), &installationv1.ListRequest{OrganizationId: organization})
	if err != nil {
		return
	}
	named := map[string]string{}
	for _, i := range listed.GetInstallations() {
		named[i.GetId()] = i.GetNamespace()
	}
	for i := range usable {
		usable[i].Namespace = named[usable[i].ID]
	}
}

// installation is one installation a frontend may bind a call to: its id, the
// module or solution installed, and the namespace its authored content belongs
// to (an agent's source).
type installation struct {
	ID        string `json:"id"`
	Target    string `json:"target"`
	Namespace string `json:"namespace,omitempty"`
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
		// Never through a proxy from the environment, which would read the
		// person's Work Context.
		Transport: host.HTTPTransport(),
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
