package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	installationv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/installation/v1"
	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/host"
	"github.com/codefly-dev/sdk-go/receipts"
	"github.com/google/uuid"
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
	// End ends the bearer's session and every role view and cast opened from
	// it, at the host: a sign-out, and the way back from a cast (session.go).
	End(ctx context.Context, in *sessionv1.EndRequest, opts ...grpc.CallOption) (*sessionv1.EndResponse, error)
	ListFixturePeople(ctx context.Context, in *sessionv1.ListFixturePeopleRequest, opts ...grpc.CallOption) (*sessionv1.ListFixturePeopleResponse, error)
	// OpenTeamCast opens a session that acts as one team and nothing else
	// (actas.go); the authority decides whether the caller may.
	OpenTeamCast(ctx context.Context, in *sessionv1.OpenTeamCastRequest, opts ...grpc.CallOption) (*sessionv1.Session, error)
	// ListCastableTeams is the teams the caller may act as, with what each
	// holds (session_face.go); the authority lists them by its own rule.
	ListCastableTeams(ctx context.Context, in *sessionv1.ListCastableTeamsRequest, opts ...grpc.CallOption) (*sessionv1.ListCastableTeamsResponse, error)
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
// for the procedures it publishes (/package.Service/Method, routes.go).
type Module struct {
	Name       string
	REST       *url.URL
	Connect    *url.URL
	Procedures []string
}

// Edge serves the browser.
type Edge struct {
	// Credential is this edge's workload credential, read on each use
	// (hop.RunCredential): what proves to the authority that a page it names
	// is the module edge's. Nil reads the run's.
	Credential    func() (string, error)
	SignInChoices []signInChoice
	Sessions      Sessions
	Authority     Issuer
	Installations Installations
	// Offers and Installer serve the setup page and the host face
	// (host_connect.go); nil serves neither.
	Offers    Offers
	Installer Installer
	// Delegations serves a page's delegation of a run on the host face
	// (host_connect.go); nil serves none.
	Delegations Delegations
	Modules     map[string]Module
	// Frontend serves every path no module claims; nil serves none.
	Frontend *url.URL
	Now      func() time.Time

	mu              sync.Mutex
	held            map[[32]byte]held
	cacheGeneration uint64
	// setupKnown and setupServed are the host's answer to whether it serves
	// OfferService, once it has given a definite one (servesSetup).
	setupKnown, setupServed bool
	// faceOnce builds face, the host face's procedures (host_connect.go).
	faceOnce sync.Once
	face     http.Handler
}

type held struct {
	bearer [32]byte
	token  string
	// installation is the installation the authority sealed the context to.
	installation string
	renew        time.Time
	// epoch is the session's grant epoch, as Current stated it, when this
	// context was asked for: once Current states another, what the session
	// holds has changed and the context is dropped (workContext).
	epoch string
	// cached: this copy was handed out of what the edge held, not issued for
	// the call asking; never set on what is held.
	cached bool
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
	case "/auth/act-as":
		e.actAs(w, r)
		return
	case "/auth/setup":
		served, err := e.servesSetup(r.Context())
		switch {
		case err != nil:
			refuse(w, http.StatusServiceUnavailable, "the host did not say whether it serves the setup page: "+status.Convert(err).Message())
		case !served:
			refuse(w, http.StatusNotFound, "this host serves no setup page: only the local authority serves OfferService")
		default:
			e.setup(w, r)
		}
		return
	}
	if strings.HasPrefix(r.URL.Path, "/auth/assets/") {
		e.signInAsset(w, r)
		return
	}
	if isHostPath(r.URL.Path) {
		e.toHost(w, r)
		return
	}
	if page, procedure, aimed, ok := pageCall(r); aimed {
		if !ok {
			refuseCall(w, r, http.StatusNotFound, "not a page's module call: POST /api/solutions/<alias>/proxy/_browser/<package.Service>/<Method>")
			return
		}
		module, target, routed := e.route(procedure)
		if !routed || module.REST != nil && target == module.REST {
			refuseCall(w, r, http.StatusNotFound, "no module serves "+procedure)
			return
		}
		out := r.Clone(context.WithValue(r.Context(), pageKey{}, page))
		out.URL.Path, out.URL.RawPath = procedure, ""
		out.RequestURI = out.URL.RequestURI()
		e.toModule(w, out, module, target)
		return
	}
	if module, target, ok := e.route(r.URL.Path); ok {
		e.toModule(w, r, module, target)
		return
	}
	if e.Frontend == nil {
		refuseCall(w, r, http.StatusNotFound, "no module serves "+r.URL.Path)
		return
	}
	proxy(e.Frontend, "", "", w, r)
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
	// A procedure is routed exactly when a module publishes it: a method the
	// module's catalog does not declare is no module's, and one procedure has
	// one publisher (mount refuses a second).
	for _, m := range e.Modules {
		if m.Connect != nil && slices.Contains(m.Procedures, path) {
			return m, m.Connect, true
		}
	}
	return Module{}, nil, false
}

func (e *Edge) toModule(w http.ResponseWriter, r *http.Request, module Module, target *url.URL) {
	bearer, fromCookie := bearerOf(r)
	if bearer == "" {
		refuseCall(w, r, http.StatusUnauthorized, "no session: sign in at /auth/sign-in")
		return
	}
	// A cookie rides every request the browser makes to this origin, including
	// one another site causes; a write authenticated by it must say it comes
	// from this origin. A caller presenting its bearer itself is not a browser
	// being steered.
	if fromCookie && r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r) {
		refuseCall(w, r, http.StatusForbidden, "a write must come from this origin")
		return
	}
	// Who the bearer is, read now and never from what the edge holds: a
	// session ended or expired at the host reaches no module though a Work
	// Context issued for it has not lapsed, and its grant epoch says whether
	// what it holds is still what a held context was issued for.
	sess, err := e.currentSession(r.Context(), bearer)
	if err != nil {
		if status.Code(err) == codes.Unauthenticated {
			e.evict(bearer)
			refuseCall(w, r, http.StatusUnauthorized, "no open session: sign in at /auth/sign-in ("+status.Convert(err).Message()+")")
		} else {
			refuseCall(w, r, http.StatusServiceUnavailable, "the authority could not answer Current: "+status.Convert(err).Message())
		}
		return
	}
	issue := func() (held, bool) {
		wc, err := e.workContext(r.Context(), bearer, module.Name, pageOf(r), sess.GetGrantEpoch())
		if err != nil {
			code := http.StatusForbidden
			if status.Code(err) == codes.Unauthenticated {
				code = http.StatusUnauthorized
			}
			refuseCall(w, r, code, "the authority refused this person at "+module.Name+": "+status.Convert(err).Message())
		}
		return wc, err == nil
	}
	wc, ok := issue()
	if !ok {
		return
	}
	// Each module call is its own effect, minted here: an operation that keeps
	// receipts requires an effect id, and a browser may not name one.
	if !wc.cached {
		proxy(target, wc.token, uuid.NewString(), w, r)
		return
	}
	// A held context is the person's roles as they were when it was issued,
	// and nothing tells the edge they changed since: a role granted is not in
	// it, and a revoke that leaves them another role ends it. The module's
	// refusal of a held context is therefore not yet the person's answer: the
	// edge drops it, asks the authority again and sends the call once more,
	// as a new effect. A refusal of a context issued for this call is.
	again := replayable(r)
	send(target, wc.token, uuid.NewString(), w, r, func(res *http.Response) bool {
		if !refusedByModule(res) {
			return false
		}
		e.forget(bearer, module.Name, pageOf(r), wc.token)
		return again != nil
	}, func() {
		if fresh, ok := issue(); ok {
			proxy(target, fresh.token, uuid.NewString(), w, again())
		}
	})
}

// refusedByModule is whether the module's face (the hop behind it) refused the
// call's Work Context: 401 or 403, or a gRPC answer of nothing but
// Unauthenticated or PermissionDenied.
func refusedByModule(res *http.Response) bool {
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return true
	}
	code := res.Header.Get("Grpc-Status")
	return code == strconv.Itoa(int(codes.PermissionDenied)) || code == strconv.Itoa(int(codes.Unauthenticated))
}

// replayBytes is the largest body the edge keeps to send a call again.
const replayBytes = 1 << 20

// replayable keeps r's body when it can be sent a second time, and answers the
// call to send again; nil when it cannot: a body whose length is not known (a
// stream, which is never read ahead) or is more than replayBytes.
func replayable(r *http.Request) func() *http.Request {
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return func() *http.Request { return r.Clone(r.Context()) }
	}
	if r.ContentLength < 0 || r.ContentLength > replayBytes {
		return nil
	}
	body := r.Body
	kept, err := io.ReadAll(io.LimitReader(body, r.ContentLength))
	if err != nil || int64(len(kept)) != r.ContentLength {
		// What was read is sent on with the rest, which fails as it would have.
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(kept), body), body}
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(kept))
	return func() *http.Request {
		out := r.Clone(r.Context())
		out.Body = io.NopCloser(bytes.NewReader(kept))
		return out
	}
}

// heldKey is what a held Work Context is kept under.
func heldKey(bearer, module, page string) [32]byte {
	return sha256.Sum256([]byte(bearer + "\x00" + module + "\x00" + page))
}

// forget drops the Work Context held for bearer at module and page when it is
// still token: a call refused with an older one leaves a fresh one held.
func (e *Edge) forget(bearer, module, page, token string) {
	key := heldKey(bearer, module, page)
	e.mu.Lock()
	defer e.mu.Unlock()
	if h, ok := e.held[key]; ok && h.token == token {
		delete(e.held, key)
	}
}

// rolesChanged drops every Work Context the edge holds and fences in-flight
// cache writes: a role was granted or revoked through this edge, to a person
// or to a team whose members the edge does not know, so anything held may be
// from before it.
func (e *Edge) rolesChanged() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cacheGeneration++
	clear(e.held)
}

// workContext is the person's Work Context at module, issued by the authority
// for everything the person holds there and held until shortly before it
// lapses, or until what the session holds changes: epoch is the session's
// grant epoch as Current states it now, and a context held from another epoch
// is dropped, so a grant or a revoke made anywhere applies from this call. A
// host that states no epoch (empty) leaves a held context until it lapses or
// a module refuses it. The hop narrows each call to what its method requires.
func (e *Edge) workContext(ctx context.Context, bearer, module, page, epoch string) (held, error) {
	key := heldKey(bearer, module, page)
	e.mu.Lock()
	for key, h := range e.held {
		if !e.now().Before(h.renew) {
			delete(e.held, key)
		}
	}
	generation := e.cacheGeneration
	if h, ok := e.held[key]; ok && h.epoch != epoch {
		delete(e.held, key)
	} else if ok && e.now().Before(h.renew) {
		e.mu.Unlock()
		h.cached = true
		return h, nil
	}
	e.mu.Unlock()
	ctx, cancel := context.WithTimeout(metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+bearer), 10*time.Second)
	defer cancel()
	req := &authorityv1.IssueRequest{
		As:         &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}},
		Audience:   module,
		PageTarget: page,
	}
	if page != "" {
		// The page is this host's module edge's to name, and the authority
		// takes it from no one else: the edge proves itself with its own
		// workload credential (module-identity), as the hop does.
		credential, err := e.credential()
		if err != nil {
			return held{}, status.Error(codes.Unavailable, "the edge holds no workload credential to name a page with: "+err.Error())
		}
		req.Actor = &authorityv1.WorkloadCredential{Credential: credential}
	}
	issued, err := e.Authority.Issue(ctx, req)
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
	h := held{bearer: sha256.Sum256([]byte(bearer)), token: issued.GetToken(), installation: issued.GetContext().GetSeal().GetInstallationId(), renew: expires.Add(-lead), epoch: epoch}
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
	cookie, err := e.sessionCookie(SessionKey, sess.GetBearer(), sess)
	if err != nil {
		// Not a session this edge keeps: it is ended rather than left open.
		_ = e.end(r.Context(), sess.GetBearer())
		refuse(w, http.StatusBadGateway, "the sign-in opened no session the edge keeps: "+err.Error())
		return
	}
	http.SetCookie(w, cookie)
	// A sign-in is a new person's session: the way back a cast kept (actAs)
	// goes with the session it belonged to, so a later "back" never restores
	// an earlier person's session with no credential.
	http.SetCookie(w, clearedCookie(ParentKey))
	if form {
		http.Redirect(w, r, localPath(back), http.StatusSeeOther)
		return
	}
	// A caller that is not a browser (a CLI applying an agent bundle) presents
	// the bearer itself on each call, so the JSON answer hands it back as the
	// session interface does; the cookie above carries the same value.
	writeJSON(w, http.StatusOK, map[string]any{"personId": sess.GetPersonId(), "organizationId": sess.GetOrganizationId(), "bearer": sess.GetBearer(), "expiresAtUnix": sess.GetExpiresAtUnix()})
}

// signOut ends the browser's session, here and at the host (End): the cookie
// is cleared, what the edge held for it is dropped, and a copy of its bearer
// is unauthenticated from then on. From a cast it ends the session the cast
// was opened from too, the one the way back kept: signing out leaves no
// session of the person's this browser held. It is a write, so it must come
// from this origin. When the host did not end a session the browser is signed
// out here all the same, and is told so.
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
	bearers := []string{bearer}
	if parent, err := r.Cookie(ParentKey); err == nil {
		bearers = append(bearers, parent.Value)
	}
	var failed error
	for _, b := range bearers {
		if b == "" {
			continue
		}
		e.evict(b)
		if err := e.end(r.Context(), b); err != nil {
			failed = err
		}
	}
	for _, name := range []string{SessionKey, ParentKey} {
		http.SetCookie(w, clearedCookie(name))
	}
	if failed != nil {
		refuse(w, http.StatusServiceUnavailable, "this browser is signed out, and the host did not end the session, which lasts until it expires: "+status.Convert(failed).Message())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// localPath is where a sign-in returns the browser: a path on this origin,
// never another site; anything else returns to the root.
//
// It is judged as a browser reads it, not as it is spelled: a browser strips
// tab, line feed and carriage return from a URL before it parses it and reads
// a backslash as a slash, so "/<TAB>/elsewhere.test" is "//elsewhere.test" to
// it, another site. A return therefore carries no control character, space or
// backslash anywhere, parses as a URL with no scheme, no host and no user, and
// its path starts with one slash and has no empty segment.
func localPath(back string) string {
	for i := 0; i < len(back); i++ {
		if c := back[i]; c <= ' ' || c == 0x7f || c == '\\' {
			return "/"
		}
	}
	u, err := url.Parse(back)
	if err != nil || u.Scheme != "" || u.Opaque != "" || u.Host != "" || u.User != nil ||
		!strings.HasPrefix(u.Path, "/") || strings.Contains(u.Path, "//") {
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
	sess, err := e.currentSession(r.Context(), bearer)
	if err != nil {
		if status.Code(err) == codes.Unauthenticated {
			e.evict(bearer)
			refuse(w, http.StatusUnauthorized, status.Convert(err).Message())
		} else {
			refuse(w, http.StatusServiceUnavailable, "the authority could not answer Current: "+status.Convert(err).Message())
		}
		return
	}
	usable, refused, err := e.usable(r.Context(), bearer, sess.GetOrganizationId(), sess.GetGrantEpoch())
	if err != nil {
		// What the person may open is not known, and an answer without it
		// would read as their holding nothing: a page with no backend of its
		// own is listed by the host's answer alone.
		log.Printf("edge: the host did not answer which installations a person of %q holds a role on (ListHeld), so their session is not answered: %v", sess.GetOrganizationId(), err)
		refuse(w, http.StatusServiceUnavailable, "the host did not answer which installations this person holds a role on, so what they may open is not known: "+status.Convert(err).Message())
		return
	}
	e.namespaces(r.Context(), bearer, sess.GetOrganizationId(), usable)
	writeJSON(w, http.StatusOK, map[string]any{
		// This edge mounts its public module procedures at the root. Publish
		// that path, never a listener/upstream address or a request-derived origin.
		"moduleApiBase": "/",
		"personId":      sess.GetPersonId(), "organizationId": sess.GetOrganizationId(), "roles": sess.GetRoles(),
		"personDisplayName": sess.GetPersonDisplayName(), "organizationDisplayName": sess.GetOrganizationDisplayName(),
		// A cast: the session acts as this team and nothing else (actas.go).
		"teamIds": nonNil(sess.GetTeamIds()), "castTeamId": sess.GetCastTeamId(),
		"installations": usable, "refused": refused,
		// When the session ends on its own, as the host states it.
		"expiresAtUnix": sess.GetExpiresAtUnix(),
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
//
// A page whose roles reach only through its bindings (a solution serving
// nothing of its own) is issued nothing at itself: the authority hands nobody
// an empty capability, and decides each of the page's calls through the
// binding (IssueForPage). Whether such a page is the person's to open is the
// host's answer to which installations they hold a role on (ListHeld), so a
// target the person holds a role on is usable with that installation, its
// refusal at the target itself dropped.
//
// A page with no backend of its own (neither a REST nor a Connect face) is no
// module this edge routes to, so nothing is asked at it and nothing refuses
// it: the host's answer alone lists it, once, for a person who holds a role on
// its installation, and it is absent for everyone else.
//
// Only the authority's refusal to issue at a target is what a holding
// answers: a target the authority did not answer at stays refused though the
// host lists a role on it. And a host that did not answer what the person
// holds has not said they hold nothing: a page with no backend of its own has
// no entry to say that under, so nothing is answered and the error is the
// host's (session answers 503).
func (e *Edge) usable(ctx context.Context, bearer, organization, epoch string) ([]installation, map[string]string, error) {
	type result struct {
		name string
		wc   held
		err  error
	}
	results := make(chan result, len(e.Modules))
	for name := range e.Modules {
		go func() { wc, err := e.workContext(ctx, bearer, name, "", epoch); results <- result{name, wc, err} }()
	}
	usable, refused := []installation{}, map[string]string{}
	// heldAnswers are the refused targets a holding makes the person's to open.
	heldAnswers := map[string]bool{}
	for range e.Modules {
		r := <-results
		if r.err != nil {
			refused[r.name] = status.Convert(r.err).Message()
			if code := status.Code(r.err); code == codes.PermissionDenied || code == codes.FailedPrecondition {
				heldAnswers[r.name] = true
			}
			continue
		}
		if r.wc.installation == "" {
			refused[r.name] = "the authority sealed the person's Work Context at " + r.name + " to no installation"
			heldAnswers[r.name] = true
			continue
		}
		usable = append(usable, installation{ID: r.wc.installation, Target: r.name, ModuleAPIBase: pageRoute(r.name)})
	}
	listed := map[string]bool{}
	for _, u := range usable {
		listed[u.Target] = true
	}
	pages, err := e.heldPages(ctx, bearer, organization)
	if err != nil {
		return nil, nil, err
	}
	for _, page := range pages {
		if _, was := refused[page.Target]; listed[page.Target] || was && !heldAnswers[page.Target] {
			continue
		}
		listed[page.Target] = true
		delete(refused, page.Target)
		usable = append(usable, page)
	}
	sort.Slice(usable, func(i, j int) bool { return usable[i].Target < usable[j].Target })
	return usable, refused, nil
}

// heldPages are the active installations the person holds a role on, as the
// host answers (ListHeld); none when the edge composes no installation
// interface or the host serves no ListHeld (Unimplemented). Any other failure
// to answer is an error: it is never the person holding nothing.
func (e *Edge) heldPages(ctx context.Context, bearer, organization string) ([]installation, error) {
	if e.Installer == nil || organization == "" {
		return nil, nil
	}
	held, err := e.Installer.ListHeld(metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+bearer), &installationv1.ListHeldRequest{OrganizationId: organization})
	if status.Code(err) == codes.Unimplemented {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []installation
	for _, h := range held.GetInstallations() {
		i := h.GetInstallation()
		if len(h.GetRoles()) == 0 || i.GetStatus() != installationv1.Installation_STATUS_ACTIVE {
			continue
		}
		out = append(out, installation{ID: i.GetId(), Target: i.GetTarget(), ModuleAPIBase: pageRoute(i.GetTarget())})
	}
	return out, nil
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
	// ModuleAPIBase is the page route this edge serves for the target's page,
	// /api/solutions/<target>/proxy/_browser (pageCall): what a shell hands the
	// page as its moduleApiBase, read here rather than spelled by every shell.
	ModuleAPIBase string `json:"moduleApiBase,omitempty"`
}

// pageRoute is the base a page of target reaches its modules at, or empty for
// a target no page route can name.
func pageRoute(target string) string {
	if !pageAlias.MatchString(target) {
		return ""
	}
	return pageCallPrefix + target + "/proxy/_browser"
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
// x-codefly-* header leaves the edge unless the edge set it. effect, when set,
// is the effect id the call is attempted under: the edge names every module
// call's effect, so a caller can never name one and replay another person's
// receipt.
func proxy(target *url.URL, token, effect string, w http.ResponseWriter, r *http.Request) {
	send(target, token, effect, w, r, nil, nil)
}

// errAskAgain is the module's answer withheld from the caller (send).
var errAskAgain = errors.New("the module refused a held Work Context")

// send is proxy, with the module's answer shown to withhold before any of it
// reaches the caller: when withhold says so the answer is dropped and again
// answers the caller instead.
func send(target *url.URL, token, effect string, w http.ResponseWriter, r *http.Request, withhold func(*http.Response) bool, again func()) {
	rp := &httputil.ReverseProxy{
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
			if effect != "" {
				// Idempotency-Key is the SDK's HTTP spelling of the effect id;
				// a caller's would be a second effect id beside the minted one.
				pr.Out.Header.Del(receipts.IdempotencyKeyHeaderName)
				pr.Out.Header.Set(receipts.EffectIDHeaderName, effect)
			}
		},
		// The transport error can name the module's internal address: the
		// edge's log is told it, the caller is told what happened.
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, errAskAgain) {
				again()
				return
			}
			log.Printf("edge: the module did not answer %s %s: %v", r.Method, r.URL.Path, err)
			refuseCall(w, r, http.StatusBadGateway, "the module did not answer")
		},
	}
	if withhold != nil {
		rp.ModifyResponse = func(res *http.Response) error {
			if withhold(res) {
				return errAskAgain
			}
			return nil
		}
	}
	rp.ServeHTTP(w, r)
}

// connectRefusal answers in Connect's (or gRPC's) words only a caller that
// says it speaks the protocol: a Connect-Protocol-Version header, or
// ?connect=v1 on a GET, or a gRPC content type. Every other caller, a REST or
// form caller included, keeps {"error": reason}.
var connectRefusal = connect.NewErrorWriter(connect.WithRequireConnectProtocolHeader())

// refuseCall refuses a call; a Connect caller is answered in Connect's words,
// so its client keeps the reason and reads the right kind of answer. Only a
// decision about the person is a denial: a call nothing here serves (404) is
// unimplemented, never permission denied, and a host that did not answer
// (503) is unavailable.
func refuseCall(w http.ResponseWriter, r *http.Request, code int, reason string) {
	if connectRefusal.IsSupported(r) {
		c := connect.CodePermissionDenied
		switch code {
		case http.StatusUnauthorized:
			c = connect.CodeUnauthenticated
		case http.StatusNotFound:
			c = connect.CodeUnimplemented
		case http.StatusBadGateway, http.StatusServiceUnavailable:
			c = connect.CodeUnavailable
		}
		_ = connectRefusal.Write(w, r, connect.NewError(c, errors.New(reason)))
		return
	}
	refuse(w, code, reason)
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

// A page's module call, at the path a hosted page reaches its modules on
// (/api/solutions/<alias>/proxy/_browser/<package.Service>/<Method>, the
// saas host's own): the edge names the page to the authority's Issue
// (page_target), which issues through the page's target's binding to the
// module when the target declares one, the person present on the page, and
// on the person's own access otherwise. The page is the path's, never a
// header a browser sent, and is a route alias or nothing; the held context
// is keyed on it, as the saas gateway keys its own.
const pageCallPrefix = "/api/solutions/"

var (
	pageAlias     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	pageProcedure = regexp.MustCompile(`^/(?:[A-Za-z_][A-Za-z0-9_]*\.)+[A-Za-z_][A-Za-z0-9_]*/[A-Za-z_][A-Za-z0-9_]*$`)
)

type pageKey struct{}

// pageCall is the page and the module procedure a page's module call names.
// aimed: the path is one (under /api/solutions/<…>/proxy/_browser), which
// nothing else serves; ok: it is well formed, and is served as one.
func pageCall(r *http.Request) (page, procedure string, aimed, ok bool) {
	rest, found := strings.CutPrefix(r.URL.Path, pageCallPrefix)
	if !found {
		return "", "", false, false
	}
	page, rest, found = strings.Cut(rest, "/proxy/_browser")
	if !found {
		return "", "", false, false
	}
	if r.Method != http.MethodPost || r.URL.EscapedPath() != r.URL.Path || !pageAlias.MatchString(page) ||
		!pageProcedure.MatchString(rest) || strings.HasPrefix(rest, "/host.") || strings.HasPrefix(rest, "/saas.") {
		return "", "", true, false
	}
	return page, rest, true, true
}

func pageOf(r *http.Request) string {
	page, _ := r.Context().Value(pageKey{}).(string)
	return page
}

func (e *Edge) credential() (string, error) {
	if e.Credential != nil {
		return e.Credential()
	}
	return hop.RunCredential()
}
