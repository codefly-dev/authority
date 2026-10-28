package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	installationv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/installation/v1"
	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// standIn is the authority for one fixture person, Rémi, whose session bearer
// is "remi-session": Acme's records installation is his to use, he holds
// nothing at "secrets", "wiki" is not installed at Acme, and "down" does not
// answer.
type standIn struct {
	mu     sync.Mutex
	issued []string
}

func bearerIn(ctx context.Context) string {
	md, _ := metadata.FromOutgoingContext(ctx)
	if v := md.Get("authorization"); len(v) == 1 {
		return strings.TrimPrefix(v[0], "Bearer ")
	}
	return ""
}

func (s *standIn) SignIn(_ context.Context, in *sessionv1.SignInRequest, _ ...grpc.CallOption) (*sessionv1.Session, error) {
	if in.GetFixtureToken() != "fixture-remi" {
		return nil, status.Error(codes.NotFound, "no such fixture person")
	}
	return &sessionv1.Session{SessionId: "s1", PersonId: "remi", OrganizationId: "acme", PersonDisplayName: "Rémi", OrganizationDisplayName: "Acme", Bearer: "remi-session"}, nil
}

func (s *standIn) Current(ctx context.Context, _ *sessionv1.CurrentRequest, _ ...grpc.CallOption) (*sessionv1.Session, error) {
	if bearerIn(ctx) != "remi-session" {
		return nil, status.Error(codes.Unauthenticated, "no session")
	}
	return &sessionv1.Session{SessionId: "s1", PersonId: "remi", OrganizationId: "acme", PersonDisplayName: "Rémi", OrganizationDisplayName: "Acme"}, nil
}

func (s *standIn) ListFixturePeople(context.Context, *sessionv1.ListFixturePeopleRequest, ...grpc.CallOption) (*sessionv1.ListFixturePeopleResponse, error) {
	return &sessionv1.ListFixturePeopleResponse{People: []*sessionv1.FixturePerson{{PersonId: "remi", Email: "remi@acme.test", OrganizationId: "acme", OrganizationDisplayName: "Acme", Roles: []string{"editor"}, FixtureToken: "fixture-remi"}}}, nil
}

func (s *standIn) Issue(ctx context.Context, in *authorityv1.IssueRequest, _ ...grpc.CallOption) (*authorityv1.IssueResponse, error) {
	if bearerIn(ctx) != "remi-session" || in.GetPerson() == nil {
		return nil, status.Error(codes.Unauthenticated, "no session")
	}
	switch in.GetAudience() {
	case "secrets":
		return nil, status.Error(codes.PermissionDenied, "remi holds nothing at secrets")
	case "wiki":
		return nil, status.Error(codes.FailedPrecondition, `audience "wiki" is not installed in this organization, so there is no installation to seal the capability to`)
	case "down":
		return nil, status.Error(codes.Unavailable, "connection refused")
	}
	s.mu.Lock()
	s.issued = append(s.issued, in.GetAudience())
	s.mu.Unlock()
	return &authorityv1.IssueResponse{
		Token: "wc-" + in.GetAudience(), ExpiresAtUnix: time.Now().Add(5 * time.Minute).Unix(),
		Context: &authorityv1.WorkContextV1{Seal: &authorityv1.WorkSealV1{InstallationId: recordsInstallation}},
	}, nil
}

// recordsInstallation is Acme's installation of records.
const recordsInstallation = "4f0c5b1e-0000-5000-8000-000000000001"

// List answers Acme's installations, as a host answers an administrator:
// records active, a solution still pending.
func (s *standIn) List(ctx context.Context, in *installationv1.ListRequest, _ ...grpc.CallOption) (*installationv1.ListResponse, error) {
	if bearerIn(ctx) != "remi-session" {
		return nil, status.Error(codes.Unauthenticated, "no session")
	}
	if in.GetOrganizationId() != "acme" {
		return nil, status.Error(codes.PermissionDenied, "not acme")
	}
	return &installationv1.ListResponse{Installations: []*installationv1.Installation{
		{Id: recordsInstallation, OrganizationId: "acme", Target: "records", Status: installationv1.Installation_STATUS_ACTIVE, Namespace: "acme.records"},
		{Id: "4f0c5b1e-0000-5000-8000-000000000002", OrganizationId: "acme", Target: "proposals", Status: installationv1.Installation_STATUS_PENDING},
	}}, nil
}

// upstream records what each call arrived with.
type upstream struct {
	*httptest.Server
	mu   sync.Mutex
	seen []http.Header
	path []string
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.seen, u.path = append(u.seen, r.Header.Clone()), append(u.path, r.URL.Path)
		u.mu.Unlock()
		_, _ = w.Write([]byte("answered"))
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *upstream) last() (http.Header, string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.seen) == 0 {
		return nil, ""
	}
	return u.seen[len(u.seen)-1], u.path[len(u.path)-1]
}

func mustURL(t *testing.T, s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

type fixture struct {
	edge                             *httptest.Server
	authority                        *standIn
	rest, connect, frontend, secrets *upstream
}

func newFixture(t *testing.T) fixture {
	f := fixture{authority: &standIn{}, rest: newUpstream(t), connect: newUpstream(t), frontend: newUpstream(t), secrets: newUpstream(t)}
	e := &Edge{Sessions: f.authority, Authority: f.authority, Installations: f.authority, Frontend: mustURL(t, f.frontend.URL), Modules: map[string]Module{
		"records": {Name: "records", REST: mustURL(t, f.rest.URL), Connect: mustURL(t, f.connect.URL), Services: []string{"records.v1.RecordsService"}},
		"secrets": {Name: "secrets", REST: mustURL(t, f.secrets.URL)},
	}}
	f.edge = httptest.NewServer(e)
	t.Cleanup(f.edge.Close)
	return f
}

func (f fixture) do(t *testing.T, method, path string, header http.Header) (*http.Response, string) {
	t.Helper()
	return f.send(t, method, path, header, "{}")
}

func (f fixture) send(t *testing.T, method, path string, header http.Header, payload string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, f.edge.URL+path, strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := res.Body.Read(buf)
		body.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return res, body.String()
}

func (f fixture) signIn(t *testing.T) *http.Cookie {
	t.Helper()
	res, body := f.signInAs(t, "fixture-remi", "/records", f.edge.URL)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/records" {
		t.Fatalf("sign-in answered %d: %s", res.StatusCode, body)
	}
	for _, c := range res.Cookies() {
		if c.Name == SessionKey {
			if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Value != "remi-session" {
				t.Fatalf("session cookie %+v", c)
			}
			return c
		}
	}
	t.Fatal("sign-in set no session cookie")
	return nil
}

// signInAs posts the sign-in page's form.
func (f fixture) signInAs(t *testing.T, token, back, origin string) (*http.Response, string) {
	t.Helper()
	form := url.Values{"fixtureToken": {token}, "return": {back}}
	return f.send(t, http.MethodPost, "/auth/sign-in", http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Origin": {origin}}, form.Encode())
}

// A person signs in at the edge and holds a session cookie the frontend cannot
// read; the edge answers who is signed in.
func TestAPersonSignsInAtTheEdge(t *testing.T) {
	f := newFixture(t)
	cookie := f.signIn(t)
	res, body := f.do(t, http.MethodGet, "/auth/session", http.Header{"Cookie": {cookie.String()}})
	var who map[string]any
	_ = json.Unmarshal([]byte(body), &who)
	if res.StatusCode != http.StatusOK || who["personId"] != "remi" || who["organizationId"] != "acme" || who["personDisplayName"] != "Rémi" || who["organizationDisplayName"] != "Acme" || who["moduleApiBase"] != "/" {
		t.Fatalf("session answered %d: %s", res.StatusCode, body)
	}
	// What the person may use, which the frontend binds its calls to: records,
	// with the installation the authority sealed his context to; secrets, which
	// is installed but where he holds nothing, refused with the authority's reason.
	installed, _ := who["installations"].([]any)
	if len(installed) != 1 {
		t.Fatalf("installations = %v", who["installations"])
	}
	if records, _ := installed[0].(map[string]any); records["target"] != "records" || records["id"] != recordsInstallation || records["namespace"] != "acme.records" {
		t.Fatalf("installation = %v", records)
	}
	if refused, _ := who["refused"].(map[string]any); len(refused) != 1 || !strings.Contains(refused["secrets"].(string), "holds nothing at secrets") {
		t.Fatalf("refused = %v", who["refused"])
	}
	// The Work Context the session read was issued is the one a call presents.
	if res, _ := f.do(t, http.MethodGet, "/v1/records/types", http.Header{"Cookie": {cookie.String()}}); res.StatusCode != http.StatusOK || len(f.authority.issued) != 1 {
		t.Fatalf("a call after the session read answered %d, issued %v", res.StatusCode, f.authority.issued)
	}
	if res, _ := f.signInAs(t, "nobody", "/", f.edge.URL); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an unknown fixture signed in: %d", res.StatusCode)
	}
}

func TestTheSessionPublishesNoModuleConnectionWithoutASession(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	w := httptest.NewRecorder()
	(&Edge{}).ServeHTTP(w, r)
	var answer map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	_, present := answer["moduleApiBase"]
	if w.Code != http.StatusUnauthorized || present {
		t.Fatalf("unauthenticated session answered %d: %s", w.Code, w.Body)
	}
}

// listing answers List with a fixed error, as a host does that lists an
// organisation's installations for its admins only, or cannot be reached.
type listing struct {
	*standIn
	err error
}

func (l listing) List(context.Context, *installationv1.ListRequest, ...grpc.CallOption) (*installationv1.ListResponse, error) {
	return nil, l.err
}

// sessionOf reads /auth/session from e as the signed-in cookie.
func sessionOf(t *testing.T, e *Edge, cookie *http.Cookie) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	req.AddCookie(cookie)
	e.ServeHTTP(res, req)
	var who map[string]any
	_ = json.Unmarshal(res.Body.Bytes(), &who)
	return res, who
}

// A member is not an administrator: a host refuses them the organisation's
// installation list, and the session still names what they may use, because
// that is the authority's Issue, never the list. Only the namespace, which the
// list alone carries, goes unnamed.
func TestAMemberSeesWhatTheyHoldWithoutTheAdministratorsList(t *testing.T) {
	for _, err := range []error{
		status.Error(codes.PermissionDenied, "requires org admin or owner role"),
		status.Error(codes.Unavailable, "connection refused"),
	} {
		f := newFixture(t)
		cookie := f.signIn(t)
		e := &Edge{Sessions: f.authority, Authority: f.authority, Installations: listing{f.authority, err}, Modules: map[string]Module{
			"records": {Name: "records", REST: mustURL(t, f.rest.URL)},
		}}
		res, who := sessionOf(t, e, cookie)
		installed, _ := who["installations"].([]any)
		if res.Code != http.StatusOK || len(installed) != 1 {
			t.Fatalf("with List answering %v the session answered %d: %s", err, res.Code, res.Body)
		}
		if records, _ := installed[0].(map[string]any); records["target"] != "records" || records["id"] != recordsInstallation || records["namespace"] != nil {
			t.Fatalf("installation = %v", records)
		}
	}
}

// Each target the person cannot use is refused by name with the authority's
// reason: holding nothing there is not the same answer as an organisation that
// never installed it. An unavailable module is refused without losing the session.
func TestTheSessionSaysWhyATargetIsNotUsable(t *testing.T) {
	f := newFixture(t)
	cookie := f.signIn(t)
	modules := map[string]Module{
		"records": {Name: "records", REST: mustURL(t, f.rest.URL)},
		"secrets": {Name: "secrets", REST: mustURL(t, f.secrets.URL)},
		"wiki":    {Name: "wiki", REST: mustURL(t, f.secrets.URL)},
	}
	res, who := sessionOf(t, &Edge{Sessions: f.authority, Authority: f.authority, Modules: modules}, cookie)
	refused, _ := who["refused"].(map[string]any)
	if res.Code != http.StatusOK || len(refused) != 2 {
		t.Fatalf("session answered %d: %s", res.Code, res.Body)
	}
	if reason, _ := refused["secrets"].(string); !strings.Contains(reason, "holds nothing at secrets") {
		t.Errorf("secrets refused as %q", reason)
	}
	if reason, _ := refused["wiki"].(string); !strings.Contains(reason, "not installed") {
		t.Errorf("wiki refused as %q", reason)
	}
	modules["down"] = Module{Name: "down", REST: mustURL(t, f.secrets.URL)}
	if res, _ := sessionOf(t, &Edge{Sessions: f.authority, Authority: f.authority, Modules: modules}, cookie); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"down":"connection refused"`) {
		t.Fatalf("an authority that does not answer: %d %s", res.Code, res.Body)
	}
}

// The sign-in page lists the authority's fixture people, each signing in and
// returning where the browser came from; a return to another site lands on
// this origin's root.
func TestTheSignInPageListsTheAuthoritysPeople(t *testing.T) {
	f := newFixture(t)
	res, body := f.do(t, http.MethodGet, "/auth/sign-in?return=/records%3Ftab%3Dschemas", nil)
	data := pageData(t, res, body)
	if data.Return != "/records?tab=schemas" || len(data.People) != 1 || data.People[0].Email != "remi@acme.test" || data.People[0].FixtureToken != "fixture-remi" {
		t.Fatalf("the page carries %+v", data)
	}
	for _, elsewhere := range []string{"https://elsewhere.test/", "//elsewhere.test/", "/\\elsewhere.test/", "records"} {
		if res, _ := f.signInAs(t, "fixture-remi", elsewhere, f.edge.URL); res.Header.Get("Location") != "/" {
			t.Errorf("a return to %q went to %q", elsewhere, res.Header.Get("Location"))
		}
	}
}

// Signing a browser in or out is a write: another site cannot do either, and
// a page reads the session only through the edge.
func TestSignInAndSignOutComeFromThisOrigin(t *testing.T) {
	f := newFixture(t)
	if res, body := f.signInAs(t, "fixture-remi", "/", "http://elsewhere.test"); res.StatusCode != http.StatusForbidden || !strings.Contains(body, "this origin") {
		t.Fatalf("another site signed the browser in: %d %s", res.StatusCode, body)
	}
	cookie := f.signIn(t)
	if res, _ := f.do(t, http.MethodGet, "/auth/sign-out", http.Header{"Cookie": {cookie.String()}}); res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("a GET signed out: %d", res.StatusCode)
	}
	if res, _ := f.do(t, http.MethodPost, "/auth/sign-out", http.Header{"Cookie": {cookie.String()}, "Origin": {"http://elsewhere.test"}}); res.StatusCode != http.StatusForbidden {
		t.Fatalf("another site signed the browser out: %d", res.StatusCode)
	}
	res, _ := f.do(t, http.MethodPost, "/auth/sign-out", http.Header{"Cookie": {cookie.String()}, "Origin": {f.edge.URL}})
	if res.StatusCode != http.StatusNoContent || len(res.Cookies()) != 1 || res.Cookies()[0].MaxAge >= 0 {
		t.Fatalf("sign-out answered %d with %v", res.StatusCode, res.Cookies())
	}
}

// A module call carries the person's Work Context for that module and nothing
// the caller said about who it is.
func TestAModuleCallCarriesThePersonsWorkContextAndNothingElse(t *testing.T) {
	f := newFixture(t)
	cookie := f.signIn(t)
	res, body := f.do(t, http.MethodGet, "/v1/records/types", http.Header{
		"Cookie":                 {cookie.String()},
		"X-Codefly-Work-Context": {"forged"},
		"X-Codefly-Hop-Proof":    {"forged"},
		"Authorization":          {"Bearer forged"},
	})
	if res.StatusCode != http.StatusOK || body != "answered" {
		t.Fatalf("answered %d: %s", res.StatusCode, body)
	}
	seen, path := f.rest.last()
	if path != "/v1/records/types" || seen.Get(WorkContextKey) != "wc-records" || seen.Get("X-Codefly-Hop-Proof") != "" || seen.Get("Authorization") != "" || seen.Get("Cookie") != "" {
		t.Fatalf("the module received %s with %v", path, seen)
	}
	// The Connect face, by the service its path names.
	if res, _ := f.do(t, http.MethodPost, "/records.v1.RecordsService/Query", http.Header{"Cookie": {cookie.String()}, "Origin": {f.edge.URL}}); res.StatusCode != http.StatusOK {
		t.Fatalf("a Connect call answered %d", res.StatusCode)
	}
	if seen, path := f.connect.last(); path != "/records.v1.RecordsService/Query" || seen.Get(WorkContextKey) != "wc-records" {
		t.Fatalf("the Connect face received %s with %v", path, seen)
	}
	// Held, not issued again for every call.
	if f.authority.issued == nil || len(f.authority.issued) != 1 {
		t.Fatalf("issued %v", f.authority.issued)
	}
	// Every other path is the frontend's, with no Work Context.
	if res, _ := f.do(t, http.MethodGet, "/index.html", http.Header{"Cookie": {cookie.String()}}); res.StatusCode != http.StatusOK {
		t.Fatalf("the frontend answered %d", res.StatusCode)
	}
	if seen, _ := f.frontend.last(); seen.Get(WorkContextKey) != "" || seen.Get("Cookie") != "" {
		t.Fatalf("the frontend received %v", seen)
	}
}

// No session, another site's write, and a module the person holds nothing at
// are refused at the edge, each saying why; nothing reaches the module.
func TestTheEdgeRefusesWithItsReason(t *testing.T) {
	f := newFixture(t)
	cookie := f.signIn(t)
	for name, c := range map[string]struct {
		method, path string
		header       http.Header
		code         int
		reason       string
	}{
		"no session":             {http.MethodGet, "/v1/records/types", nil, http.StatusUnauthorized, "sign in"},
		"another site's write":   {http.MethodPost, "/v1/records/types", http.Header{"Cookie": {cookie.String()}, "Origin": {"http://elsewhere.test"}}, http.StatusForbidden, "this origin"},
		"a write with no origin": {http.MethodPost, "/v1/records/types", http.Header{"Cookie": {cookie.String()}}, http.StatusForbidden, "this origin"},
		"nothing held there":     {http.MethodGet, "/v1/secrets/all", http.Header{"Cookie": {cookie.String()}}, http.StatusForbidden, "holds nothing at secrets"},
	} {
		res, body := f.do(t, c.method, c.path, c.header)
		if res.StatusCode != c.code || !strings.Contains(body, c.reason) {
			t.Errorf("%s: answered %d: %s", name, res.StatusCode, body)
		}
	}
	if seen, _ := f.secrets.last(); seen != nil {
		t.Fatal("a refused call reached the module")
	}
	// A caller presenting its bearer itself is not a browser being steered.
	if res, body := f.do(t, http.MethodPost, "/v1/records/types", http.Header{"Authorization": {"Bearer remi-session"}}); res.StatusCode != http.StatusOK {
		t.Fatalf("a bearer-presenting write answered %d: %s", res.StatusCode, body)
	}
}

// A caller that is not a browser (a CLI applying an agent bundle) signs in with
// JSON and is handed its bearer back, which it then presents on each call; the
// cookie carries the same value for a browser.
func TestAJSONSignInHandsTheBearerBack(t *testing.T) {
	f := newFixture(t)
	res, body := f.send(t, http.MethodPost, "/auth/sign-in", http.Header{"Content-Type": {"application/json"}, "Origin": {f.edge.URL}}, `{"fixtureToken":"fixture-remi"}`)
	var answer map[string]string
	_ = json.Unmarshal([]byte(body), &answer)
	if res.StatusCode != http.StatusOK || answer["bearer"] != "remi-session" || answer["personId"] != "remi" {
		t.Fatalf("sign-in answered %d: %s", res.StatusCode, body)
	}
	if res, _ := f.do(t, http.MethodGet, "/v1/records/types", http.Header{"Authorization": {"Bearer " + answer["bearer"]}}); res.StatusCode != http.StatusOK {
		t.Fatalf("the bearer handed back does not sign a call: %d", res.StatusCode)
	}
}

func TestCacheEvictsOnExpiryAndSignOut(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	e := &Edge{Authority: f.authority, Now: func() time.Time { return now }}
	if _, err := e.workContext(context.Background(), "remi-session", "records"); err != nil {
		t.Fatal(err)
	}
	if len(e.held) != 1 {
		t.Fatal("missing cache")
	}
	now = now.Add(time.Hour)
	// Even a refused refresh must remove old contexts.
	if _, err := e.workContext(context.Background(), "remi-session", "down"); err == nil {
		t.Fatal("expected refused target")
	}
	if len(e.held) != 0 {
		t.Fatal("expired context retained")
	}
	now = time.Now()
	if _, err := e.workContext(context.Background(), "remi-session", "records"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://edge.test/auth/sign-out", nil)
	req.Header.Set("Origin", "http://edge.test")
	req.AddCookie(&http.Cookie{Name: SessionKey, Value: "remi-session"})
	e.ServeHTTP(httptest.NewRecorder(), req)
	if len(e.held) != 0 {
		t.Fatal("signed-out bearer retained")
	}
}

type blockedIssuer struct {
	*standIn
	started chan string
	release chan struct{}
}

func (s *blockedIssuer) Issue(ctx context.Context, req *authorityv1.IssueRequest, opts ...grpc.CallOption) (*authorityv1.IssueResponse, error) {
	s.started <- req.GetAudience()
	<-s.release
	return s.standIn.Issue(ctx, req, opts...)
}
func TestSessionIssuesConcurrently(t *testing.T) {
	s := &blockedIssuer{standIn: &standIn{}, started: make(chan string, 2), release: make(chan struct{})}
	e := &Edge{Authority: s, Modules: map[string]Module{"a": {}, "b": {}}}
	done := make(chan struct{})
	go func() { e.usable(context.Background(), "remi-session"); close(done) }()
	defer func() { close(s.release); <-done }()
	for range 2 {
		select {
		case <-s.started:
		case <-time.After(time.Second):
			t.Fatal("session issued modules serially")
		}
	}
}
func TestSignOutFencesAnInflightCacheWrite(t *testing.T) {
	s := &blockedIssuer{standIn: &standIn{}, started: make(chan string, 1), release: make(chan struct{})}
	e := &Edge{Authority: s}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = e.workContext(context.Background(), "remi-session", "records") }()
	<-s.started
	e.evict("remi-session")
	close(s.release)
	<-done
	if len(e.held) != 0 {
		t.Fatal("inflight issue restored signed-out cache")
	}
}

type failingCurrent struct {
	*standIn
	failure error
}

func (s failingCurrent) Current(context.Context, *sessionv1.CurrentRequest, ...grpc.CallOption) (*sessionv1.Session, error) {
	return nil, s.failure
}
func TestSessionOutagePreservesCacheAndReportsTheActualReason(t *testing.T) {
	for _, code := range []codes.Code{codes.Unavailable, codes.DeadlineExceeded, codes.Internal, codes.Unauthenticated} {
		t.Run(code.String(), func(t *testing.T) {
			s := &standIn{}
			e := &Edge{Authority: s, Sessions: failingCurrent{s, status.Error(code, "Current failed: test reason")}}
			if _, err := e.workContext(context.Background(), "remi-session", "records"); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
			r.Header.Set("Authorization", "Bearer remi-session")
			w := httptest.NewRecorder()
			e.ServeHTTP(w, r)
			want, cached := http.StatusServiceUnavailable, 1
			if code == codes.Unauthenticated {
				want, cached = http.StatusUnauthorized, 0
			}
			if w.Code != want || len(e.held) != cached || !strings.Contains(w.Body.String(), "Current failed: test reason") {
				t.Fatalf("code=%d cache=%d reason=%s", w.Code, len(e.held), w.Body)
			}
			var answer map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
				t.Fatal(err)
			}
			if _, present := answer["moduleApiBase"]; present {
				t.Fatalf("failed session published a module connection: %s", w.Body)
			}
		})
	}
}
