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
	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// standIn is the authority for one fixture person, Rémi, whose session bearer
// is "remi-session"; it holds nothing at "secrets".
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
	return &sessionv1.Session{SessionId: "s1", PersonId: "remi", OrganizationId: "acme", Bearer: "remi-session"}, nil
}

func (s *standIn) Current(ctx context.Context, _ *sessionv1.CurrentRequest, _ ...grpc.CallOption) (*sessionv1.Session, error) {
	if bearerIn(ctx) != "remi-session" {
		return nil, status.Error(codes.Unauthenticated, "no session")
	}
	return &sessionv1.Session{SessionId: "s1", PersonId: "remi", OrganizationId: "acme"}, nil
}

func (s *standIn) ListFixturePeople(context.Context, *sessionv1.ListFixturePeopleRequest, ...grpc.CallOption) (*sessionv1.ListFixturePeopleResponse, error) {
	return &sessionv1.ListFixturePeopleResponse{People: []*sessionv1.FixturePerson{{PersonId: "remi", Email: "remi@acme.test", OrganizationId: "acme", Roles: []string{"editor"}, FixtureToken: "fixture-remi"}}}, nil
}

func (s *standIn) Issue(ctx context.Context, in *authorityv1.IssueRequest, _ ...grpc.CallOption) (*authorityv1.IssueResponse, error) {
	if bearerIn(ctx) != "remi-session" || in.GetPerson() == nil {
		return nil, status.Error(codes.Unauthenticated, "no session")
	}
	if in.GetAudience() == "secrets" {
		return nil, status.Error(codes.PermissionDenied, "remi holds nothing at secrets")
	}
	s.mu.Lock()
	s.issued = append(s.issued, in.GetAudience())
	s.mu.Unlock()
	return &authorityv1.IssueResponse{Token: "wc-" + in.GetAudience(), ExpiresAtUnix: time.Now().Add(5 * time.Minute).Unix()}, nil
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
	e := &Edge{Sessions: f.authority, Authority: f.authority, Frontend: mustURL(t, f.frontend.URL), Modules: map[string]Module{
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
	if res.StatusCode != http.StatusOK || who["personId"] != "remi" || who["organizationId"] != "acme" {
		t.Fatalf("session answered %d: %s", res.StatusCode, body)
	}
	if res, _ := f.signInAs(t, "nobody", "/", f.edge.URL); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an unknown fixture signed in: %d", res.StatusCode)
	}
}

// The sign-in page lists the authority's fixture people, each signing in and
// returning where the browser came from; a return to another site lands on
// this origin's root.
func TestTheSignInPageListsTheAuthoritysPeople(t *testing.T) {
	f := newFixture(t)
	res, body := f.do(t, http.MethodGet, "/auth/sign-in?return=/records%3Ftab%3Dschemas", nil)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "remi@acme.test") || !strings.Contains(body, `value="fixture-remi"`) || !strings.Contains(body, `value="/records?tab=schemas"`) {
		t.Fatalf("the page answered %d: %s", res.StatusCode, body)
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
