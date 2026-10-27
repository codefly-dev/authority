package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	installationv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/installation/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// setupHost is the authority behind the setup page: it offers "proposals",
// reviews it uninstalled, and records each change it is asked for with the
// session that asked. refuse, when set, is its answer to every call.
type setupHost struct {
	*standIn
	mu      sync.Mutex
	calls   []any
	bearers []string
	refuse  error
	// offers, when set, is the host's answer to whether it serves
	// OfferService: Unimplemented for a host that does not.
	offers error
	probes int
}

func (h *setupHost) record(ctx context.Context, call any) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls, h.bearers = append(h.calls, call), append(h.bearers, bearerIn(ctx))
	return h.refuse
}

func (h *setupHost) ListOffers(ctx context.Context, in *installationv1.ListOffersRequest, _ ...grpc.CallOption) (*installationv1.ListOffersResponse, error) {
	h.mu.Lock()
	offers := h.offers
	if bearerIn(ctx) == "" {
		h.probes++
	}
	h.mu.Unlock()
	if offers != nil {
		return nil, offers
	}
	// The local authority refuses an unauthenticated read by name.
	if bearerIn(ctx) == "" {
		return nil, status.Error(codes.Unauthenticated, "no session")
	}
	if h.refuse != nil {
		return nil, h.refuse
	}
	return &installationv1.ListOffersResponse{Offers: []*installationv1.Offer{{Target: "proposals", Generation: 3}}}, nil
}

func (h *setupHost) ReviewOffer(ctx context.Context, in *installationv1.ReviewRequest, _ ...grpc.CallOption) (*installationv1.ReviewedOffer, error) {
	return &installationv1.ReviewedOffer{Target: in.GetTarget(), ToolsComposed: true,
		Approval: &installationv1.ConsentApproval{TargetId: "proposals", Generation: 3, Digest: "sha256:reviewed"},
		Roles: []*installationv1.OfferRole{{Name: "viewer", Capabilities: []*installationv1.OfferCapability{{Module: "proposals", Operation: "/tools.Solution/Read",
			Tools: []*installationv1.OfferTool{{Name: "read_item", Binding: "PROPOSALS__READ"}}}}}}}, nil
}

func (h *setupHost) Review(ctx context.Context, in *installationv1.ReviewRequest, _ ...grpc.CallOption) (*installationv1.ConsentApproval, error) {
	return &installationv1.ConsentApproval{TargetId: "proposals", Generation: 3, Digest: "sha256:reviewed"}, h.record(ctx, in)
}

func (h *setupHost) Install(ctx context.Context, in *installationv1.InstallRequest, _ ...grpc.CallOption) (*installationv1.Installation, error) {
	return &installationv1.Installation{Status: installationv1.Installation_STATUS_ACTIVE}, h.record(ctx, in)
}

func (h *setupHost) GrantRole(ctx context.Context, in *installationv1.GrantRoleRequest, _ ...grpc.CallOption) (*installationv1.Installation, error) {
	return &installationv1.Installation{}, h.record(ctx, in)
}

func (h *setupHost) RevokeRole(ctx context.Context, in *installationv1.RevokeRoleRequest, _ ...grpc.CallOption) (*installationv1.Installation, error) {
	return &installationv1.Installation{}, h.record(ctx, in)
}

func (h *setupHost) ListRoleGrants(context.Context, *installationv1.ListRoleGrantsRequest, ...grpc.CallOption) (*installationv1.ListRoleGrantsResponse, error) {
	return &installationv1.ListRoleGrantsResponse{}, nil
}

func newSetup(t *testing.T) (fixture, *setupHost) {
	f := newFixture(t)
	host := &setupHost{standIn: f.authority}
	e := &Edge{Sessions: host, Authority: host, Installations: host, Offers: host, Installer: host, Modules: map[string]Module{}}
	f.edge = httptest.NewServer(e)
	t.Cleanup(f.edge.Close)
	return f, host
}

func (f fixture) post(t *testing.T, cookie *http.Cookie, origin string, form url.Values) (*http.Response, string) {
	t.Helper()
	return f.send(t, http.MethodPost, "/auth/setup", http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Cookie": {cookie.String()}, "Origin": {origin}}, form.Encode())
}

// The page is the authority's answer, read with the person's session: what is
// offered, the reviewed offer with its roles and tools, and the organization's
// people by email, never their sign-in tokens.
func TestTheSetupPageShowsTheReviewedOffer(t *testing.T) {
	f, _ := newSetup(t)
	if res, _ := f.do(t, http.MethodGet, "/auth/setup", nil); res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/auth/sign-in?return=%2Fauth%2Fsetup" {
		t.Fatalf("no session must sign in first: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	cookie := f.signIn(t)
	res, body := f.do(t, http.MethodGet, "/auth/setup?target=proposals", http.Header{"Cookie": {cookie.String()}})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("answered %d: %s", res.StatusCode, body)
	}
	for _, want := range []string{`"setup"`, `"target":"proposals"`, `"digest":"sha256:reviewed"`, `"name":"read_item"`, `"email":"remi@acme.test"`, `"operationId":"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %s", want)
		}
	}
	if strings.Contains(body, "fixture-remi") {
		t.Fatal("the setup page carries a sign-in token")
	}
}

// Each change is the posted form, sent with the person's session, from this
// origin only; consent is required before an install is sent at all.
func TestSetupChangesAreThePersonsAndComeFromThisOrigin(t *testing.T) {
	f, host := newSetup(t)
	cookie := f.signIn(t)
	install := url.Values{"action": {"install"}, "target": {"proposals"}, "role": {"viewer"}, "targetId": {"proposals"}, "generation": {"3"}, "expectedRevision": {"0"},
		"digest": {"sha256:reviewed"}, "operationId": {"5d3c0b0e-8f5e-4c3f-9d55-6c1f1a0b7e21"}}
	if res, _ := f.post(t, cookie, "http://elsewhere.test", install); res.StatusCode != http.StatusForbidden {
		t.Fatalf("another site's install answered %d", res.StatusCode)
	}
	if _, body := f.post(t, cookie, f.edge.URL, install); !strings.Contains(body, "Consent to the reviewed version") {
		t.Fatalf("an install without consent must say so: %s", body)
	}
	if len(host.calls) != 0 {
		t.Fatalf("refused forms reached the authority: %v", host.calls)
	}
	install.Set("consent", "on")
	res, _ := f.post(t, cookie, f.edge.URL, install)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/auth/setup?done=installed&target=proposals" {
		t.Fatalf("install answered %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	got := host.calls[0].(*installationv1.InstallRequest)
	if got.GetOwnerPersonId() != "remi" || got.GetOrganizationId() != "acme" || got.GetApproval().GetDigest() != "sha256:reviewed" || got.GetApproval().GetGeneration() != 3 ||
		got.GetApproval().GetOperationId() != install.Get("operationId") || host.bearers[0] != "remi-session" {
		t.Fatalf("install sent %v as %s", got, host.bearers[0])
	}
	f.post(t, cookie, f.edge.URL, url.Values{"action": {"grant"}, "target": {"proposals"}, "installationId": {"i1"}, "role": {"viewer"}, "subject": {"team:finance"}})
	f.post(t, cookie, f.edge.URL, url.Values{"action": {"revoke"}, "target": {"proposals"}, "installationId": {"i1"}, "role": {"viewer"}, "subject": {"person:maya"}})
	if g := host.calls[1].(*installationv1.GrantRoleRequest); g.GetTeamId() != "finance" || g.GetPersonId() != "" || g.GetRole() != "viewer" {
		t.Fatalf("grant sent %v", g)
	}
	if r := host.calls[2].(*installationv1.RevokeRoleRequest); r.GetPersonId() != "maya" || r.GetTeamId() != "" {
		t.Fatalf("revoke sent %v", r)
	}
}

// A refusal is shown with the authority's reason; an install the authority did
// not confirm keeps its exact request, so retrying it is the same operation.
func TestSetupShowsRefusalsAndKeepsAnUncertainInstall(t *testing.T) {
	f, host := newSetup(t)
	cookie := f.signIn(t)
	host.refuse = status.Error(codes.Unavailable, "the authority is restarting")
	form := url.Values{"action": {"install"}, "target": {"proposals"}, "role": {"viewer"}, "consent": {"on"}, "operationId": {"5d3c0b0e-8f5e-4c3f-9d55-6c1f1a0b7e21"}}
	_, body := f.post(t, cookie, f.edge.URL, form)
	if !strings.Contains(body, "Retry the same install") || !strings.Contains(body, `"operationId":"5d3c0b0e-8f5e-4c3f-9d55-6c1f1a0b7e21"`) {
		t.Fatalf("an uncertain install must keep its request: %s", body)
	}
	host.refuse = status.Error(codes.PermissionDenied, `installation administration requires an administrator or owner of organization "acme"`)
	_, body = f.do(t, http.MethodGet, "/auth/setup", http.Header{"Cookie": {cookie.String()}})
	if !strings.Contains(body, "requires an administrator or owner") {
		t.Fatalf("a refused read must name its reason: %s", body)
	}
}

// A Connect caller refused at a module reads the code and the reason.
func TestAModuleRefusalKeepsItsReasonForAConnectCaller(t *testing.T) {
	f := newFixture(t)
	res, body := f.do(t, http.MethodPost, "/records.v1.RecordsService/List", http.Header{"Content-Type": {"application/json"}, "Connect-Protocol-Version": {"1"}})
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(body, `"code":"unauthenticated"`) || !strings.Contains(body, "sign in") {
		t.Fatalf("answered %d: %s", res.StatusCode, body)
	}
}

// Review #30 F3: the setup page, its installs and grants included, is mounted
// only on a host that serves OfferService (the local authority). Another host
// answers Unimplemented, and the edge serves no setup page at all there, so no
// cookie-driven install is ever sent to it. An unreachable host is asked again.
func TestTheSetupPageIsMountedOnlyWhereTheHostServesOffers(t *testing.T) {
	f, host := newSetup(t)
	cookie := f.signIn(t)
	host.offers = status.Error(codes.Unavailable, "connection refused")
	if res, body := f.do(t, http.MethodGet, "/auth/setup", http.Header{"Cookie": {cookie.String()}}); res.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "connection refused") {
		t.Fatalf("an unreachable host answered %d: %s", res.StatusCode, body)
	}
	host.offers = status.Error(codes.Unimplemented, "unknown service host.installation.v1.OfferService")
	install := url.Values{"action": {"install"}, "target": {"proposals"}, "role": {"viewer"}, "consent": {"on"}, "operationId": {"5d3c0b0e-8f5e-4c3f-9d55-6c1f1a0b7e21"}}
	if res, body := f.post(t, cookie, f.edge.URL, install); res.StatusCode != http.StatusNotFound || !strings.Contains(body, "serves no setup page") {
		t.Fatalf("a host without OfferService was sent a setup change: %d %s", res.StatusCode, body)
	}
	if res, _ := f.do(t, http.MethodGet, "/auth/setup", http.Header{"Cookie": {cookie.String()}}); res.StatusCode != http.StatusNotFound {
		t.Fatalf("a host without OfferService served the setup page: %d", res.StatusCode)
	}
	if len(host.calls) != 0 || host.probes != 2 {
		t.Fatalf("calls %v reached the host; it was asked %d times (once unreachable, once answered)", host.calls, host.probes)
	}
	// A definite answer is kept: the host is not asked on every request.
	host.offers = nil
	if res, _ := f.do(t, http.MethodGet, "/auth/setup", http.Header{"Cookie": {cookie.String()}}); res.StatusCode != http.StatusNotFound || host.probes != 2 {
		t.Fatalf("the answer was not kept: %d after %d probes", res.StatusCode, host.probes)
	}

	// With no setup clients at all, the path is not the frontend's either.
	plain := newFixture(t)
	if res, _ := plain.do(t, http.MethodGet, "/auth/setup", nil); res.StatusCode != http.StatusNotFound {
		t.Fatalf("an edge with no setup clients answered %d", res.StatusCode)
	}
	if _, path := plain.frontend.last(); path != "" {
		t.Fatalf("/auth/setup reached the frontend at %s", path)
	}
}

// Review #30 F2: the pages that change authority on a click are never framed.
func TestTheSignInAndSetupPagesRefuseToBeFramed(t *testing.T) {
	f, _ := newSetup(t)
	cookie := f.signIn(t)
	for _, page := range []struct {
		path   string
		header http.Header
	}{{"/auth/sign-in", nil}, {"/auth/setup", http.Header{"Cookie": {cookie.String()}}}, {"/auth/setup?target=proposals", http.Header{"Cookie": {cookie.String()}}}} {
		res, _ := f.do(t, http.MethodGet, page.path, page.header)
		if res.StatusCode != http.StatusOK || res.Header.Get("X-Frame-Options") != "DENY" || res.Header.Get("Content-Security-Policy") != "frame-ancestors 'none'" {
			t.Errorf("%s answered %d with X-Frame-Options %q and CSP %q", page.path, res.StatusCode, res.Header.Get("X-Frame-Options"), res.Header.Get("Content-Security-Policy"))
		}
	}
	res, _ := f.post(t, cookie, f.edge.URL, url.Values{"action": {"install"}, "target": {"proposals"}})
	if res.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("the setup page re-rendered after a refused change can be framed")
	}
}

// Review #30 F1: only a caller that says it speaks Connect is refused in
// Connect's words; a REST or form caller keeps {"error": reason}.
func TestAModuleRefusalKeepsTheRESTBodyForARESTCaller(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct{ name, path, contentType string }{
		{"JSON POST", "/v1/records/items", "application/json"},
		{"form POST", "/v1/records/items", "application/x-www-form-urlencoded"},
		{"no content type", "/v1/records/items", ""},
		{"JSON POST to a Connect path", "/records.v1.RecordsService/List", "application/json"},
	} {
		header := http.Header{}
		if tc.contentType != "" {
			header.Set("Content-Type", tc.contentType)
		}
		res, body := f.do(t, http.MethodPost, tc.path, header)
		if res.StatusCode != http.StatusUnauthorized || body != "{\"error\":\"no session: sign in at /auth/sign-in\"}\n" {
			t.Errorf("%s: answered %d %s", tc.name, res.StatusCode, body)
		}
	}
	res, body := f.do(t, http.MethodGet, "/v1/records/items", nil)
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(body, `"error":`) {
		t.Errorf("GET answered %d %s", res.StatusCode, body)
	}
}
