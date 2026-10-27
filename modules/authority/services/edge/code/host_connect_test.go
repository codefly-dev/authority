package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	installationv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/installation/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// installationHost is the host behind the face, answering as the shared core
// answers, in its words: Alex administers Acme, Maya is an Acme member holding
// the proposals installation's viewer role, Zoë administers Globex. It records
// every call it is sent with the session that sent it. The decisions
// themselves are the core's, proven there (authority-core
// TestAMemberHoldingARoleReviewsTheOfferWithoutItsConsent); this proves the
// face carries the person's session in and the authority's answer out.
type installationHost struct {
	mu      sync.Mutex
	calls   []string
	bearers []string
	grants  []*installationv1.RoleGrant
}

const proposalsInstallation = "4f0c5b1e-0000-5000-8000-0000000000aa"

type hostPerson struct {
	org   string
	admin bool
	holds bool
}

var hostPeople = map[string]hostPerson{
	"alex-session": {"acme", true, true},
	"maya-session": {"acme", false, true},
	"zoe-session":  {"globex", true, false},
}

func (h *installationHost) caller(ctx context.Context, call, org string) (hostPerson, error) {
	bearer := bearerIn(ctx)
	h.mu.Lock()
	h.calls, h.bearers = append(h.calls, call), append(h.bearers, bearer)
	h.mu.Unlock()
	p, ok := hostPeople[bearer]
	if !ok {
		return p, status.Error(codes.Unauthenticated, "no session")
	}
	if p.org != org || !p.admin {
		return p, status.Errorf(codes.PermissionDenied, "installation administration requires an administrator or owner of organization %q", org)
	}
	return p, nil
}

// administers answers a grant-shaped call as decide.ChangeRole does.
func (h *installationHost) administers(ctx context.Context, call, org, installation string) error {
	if _, err := h.caller(ctx, call, org); err != nil {
		if status.Code(err) == codes.Unauthenticated {
			return err
		}
		return status.Errorf(codes.PermissionDenied, "installation %s belongs to another organization than %q", installation, org)
	}
	return nil
}

func (h *installationHost) List(ctx context.Context, in *installationv1.ListRequest, _ ...grpc.CallOption) (*installationv1.ListResponse, error) {
	if _, err := h.caller(ctx, "List", in.GetOrganizationId()); err != nil {
		return nil, err
	}
	return &installationv1.ListResponse{Installations: []*installationv1.Installation{{Id: proposalsInstallation, OrganizationId: "acme", Target: "proposals", Status: installationv1.Installation_STATUS_ACTIVE}}}, nil
}

func (h *installationHost) Review(ctx context.Context, in *installationv1.ReviewRequest, _ ...grpc.CallOption) (*installationv1.ConsentApproval, error) {
	if _, err := h.caller(ctx, "Review", in.GetOrganizationId()); err != nil {
		return nil, err
	}
	return &installationv1.ConsentApproval{TargetId: "proposals", Generation: 3, Digest: "sha256:reviewed"}, nil
}

func (h *installationHost) ListOffers(ctx context.Context, in *installationv1.ListOffersRequest, _ ...grpc.CallOption) (*installationv1.ListOffersResponse, error) {
	if _, err := h.caller(ctx, "ListOffers", in.GetOrganizationId()); err != nil {
		return nil, err
	}
	return &installationv1.ListOffersResponse{Offers: []*installationv1.Offer{{Target: "proposals", Generation: 3}}}, nil
}

// ReviewOffer answers an administrator with the consent, a member holding a
// role without it, and anyone else with the core's refusal.
func (h *installationHost) ReviewOffer(ctx context.Context, in *installationv1.ReviewRequest, _ ...grpc.CallOption) (*installationv1.ReviewedOffer, error) {
	p, err := h.caller(ctx, "ReviewOffer", in.GetOrganizationId())
	if status.Code(err) == codes.Unauthenticated {
		return nil, err
	}
	if err != nil && (p.org != in.GetOrganizationId() || !p.holds) {
		return nil, status.Errorf(codes.PermissionDenied, "reviewing %q requires an administrator or owner of organization %q, or a role on its installation there", in.GetTarget(), in.GetOrganizationId())
	}
	offer := &installationv1.ReviewedOffer{Target: in.GetTarget(), ToolsComposed: true,
		Installation: &installationv1.Installation{Id: proposalsInstallation, OrganizationId: "acme", Target: "proposals", Status: installationv1.Installation_STATUS_ACTIVE},
		Roles: []*installationv1.OfferRole{{Name: "viewer",
			Scopes: []*installationv1.OfferScope{{ResourceKind: "proposals.item", Actions: []string{"read"}}},
			Capabilities: []*installationv1.OfferCapability{{Module: "proposals", Operation: "/tools.Solution/Read",
				Requires: []*installationv1.OfferScope{{ResourceKind: "proposals.item", Actions: []string{"read"}}},
				Tools:    []*installationv1.OfferTool{{Name: "read_item", Binding: "PROPOSALS__READ"}}}}}},
		Ceiling: []*installationv1.OfferBinding{{Binding: "store", Module: "documents", Scopes: []*installationv1.OfferScope{{ResourceKind: "documents", Actions: []string{"read", "write"}}}}}}
	if err == nil {
		offer.Approval = &installationv1.ConsentApproval{TargetId: "proposals", Generation: 3, Digest: "sha256:reviewed"}
	}
	return offer, nil
}

func (h *installationHost) GrantRole(ctx context.Context, in *installationv1.GrantRoleRequest, _ ...grpc.CallOption) (*installationv1.Installation, error) {
	if err := h.administers(ctx, "GrantRole", in.GetOrganizationId(), in.GetInstallationId()); err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.grants = append(h.grants, &installationv1.RoleGrant{Role: in.GetRole(), PersonId: in.GetPersonId(), TeamId: in.GetTeamId()})
	h.mu.Unlock()
	return &installationv1.Installation{Id: in.GetInstallationId()}, nil
}

func (h *installationHost) RevokeRole(ctx context.Context, in *installationv1.RevokeRoleRequest, _ ...grpc.CallOption) (*installationv1.Installation, error) {
	if err := h.administers(ctx, "RevokeRole", in.GetOrganizationId(), in.GetInstallationId()); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	kept := h.grants[:0]
	for _, g := range h.grants {
		if g.GetRole() != in.GetRole() || g.GetPersonId() != in.GetPersonId() || g.GetTeamId() != in.GetTeamId() {
			kept = append(kept, g)
		}
	}
	h.grants = kept
	return &installationv1.Installation{Id: in.GetInstallationId()}, nil
}

func (h *installationHost) ListRoleGrants(ctx context.Context, in *installationv1.ListRoleGrantsRequest, _ ...grpc.CallOption) (*installationv1.ListRoleGrantsResponse, error) {
	if err := h.administers(ctx, "ListRoleGrants", in.GetOrganizationId(), in.GetInstallationId()); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return &installationv1.ListRoleGrantsResponse{Grants: append([]*installationv1.RoleGrant(nil), h.grants...)}, nil
}

// ListHeld answers the caller their own holdings as the core does: a member
// holding a role reads that installation and role, a member holding nothing
// an empty list, and a session of another organization the core's refusal.
func (h *installationHost) ListHeld(ctx context.Context, in *installationv1.ListHeldRequest, _ ...grpc.CallOption) (*installationv1.ListHeldResponse, error) {
	p, err := h.caller(ctx, "ListHeld", in.GetOrganizationId())
	if status.Code(err) == codes.Unauthenticated {
		return nil, err
	}
	if p.org != in.GetOrganizationId() {
		return nil, status.Errorf(codes.PermissionDenied, "the installations held at organization %q are read by a member of it, signed in there", in.GetOrganizationId())
	}
	out := &installationv1.ListHeldResponse{}
	if p.holds {
		out.Installations = []*installationv1.HeldInstallation{{Roles: []string{"viewer"},
			Installation: &installationv1.Installation{Id: proposalsInstallation, OrganizationId: "acme", Target: "proposals", Status: installationv1.Installation_STATUS_ACTIVE}}}
	}
	return out, nil
}

func (h *installationHost) Install(context.Context, *installationv1.InstallRequest, ...grpc.CallOption) (*installationv1.Installation, error) {
	return nil, errors.New("the face must never send Install")
}

func (h *installationHost) sent() ([]string, []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.calls...), append([]string(nil), h.bearers...)
}

func newHostFace(t *testing.T) (*httptest.Server, *installationHost) {
	h := &installationHost{}
	srv := httptest.NewServer(&Edge{Installer: h, Offers: h, Modules: map[string]Module{}})
	t.Cleanup(srv.Close)
	return srv, h
}

// browser calls procedure as a page on origin does with the generated web
// client: Connect JSON, the session in the cookie, the origin in Origin.
func browser[Req, Res any](t *testing.T, srv *httptest.Server, origin, session, procedure string, in *Req) (*Res, error) {
	t.Helper()
	client := connect.NewClient[Req, Res](srv.Client(), srv.URL+procedure, connect.WithProtoJSON())
	req := connect.NewRequest(in)
	if origin != "" {
		req.Header().Set("Origin", origin)
	}
	if session != "" {
		req.Header().Set("Cookie", (&http.Cookie{Name: SessionKey, Value: session}).String())
	}
	res, err := client.CallUnary(context.Background(), req)
	if err != nil {
		return nil, err
	}
	if res.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("%s answered with a CORS grant", procedure)
	}
	return res.Msg, nil
}

func refusedWith(t *testing.T, err error, code connect.Code, reason string) {
	t.Helper()
	if connect.CodeOf(err) != code || !strings.Contains(err.Error(), reason) {
		t.Fatalf("want %v naming %q, got %v", code, reason, err)
	}
}

// An administrator lists the installations, reviews an offer down to its
// roles' operations, tools and ceiling, and grants and revokes a role, each
// call sent to the host as itself with their own session.
func TestAnAdministratorSetsUpASolutionThroughTheHostFace(t *testing.T) {
	srv, host := newHostFace(t)
	listed, err := browser[installationv1.ListRequest, installationv1.ListResponse](t, srv, srv.URL, "alex-session", installationv1.InstallationService_List_FullMethodName, &installationv1.ListRequest{OrganizationId: "acme"})
	if err != nil || len(listed.GetInstallations()) != 1 || listed.GetInstallations()[0].GetId() != proposalsInstallation {
		t.Fatalf("List: %v %v", listed, err)
	}
	offers, err := browser[installationv1.ListOffersRequest, installationv1.ListOffersResponse](t, srv, srv.URL, "alex-session", installationv1.OfferService_ListOffers_FullMethodName, &installationv1.ListOffersRequest{OrganizationId: "acme"})
	if err != nil || offers.GetOffers()[0].GetTarget() != "proposals" {
		t.Fatalf("ListOffers: %v %v", offers, err)
	}
	review, err := browser[installationv1.ReviewRequest, installationv1.ReviewedOffer](t, srv, srv.URL, "alex-session", installationv1.OfferService_ReviewOffer_FullMethodName, &installationv1.ReviewRequest{OrganizationId: "acme", Target: "proposals"})
	if err != nil {
		t.Fatal(err)
	}
	role := review.GetRoles()[0]
	if role.GetName() != "viewer" || role.GetCapabilities()[0].GetOperation() != "/tools.Solution/Read" || role.GetCapabilities()[0].GetTools()[0].GetName() != "read_item" ||
		review.GetCeiling()[0].GetModule() != "documents" || review.GetApproval().GetDigest() != "sha256:reviewed" {
		t.Fatalf("the review lost its roles, operations, tools, ceiling or consent: %v", review)
	}
	approval, err := browser[installationv1.ReviewRequest, installationv1.ConsentApproval](t, srv, srv.URL, "alex-session", installationv1.InstallationService_Review_FullMethodName, &installationv1.ReviewRequest{OrganizationId: "acme", Target: "proposals"})
	if err != nil || approval.GetDigest() != "sha256:reviewed" {
		t.Fatalf("Review: %v %v", approval, err)
	}
	grant := &installationv1.GrantRoleRequest{OrganizationId: "acme", InstallationId: proposalsInstallation, Role: "viewer", TeamId: "finance"}
	if _, err := browser[installationv1.GrantRoleRequest, installationv1.Installation](t, srv, srv.URL, "alex-session", installationv1.InstallationService_GrantRole_FullMethodName, grant); err != nil {
		t.Fatal(err)
	}
	grants, err := browser[installationv1.ListRoleGrantsRequest, installationv1.ListRoleGrantsResponse](t, srv, srv.URL, "alex-session", installationv1.InstallationService_ListRoleGrants_FullMethodName,
		&installationv1.ListRoleGrantsRequest{OrganizationId: "acme", InstallationId: proposalsInstallation})
	if err != nil || len(grants.GetGrants()) != 1 || grants.GetGrants()[0].GetTeamId() != "finance" || grants.GetGrants()[0].GetRole() != "viewer" {
		t.Fatalf("the grant was not sent as asked: %v %v", grants, err)
	}
	revoke := &installationv1.RevokeRoleRequest{OrganizationId: "acme", InstallationId: proposalsInstallation, Role: "viewer", TeamId: "finance"}
	if _, err := browser[installationv1.RevokeRoleRequest, installationv1.Installation](t, srv, srv.URL, "alex-session", installationv1.InstallationService_RevokeRole_FullMethodName, revoke); err != nil {
		t.Fatal(err)
	}
	grants, err = browser[installationv1.ListRoleGrantsRequest, installationv1.ListRoleGrantsResponse](t, srv, srv.URL, "alex-session", installationv1.InstallationService_ListRoleGrants_FullMethodName,
		&installationv1.ListRoleGrantsRequest{OrganizationId: "acme", InstallationId: proposalsInstallation})
	if err != nil || len(grants.GetGrants()) != 0 {
		t.Fatalf("the revoke was not sent: %v %v", grants, err)
	}
	calls, bearers := host.sent()
	if strings.Join(calls, ",") != "List,ListOffers,ReviewOffer,Review,GrantRole,ListRoleGrants,RevokeRole,ListRoleGrants" {
		t.Fatalf("the host was sent %v", calls)
	}
	for _, b := range bearers {
		if b != "alex-session" {
			t.Fatalf("a call reached the host as %q", b)
		}
	}
}

// A member reads what the solution they use grants, without its consent, and
// is refused every administrator's call with the authority's own reason.
func TestAMemberReadsTheRolesButIsRefusedAGrantWithItsReason(t *testing.T) {
	srv, _ := newHostFace(t)
	review, err := browser[installationv1.ReviewRequest, installationv1.ReviewedOffer](t, srv, srv.URL, "maya-session", installationv1.OfferService_ReviewOffer_FullMethodName, &installationv1.ReviewRequest{OrganizationId: "acme", Target: "proposals"})
	if err != nil || review.GetApproval() != nil || review.GetRoles()[0].GetCapabilities()[0].GetTools()[0].GetName() != "read_item" {
		t.Fatalf("the member's read: %v %v", review, err)
	}
	_, err = browser[installationv1.GrantRoleRequest, installationv1.Installation](t, srv, srv.URL, "maya-session", installationv1.InstallationService_GrantRole_FullMethodName,
		&installationv1.GrantRoleRequest{OrganizationId: "acme", InstallationId: proposalsInstallation, Role: "viewer", PersonId: "maya"})
	refusedWith(t, err, connect.CodePermissionDenied, fmt.Sprintf("installation %s belongs to another organization than \"acme\"", proposalsInstallation))
	_, err = browser[installationv1.ListRequest, installationv1.ListResponse](t, srv, srv.URL, "maya-session", installationv1.InstallationService_List_FullMethodName, &installationv1.ListRequest{OrganizationId: "acme"})
	refusedWith(t, err, connect.CodePermissionDenied, `installation administration requires an administrator or owner of organization "acme"`)
}

// A member lists the installations they may use, with their own session: the
// one they hold a role on, or none, never refused for holding nothing; a
// session of another organization is refused by the authority with its reason.
func TestAMemberListsTheInstallationsTheyHoldThroughTheHostFace(t *testing.T) {
	srv, host := newHostFace(t)
	held, err := browser[installationv1.ListHeldRequest, installationv1.ListHeldResponse](t, srv, srv.URL, "maya-session", installationv1.InstallationService_ListHeld_FullMethodName, &installationv1.ListHeldRequest{OrganizationId: "acme"})
	if err != nil || len(held.GetInstallations()) != 1 || held.GetInstallations()[0].GetInstallation().GetId() != proposalsInstallation || strings.Join(held.GetInstallations()[0].GetRoles(), ",") != "viewer" {
		t.Fatalf("maya's held installations: %v %v", held, err)
	}
	held, err = browser[installationv1.ListHeldRequest, installationv1.ListHeldResponse](t, srv, srv.URL, "zoe-session", installationv1.InstallationService_ListHeld_FullMethodName, &installationv1.ListHeldRequest{OrganizationId: "globex"})
	if err != nil || len(held.GetInstallations()) != 0 {
		t.Fatalf("zoe holds nothing at globex and reads an empty list: %v %v", held, err)
	}
	_, err = browser[installationv1.ListHeldRequest, installationv1.ListHeldResponse](t, srv, srv.URL, "zoe-session", installationv1.InstallationService_ListHeld_FullMethodName, &installationv1.ListHeldRequest{OrganizationId: "acme"})
	refusedWith(t, err, connect.CodePermissionDenied, `the installations held at organization "acme" are read by a member of it`)
	_, err = browser[installationv1.ListHeldRequest, installationv1.ListHeldResponse](t, srv, "http://elsewhere.test", "maya-session", installationv1.InstallationService_ListHeld_FullMethodName, &installationv1.ListHeldRequest{OrganizationId: "acme"})
	refusedWith(t, err, connect.CodePermissionDenied, "must come from this origin")
	_, err = browser[installationv1.ListHeldRequest, installationv1.ListHeldResponse](t, srv, srv.URL, "", installationv1.InstallationService_ListHeld_FullMethodName, &installationv1.ListHeldRequest{OrganizationId: "acme"})
	refusedWith(t, err, connect.CodeUnauthenticated, "no session")
	calls, bearers := host.sent()
	if strings.Join(calls, ",") != "ListHeld,ListHeld,ListHeld" || strings.Join(bearers, ",") != "maya-session,zoe-session,zoe-session" {
		t.Fatalf("the host was sent %v as %v", calls, bearers)
	}
}

// Another organization's administrator is refused Acme's installation, by the
// authority, with its reason.
func TestAPersonOfAnotherOrganizationIsRefused(t *testing.T) {
	srv, _ := newHostFace(t)
	_, err := browser[installationv1.ReviewRequest, installationv1.ReviewedOffer](t, srv, srv.URL, "zoe-session", installationv1.OfferService_ReviewOffer_FullMethodName, &installationv1.ReviewRequest{OrganizationId: "acme", Target: "proposals"})
	refusedWith(t, err, connect.CodePermissionDenied, `requires an administrator or owner of organization "acme"`)
	_, err = browser[installationv1.RevokeRoleRequest, installationv1.Installation](t, srv, srv.URL, "zoe-session", installationv1.InstallationService_RevokeRole_FullMethodName,
		&installationv1.RevokeRoleRequest{OrganizationId: "acme", InstallationId: proposalsInstallation, Role: "viewer", PersonId: "maya"})
	refusedWith(t, err, connect.CodePermissionDenied, "belongs to another organization")
	_, err = browser[installationv1.ListRequest, installationv1.ListResponse](t, srv, srv.URL, "", installationv1.InstallationService_List_FullMethodName, &installationv1.ListRequest{OrganizationId: "acme"})
	refusedWith(t, err, connect.CodeUnauthenticated, "no session: sign in at /auth/sign-in")
}

// A call made with the cookie from another origin, or from no origin, or in
// any shape but Connect, never reaches the host; nothing grants CORS; Install
// and Current are not served to a browser at all.
func TestACrossOriginOrNonConnectCallNeverReachesTheHost(t *testing.T) {
	srv, host := newHostFace(t)
	grant := &installationv1.GrantRoleRequest{OrganizationId: "acme", InstallationId: proposalsInstallation, Role: "viewer", PersonId: "maya"}
	for _, origin := range []string{"http://elsewhere.test", "null", ""} {
		_, err := browser[installationv1.GrantRoleRequest, installationv1.Installation](t, srv, origin, "alex-session", installationv1.InstallationService_GrantRole_FullMethodName, grant)
		refusedWith(t, err, connect.CodePermissionDenied, "must come from this origin")
	}
	_, err := browser[installationv1.InstallRequest, installationv1.Installation](t, srv, srv.URL, "alex-session", installationv1.InstallationService_Install_FullMethodName, &installationv1.InstallRequest{OrganizationId: "acme"})
	refusedWith(t, err, connect.CodeUnimplemented, "to no browser")
	_, err = browser[installationv1.CurrentInstallationRequest, installationv1.CurrentInstallation](t, srv, srv.URL, "alex-session", installationv1.InstallationService_Current_FullMethodName, &installationv1.CurrentInstallationRequest{})
	refusedWith(t, err, connect.CodeUnimplemented, "to no browser")

	path := installationv1.InstallationService_GrantRole_FullMethodName
	cookie := (&http.Cookie{Name: SessionKey, Value: "alex-session"}).String()
	for _, tc := range []struct {
		name, method string
		header       http.Header
	}{
		{"a form post", http.MethodPost, http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}},
		{"a text/plain simple request", http.MethodPost, http.Header{"Content-Type": {"text/plain"}}},
		{"JSON without the Connect header", http.MethodPost, http.Header{"Content-Type": {"application/json"}}},
		{"a GET", http.MethodGet, http.Header{"Connect-Protocol-Version": {"1"}}},
		{"a preflight", http.MethodOptions, http.Header{"Access-Control-Request-Method": {"POST"}, "Access-Control-Request-Headers": {"connect-protocol-version,content-type"}}},
	} {
		req, _ := http.NewRequest(tc.method, srv.URL+path, strings.NewReader(`{"organizationId":"acme"}`))
		req.Header = tc.header
		req.Header.Set("Cookie", cookie)
		req.Header.Set("Origin", srv.URL)
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode < 400 || res.Header.Get("Access-Control-Allow-Origin") != "" || res.Header.Get("Access-Control-Allow-Headers") != "" {
			t.Errorf("%s answered %d, CORS %q", tc.name, res.StatusCode, res.Header.Get("Access-Control-Allow-Origin"))
		}
	}
	// A well-formed gRPC-Web call from this origin is still not Connect.
	web := connect.NewClient[installationv1.GrantRoleRequest, installationv1.Installation](srv.Client(), srv.URL+path, connect.WithGRPCWeb())
	webReq := connect.NewRequest(grant)
	webReq.Header().Set("Cookie", cookie)
	webReq.Header().Set("Origin", srv.URL)
	_, err = web.CallUnary(context.Background(), webReq)
	refusedWith(t, err, connect.CodePermissionDenied, "over Connect only")
	if calls, _ := host.sent(); len(calls) != 0 {
		t.Fatalf("refused calls reached the host: %v", calls)
	}

	// A caller presenting its bearer itself is not a browser being steered:
	// it needs no origin, and is still decided by the authority.
	client := connect.NewClient[installationv1.ListRequest, installationv1.ListResponse](srv.Client(), srv.URL+installationv1.InstallationService_List_FullMethodName)
	req := connect.NewRequest(&installationv1.ListRequest{OrganizationId: "acme"})
	req.Header().Set("Authorization", "Bearer alex-session")
	if _, err := client.CallUnary(context.Background(), req); err != nil {
		t.Fatalf("a bearer caller: %v", err)
	}
}
