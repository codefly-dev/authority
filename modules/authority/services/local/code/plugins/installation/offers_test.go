package installation

import (
	"context"
	"testing"
	"time"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	installationv1 "gateway/pkg/gen/host/installation/v1"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/google/uuid"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	runnablev0 "github.com/codefly-dev/core/generated/go/codefly/runnable/v0"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/runnable"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

const (
	readItems  = "/tools.Solution/Read"
	writeItems = "/tools.Solution/Write"
)

// prepared is one composed Connect operation as `codefly generate
// runnable-bindings` delivers it; an empty tool is an operation its owner
// exposes as no tool.
func prepared(method, tool string, effect runnablev0.ToolExposure_Effect, actions ...string) *runnablev0.PreparedBinding {
	scopes := []*basev0.WorkScopeV1{{ResourceKind: "proposals.item", Actions: actions}}
	p := &runnablev0.PreparedBinding{
		Operation: &runnablev0.PreparedOperation{Module: "proposals", Service: "api", Endpoint: "connect", Spelling: method},
		Call:      &runnablev0.PreparedCall{Address: "https://proposals.invalid", Route: &runnablev0.PreparedCall_Connect{Connect: &runnablev0.ConnectProcedure{Procedure: method}}},
		Contract: &basev0.RunnableContract{Protocol: resources.RunnableServiceProtocolV1,
			Input:  &basev0.RunnableSchema{Fields: []*basev0.RunnableField{{Name: "id", Type: basev0.RunnableField_STRING}}},
			Output: &basev0.RunnableSchema{Fields: []*basev0.RunnableField{{Name: "title", Type: basev0.RunnableField_STRING}}}},
		Policy: &runnablev0.Operation{AttemptTimeout: durationpb.New(10 * time.Second), TotalTimeout: durationpb.New(30 * time.Second), MaxAttempts: 1,
			Backoff: durationpb.New(time.Second), Audience: "proposals", InvokeScopes: scopes, Completion: basev0.RunnableExecution_COMPLETION_CALL},
	}
	if tool != "" {
		p.Policy.Tool = &runnablev0.ToolExposure{Name: tool, Description: "A proposals tool.", Effect: effect}
	}
	return composed(p)
}

// grpcEndpoint is the same operation composed from its gRPC endpoint, which a
// tool caller reaches over Connect all the same.
func grpcEndpoint(p *runnablev0.PreparedBinding) *runnablev0.PreparedBinding {
	p.Operation.Endpoint = "grpc"
	return composed(p)
}

// composed round-trips a binding through the generator's encoding, as the run
// delivers it: schema and contract digest stamped.
func composed(p *runnablev0.PreparedBinding) *runnablev0.PreparedBinding {
	raw, err := runnable.EncodePrepared(p)
	if err != nil {
		panic(err)
	}
	out, err := runnable.DecodePrepared(raw)
	if err != nil {
		panic(err)
	}
	return out
}

func signedIn(t *testing.T, k *testkit.Kit, token string) context.Context {
	t.Helper()
	sess, err := k.State.SignIn(token)
	if err != nil {
		t.Fatal(err)
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+sess.ID))
}

// The review is what installing grants, joined to what the run composes: each
// role's operations, and the tool-exposed Connect bindings its scopes cover.
func TestReviewOfferShowsEachRolesOperationsAndTools(t *testing.T) {
	k := testkit.New(t)
	solution := testkit.Proposals(1)
	solution.Methods = map[string]state.MethodPolicy{
		readItems:  {Requires: []*basev0.WorkScopeV1{testkit.Scope("proposals.item", "read")}},
		writeItems: {Requires: []*basev0.WorkScopeV1{testkit.Scope("proposals.item", "write")}},
	}
	if _, err := k.State.ApplyManifest(solution); err != nil {
		t.Fatal(err)
	}
	offers := &Offers{plugin: &Plugin{State: k.State}, runnables: func(context.Context) (map[string]*runnablev0.PreparedBinding, error) {
		return map[string]*runnablev0.PreparedBinding{
			"PROPOSALS__API_CONNECT_READ":       prepared(readItems, "read_item", runnablev0.ToolExposure_EFFECT_READ_ONLY, "read"),
			"PROPOSALS__API_CONNECT_READ_AGAIN": prepared(readItems, "", runnablev0.ToolExposure_EFFECT_READ_ONLY, "read"),
			"PROPOSALS__API_ALT_GRPC_READ":      grpcEndpoint(prepared(readItems, "read_item", runnablev0.ToolExposure_EFFECT_READ_ONLY, "read")),
			"PROPOSALS__API_CONNECT_WRITE":      prepared(writeItems, "write_item", runnablev0.ToolExposure_EFFECT_MUTATION, "write"),
		}, nil
	}}
	admin := signedIn(t, k, "fixture-alex")

	listed, err := offers.ListOffers(admin, &installationv1.ListOffersRequest{OrganizationId: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, o := range listed.GetOffers() {
		names = append(names, o.GetTarget())
	}
	if !contains(names, "proposals") || contains(names, "documents") {
		t.Fatalf("offers are delivered solutions only: %v", names)
	}

	review, err := offers.ReviewOffer(admin, &installationv1.ReviewRequest{OrganizationId: "acme", Target: "proposals"})
	if err != nil {
		t.Fatal(err)
	}
	if review.GetInstallation() != nil || !review.GetToolsComposed() {
		t.Fatalf("an uninstalled offer with composed tools: %v", review)
	}
	approval, err := k.State.Service().Review(context.Background(), mustCaller(t, k, "fixture-alex"), "acme", "proposals")
	if err != nil || review.GetApproval().GetDigest() != approval.Digest || review.GetApproval().GetGeneration() != 1 {
		t.Fatalf("the review must carry Review's consent tuple: %v %v", review.GetApproval(), err)
	}
	roles := map[string]*installationv1.OfferRole{}
	for _, r := range review.GetRoles() {
		roles[r.GetName()] = r
	}
	viewer := tools(roles["viewer"])
	if len(viewer) != 1 || viewer[readItems] != "read_item:PROPOSALS__API_CONNECT_READ:false" {
		t.Fatalf("viewer reaches Read and its one Connect tool, never Write: %v", viewer)
	}
	installer := tools(roles[state.InstallerRole])
	if installer[writeItems] != "write_item:PROPOSALS__API_CONNECT_WRITE:true" {
		t.Fatalf("installer reaches Write as a write tool: %v", installer)
	}

	// The tuple installs exactly what was reviewed; a changed offer refuses it.
	tuple := review.GetApproval()
	tuple.OperationId = uuid.NewString()
	p := &Plugin{State: k.State}
	if _, err := k.State.ApplyManifest(func() state.Manifest { m := solution; m.Generation = 2; return m }()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Install(admin, &installationv1.InstallRequest{OrganizationId: "acme", Target: "proposals", Role: "viewer", OwnerPersonId: "alex", Approval: tuple}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a reviewed generation that changed must be reviewed again: %v", err)
	}
}

func TestOffersAreAnAdministratorsRead(t *testing.T) {
	k := testkit.New(t)
	offers := &Offers{plugin: &Plugin{State: k.State}}
	viewer := signedIn(t, k, "fixture-maya")
	if _, err := offers.ListOffers(viewer, &installationv1.ListOffersRequest{OrganizationId: "acme"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a viewer lists no offers: %v", err)
	}
	if _, err := offers.ReviewOffer(viewer, &installationv1.ReviewRequest{OrganizationId: "acme", Target: "wiki"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a viewer reviews no offer: %v", err)
	}
	admin := signedIn(t, k, "fixture-alex")
	if _, err := offers.ReviewOffer(admin, &installationv1.ReviewRequest{OrganizationId: "acme", Target: "documents"}); status.Code(err) != codes.NotFound {
		t.Fatalf("a module is installed by composition, never reviewed: %v", err)
	}
	review, err := offers.ReviewOffer(admin, &installationv1.ReviewRequest{OrganizationId: "acme", Target: "wiki"})
	if err != nil || review.GetInstallation() == nil || review.GetToolsComposed() {
		t.Fatalf("the installed wiki, no tools composed: %v %v", review, err)
	}
}

func mustCaller(t *testing.T, k *testkit.Kit, token string) authority.Person {
	t.Helper()
	sess, err := k.State.SignIn(token)
	if err != nil {
		t.Fatal(err)
	}
	caller, err := k.State.Caller(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	return caller
}

// tools is operation -> "tool:binding:write" for the role's single tools.
func tools(r *installationv1.OfferRole) map[string]string {
	out := map[string]string{}
	for _, c := range r.GetCapabilities() {
		for _, tool := range c.GetTools() {
			out[c.GetOperation()] = tool.GetName() + ":" + tool.GetBinding() + ":" + map[bool]string{true: "true", false: "false"}[tool.GetWrite()]
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
