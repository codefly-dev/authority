package state_test

import (
	"context"
	"errors"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
)

func TestFixtureSeedsPeopleRolesAndInstallsThroughTheRealPath(t *testing.T) {
	k := testkit.New(t)
	sess, err := k.State.SignIn("fixture-maya")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Person != "maya" || sess.Organization != "acme" || sess.Roles[0] != "viewer" {
		t.Fatalf("session = %+v", sess)
	}
	if _, err := k.State.SignIn("nobody"); !errors.Is(err, state.ErrUnknown) {
		t.Fatalf("unknown token: %v", err)
	}
	wiki, ok := k.State.Installation("acme/wiki")
	if !ok || wiki.Status != state.Active || wiki.Role != "viewer" || len(wiki.Teams) != 1 || wiki.Teams[0] != "finance" {
		t.Fatalf("wiki installation = %+v", wiki)
	}
}

func TestEntitlementIsTheNavigation(t *testing.T) {
	k := testkit.New(t)
	if got := k.State.Entitled("maya"); len(got) != 1 || got[0].Target != "wiki" {
		t.Fatalf("maya (finance) sees %+v", got)
	}
	if got := k.State.Entitled("remi"); len(got) != 0 {
		t.Fatalf("remi (engineering) sees %+v", got)
	}
	if _, err := k.State.GrantToTeam(context.Background(), "acme", "acme/wiki", "engineering"); err != nil {
		t.Fatal(err)
	}
	if got := k.State.Entitled("remi"); len(got) != 1 {
		t.Fatalf("after the grant remi sees %+v", got)
	}
}

func TestAModuleInstallationExistsPerOrganisationWithoutAClick(t *testing.T) {
	k := testkit.New(t)
	for _, id := range []string{"acme/documents", "acme/model"} {
		inst, ok := k.State.Installation(id)
		if !ok || inst.Status != state.Active {
			t.Fatalf("%s = %+v", id, inst)
		}
	}
	if got := k.State.Entitled("alex"); len(got) != 1 {
		t.Fatalf("module installations are not navigation entries: %+v", got)
	}
}

func TestAManifestMovesOnlyForward(t *testing.T) {
	k := testkit.New(t)
	if _, err := k.State.ApplyManifest(testkit.Documents(1)); !errors.Is(err, state.ErrStale) {
		t.Fatalf("same generation: %v", err)
	}
	if _, err := k.State.ApplyManifest(testkit.Documents(2)); err != nil {
		t.Fatal(err)
	}
	m, _ := k.State.Module("documents")
	if m.Generation != 2 {
		t.Fatalf("generation = %d", m.Generation)
	}
	epoch, _ := k.State.PrincipalEpoch(context.Background(), "documents")
	if epoch != 2 {
		t.Fatalf("epoch follows the generation, got %d", epoch)
	}
}

func TestAManifestWithSomeBindingsIsNotAllOrNothing(t *testing.T) {
	// The host today drops a module's whole registry entry when one binding is
	// not granted. Here the ceiling is the manifest: a module with one binding
	// granted and nothing else still gets its principal and that binding.
	k := testkit.New(t)
	m := testkit.Documents(2)
	m.Bindings["tracing"] = state.Binding{ID: "tracing", Audience: "tracing",
		InvokeScopes: []*basev0.WorkScopeV1{testkit.Scope("trace.span", "write")}}
	if _, err := k.State.ApplyManifest(m); err != nil {
		t.Fatal(err)
	}
	if _, err := k.State.OperationBinding(context.Background(), "acme/documents/model"); err != nil {
		t.Fatalf("the granted binding: %v", err)
	}
	if _, err := k.State.OperationBinding(context.Background(), "acme/documents/missing"); !errors.Is(err, workcontext.ErrNoBinding) {
		t.Fatalf("an undeclared binding: %v", err)
	}
}

func TestHeadlessScopesMayNotExceedInvokeScopes(t *testing.T) {
	k := testkit.New(t)
	m := testkit.Documents(2)
	b := m.Bindings["model"]
	b.HeadlessScopes = append(b.HeadlessScopes, testkit.Scope("modelservice.profiles", "admin"))
	m.Bindings["model"] = b
	if _, err := k.State.ApplyManifest(m); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("widening headless: %v", err)
	}
}

func TestOnePrincipalBelongsToOneModule(t *testing.T) {
	k := testkit.New(t)
	m := testkit.Wiki(2)
	m.Module = "wiki2"
	if _, err := k.State.ApplyManifest(m); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("stolen principal: %v", err)
	}
}

func TestSealAnswersOnlyForAnActiveInstallationAndAKnownPrincipal(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	if s, err := k.State.Seal(ctx, "maya", "acme/documents"); err != nil || s.InstallationRevision != 1 {
		t.Fatalf("member at module installation: %v %+v", err, s)
	}
	if _, err := k.State.Seal(ctx, "stranger", "acme/documents"); !errors.Is(err, workcontext.ErrNoSeal) {
		t.Fatalf("stranger: %v", err)
	}
	if _, err := k.State.Seal(ctx, "acme/wiki/agent", "acme/wiki"); err != nil {
		t.Fatalf("the installation's own agent: %v", err)
	}
	if err := k.State.Revoke("acme/wiki"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.State.Seal(ctx, "maya", "acme/wiki"); !errors.Is(err, workcontext.ErrNoSeal) {
		t.Fatalf("revoked installation: %v", err)
	}
}

func TestTheAuthorizationRevisionMovesOnEveryGrantChange(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	before, _ := k.State.AuthorizationRevision(ctx, "acme")
	if _, err := k.State.GrantToTeam(ctx, "acme", "acme/wiki", "engineering"); err != nil {
		t.Fatal(err)
	}
	after, _ := k.State.AuthorizationRevision(ctx, "acme")
	if after != before+1 {
		t.Fatalf("revision %d → %d", before, after)
	}
	if _, err := k.State.AuthorizationRevision(ctx, "nowhere"); !errors.Is(err, state.ErrUnknown) {
		t.Fatalf("unknown tenant: %v", err)
	}
}

func TestInstallRunsTheTargetsInstallStepAndStaysPendingUntilItConverges(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	calls := 0
	k.State.OnInstall(func(_ context.Context, inst state.Installation) error {
		calls++
		if inst.Status != state.Pending {
			t.Fatalf("install step sees %s", inst.Status)
		}
		if calls == 1 {
			return errors.New("transient")
		}
		return nil
	})
	if _, err := k.State.ApplyManifest(state.Manifest{Module: "proposals", Principal: "proposals", Kind: "solution", Generation: 1}); err != nil {
		t.Fatal(err)
	}
	inst, err := k.State.Install(ctx, "acme", "proposals", "viewer", "alex")
	if err == nil || inst.Status != state.Pending {
		t.Fatalf("first attempt: %v %+v", err, inst)
	}
	if _, err := k.State.Install(ctx, "acme", "proposals", "viewer", "alex"); err == nil {
		t.Fatal("a pending installation is not installed twice")
	}
	inst, err = k.State.Acknowledge("acme/proposals")
	if err != nil || inst.Status != state.Active {
		t.Fatalf("after acknowledgement: %v %+v", err, inst)
	}
}

func TestInstallRefusesAnUnknownRoleAndAForeignOwner(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	if _, err := k.State.Install(ctx, "acme", "x", "nope", "alex"); !errors.Is(err, state.ErrUnknown) {
		t.Fatalf("unknown role: %v", err)
	}
	if _, err := k.State.Install(ctx, "acme", "x", "viewer", "stranger"); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("foreign owner: %v", err)
	}
}

func TestWorkloadCredentialIsTheLaunchersWordAndNothingElse(t *testing.T) {
	k := testkit.New(t)
	good := state.WorkloadCredential(k.Launcher, "documents")
	if m, err := k.State.VerifyWorkload(good); err != nil || m.Module != "documents" {
		t.Fatalf("good credential: %v %+v", err, m)
	}
	if _, err := k.State.VerifyWorkload(state.WorkloadCredential(k.Launcher, "ghost")); !errors.Is(err, state.ErrUnknown) {
		t.Fatalf("uncomposed module: %v", err)
	}
	other := testkit.New(t)
	if _, err := k.State.VerifyWorkload(state.WorkloadCredential(other.Launcher, "documents")); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("another launcher's key: %v", err)
	}
	if _, err := k.State.VerifyWorkload("garbage"); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("garbage: %v", err)
	}
}

func TestScopeAlgebra(t *testing.T) {
	a := []*basev0.WorkScopeV1{testkit.Scope("documents", "write", "read"), testkit.Scope("documents", "ingest")}
	n := state.Normalize(a)
	if len(n) != 1 || len(n[0].Actions) != 3 || n[0].Actions[0] != "ingest" {
		t.Fatalf("normalize = %v", n)
	}
	ceiling := []*basev0.WorkScopeV1{testkit.Scope("documents", "read")}
	if got := state.Intersect(a, ceiling); len(got) != 1 || len(got[0].Actions) != 1 || got[0].Actions[0] != "read" {
		t.Fatalf("intersect = %v", got)
	}
	if !state.Attenuates(ceiling, a) || state.Attenuates(a, ceiling) {
		t.Fatal("attenuates is not the subset relation")
	}
	if !state.Attenuates(nil, ceiling) {
		t.Fatal("nothing attenuates everything")
	}
}
