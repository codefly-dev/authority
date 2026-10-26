package state_test

import (
	"context"
	"errors"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"regexp"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
	"github.com/codefly-dev/core/workloadidentity/native"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
)

func TestAModuleInstallationExistsPerOrganisationWithoutAClick(t *testing.T) {
	k := testkit.New(t)
	for _, id := range []string{state.InstallationID("acme", "documents"), state.InstallationID("acme", "model")} {
		inst, ok := k.State.Installation(id)
		if !ok || inst.Status != state.Active {
			t.Fatalf("%s = %+v", id, inst)
		}
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
	epoch, _ := k.State.Service().Seals().PrincipalEpoch(context.Background(), "documents")
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
	if _, err := k.State.Service().Seals().OperationBinding(context.Background(), "acme/documents/model"); err != nil {
		t.Fatalf("the granted binding: %v", err)
	}
	if _, err := k.State.Service().Seals().OperationBinding(context.Background(), "acme/documents/missing"); !errors.Is(err, workcontext.ErrNoBinding) {
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
	// A binding only for the module's own work declares no invoke scopes.
	m = testkit.Documents(3)
	m.Bindings["tracing"] = state.Binding{ID: "tracing", Audience: "tracing", HeadlessScopes: []*basev0.WorkScopeV1{testkit.Scope("tracing.spans", "export")}}
	if _, err := k.State.ApplyManifest(m); err != nil {
		t.Fatalf("a headless-only binding stands alone: %v", err)
	}
}

func TestOnePrincipalBelongsToOneModule(t *testing.T) {
	k := testkit.New(t)
	m := testkit.Wiki(2)
	m.Name = "wiki2"
	if _, err := k.State.ApplyManifest(m); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("stolen principal: %v", err)
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
	if _, err := k.State.ApplyManifest(testkit.Proposals(1)); err != nil {
		t.Fatal(err)
	}
	inst, err := k.State.InstallAsHost(ctx, "acme", "proposals", "viewer", "alex")
	if err == nil || inst.Status != state.Pending {
		t.Fatalf("first attempt: %v %+v", err, inst)
	}
	// The host's own setup asking again resumes the pending attempt.
	inst, err = k.State.InstallAsHost(ctx, "acme", "proposals", "viewer", "alex")
	if err != nil || inst.Status != state.Active || calls != 2 {
		t.Fatalf("resumed attempt: %v %+v, calls %d", err, inst, calls)
	}
}

func TestInstallRefusesAnUnknownRoleAndAForeignOwner(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	if _, err := k.State.InstallAsHost(ctx, "acme", "wiki", "nope", "alex"); !errors.Is(err, state.ErrUnknown) {
		t.Fatalf("a role the solution does not declare: %v", err)
	}
	if _, err := k.State.InstallAsHost(ctx, "acme", "wiki", "viewer", "stranger"); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("foreign owner: %v", err)
	}
	if _, err := k.State.InstallAsHost(ctx, "acme", "documents", "viewer", "alex"); !errors.Is(err, state.ErrUnknown) {
		t.Fatalf("a module is installed by composition, never by a click: %v", err)
	}
}

// A solution declares its roles: an installer always, each within what it serves;
// a module declares none.
func TestASolutionDeclaresAnInstallerAndRolesWithinWhatItServes(t *testing.T) {
	k := testkit.New(t)
	noInstaller := testkit.Proposals(1)
	delete(noInstaller.Roles, state.InstallerRole)
	if _, err := k.State.ApplyManifest(noInstaller); !errors.Is(err, domain.ErrNoInstallerRole) {
		t.Fatalf("no installer: %v", err)
	}
	beyond := testkit.Proposals(1)
	beyond.Roles["auditor"] = []*basev0.WorkScopeV1{testkit.Scope("proposals.item", "read", "delete")}
	if _, err := k.State.ApplyManifest(beyond); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("a role beyond what the solution serves: %v", err)
	}
	module := testkit.Records(2)
	module.Roles = map[string][]*basev0.WorkScopeV1{"viewer": {testkit.Scope("records.records", "read")}}
	if _, err := k.State.ApplyManifest(module); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("a module declaring roles: %v", err)
	}
}

func TestWorkloadCredentialIsTheLaunchersNativeOneAndNothingElse(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	if m, err := k.State.VerifyWorkload(ctx, k.Credential(t, "documents")); err != nil || m.Name != "documents" {
		t.Fatalf("the launcher's credential for documents: %v %+v", err, m)
	}
	// A module the launcher never declared is refused by core's attester: the
	// anchor vouches for declared subjects only.
	if _, err := k.Launcher.Issue(native.Subject{Workload: testkit.Workload("ghost"), Container: "ghost"}, testkit.Audience); err == nil {
		t.Fatal("the launcher issued for a process it never declared")
	}
	other := testkit.New(t)
	if _, err := k.State.VerifyWorkload(ctx, other.Credential(t, "documents")); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("another launcher's credential: %v", err)
	}
	if _, err := k.State.VerifyWorkload(ctx, "garbage"); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("garbage: %v", err)
	}
	if _, err := k.State.VerifyWorkload(ctx, k.Credential(t, "wiki")); err != nil {
		t.Fatalf("a declared, composed solution process: %v", err)
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

// TestAnInstallationIsNamedByACanonicalUUID pins what a module keys its rows
// by: a lower-case hyphenated UUID, as the host issues, the same for one
// organisation's installation of one target on every start, and another for
// any other pair.
func TestAnInstallationIsNamedByACanonicalUUID(t *testing.T) {
	id := state.InstallationID("acme", "robin")
	canonical := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !canonical.MatchString(id) {
		t.Fatalf("installation id %q is not a canonical UUID", id)
	}
	if again := state.InstallationID("acme", "robin"); again != id {
		t.Fatalf("named %q, then %q", id, again)
	}
	for _, other := range []string{state.InstallationID("globex", "robin"), state.InstallationID("acme", "documents"), state.InstallationID("acme/robin", ""), state.InstallationID("acme", "/robin")} {
		if other == id {
			t.Fatalf("two installations share %q", id)
		}
	}
	k := testkit.New(t)
	if _, ok := k.State.Installation(state.InstallationID("acme", "documents")); !ok {
		t.Fatal("the composed module's installation is not named by InstallationID")
	}
}
