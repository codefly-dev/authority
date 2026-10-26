// The local authority, end to end: every plugin registered on one gRPC server over
// an in-memory connection, driven by the suite every implementation must pass.
package registry_test

import (
	"context"
	core "github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"gateway/pkg/business/testkit"
	"gateway/pkg/framework"
	"gateway/plugins/authority"
	"gateway/plugins/composition"
	"gateway/plugins/installation"
	"gateway/plugins/session"

	conformance "github.com/codefly-dev/authority/libraries/conformance/go"

	"gateway/pkg/business/state"
)

func TestTheLocalAuthorityPassesTheSuiteEveryImplementationMustPass(t *testing.T) {
	k := testkit.New(t)
	testkit.SolutionTools(t, k)
	// The staleness probe revokes the viewer's own role, so her access to the
	// wiki must be hers alone: the composition's team grants become the same
	// role granted to each member directly.
	directGrants(t, k, state.InstallationID("acme", "wiki"), "viewer", map[string][]string{"finance": {"maya", "alex"}, "engineering": {"remi", "alex", "dev"}})
	if err := k.State.LoadFixture(context.Background(), []byte(`roles:
  - organization: acme
    name: owner
    scopes: []
people:
  - id: inventory-owner
    fixture_token: fixture-owner
    organization: acme
    roles: [owner]
`)); err != nil {
		t.Fatal(err)
	}
	source := testkit.Wiki(1)
	source.Name, source.Principal = "assistant", "assistant"
	source.Bindings = map[string]state.Binding{
		"directory": {ID: "directory", Audience: "org-directory", InvokeScopes: testkit.OrgDirectory(1).ResourceKinds},
		"documents": testkit.OrgDirectory(1).Bindings["documents"],
		"model":     testkit.Documents(1).Bindings["model"],
	}
	source.Roles["viewer"] = append(source.Roles["viewer"], testkit.Scope("directory.entry", "read"), testkit.Scope("documents", "read"), testkit.Scope("modelservice.profiles", "read"))
	if _, err := k.State.ApplyManifest(source); err != nil {
		t.Fatal(err)
	}
	installedChain, err := k.State.Install(context.Background(), "acme", source.Name, "viewer", "alex")
	if err != nil {
		t.Fatal(err)
	}
	// The explicit two-target delegation must name a target the granting module
	// declares, even when the live call reaches it through another module.
	directory := testkit.OrgDirectory(2)
	directory.Bindings["model"] = testkit.Documents(1).Bindings["model"]
	if _, err := k.State.ApplyManifest(directory); err != nil {
		t.Fatal(err)
	}
	model := testkit.Model(2)
	model.ResourceKinds = append(model.ResourceKinds, testkit.Scope("documents", "read", "write"))
	model.Bindings = map[string]state.Binding{
		"records": testkit.OrgDirectory(1).Bindings["records"],
		"self":    {ID: "self", Audience: "model", InvokeScopes: model.ResourceKinds},
	}
	if _, err := k.State.ApplyManifest(model); err != nil {
		t.Fatal(err)
	}
	records := testkit.Records(2)
	records.Bindings = map[string]state.Binding{"model": testkit.Documents(1).Bindings["model"]}
	if _, err := k.State.ApplyManifest(records); err != nil {
		t.Fatal(err)
	}
	plugins := []framework.Plugin{
		&authority.Plugin{Issuer: k.Issuer},
		&composition.Plugin{State: k.State, Coordinate: "local", Verifier: testkit.ReleaseVerifier(t, "local"), Carrier: k.CarrierAuthority, Keys: testkit.ReleaseKeys()},
		&installation.Plugin{State: k.State}, &session.Plugin{State: k.State},
	}
	server := grpc.NewServer()
	for _, p := range plugins {
		p.RegisterGRPC(server)
	}
	listener := bufconn.Listen(1 << 20)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_, file, _, _ := runtime.Caller(0)
	descriptors, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "..", "..", "..", "libraries", "authority-client", "contract", "contract.binpb"))
	if err != nil {
		t.Fatal(err)
	}
	chain := conformance.Chain{Token: "fixture-remi", Start: "org-directory", Hops: []conformance.Hop{
		{Credential: k.Credential(t, "org-directory"), Binding: "documents", Audience: "documents", AskKind: "documents", AskAction: "read"},
		{Credential: k.Credential(t, "documents"), Binding: "model", Audience: "model", AskKind: "modelservice.profiles", AskAction: "read"},
	}}
	// A dedicated declared workload with no active installation exercises the
	// refusal without removing any installation other cases need.
	absent := testkit.Documents(2)
	absent.Name, absent.Principal = "runtime", "runtime"
	if _, err := k.State.ApplyManifest(absent); err != nil {
		t.Fatal(err)
	}
	for _, org := range []string{"acme", "globex"} {
		if err := k.State.Uninstall(state.InstallationID(org, "runtime")); err != nil {
			t.Fatal(err)
		}
	}
	conformance.Run(t, conn, descriptors, conformance.Fixture{
		WorkloadOrganizations: &conformance.WorkloadOrganizationsCase{
			Ambiguous: conformance.WorkloadOrganizationCase{Credential: k.Credential(t, "org-directory"), Module: "org-directory", Binding: "records", Audience: "records"},
			None:      conformance.WorkloadOrganizationCase{Credential: k.Credential(t, "runtime"), Module: "runtime", Binding: "model", Audience: "model"},
		},
		LocalAdvisory: true,
		OwnerToken:    "fixture-owner",
		SlowChecks:    true,
		SolutionRoles: &conformance.SolutionRoleCase{
			Solution: "wiki", Credential: k.Credential(t, "wiki"), Token: "fixture-maya", Outsider: "fixture-no-roles",
			OwnKind: "wiki.page", OwnActions: []string{"read", "write", "publish"},
			Binding: "documents", Audience: "documents", ConsumedKind: "documents", ConsumedAction: "write", ForbiddenAction: "ingest", Generation: 2,
		},
		Lifecycle: &conformance.InstallationLifecycleCase{
			Target: "conformance-solution", Credential: k.Credential(t, "conformance-solution"), Kind: "conformance.page", Team: "finance",
			PauseInstall: func() func() {
				done := make(chan struct{})
				var once sync.Once
				k.State.OnInstall(func(ctx context.Context, _ state.Installation) error {
					select {
					case <-done:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				})
				return func() { once.Do(func() { close(done) }) }
			},
			Revoke: func(_ context.Context, id string) error { return k.State.Uninstall(id) },
		},
		UnentitledToken: "fixture-no-roles",
		Organization:    "acme", ViewerToken: "fixture-maya", AdminToken: "fixture-alex",
		// Maya reads records; the directory page hops on her context through its
		// records binding; a context at records is refused at model.
		Audience: "records", ReadKind: "records.records",
		WorkloadModule: "org-directory", WorkloadCredential: k.Credential(t, "org-directory"), Binding: "records", BindingAudience: "records", Elsewhere: "model",
		InstalledSolution: state.InstallationID("acme", "wiki"), InstalledAudience: "wiki", InstalledCredential: k.Credential(t, "wiki"),
		// Acme's wiki reaches finance and engineering; a local team is the id its
		// members carry, so one no person carries is a real team with no members.
		UnexposedTeam: "auditors",
		SolutionTools: &conformance.SolutionToolsCase{Token: "fixture-maya", Outsider: "fixture-remi", Module: "robin", Credential: k.Credential(t, "robin"), Binding: testkit.SolutionToolBinding, Audience: "proposals", Kind: "proposals.item", Action: "read", Method: testkit.SolutionToolMethod},
		// Deliveries are signed with the kit's release key and carried by the
		// module's own workload under the launcher.
		HostCoordinate: "local", HostDomain: "local",
		SignManifest:       testkit.SignDocument,
		SignAuthority:      testkit.SignAuthority,
		DeliveryCredential: func(module string) string { return k.Credential(t, module) },
		Matrix:             testkit.Matrix(),
		ParentLimits: &conformance.ParentLimitsCase{Token: "fixture-remi", Root: "model", Credential: k.Credential(t, "model"), SelfBinding: "self",
			Kind: "modelservice.profiles", DroppedKind: "documents", Action: "read", DroppedAction: "invoke", ResourceID: "a", OtherResourceID: "b",
			Out:  conformance.Hop{Credential: k.Credential(t, "model"), Audience: "records", Binding: "records"},
			Back: conformance.Hop{Credential: k.Credential(t, "records"), Audience: "model", Binding: "model"}},
		ChildScopes: &conformance.ChildScopesCase{Chain: chain, FirstActions: []string{"read", "write"}, NextActions: []string{"read", "invoke"},
			OutsideKind: "directory.entry", OutsideAction: "read", ResourceID: "a", OtherResourceID: "b", DroppedAction: "invoke"},
		InstallationChain: &conformance.InstallationChainCase{
			Installation: installedChain.ID, Source: source.Principal, Credential: k.Credential(t, source.Name),
			Hops: []conformance.Hop{
				{Credential: k.Credential(t, source.Name), Binding: "directory", Audience: "org-directory", AskKind: "directory.entry", AskAction: "read"},
				{Credential: k.Credential(t, "org-directory"), Binding: "documents", Audience: "documents", AskKind: "documents", AskAction: "read"},
				{Credential: k.Credential(t, "documents"), Binding: "model", Audience: "model", AskKind: "modelservice.profiles", AskAction: "read"},
			},
		},
		// Maya reads the directory's and the wiki's collections and every shared
		// one, and administers none: the authority's answer, not her token's.
		// The page may write documents for Rémi, and a lookup through it reads.
		Lookup: &conformance.LookupCase{Token: "fixture-remi", Start: "org-directory", Credential: k.Credential(t, "org-directory"),
			Binding: "documents", Audience: "documents", Kind: "documents", Invoke: "write", Lookup: "read"},
		// Rémi lets the page write documents for him; Maya, a viewer, cannot.
		Delegation: &conformance.DelegationCase{Token: "fixture-remi", Outsider: "fixture-maya", Module: "org-directory",
			Credential: k.Credential(t, "org-directory"), Binding: "documents", Audience: "documents", Kind: "documents", Action: "write"},
		Resources: &conformance.ResourceCase{
			Token: "fixture-maya", Audience: "documents", Kind: "documents.collection", Action: "read",
			Covered: []string{"derived\x1fdirectory", "derived\x1fwiki", "shared-finance"}, Uncovered: []string{"finance", "shared-Finance"}, Unheld: "admin",
		},
		// Rémi at the page; the page asks documents; documents asks the model,
		// for a read Rémi holds at the model and his first token never carried.
		Chain: &chain,
	})
}

// directGrants replaces each team's grant of role on installation id with the
// same role granted to each of its members.
func directGrants(t *testing.T, k *testkit.Kit, id, role string, members map[string][]string) {
	t.Helper()
	admin := core.Person{ID: "alex", Organization: "acme"}
	for team, people := range members {
		if _, err := k.State.Service().RevokeRole(context.Background(), admin, core.RoleRequest{Organization: "acme", InstallationID: id, Role: role, TeamID: team}); err != nil {
			t.Fatal(err)
		}
		for _, person := range people {
			if err := k.State.GrantRole(domain.RoleGrant{InstallationID: id, Role: role, PersonID: person}); err != nil {
				t.Fatal(err)
			}
		}
	}
}
