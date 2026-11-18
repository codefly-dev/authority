package composition

import (
	"context"
	"errors"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"strings"
	"testing"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	compositionv1 "gateway/pkg/gen/host/composition/v1"

	delivery "github.com/codefly-dev/authority/libraries/delivery/go"
	"github.com/codefly-dev/authority/libraries/solutionhost/go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// carrier is one delivery as the CLI makes it: core's manifest signed with the
// release key, the authority's document signed by the same key and naming it,
// and the module's own delivery credential under the kit's launcher.
func carrier(t *testing.T, k *testkit.Kit, alias string, kind solutionhost.Kind, generation uint64, kinds []string, authority *compositionv1.AuthorityManifestV1, configure ...func(*solutionhost.ModuleManifest)) *compositionv1.ApplyManifestRequest {
	t.Helper()
	manifest := &solutionhost.ModuleManifest{
		Schema: solutionhost.SchemaModuleManifestV1, Binding: alias, Alias: alias, Kind: kind, Generation: generation,
		Host:      solutionhost.HostTarget{Coordinate: "local", Domain: "local"},
		Release:   solutionhost.Release{Publisher: "test", Name: alias, Version: "0.1.0"},
		Workloads: []solutionhost.Workload{{Service: "api", Container: "app"}},
		Authority: &solutionhost.Authority{Principal: alias, ResourceKinds: kinds},
	}
	for _, change := range configure {
		change(manifest)
	}
	document, err := solutionhost.SignedPayload(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := testkit.SignDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	req := &compositionv1.ApplyManifestRequest{Carrier: &compositionv1.SignedManifestV1{Document: document, Envelope: envelope}, Credential: k.Credential(t, alias)}
	if authority != nil {
		authority.Module, authority.Generation, authority.CoreManifestDigest = alias, generation, delivery.Digest(document)
		// A solution receives its roles' owner-selected scopes, so it declares
		// owner-aware checking.
		authority.OwnerAware = authority.OwnerAware || kind == solutionhost.KindSolution
		doc, err := proto.MarshalOptions{Deterministic: true}.Marshal(authority)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := testkit.SignAuthority(doc)
		if err != nil {
			t.Fatal(err)
		}
		req.Authority = &compositionv1.SignedManifestV1{Document: doc, Envelope: signed}
	}
	return req
}

func scope(kind string, actions ...string) *authorityv1.WorkScopeV1 {
	return &authorityv1.WorkScopeV1{ResourceKind: kind, Actions: actions}
}

// verifying is the plugin as the local authority wires it: the kit's state, its pinned
// release key, and deliveries admitted from the module's own workload.
func verifying(t *testing.T) (*Plugin, *testkit.Kit) {
	t.Helper()
	k := testkit.Conformance(t)
	return &Plugin{State: k.State, Coordinate: "local", Verifier: testkit.ReleaseVerifier(t, "local"), Carrier: k.CarrierAuthority, Keys: testkit.ReleaseKeys()}, k
}

func held(t *testing.T, k *testkit.Kit, person, audience string) string {
	t.Helper()
	scopes, err := k.PersonScopes(t, person, audience)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, sc := range scopes {
		out = append(out, sc.GetResourceKind()+":"+strings.Join(sc.GetActions(), ","))
	}
	return strings.Join(out, " ")
}

// A solution delivered as a carrier arrives with its roles in the authority's
// document: the wiki at its next generation replaces the sketch the kit composed
// it through, and the fixture's installations grant exactly those roles — the
// admin role to its owner, the installation's role through the granted teams.
func TestASolutionDeliveredAsACarrierInstallsWithItsRoles(t *testing.T) {
	p, k := verifying(t)
	page := scope("wiki.page", "read", "write", "publish")
	roles := []*compositionv1.RoleV1{
		{Name: state.AdminRole, Scopes: []*authorityv1.WorkScopeV1{page}},
		{Name: state.UserRole, Scopes: []*authorityv1.WorkScopeV1{scope("wiki.page", "read")}},
	}
	out, err := p.ApplyManifest(context.Background(), carrier(t, k, "wiki", solutionhost.KindSolution, 2, []string{"wiki.page"},
		&compositionv1.AuthorityManifestV1{ScopeCeilings: []*authorityv1.WorkScopeV1{page}, Roles: roles}))
	if err != nil || out.GetGeneration() != 2 || out.GetPrincipal() != "wiki" {
		t.Fatalf("apply: %v %v", out, err)
	}
	for person, want := range map[string]string{
		"alex": "wiki.page:publish,read,write", // the owner holds the admin role
		"maya": "wiki.page:read",               // finance holds Acme's user role, which reads
		"remi": "wiki.page:read",               // engineering too, since the fixture grants both
		"omar": "wiki.page:read",               // ops holds Globex's user role
	} {
		if got := held(t, k, person, "wiki"); got != want {
			t.Errorf("%s holds %q at the wiki, want %q", person, got, want)
		}
	}
}

// The role contract holds at the carrier as at the sketch: a solution with no
// admin, or no roles at all, a role beyond the solution's own kinds, a
// module declaring roles, and a document naming a role twice are each refused by
// name, and nothing of the refused composes.
func TestRolesInTheDocumentAreHeldToTheRoleContract(t *testing.T) {
	p, k := verifying(t)
	all := []*authorityv1.WorkScopeV1{scope("conformance.page", "read", "write")}
	admin := func(scopes ...*authorityv1.WorkScopeV1) *compositionv1.RoleV1 {
		return &compositionv1.RoleV1{Name: state.AdminRole, Scopes: scopes}
	}
	user := &compositionv1.RoleV1{Name: "user", Scopes: all}
	for name, c := range map[string]struct {
		alias  string
		kind   solutionhost.Kind
		doc    *compositionv1.AuthorityManifestV1
		code   codes.Code
		reason string
	}{
		"no admin": {"conformance-solution", solutionhost.KindSolution,
			&compositionv1.AuthorityManifestV1{ScopeCeilings: all, Roles: []*compositionv1.RoleV1{{Name: "user", Scopes: all}}}, codes.PermissionDenied, `none is "admin"`},
		"no roles at all": {"conformance-solution", solutionhost.KindSolution,
			&compositionv1.AuthorityManifestV1{ScopeCeilings: all}, codes.PermissionDenied, "declares 0 role(s)"},
		"a role beyond the kind's actions": {"conformance-solution", solutionhost.KindSolution,
			&compositionv1.AuthorityManifestV1{ScopeCeilings: all, Roles: []*compositionv1.RoleV1{admin(scope("conformance.page", "read", "write", "delete")), user}}, codes.PermissionDenied, "grants beyond what conformance-solution serves"},
		"a role on a kind the solution does not serve": {"conformance-solution", solutionhost.KindSolution,
			&compositionv1.AuthorityManifestV1{ScopeCeilings: all, Roles: []*compositionv1.RoleV1{admin(all[0], scope("documents", "read")), user}}, codes.PermissionDenied, "grants beyond what conformance-solution serves"},
		"a module declaring roles": {"conformance-probe", solutionhost.KindModule,
			&compositionv1.AuthorityManifestV1{ScopeCeilings: all, Roles: []*compositionv1.RoleV1{admin(all...)}}, codes.PermissionDenied, "declares roles and no page"},
		"a role neither admin nor user": {"conformance-solution", solutionhost.KindSolution,
			&compositionv1.AuthorityManifestV1{ScopeCeilings: all, Roles: []*compositionv1.RoleV1{admin(all...), user, {Name: "viewer", Scopes: all}}}, codes.PermissionDenied, `declares role "viewer", which is neither "admin" nor "user"`},
		"no user": {"conformance-solution", solutionhost.KindSolution,
			&compositionv1.AuthorityManifestV1{ScopeCeilings: all, Roles: []*compositionv1.RoleV1{admin(all...)}}, codes.PermissionDenied, `none is "user"`},
		"a role named twice": {"conformance-solution", solutionhost.KindSolution,
			&compositionv1.AuthorityManifestV1{ScopeCeilings: all, Roles: []*compositionv1.RoleV1{admin(all...), admin(all...)}}, codes.InvalidArgument, "twice or unnamed"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := p.ApplyManifest(context.Background(), carrier(t, k, c.alias, c.kind, 1, []string{"conformance.page"}, c.doc))
			if status.Code(err) != c.code || !strings.Contains(err.Error(), c.reason) {
				t.Fatalf("got %v, want %s naming %q", err, c.code, c.reason)
			}
		})
	}
	if _, err := k.PersonScopes(t, "alex", "conformance-solution"); !errors.Is(err, state.ErrUnknown) {
		t.Fatalf("a refused solution composed: %v", err)
	}
	// The same solution with the contract met composes, and its admin and
	// user are what the admin and user hold.
	doc := &compositionv1.AuthorityManifestV1{ScopeCeilings: all, Roles: []*compositionv1.RoleV1{admin(all...), {Name: "user", Scopes: []*authorityv1.WorkScopeV1{scope("conformance.page", "read")}}}}
	if _, err := p.ApplyManifest(context.Background(), carrier(t, k, "conformance-solution", solutionhost.KindSolution, 1, []string{"conformance.page"}, doc)); err != nil {
		t.Fatal(err)
	}
	inst, err := k.State.InstallAsHost(context.Background(), "acme", "conformance-solution", "user", "alex")
	if err != nil {
		t.Fatal(err)
	}
	if err := k.State.GrantRole(domain.RoleGrant{InstallationID: inst.ID, Role: state.AdminRole, PersonID: "alex"}); err != nil {
		t.Fatal(err)
	}
	if got := held(t, k, "alex", "conformance-solution"); got != "conformance.page:read,write" {
		t.Fatalf("the admin holds %q", got)
	}
}
