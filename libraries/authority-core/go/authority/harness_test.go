package authority_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/codefly-dev/core/workcontext"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/memstore"
	resources "github.com/codefly-dev/authority/libraries/resources/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The fixture mirrors the conformance target (RunSolutionPrincipalTarget): two
// solutions A and B and a solution C that checks no owners, a store serving
// "collection" (owner-aware) and a legacy store (not), people at acme and globex.
const (
	kind, legacyKind = "collection", "legacy"
	acme, globex     = "acme", "globex"
)

type keys struct{ public ed25519.PublicKey }

func (k keys) PublicKeys(context.Context) (map[string]ed25519.PublicKey, error) {
	return map[string]ed25519.PublicKey{"k1": k.public}, nil
}

type harness struct {
	t     *testing.T
	store *memstore.Store
	svc   *authority.Service
	now   time.Time
	ctx   context.Context
}

func sc(k string, actions ...string) *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: k, Actions: actions}
}

func owned(k, owner string, actions []string, ids ...string) *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: k, Actions: actions, ResourceIds: ids, ResourceOwnerId: owner}
}

func solution(name string, ownerAware bool) domain.Module {
	own := name + ".note"
	return domain.Module{Name: name, Principal: name, Kind: domain.KindSolution, Generation: 1, OwnerAware: ownerAware,
		ResourceKinds: []*basev0.WorkScopeV1{sc(own, "read", "write")},
		Bindings: map[string]domain.Binding{
			"store":  {ID: "store", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "admin", "create", "read", "write")}},
			"legacy": {ID: "legacy", Audience: "legacy-store", InvokeScopes: []*basev0.WorkScopeV1{sc(legacyKind, "read")}},
		},
		Roles: map[string][]*basev0.WorkScopeV1{
			domain.InstallerRole: {sc(own, "read", "write"), sc(kind, "admin", "create", "read", "write")},
			"author":             {sc(own, "read", "write"), sc(kind, "create", "read", "write")},
			"editor":             {sc(own, "read"), sc(kind, "read")},
			"viewer":             {sc(own, "read"), sc(kind, "read"), sc(legacyKind, "read")},
		}}
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, store: memstore.New(), now: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC), ctx: context.Background()}
	n := 0
	replay := workcontext.NewMemoryReplayStore()
	replay.Now = func() time.Time { return h.now }
	h.svc, err = authority.New(h.store, authority.Config{Issuer: "https://authority.test", KeyID: "k1", Signer: private, Keys: keys{public}, Replay: replay,
		Clock: func() time.Time { return h.now }, NewID: func() string { n++; return fmt.Sprintf("id-%d", n) }})
	if err != nil {
		t.Fatal(err)
	}
	for _, org := range []string{acme, globex} {
		h.store.PutOrganization(domain.Organization{ID: org, Name: org})
	}
	h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "admin", Scopes: nil})
	h.store.PutOrgRole(domain.OrgRole{Organization: globex, Name: "admin", Scopes: nil})
	h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "store-admin", Scopes: []domain.RoleScope{{Kind: kind, Actions: []string{"admin"}, Resources: []resources.Grant{{ID: "store-x"}}}}})
	h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "store-reader", Scopes: []domain.RoleScope{{Kind: kind, Actions: []string{"read"}, Resources: []resources.Grant{{ID: "store-x"}}}}})
	for _, p := range []domain.Person{
		{ID: "alex", Organization: acme, Roles: []string{"admin"}},
		{ID: "maya", Organization: acme}, {ID: "remi", Organization: acme}, {ID: "dev", Organization: acme},
		{ID: "ines", Organization: acme}, {ID: "tam", Organization: acme, Teams: []string{"team"}}, {ID: "tal", Organization: acme, Teams: []string{"team"}},
		{ID: "ada", Organization: acme, Roles: []string{"store-admin"}}, {ID: "rob", Organization: acme, Roles: []string{"store-reader"}},
		{ID: "zoe", Organization: globex, Roles: []string{"admin"}}, {ID: "omar", Organization: globex, Teams: []string{"ops"}},
	} {
		h.store.PutPerson(p)
	}
	for _, m := range []domain.Module{
		{Name: "store", Principal: "store", Kind: domain.KindModule, Generation: 1, OwnerAware: true,
			ResourceKinds: []*basev0.WorkScopeV1{sc(kind, "admin", "create", "read", "write")},
			Bindings: map[string]domain.Binding{
				"self":   {ID: "self", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read", "write")}, HeadlessScopes: []*basev0.WorkScopeV1{sc(kind, "read")}},
				"legacy": {ID: "legacy", Audience: "legacy-store", InvokeScopes: []*basev0.WorkScopeV1{sc(legacyKind, "read")}},
			}},
		{Name: "legacy-store", Principal: "legacy-store", Kind: domain.KindModule, Generation: 1, ResourceKinds: []*basev0.WorkScopeV1{sc(legacyKind, "read")}},
		solution("a", true), solution("b", true), solution("c", false),
	} {
		if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	h.install(acme, "a")
	h.install(acme, "b")
	h.install(acme, "c")
	h.install(globex, "a")
	return h
}

func (h *harness) person(id string) authority.Person {
	org := acme
	if id == "zoe" || id == "omar" {
		org = globex
	}
	return authority.Person{ID: id, Organization: org, SessionID: "session-" + id}
}

func (h *harness) admin(org string) authority.Person {
	if org == globex {
		return h.person("zoe")
	}
	return h.person("alex")
}

func (h *harness) install(org, target string) domain.Installation {
	h.t.Helper()
	admin := h.admin(org)
	inst, err := h.svc.Install(h.ctx, &admin, org, target, "author", admin.ID, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	return inst
}

func (h *harness) inst(org, target string) domain.Installation {
	return domain.Installation{ID: authority.StableInstallationID(org, target), PrincipalID: authority.StablePrincipalID(org, target)}
}

func (h *harness) principal(org, target string) string { return h.inst(org, target).PrincipalID }

func (h *harness) grant(target, role, person string) {
	h.t.Helper()
	if _, err := h.svc.GrantRole(h.ctx, h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, target).ID, Role: role, PersonID: person}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) grantTeam(target, role, team string) {
	h.t.Helper()
	if _, err := h.svc.GrantRole(h.ctx, h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, target).ID, Role: role, TeamID: team}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) revoke(target, role, person, team string) {
	h.t.Helper()
	if _, err := h.svc.RevokeRole(h.ctx, h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, target).ID, Role: role, PersonID: person, TeamID: team}); err != nil {
		h.t.Fatal(err)
	}
}

// refused requires a refusal naming reason.
func refused(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), reason) {
		t.Fatalf("want a refusal naming %q, got %v", reason, err)
	}
}

func code(t *testing.T, err error, want domain.Code) {
	t.Helper()
	if got, ok := domain.CodeOf(err); !ok || got != want {
		t.Fatalf("want code %v, got %v (%v)", want, got, err)
	}
}

var _ = errors.New
