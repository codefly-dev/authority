package authority_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/core/workcontext"
	"github.com/google/uuid"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/memstore"
	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"
)

// The fixture mirrors the conformance target (RunSolutionPrincipalTarget): two
// solutions A and B and a solution C that checks no owners, a store serving
// "collection" (owner-aware), a legacy store and a ledger (neither checks
// owners), people at acme and globex.
//
// Organisation roles decide administration only and reach no module: alex and
// zoe administer their organisations, and neither they nor ada and rob, whose
// organisation roles are named after the store and the ledger, are issued
// anything by one. A person reaches a module through a role on an
// installation.
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
	cfg   authority.Config
	now   time.Time
	ctx   context.Context
}

func sc(k string, actions ...string) *basev1.WorkScopeV1 {
	return &basev1.WorkScopeV1{ResourceKind: k, Actions: actions}
}

func owned(k, owner string, actions []string, ids ...string) *basev1.WorkScopeV1 {
	return &basev1.WorkScopeV1{ResourceKind: k, Actions: actions, ResourceIds: ids, ResourceOwnerId: owner}
}

func solution(name string, ownerAware bool) domain.Module {
	own := name + ".note"
	return domain.Module{Name: name, Principal: name, Kind: domain.KindSolution, Generation: 1, OwnerAware: ownerAware,
		ResourceKinds: []*basev1.WorkScopeV1{sc(own, "read", "write")},
		Bindings: map[string]domain.Binding{
			"store":  {ID: "store", Audience: "store", InvokeScopes: []*basev1.WorkScopeV1{sc(kind, "admin", "create", "read", "write")}},
			"legacy": {ID: "legacy", Audience: "legacy-store", InvokeScopes: []*basev1.WorkScopeV1{sc(legacyKind, "read")}},
		},
		// The two roles a solution declares. Neither holds the store's admin
		// action, which the store binding offers: what no role names is
		// beyond every person and the installation's agent.
		Roles: map[string][]*basev1.WorkScopeV1{
			domain.AdminRole: {sc(own, "read", "write"), sc(kind, "create", "read", "write")},
			domain.UserRole:  {sc(own, "read"), sc(kind, "read"), sc(legacyKind, "read")},
		}}
}

// newHarness is the fixture: bareHarness, the fixture's modules delivered and
// its solutions installed.
func newHarness(t *testing.T) *harness {
	t.Helper()
	h := bareHarness(t)
	for _, m := range []domain.Module{
		{Name: "store", Principal: "store", Kind: domain.KindModule, Generation: 1, OwnerAware: true,
			ResourceKinds: []*basev1.WorkScopeV1{sc(kind, "admin", "create", "read", "write")},
			Bindings: map[string]domain.Binding{
				"self":   {ID: "self", Audience: "store", InvokeScopes: []*basev1.WorkScopeV1{sc(kind, "read", "write")}, HeadlessScopes: []*basev1.WorkScopeV1{sc(kind, "read")}},
				"legacy": {ID: "legacy", Audience: "legacy-store", InvokeScopes: []*basev1.WorkScopeV1{sc(legacyKind, "read")}},
			}},
		{Name: "legacy-store", Principal: "legacy-store", Kind: domain.KindModule, Generation: 1, ResourceKinds: []*basev1.WorkScopeV1{sc(legacyKind, "read")}},
		ledger(),
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

// bareHarness is a service over a store of its own holding the fixture's
// organisations, teams and people, and no module: for a test that delivers a
// composition of its own.
func bareHarness(t *testing.T) *harness {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, store: memstore.New(), now: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC), ctx: context.Background()}
	n := 0
	replay := workcontext.NewMemoryReplayStore()
	replay.Now = func() time.Time { return h.now }
	h.cfg = authority.Config{Issuer: "https://authority.test", KeyID: "k1", Signer: private, Keys: keys{public}, Replay: replay,
		Clock: func() time.Time { return h.now }, NewID: func() string { n++; return fmt.Sprintf("id-%d", n) }}
	h.svc, err = authority.New(h.store, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, org := range []string{acme, globex} {
		h.store.PutOrganization(domain.Organization{ID: org, Name: org})
	}
	h.store.PutTeam(acme, "team")
	h.store.PutTeam(globex, "ops")
	// An organisation role is a name a person holds. "admin" alone
	// administers; ada's and rob's are names of no meaning to the core, held to
	// prove that no name reaches a module.
	for _, p := range []domain.Person{
		{ID: "alex", Organization: acme, Roles: []string{"admin"}},
		{ID: "maya", Organization: acme}, {ID: "remi", Organization: acme}, {ID: "dev", Organization: acme},
		{ID: "ines", Organization: acme}, {ID: "tam", Organization: acme, Teams: []string{"team"}}, {ID: "tal", Organization: acme, Teams: []string{"team"}},
		{ID: "ada", Organization: acme, Roles: []string{"store-admin"}}, {ID: "rob", Organization: acme, Roles: []string{"store-reader", "ledger-reader"}},
		{ID: "zoe", Organization: globex, Roles: []string{"admin"}}, {ID: "omar", Organization: globex, Teams: []string{"ops"}},
	} {
		h.store.PutPerson(p)
	}
	return h
}

func (h *harness) person(id string) authority.Person {
	org := acme
	if id == "zoe" || id == "omar" {
		org = globex
	}
	return authority.Person{ID: id, Organization: org, SessionID: "session-" + id}
}

// administrator makes person an administrator of acme beside alex: the
// organisation role that hands an organisation's resource to an installation.
func (h *harness) administrator(person string) {
	h.store.PutPerson(domain.Person{ID: person, Organization: acme, Roles: []string{"admin"}})
}

func (h *harness) admin(org string) authority.Person {
	if org == globex {
		return h.person("zoe")
	}
	return h.person("alex")
}

func (h *harness) install(org, target string) domain.Installation {
	return h.installAs(org, target, "admin")
}

// installAs installs target at org through the administrator's review, with
// role as the installation's agent role ("" leaves it to the declaration).
func (h *harness) installAs(org, target, role string) domain.Installation {
	h.t.Helper()
	admin := h.admin(org)
	inst, err := h.svc.Install(h.ctx, admin, org, target, role, admin.ID, h.approval(org, target), nil)
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

func (h *harness) root(person, target string, scopes ...*basev1.WorkScopeV1) (authority.Issued, error) {
	return h.svc.IssueForPerson(h.ctx, h.person(person), authority.IssueRequest{Audience: target, Scopes: scopes})
}

// through is a person at target, then target's hop to the store (or binding).
func (h *harness) through(person, target, binding string, scopes ...*basev1.WorkScopeV1) (authority.Issued, error) {
	r, err := h.root(person, target)
	if err != nil {
		return r, err
	}
	return h.svc.IssueChild(h.ctx, r.Token, authority.Workload{Module: target}, authority.IssueRequest{Binding: binding, Scopes: scopes})
}

func (h *harness) hop(parent authority.Issued, binding string, scopes ...*basev1.WorkScopeV1) (authority.Issued, error) {
	return h.svc.IssueChild(h.ctx, parent.Token, authority.Workload{Module: "store"}, authority.IssueRequest{Binding: binding, Scopes: scopes})
}

func (h *harness) agent(target, binding string, scopes ...*basev1.WorkScopeV1) (authority.Issued, error) {
	audience := target
	if binding != "" {
		audience = map[string]string{"store": "store", "legacy": "legacy-store"}[binding]
	}
	return h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: target}, h.inst(acme, target).ID, authority.IssueRequest{Audience: audience, Binding: binding, Scopes: scopes})
}

func (h *harness) check(i authority.Issued) error {
	_, _, err := h.svc.Check(h.ctx, i.Token, i.Context.GetAudience())
	return err
}

func (h *harness) must(i authority.Issued, err error) authority.Issued {
	h.t.Helper()
	if err != nil {
		h.t.Fatal(err)
	}
	return i
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

// effective is a capability's effective scopes.
func effective(i authority.Issued) []*basev1.WorkScopeV1 {
	if chain := i.Context.GetActorChain(); len(chain) > 0 {
		return chain[len(chain)-1].GetGrantedScopes()
	}
	return i.Context.GetAuthorityScopes()
}

// exactly requires the effective scopes to be exactly one row of k with
// actions, owner and ids.
func exactly(t *testing.T, i authority.Issued, k, owner string, actions []string, ids ...string) {
	t.Helper()
	var rows []*basev1.WorkScopeV1
	for _, s := range effective(i) {
		if len(s.GetActions()) > 0 {
			rows = append(rows, s)
		}
	}
	if len(rows) != 1 || rows[0].GetResourceKind() != k || rows[0].GetResourceOwnerId() != owner ||
		strings.Join(rows[0].GetActions(), ",") != strings.Join(actions, ",") || strings.Join(rows[0].GetResourceIds(), ",") != strings.Join(ids, ",") {
		t.Fatalf("effective %v, want %s %v owned by %q ids %v", rows, k, actions, owner, ids)
	}
}

var _ = errors.New

func (h *harness) approval(org, target string) *domain.ConsentApproval {
	h.t.Helper()
	a, err := h.svc.Review(h.ctx, h.admin(org), org, target)
	if err != nil {
		h.t.Fatal(err)
	}
	a.OperationID = uuid.NewString()
	return &a
}
