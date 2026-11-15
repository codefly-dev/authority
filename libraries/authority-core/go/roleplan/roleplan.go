// Package roleplan holds a product's role plan to the authority's own
// decisions, in a plain unit test: no cluster, no running host, no network.
//
// A product (a solution, or a module with a page) states its plan: for each
// call a person makes, whether a holder of its admin role, a holder of its user
// role and a member holding no role on it are let through. Assert composes the
// product exactly as a host would from what its repository declares — its
// module contract read by core (modulecontract) and its generated method table,
// delivered through the authority's one reader (delivered.Module) — into the
// authority's own Service on an in-memory store, installs it with an
// administrator's consent, grants the two roles, and asks the Service each
// call: IssueForPerson then CheckMethod for a method the product serves,
// IssueChild through a binding for what that method relays, IssueForPage for a
// call its page makes on the host's module edge, GrantRole for administering
// the installation. Nothing here decides; every verdict is the Service's.
//
// Assert also fails a plan that does not cover what the product declares: a
// method in its table with no row, a row naming a method it does not serve, a
// permission a binding carries that no row asks for, and, for least privilege,
// a permission a role grants that no row it is let through uses.
//
// What it cannot see: a module the product's bindings reach is a stand-in
// serving the kinds the binding carries (and, for what a role names through
// the binding, binding onward to a stand-in per namespace), so that module's
// own method policy, its real onward bindings and its resource checks are its
// own plan's to prove; an installation's later consent changes and a host's
// envelope are not composed.
package roleplan

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/delivered"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/memstore"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	modulecontract "github.com/codefly-dev/core/contracts/module"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/solutionhost"
	"github.com/codefly-dev/core/workcontext"
	"github.com/google/uuid"
)

// Policy is what one method requires of a call, as a generated permissions
// table states it: each permission "<resource kind>:<action>", or open to any
// checked caller.
type Policy struct {
	Requires         []string
	AnyCheckedCaller bool
}

// Product is a solution or a module page as its repository declares it.
type Product struct {
	// Contract is its module.contract.codefly.yaml.
	Contract []byte
	// Values are the composition's values the contract's slots resolve from.
	Values modulecontract.Values
	// Kind is domain.KindSolution or domain.KindModule (a module with a page).
	Kind string
	// Methods is every method or route "<VERB> <template>" it serves, from its
	// generated table.
	Methods map[string]Policy
}

// Verdict is what a plan expects of one subject on one call.
type Verdict int

// The two verdicts. The zero Verdict is no expectation, which Assert refuses.
const (
	Refused Verdict = iota + 1
	Allowed
)

// Row is one call a person makes, and what the plan expects of each subject.
type Row struct {
	// Name is the call in a person's words: "upload a document".
	Name string
	// Method is a method the product serves; empty for a call its page makes
	// at Binding's audience on the host's module edge.
	Method string
	// Binding is the product's binding the call continues through (Method's
	// relay) or the page calls through; empty for none.
	Binding string
	// Asks are the permissions "<kind>:<action>" the call asks through Binding.
	Asks []string
	// Onward are the permissions the call carries through Binding for what
	// its audience reaches in turn (a role's scopes named through the
	// binding): the audience's hop onward, asking them, must be admitted.
	Onward []string
	// Administer: the call grants a role on the installation, the admin
	// role's administration of it. Method, Binding and Asks are then empty.
	Administer bool
	// Admin, User and None are the verdicts for a holder of the admin role, a
	// holder of the user role and a member holding no role on the product.
	Admin, User, None Verdict
}

// Plan is a product and every call a person makes on it.
type Plan struct {
	Product Product
	Rows    []Row
}

// Subjects of the plan, as the composed organization names them.
const (
	organization = "org"
	installer    = "installer" // the organization's administrator, who installs
	newcomer     = "newcomer"  // the member an administering call grants a role to
)

var subjects = []struct{ id, role string }{{"admin-holder", domain.AdminRole}, {"user-holder", domain.UserRole}, {"no-role", ""}}

// Assert holds the product to plan: every row's verdict for every subject is
// the authority's, every refusal names its reason, and the plan covers
// everything the product declares (Problems).
func Assert(t testing.TB, plan Plan) {
	t.Helper()
	for _, problem := range Problems(plan) {
		t.Error(problem)
	}
}

// Problems is everything that holds the product off its plan, each in words:
// a verdict the authority gives that the plan does not, a refusal with no
// reason, and what the plan leaves of the declaration uncovered (Coverage).
func Problems(plan Plan) []string {
	m, err := Module(plan.Product)
	if err != nil {
		return []string{fmt.Sprintf("roleplan: the product does not compose: %v", err)}
	}
	out := Coverage(m, plan.Rows)
	h, err := compose(m)
	if err != nil {
		return append(out, fmt.Sprintf("roleplan: %v", err))
	}
	for _, row := range plan.Rows {
		want := []Verdict{row.Admin, row.User, row.None}
		for i, s := range subjects {
			if want[i] == 0 {
				out = append(out, fmt.Sprintf("%q: the plan states no verdict for %s", row.Name, s.id))
				continue
			}
			err := h.decide(row, s.id)
			switch {
			case want[i] == Allowed && err != nil:
				out = append(out, fmt.Sprintf("%q: %s is refused, the plan allows it: %v", row.Name, s.id, err))
			case want[i] == Refused && err == nil:
				out = append(out, fmt.Sprintf("%q: %s is allowed, the plan refuses it", row.Name, s.id))
			case err != nil && strings.TrimSpace(err.Error()) == "":
				out = append(out, fmt.Sprintf("%q: %s is refused with no reason", row.Name, s.id))
			}
		}
	}
	return out
}

// Module is the product as a host composes it: core reads its contract and
// resolves it against Values; the manifest and the authority's document carry
// it as the render does; delivered.Module reads them.
//
// STOPGAP: the step from the resolved contract to the manifest's authority
// block and the authority's document is the CLI's render (cli pkg/gitops:
// moduleAuthority, Roles, SharedKinds, AuthoritySources.Declaration), which a
// library cannot import, so it is restated here field for field. A change to
// what the render carries must be mirrored until the render is a library
// function both call.
func Module(p Product) (domain.Module, error) {
	contract, err := modulecontract.Parse(p.Contract)
	if err != nil {
		return domain.Module{}, err
	}
	resolved, err := contract.Resolve(p.Values)
	if err != nil {
		return domain.Module{}, err
	}
	auth := &solutionhost.Authority{Principal: resolved.Principal, InstallationRole: resolved.InstallationRole,
		EdgeDependencies: resolved.EdgeDependencies, SourceGovernance: resolved.SourceGovernance}
	doc := &delivered.Document{Module: resolved.Principal, Generation: 1, OwnerAware: resolved.OwnerAware,
		InstallationRole: resolved.InstallationRole}
	for _, e := range resolved.EdgeDependencies {
		doc.EdgeDependencies = append(doc.EdgeDependencies, domain.EdgeDependency{Module: e.Module, Presence: e.Presence})
	}
	for _, c := range resolved.ScopeCeilings {
		auth.ResourceKinds = append(auth.ResourceKinds, c.ResourceKind)
		doc.ScopeCeilings = append(doc.ScopeCeilings, &basev0.WorkScopeV1{ResourceKind: c.ResourceKind, Actions: c.Actions})
		if c.Shared {
			doc.SharedKinds = append(doc.SharedKinds, c.ResourceKind)
		}
	}
	for _, b := range resolved.Bindings {
		operations := map[string][]string{}
		for _, op := range b.Operations {
			operations[op] = b.Scopes[op]
		}
		auth.Bindings = append(auth.Bindings, solutionhost.AuthorityBinding{ID: b.ID, Audience: b.Audience, Operations: operations})
	}
	for _, role := range contract.Roles {
		r := delivered.Role{Name: role.Name, InstallationOwned: ceilingScopes(role.InstallationOwnedScopes)}
		for _, sc := range role.Scopes {
			if sc.Through == "" {
				r.Scopes = append(r.Scopes, ceilingScopes([]modulecontract.CeilingScope{sc})...)
				continue
			}
			if r.Through == nil {
				r.Through = map[string]delivered.Scopes{}
			}
			r.Through[sc.Through] = append(r.Through[sc.Through], ceilingScopes([]modulecontract.CeilingScope{sc})...)
		}
		doc.Roles = append(doc.Roles, r)
	}
	for _, name := range slices.Sorted(maps.Keys(p.Methods)) {
		policy := p.Methods[name]
		doc.Methods = append(doc.Methods, delivered.Method{Method: name, Requires: Scopes(policy.Requires), AnyCheckedCaller: policy.AnyCheckedCaller})
	}
	manifest := &solutionhost.ModuleManifest{Alias: resolved.Principal, Kind: solutionhost.Kind(p.Kind), Generation: 1, Authority: auth}
	if p.Kind == domain.KindModule {
		manifest.Frontend = &solutionhost.Frontend{}
	}
	return delivered.Module(manifest, doc)
}

// Coverage is what plan rows leave of m's declaration unplanned: a method with
// no row (or two), a row naming none m serves or no binding m declares, a
// permission a binding carries for a person that no row asks for, and a
// permission a role grants that no row its holder is allowed uses.
func Coverage(m domain.Module, rows []Row) []string {
	var out []string
	planned := map[string]int{}
	asked := map[string]bool{}
	used := map[string]map[string]bool{domain.AdminRole: {}, domain.UserRole: {}}
	for _, row := range rows {
		if row.Method != "" {
			planned[row.Method]++
			if _, ok := m.Methods[row.Method]; !ok {
				out = append(out, fmt.Sprintf("%q names %s, which %s does not serve", row.Name, row.Method, m.Name))
			}
		}
		if _, ok := m.Bindings[row.Binding]; row.Binding != "" && !ok {
			out = append(out, fmt.Sprintf("%q names binding %q, which %s does not declare", row.Name, row.Binding, m.Name))
		}
		if row.Administer != (row.Method == "" && row.Binding == "") || (row.Administer && len(row.Asks) > 0) {
			out = append(out, fmt.Sprintf("%q is either an administering call or a call at a method or a binding", row.Name))
		}
		if row.Binding == "" && len(row.Onward) > 0 {
			out = append(out, fmt.Sprintf("%q carries permissions onward through no binding", row.Name))
		}
		uses := append(slices.Clone(row.Asks), row.Onward...)
		for _, r := range m.Methods[row.Method].Requires {
			for _, a := range r.GetActions() {
				uses = append(uses, r.GetResourceKind()+":"+a)
			}
		}
		for _, p := range row.Asks {
			asked[row.Binding+" "+p] = true
		}
		for role, verdict := range map[string]Verdict{domain.AdminRole: row.Admin, domain.UserRole: row.User} {
			if verdict != Allowed {
				continue
			}
			for _, p := range uses {
				used[role][p] = true
			}
		}
	}
	for _, method := range slices.Sorted(maps.Keys(m.Methods)) {
		if planned[method] != 1 {
			out = append(out, fmt.Sprintf("%s serves %s, which %d rows of the plan name: every method has exactly one", m.Name, method, planned[method]))
		}
	}
	for _, id := range slices.Sorted(maps.Keys(m.Bindings)) {
		b := m.Bindings[id]
		for _, p := range permissions(append(slices.Clone(b.InvokeScopes), b.LookupScopes...)) {
			if !asked[id+" "+p] {
				out = append(out, fmt.Sprintf("binding %q carries %s for a person, which no row of the plan asks for", id, p))
			}
		}
	}
	for _, role := range slices.Sorted(maps.Keys(used)) {
		for _, p := range permissions(append(slices.Clone(m.Roles[role]), m.OwnedRoles[role]...)) {
			if !used[role][p] {
				out = append(out, fmt.Sprintf("role %s grants %s, which no row its holder is allowed uses: least privilege grants nothing unused", role, p))
			}
		}
	}
	return out
}

// harness is the authority composed with the product installed at one
// organization, each subject holding its role.
type harness struct {
	ctx     context.Context
	svc     *authority.Service
	product domain.Module
	inst    domain.Installation
}

func compose(m domain.Module) (*harness, error) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	now := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	replay := workcontext.NewMemoryReplayStore()
	replay.Now = func() time.Time { return now }
	store := memstore.New()
	svc, err := authority.New(store, authority.Config{Issuer: "https://authority.roleplan", KeyID: "k1", Signer: private,
		Keys: keys{public}, Replay: replay, Clock: func() time.Time { return now }})
	if err != nil {
		return nil, err
	}
	h := &harness{ctx: context.Background(), svc: svc, product: m}
	store.PutOrganization(domain.Organization{ID: organization, Name: organization})
	store.PutOrgRole(domain.OrgRole{Organization: organization, Name: "admin", Scopes: []domain.RoleScope{{Kind: scope.AnyKind, Actions: []string{scope.AnyAction}}}})
	store.PutPerson(domain.Person{ID: installer, Organization: organization, Roles: []string{"admin"}})
	store.PutPerson(domain.Person{ID: newcomer, Organization: organization})
	for _, s := range subjects {
		store.PutPerson(domain.Person{ID: s.id, Organization: organization})
	}
	// The product first: a module its roles reach through a binding is left
	// to that module's delivery until it is composed, so delivery order is free.
	if _, err := svc.ApplyModule(h.ctx, m); err != nil {
		return nil, fmt.Errorf("the authority refuses %s as delivered: %w", m.Name, err)
	}
	for _, standIn := range standIns(m) {
		if _, err := svc.ApplyModule(h.ctx, standIn); err != nil {
			return nil, fmt.Errorf("stand-in %s: %w", standIn.Name, err)
		}
	}
	admin := person(installer)
	approval, err := svc.Review(h.ctx, admin, organization, m.Name)
	if err != nil {
		return nil, fmt.Errorf("review %s: %w", m.Name, err)
	}
	approval.OperationID = uuid.NewString()
	// The installation's own agent holds what the product's installation_role
	// selects; the plan is about people, and selects nothing for it.
	if h.inst, err = svc.Install(h.ctx, admin, organization, m.Name, "", installer, &approval, nil); err != nil {
		return nil, fmt.Errorf("install %s: %w", m.Name, err)
	}
	for _, s := range subjects {
		if s.role == "" {
			continue
		}
		if _, err := svc.GrantRole(h.ctx, admin, authority.RoleRequest{Organization: organization, InstallationID: h.inst.ID, Role: s.role, PersonID: s.id}); err != nil {
			return nil, fmt.Errorf("grant %s: %w", s.role, err)
		}
	}
	return h, nil
}

// standIns are the modules m's bindings reach, each serving what the bindings
// to it carry and checking owners, as a module receiving a solution's
// capability must; and, for what m's roles name through a binding, a binding
// of that module onward to a stand-in for each such kind's namespace, as wide
// as the roles name, so only the roles' own through grant limits it.
func standIns(m domain.Module) []domain.Module {
	modules := map[string]*domain.Module{}
	at := func(name string) *domain.Module {
		if modules[name] == nil {
			modules[name] = &domain.Module{Name: name, Principal: name, Kind: domain.KindModule, Generation: 1, OwnerAware: true, Bindings: map[string]domain.Binding{}}
		}
		return modules[name]
	}
	for _, b := range m.Bindings {
		a := at(b.Audience)
		a.ResourceKinds = append(a.ResourceKinds, append(append(slices.Clone(b.InvokeScopes), b.LookupScopes...), b.HeadlessScopes...)...)
	}
	for _, through := range m.Through {
		for id, scopes := range through {
			from := at(m.Bindings[id].Audience)
			for _, sc := range scopes {
				ns := namespace(sc.GetResourceKind())
				at(ns).ResourceKinds = append(at(ns).ResourceKinds, sc)
				onward := from.Bindings[onwardBinding(ns)]
				onward.ID, onward.Audience = onwardBinding(ns), ns
				onward.InvokeScopes = scope.Normalize(append(onward.InvokeScopes, sc))
				from.Bindings[onward.ID] = onward
			}
		}
	}
	var out []domain.Module
	for _, name := range slices.Sorted(maps.Keys(modules)) {
		if name != m.Principal {
			modules[name].ResourceKinds = scope.Normalize(modules[name].ResourceKinds)
			out = append(out, *modules[name])
		}
	}
	return out
}

// namespace is a kind's first segment: "documents" of "documents.collection".
func namespace(kind string) string { ns, _, _ := strings.Cut(kind, "."); return ns }

func onwardBinding(ns string) string { return "onward-" + ns }

// decide asks the authority row's call as subject.
func (h *harness) decide(row Row, subject string) error {
	who := person(subject)
	if row.Administer {
		_, err := h.svc.GrantRole(h.ctx, who, authority.RoleRequest{Organization: organization, InstallationID: h.inst.ID, Role: domain.UserRole, PersonID: newcomer})
		if err == nil {
			_, err = h.svc.RevokeRole(h.ctx, person(installer), authority.RoleRequest{Organization: organization, InstallationID: h.inst.ID, Role: domain.UserRole, PersonID: newcomer})
			if err != nil {
				return fmt.Errorf("roleplan: revoking the grant an administering call made: %w", err)
			}
		}
		return err
	}
	// What a call asks through a binding is the installation's data at a
	// module that checks owners, selected to its principal as the runtime and
	// the module edge name it on the child.
	asks, err := scope.Owned(Scopes(row.Asks), h.inst.PrincipalID)
	if err != nil {
		return fmt.Errorf("roleplan: %w", err)
	}
	if row.Method == "" {
		b := h.product.Bindings[row.Binding]
		issued, err := h.svc.IssueForPage(h.ctx, who, h.product.Name, authority.IssueRequest{Audience: b.Audience, Binding: row.Binding, Scopes: asks})
		return h.carries(issued, err, row)
	}
	root, err := h.svc.IssueForPerson(h.ctx, who, authority.IssueRequest{Audience: h.product.Principal})
	if err != nil {
		return err
	}
	if _, _, _, err := h.svc.CheckMethod(h.ctx, root.Token, h.product.Principal, row.Method, false); err != nil {
		return err
	}
	if row.Binding == "" {
		return nil
	}
	issued, err := h.svc.IssueChild(h.ctx, root.Token, authority.Workload{Module: h.product.Name}, authority.IssueRequest{Binding: row.Binding, Scopes: asks})
	return h.carries(issued, err, row)
}

// carries holds what row carries onward to the authority: from the capability
// issued through row.Binding, its audience's hop onward to each namespace
// row.Onward names, asking those permissions for the installation's data.
func (h *harness) carries(issued authority.Issued, err error, row Row) error {
	if err != nil || len(row.Onward) == 0 {
		return err
	}
	byNamespace := map[string][]string{}
	for _, p := range row.Onward {
		kind, _, _ := strings.Cut(p, ":")
		byNamespace[namespace(kind)] = append(byNamespace[namespace(kind)], p)
	}
	for _, ns := range slices.Sorted(maps.Keys(byNamespace)) {
		asks, err := scope.Owned(Scopes(byNamespace[ns]), h.inst.PrincipalID)
		if err != nil {
			return fmt.Errorf("roleplan: %w", err)
		}
		hop := authority.Workload{Module: h.product.Bindings[row.Binding].Audience}
		if _, err := h.svc.IssueChild(h.ctx, issued.Token, hop, authority.IssueRequest{Binding: onwardBinding(ns), Scopes: asks}); err != nil {
			return fmt.Errorf("carrying %s onward through binding %q: %w", strings.Join(byNamespace[ns], ", "), row.Binding, err)
		}
	}
	return nil
}

// Scopes reads permissions "<kind>:<action>" as scopes, one per kind.
func Scopes(permissions []string) []*basev0.WorkScopeV1 {
	var out []*basev0.WorkScopeV1
	for _, p := range permissions {
		kind, action, _ := strings.Cut(p, ":")
		out = append(out, &basev0.WorkScopeV1{ResourceKind: kind, Actions: []string{action}})
	}
	return scope.Normalize(out)
}

// permissions spells scopes as "<kind>:<action>", sorted, each once.
func permissions(scopes []*basev0.WorkScopeV1) []string {
	var out []string
	for _, sc := range scope.Normalize(scopes) {
		for _, a := range sc.GetActions() {
			out = append(out, sc.GetResourceKind()+":"+a)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func ceilingScopes(in []modulecontract.CeilingScope) []*basev0.WorkScopeV1 {
	var out []*basev0.WorkScopeV1
	for _, sc := range in {
		out = append(out, &basev0.WorkScopeV1{ResourceKind: sc.ResourceKind, Actions: slices.Clone(sc.Actions)})
	}
	return out
}

func person(id string) authority.Person {
	return authority.Person{ID: id, Organization: organization, SessionID: "session-" + id}
}

type keys struct{ public ed25519.PublicKey }

func (k keys) PublicKeys(context.Context) (map[string]ed25519.PublicKey, error) {
	return map[string]ed25519.PublicKey{"k1": k.public}, nil
}
