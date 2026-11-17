// Package roleplan holds a product's role plan to the authority's own
// decisions, in a plain unit test: no cluster, no running host, no network.
//
// A product (a solution, or a module with a page) states its plan: for each
// call a person makes, whether a holder of its admin role, a holder of its user
// role and a member holding no role on it are let through, and, when refused,
// by which decision. Assert composes the product exactly as a host would from
// what its repository declares — the one render of its module contract
// (declare.Module: the render's refusals, the composition's
// configurations read by core, the class and callee options) and its method
// table, read by the authority's own reader (delivered.Declared) — into the
// authority's Service on an in-memory store, installs it with an
// administrator's consent (a module with a page is installed by composition
// at its delivery, and is held on that installation), grants the two roles,
// and asks the Service each
// call: IssueForPerson then CheckMethod for a method the product serves,
// IssueChild through a binding for what that method relays, IssueForPage for a
// call its page makes on the host's module edge, the audience's hop for what a
// role names through a binding, GrantRole for administering the installation.
// Nothing here decides; every verdict is the Service's, and so is the stage
// that refuses.
//
// Assert also fails a plan that does not cover what the product declares: a
// method in its table with no row, a row naming a method it does not serve, a
// permission a binding carries for a person that no row asks for (a headless
// binding is no person's, so it is not planned), and, for least privilege, a
// permission a role grants that no row its holder is allowed uses through the
// way it is granted: an own kind by a method's policy, a consumed kind by an
// ask through a binding that carries it, a scope named through a binding by a
// row going onward through that binding.
//
// A refused stage is the call that refused, kept only when the refusal is the
// authority's denial (domain.Denied); any other class of error is reported as
// no role decision at all, whatever the plan expects.
//
// What it cannot see: a module the product's bindings reach is a stand-in
// serving the kinds the binding carries (and, for what a role names through
// the binding, binding onward to a stand-in per namespace that checks owners
// and declares no kind shared, where the real one may issue a shared kind
// unselected), so that module's own method policy, its real onward bindings
// and its resource checks are its own plan's to prove; the prepared bindings a
// runnable host's composition adds, an installation's later consent changes
// and a host's envelope are not composed. The composition's values are read
// from one directory (Product.Configurations), where the render's workspace
// read also folds in the configurations composed modules offer and the
// environment's layering: a slot filled by a module's offer resolves
// differently here.
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
	"github.com/codefly-dev/authority/libraries/authority-core/go/declare"
	"github.com/codefly-dev/authority/libraries/authority-core/go/delivered"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/memstore"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	solutionhost "github.com/codefly-dev/authority/libraries/solutionhost/go"
	"github.com/codefly-dev/core/configurations"
	modulecontract "github.com/codefly-dev/core/contracts/module"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
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
	// Dir is its root, where its module.contract.codefly.yaml is.
	Dir string
	// Name is its module name, the principal every credential of it is
	// issued to: the render refuses a contract naming another.
	Name string
	// Configurations is a directory of the composition's Codefly workspace
	// configurations (a playground's configurations/<environment>), read by
	// core, that the contract's slots resolve against.
	Configurations string
	// Class is the environment class delivered to, for an edge whose presence
	// differs by class.
	Class string
	// Callees answers a callee's method declarations for a binding that
	// names calls; nil when none does.
	Callees modulecontract.Callees
	// Kind is domain.KindSolution or domain.KindModule (a module with a page).
	Kind string
	// Methods is every method or route "<VERB> <template>" it serves, from its
	// published table.
	Methods map[string]Policy
}

// Verdict is what a plan expects of one subject on one call: let through, or
// refused by one decision. The zero Verdict is no expectation, which Assert
// refuses.
type Verdict int

const (
	// Allowed: every decision the call takes lets it through.
	Allowed Verdict = iota + 1
	// RefusedNoRole: the authority issues the subject nothing at the product,
	// which it holds no role on.
	RefusedNoRole
	// RefusedAtProduct: the subject holds a role on the product, and the
	// authority issues it nothing at the product itself: the role names
	// nothing the product serves, and reaches only what its bindings carry.
	RefusedAtProduct
	// RefusedByPolicy: the product's method policy refuses what the subject
	// holds there (CheckMethod).
	RefusedByPolicy
	// RefusedAtBinding: the capability through the binding is refused, what
	// the subject's role carries there being less than the call asks.
	RefusedAtBinding
	// RefusedOnward: the audience's hop onward refuses what the role names
	// through the binding.
	RefusedOnward
	// RefusedAdminister: the installation's administration is refused.
	RefusedAdminister
)

func (v Verdict) String() string {
	return [...]string{"no verdict", "allowed", "refused: no role", "refused at the product", "refused by the method policy", "refused at the binding",
		"refused onward", "refused administration"}[v]
}

// Row is one call a person makes, and what the plan expects of each subject.
type Row struct {
	// Name is the call in a person's words: "upload a document".
	Name string
	// Method is a method the product serves; empty for a call its page makes
	// at Binding's audience on the host's module edge, or, with no Binding
	// either, for a capability at the product itself asking nothing.
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
			got, err := h.decide(row, s.id)
			got, err = denied(got, err)
			switch {
			case got == 0:
				out = append(out, fmt.Sprintf("%q: %s is not decided on a role: %v", row.Name, s.id, err))
			case err != nil && strings.TrimSpace(err.Error()) == "":
				out = append(out, fmt.Sprintf("%q: %s is %s with no reason", row.Name, s.id, got))
			case got != want[i] && err != nil:
				out = append(out, fmt.Sprintf("%q: %s is %s, the plan says %s: %v", row.Name, s.id, got, want[i], err))
			case got != want[i]:
				out = append(out, fmt.Sprintf("%q: %s is %s, the plan says %s", row.Name, s.id, got, want[i]))
			}
		}
	}
	return out
}

// Module is the product as a host composes it: the one render of its
// contract (declare.Module) against the composition's
// configurations as core reads them, with its method table, read by the
// authority's reader of a delivery (delivered.Declared).
func Module(p Product) (domain.Module, error) {
	infos, err := configurations.LoadConfigurationInformationsFromFiles(context.Background(), p.Configurations)
	if err != nil {
		return domain.Module{}, err
	}
	declaration, _, err := declare.Module(p.Dir, p.Name, nil, solutionhost.Resolver(infos, p.Class, p.Callees))
	if err != nil {
		return domain.Module{}, err
	}
	if declaration == nil {
		return domain.Module{}, fmt.Errorf("%s publishes no module contract", p.Dir)
	}
	var methods []delivered.Method
	for _, name := range slices.Sorted(maps.Keys(p.Methods)) {
		methods = append(methods, delivered.Method{Method: name, Requires: Scopes(p.Methods[name].Requires), AnyCheckedCaller: p.Methods[name].AnyCheckedCaller})
	}
	manifest := &solutionhost.ModuleManifest{Alias: p.Name, Kind: solutionhost.Kind(p.Kind), Generation: 1}
	if p.Kind == domain.KindModule {
		manifest.Frontend = &solutionhost.Frontend{}
	}
	return delivered.Declared(manifest, declaration, methods)
}

// Coverage is what plan rows leave of m's declaration unplanned: a method with
// no row (or two), a row naming none m serves or no binding m declares, a
// permission a binding carries for a person that no row asks for (headless
// scopes are no person's and are not planned), and a permission a role grants
// that no row its holder is allowed uses through the way it is granted.
func Coverage(m domain.Module, rows []Row) []string {
	var out []string
	planned := map[string]int{}
	asked := map[string]bool{}
	// used is, per role, each way a permission was used: "" for a method's
	// policy at m, "ask <binding>" for an ask through a binding, "onward
	// <binding>" for a row going onward through one.
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
		if row.Administer && (row.Method != "" || row.Binding != "" || len(row.Asks) > 0) {
			out = append(out, fmt.Sprintf("%q is either an administering call or a call at a method or a binding", row.Name))
		}
		if row.Binding == "" && len(row.Onward) > 0 {
			out = append(out, fmt.Sprintf("%q carries permissions onward through no binding", row.Name))
		}
		for _, p := range row.Asks {
			asked[row.Binding+" "+p] = true
		}
		for role, verdict := range map[string]Verdict{domain.AdminRole: row.Admin, domain.UserRole: row.User} {
			if verdict != Allowed {
				continue
			}
			for _, p := range permissions(m.Methods[row.Method].Requires) {
				used[role][" "+p] = true
			}
			for _, p := range row.Asks {
				used[role]["ask "+row.Binding+" "+p] = true
			}
			for _, p := range row.Onward {
				used[role]["onward "+row.Binding+" "+p] = true
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
			if !slices.ContainsFunc(grantedWays(m, role, p), func(way string) bool { return used[role][way+" "+p] }) {
				out = append(out, fmt.Sprintf("role %s grants %s, which no row its holder is allowed uses the way it is granted: least privilege grants nothing unused", role, p))
			}
		}
	}
	return out
}

// grantedWays are the ways role holds permission p on m: through m's own
// method policies for a kind m serves, by an ask through each binding whose
// ceiling carries it for a person, and onward through each binding role names
// it through.
func grantedWays(m domain.Module, role, p string) []string {
	kind, action, _ := strings.Cut(p, ":")
	var ways []string
	if scope.HoldsAction(m.ResourceKinds, kind, action) {
		ways = append(ways, "")
	}
	for _, id := range slices.Sorted(maps.Keys(m.Bindings)) {
		b := m.Bindings[id]
		if scope.HoldsAction(append(slices.Clone(b.InvokeScopes), b.LookupScopes...), kind, action) {
			ways = append(ways, "ask "+id)
		}
		if scope.HoldsAction(m.Through[role][id], kind, action) {
			ways = append(ways, "onward "+id)
		}
	}
	return ways
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
	if h.inst, err = h.install(admin); err != nil {
		return nil, err
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

// install answers the product's installation at the organization. A solution
// is installed by the administrator's consent to its reviewed offer. A module
// with a page is never installed by anyone: the authority installed it by
// composition when it was delivered (ApplyModule), at the reach its stand-ins
// then completed, so the plan is held on that installation, the one its
// people are granted roles on, and asking to install it again is refused.
func (h *harness) install(admin authority.Person) (domain.Installation, error) {
	m := h.product
	if m.Kind != domain.KindSolution {
		all, err := h.svc.Installations(h.ctx, admin, organization)
		if err != nil {
			return domain.Installation{}, fmt.Errorf("the installations of %s: %w", organization, err)
		}
		i := slices.IndexFunc(all, func(inst domain.Installation) bool { return inst.Target == m.Name })
		if i < 0 || all[i].Status != domain.Active {
			return domain.Installation{}, fmt.Errorf("%s is not installed at %s by composition", m.Name, organization)
		}
		return all[i], nil
	}
	approval, err := h.svc.Review(h.ctx, admin, organization, m.Name)
	if err != nil {
		return domain.Installation{}, fmt.Errorf("review %s: %w", m.Name, err)
	}
	approval.OperationID = uuid.NewString()
	// The installation's own agent holds what the product's installation_role
	// selects; the plan is about people, and selects nothing for it.
	inst, err := h.svc.Install(h.ctx, admin, organization, m.Name, "", installer, &approval, nil)
	if err != nil {
		return domain.Installation{}, fmt.Errorf("install %s: %w", m.Name, err)
	}
	return inst, nil
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

// decide asks the authority row's call as subject, and answers the stage
// that refused it (Allowed when none did) with the refusal.
func (h *harness) decide(row Row, subject string) (Verdict, error) {
	who := person(subject)
	if row.Administer {
		_, err := h.svc.GrantRole(h.ctx, who, authority.RoleRequest{Organization: organization, InstallationID: h.inst.ID, Role: domain.UserRole, PersonID: newcomer})
		if err != nil {
			return RefusedAdminister, err
		}
		if _, err := h.svc.RevokeRole(h.ctx, person(installer), authority.RoleRequest{Organization: organization, InstallationID: h.inst.ID, Role: domain.UserRole, PersonID: newcomer}); err != nil {
			return 0, fmt.Errorf("roleplan: revoking the grant an administering call made: %w", err)
		}
		return Allowed, nil
	}
	// What a call asks through a binding is the installation's data at a
	// module that checks owners, selected to its principal as the runtime and
	// the module edge name it on the child.
	asks, err := scope.Owned(Scopes(row.Asks), h.inst.PrincipalID)
	if err != nil {
		return 0, fmt.Errorf("roleplan: %w", err)
	}
	if row.Method == "" && row.Binding != "" {
		b := h.product.Bindings[row.Binding]
		issued, err := h.svc.IssueForPage(h.ctx, who, h.product.Name, authority.IssueRequest{Audience: b.Audience, Binding: row.Binding, Scopes: asks})
		if err != nil {
			// The page's root is the subject's roles on the product: holding
			// none, nothing is issued; holding one, the binding refused.
			if h.holdsNoRole(who) {
				return RefusedNoRole, err
			}
			return RefusedAtBinding, err
		}
		return h.carries(issued, row)
	}
	root, err := h.svc.IssueForPerson(h.ctx, who, authority.IssueRequest{Audience: h.product.Principal})
	if err != nil {
		if h.holdsNoRole(who) {
			return RefusedNoRole, err
		}
		return RefusedAtProduct, err
	}
	if row.Method == "" {
		return Allowed, nil
	}
	if _, _, _, err := h.svc.CheckMethod(h.ctx, root.Token, h.product.Principal, row.Method, false); err != nil {
		return RefusedByPolicy, err
	}
	if row.Binding == "" {
		return Allowed, nil
	}
	issued, err := h.svc.IssueChild(h.ctx, root.Token, authority.Workload{Module: h.product.Name}, authority.IssueRequest{Binding: row.Binding, Scopes: asks})
	if err != nil {
		return RefusedAtBinding, err
	}
	return h.carries(issued, row)
}

// denied keeps a refusal's stage only when the error is the authority's
// denial (domain.Denied): a refusal of another class — a binding or a module
// the composition does not hold (NotFound), a malformed ask (Invalid), an
// installation not active (Precondition), or no decision at all — says
// nothing about the subject's role, so it is no stage of the plan.
func denied(stage Verdict, err error) (Verdict, error) {
	if err == nil || stage == 0 {
		return stage, err
	}
	if code, ok := domain.CodeOf(err); !ok || code != domain.Denied {
		return 0, err
	}
	return stage, err
}

// holdsNoRole answers, as the authority reads it now, whether who holds no
// role on the product's installation.
func (h *harness) holdsNoRole(who authority.Person) bool {
	held, err := h.svc.HeldInstallations(h.ctx, who, organization)
	if err != nil {
		return false
	}
	return !slices.ContainsFunc(held, func(i authority.HeldInstallation) bool { return i.Installation.ID == h.inst.ID && len(i.Roles) > 0 })
}

// carries holds what row carries onward to the authority: from the capability
// issued through row.Binding, its audience's hop onward to each namespace
// row.Onward names, asking those permissions for the installation's data.
func (h *harness) carries(issued authority.Issued, row Row) (Verdict, error) {
	byNamespace := map[string][]string{}
	for _, p := range row.Onward {
		kind, _, _ := strings.Cut(p, ":")
		byNamespace[namespace(kind)] = append(byNamespace[namespace(kind)], p)
	}
	for _, ns := range slices.Sorted(maps.Keys(byNamespace)) {
		asks, err := scope.Owned(Scopes(byNamespace[ns]), h.inst.PrincipalID)
		if err != nil {
			return 0, fmt.Errorf("roleplan: %w", err)
		}
		hop := authority.Workload{Module: h.product.Bindings[row.Binding].Audience}
		if _, err := h.svc.IssueChild(h.ctx, issued.Token, hop, authority.IssueRequest{Binding: onwardBinding(ns), Scopes: asks}); err != nil {
			return RefusedOnward, fmt.Errorf("carrying %s onward through binding %q: %w", strings.Join(byNamespace[ns], ", "), row.Binding, err)
		}
	}
	return Allowed, nil
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

func person(id string) authority.Person {
	return authority.Person{ID: id, Organization: organization, SessionID: "session-" + id}
}

type keys struct{ public ed25519.PublicKey }

func (k keys) PublicKeys(context.Context) (map[string]ed25519.PublicKey, error) {
	return map[string]ed25519.PublicKey{"k1": k.public}, nil
}
