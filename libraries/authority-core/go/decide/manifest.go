package decide

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	delivery "github.com/codefly-dev/authority/libraries/delivery/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/protobuf/proto"
)

// ValidateModule holds a delivered module to its contract: a principal, a
// generation, bindings whose lookup and headless scopes stay within invoke;
// a module without a page declares no roles; a solution, or a module page
// that declares roles, declares installer, and every role stays within what
// it serves, consumes through its invoke/lookup bindings, or names through
// one of them (domain.Module.Through); a shared kind is one it serves; and
// a scope that governs its sources is one of its own, unshared kinds that a
// role grants (domain.Module.SourceGovernance).
func ValidateModule(m domain.Module) error {
	if err := validateModule(m); err != nil {
		return err
	}
	for _, kind := range m.SharedKinds {
		if !slices.ContainsFunc(Served(m), func(sc *basev0.WorkScopeV1) bool { return sc.GetResourceKind() == kind }) {
			return domain.Refuse("%s declares %s shared, a kind it does not serve", m.Name, kind)
		}
	}
	if err := sourceGovernance(m); err != nil {
		return err
	}
	return noOwners(m)
}

// Unreached refuses, by name, a scope a role of m names through one of its
// bindings that the composition (modules by principal) does not reach from
// that binding (ReachedThrough). A walk that meets a module not composed yet
// leaves the scope to that module's delivery, so delivery order is free; a
// later delivery is never refused for it either, which would tie every
// module's release to every solution reaching through it: what it leaves
// unreached is reported (UnreachedOf), grants nothing there (each hop
// narrows), and re-converges by itself once a delivery reaches it again.
func Unreached(m domain.Module, composed map[string]domain.Module) error {
	for _, g := range reachGaps(m, composed) {
		if len(g.missing) == 0 {
			return domain.Refuse("role %q of %s names %s through binding %q, which reaches it nowhere in the composition: neither %q nor a module it reaches consumes it for a person",
				g.role, m.Name, g.scopes, g.binding, g.binding)
		}
	}
	return nil
}

// UnreachedOf is what m's roles name through a binding that the composition
// does not reach now, one condition per role and binding, sorted: the
// readiness of an installation of m, which re-converges by itself.
func UnreachedOf(m domain.Module, composed map[string]domain.Module) []string {
	var out []string
	for _, g := range reachGaps(m, composed) {
		if len(g.missing) > 0 {
			out = append(out, fmt.Sprintf("role %s reaches nothing of %s through %s: %s not composed", g.role, g.scopes, g.binding, strings.Join(g.missing, ", ")))
			continue
		}
		out = append(out, fmt.Sprintf("role %s reaches nothing of %s through %s: no module %s reaches consumes it for a person", g.role, g.scopes, g.binding, g.binding))
	}
	return out
}

type reachGap struct {
	role, binding, scopes string
	missing               []string
}

func reachGaps(m domain.Module, composed map[string]domain.Module) []reachGap {
	var out []reachGap
	for _, role := range slices.Sorted(maps.Keys(m.Through)) {
		for _, id := range slices.Sorted(maps.Keys(m.Through[role])) {
			reached, missing := ReachedThrough(m.Bindings[id], composed)
			if gap := beyond(m.Through[role][id], reached); gap != "" {
				out = append(out, reachGap{role: role, binding: id, scopes: gap, missing: missing})
			}
		}
	}
	return out
}

// ReachedThrough is what a holder's capability can carry through binding b
// and onward through the composition (modules by principal): b's invoke and
// lookup scopes, and those of every binding of each module reached. missing
// names, sorted, each principal the walk met that the composition does not
// hold.
func ReachedThrough(b domain.Binding, composed map[string]domain.Module) (reached Scopes, missing []string) {
	seen := map[string]bool{}
	queue := []domain.Binding{b}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		reached = append(reached, current.InvokeScopes...)
		reached = append(reached, current.LookupScopes...)
		if seen[current.Audience] {
			continue
		}
		seen[current.Audience] = true
		next, ok := composed[current.Audience]
		if !ok {
			missing = append(missing, current.Audience)
			continue
		}
		for _, id := range slices.Sorted(maps.Keys(next.Bindings)) {
			queue = append(queue, next.Bindings[id])
		}
	}
	slices.Sort(missing)
	return scope.Normalize(reached), missing
}

// beyond spells, "kind:action, …", what of scopes is not within within.
func beyond(scopes, within Scopes) string {
	var out []string
	for _, sc := range scope.Normalize(scopes) {
		for _, action := range sc.GetActions() {
			if !scope.Attenuates(Scopes{{ResourceKind: sc.GetResourceKind(), Actions: []string{action}}}, within) {
				out = append(out, sc.GetResourceKind()+":"+action)
			}
		}
	}
	return strings.Join(out, ", ")
}

func validateModule(m domain.Module) error {
	if m.Name == "" || m.Principal == "" || m.Generation == 0 {
		return domain.Refuse("a manifest names its module, its principal and a generation")
	}
	for _, method := range slices.Sorted(maps.Keys(m.Methods)) {
		policy := m.Methods[method]
		requires := map[string][]string{}
		for _, sc := range policy.Requires {
			if len(sc.GetResourceIds()) > 0 || sc.GetResourceOwnerId() != "" {
				return domain.Refuse("%s: %s: method requirements name whole resource kinds; resource ids and owners are not supported", m.Name, method)
			}
			requires[sc.GetResourceKind()] = append(requires[sc.GetResourceKind()], sc.GetActions()...)
		}
		if err := delivery.ValidateMethodPolicy(method, policy.AnyCheckedCaller, requires, false); err != nil {
			return domain.Refuse("%s: %v", m.Name, err)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(m.Bindings)) {
		b := m.Bindings[id]
		lookupCeiling := b.InvokeScopes
		if len(lookupCeiling) == 0 {
			lookupCeiling = b.HeadlessScopes
		}
		if len(b.LookupScopes) > 0 && !scope.Attenuates(b.LookupScopes, lookupCeiling) {
			return domain.Refuse("binding %s: lookup scopes exceed what the binding may do", id)
		}
		if len(b.InvokeScopes) > 0 && !scope.Attenuates(b.HeadlessScopes, b.InvokeScopes) {
			return domain.Refuse("binding %s: headless scopes exceed invoke scopes", id)
		}
	}
	if m.Kind != domain.KindSolution {
		if len(m.OwnedRoles) > 0 {
			return domain.Refuse("module %q declares installation-owned roles; only a solution declares them", m.Name)
		}
		if len(m.Roles) == 0 {
			return nil
		}
		if !m.Page {
			return domain.Refuse("module %q declares roles and no page; a module's access is the organization's roles unless it declares a page", m.Name)
		}
	}
	if _, ok := m.Roles[domain.InstallerRole]; !ok {
		return &domain.Refusal{Code: domain.Denied, Cause: domain.ErrNoInstallerRole,
			Reason: fmt.Sprintf("%s declares %d role(s) and none is %q: a solution, or a module page declaring roles, declares an installer role", m.Name, len(m.Roles), domain.InstallerRole)}
	}
	// A role reaches through its target's bindings, a solution's and a
	// module page's alike (a person's capability through either carries the
	// role at each module it invokes, cut to the binding at each hop), so a
	// role may name what it serves and what its bindings consume, and, onward
	// (consent covers reach), what it declares reached through one of its
	// bindings: one a person's capability travels (invoke or lookup).
	grantable := Grantable(m)
	for _, name := range slices.Sorted(maps.Keys(m.Through)) {
		if _, declared := m.Roles[name]; !declared {
			return domain.Refuse("%s names scopes through a binding for role %q, which it does not declare", m.Name, name)
		}
		for _, id := range slices.Sorted(maps.Keys(m.Through[name])) {
			b, ok := m.Bindings[id]
			if !ok {
				return domain.Refuse("role %q of %s names scopes through binding %q, which %s does not declare", name, m.Name, id, m.Name)
			}
			if len(b.InvokeScopes) == 0 && len(b.LookupScopes) == 0 {
				return domain.Refuse("role %q of %s names scopes through binding %q, which carries nothing for a person (no invoke or lookup scopes)", name, m.Name, id)
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(m.Roles)) {
		scopes := m.Roles[name]
		if len(scopes) == 0 && len(m.OwnedRoles[name]) == 0 {
			return domain.Refuse("role %q of %s grants nothing", name, m.Name)
		}
		if scope.HasOwner(scopes) {
			return domain.Refuse("role %q of %s selects an owner; a role's owner is its installation's principal", name, m.Name)
		}
		within := grantable
		for _, through := range m.Through[name] {
			within = append(slices.Clone(within), through...)
		}
		if !scope.Attenuates(scopes, within) {
			return domain.Refuse("role %q of %s grants beyond what %s serves or explicitly consumes through invoke/lookup bindings; a kind reached downstream of a binding is named through it", name, m.Name, m.Name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(m.OwnedRoles)) {
		if _, ok := m.Roles[name]; !ok {
			return domain.Refuse("installation-owned role %q of %s is not declared", name, m.Name)
		}
		for _, sc := range m.OwnedRoles[name] {
			if len(sc.GetResourceIds()) > 0 || sc.GetResourceOwnerId() != "" {
				return domain.Refuse("installation-owned role %q names resource ids or an owner; its installation supplies the ids", name)
			}
		}
		if !scope.Attenuates(m.OwnedRoles[name], grantable) {
			return domain.Refuse("installation-owned role %q grants beyond what %s serves or explicitly consumes", name, m.Name)
		}
	}
	return nil
}

// ViewerRole and EditorRole are the two standard roles beside the installer
// (domain.InstallerRole): what a module page or a solution offers one team
// each of.
const (
	ViewerRole = "viewer"
	EditorRole = "editor"
)

// StandardRoles derives the three standard roles of a module page that
// declares none, from what it serves (its resource kinds, at their ceilings):
// the viewer reads, the editor reads and writes, the installer holds every
// action served. One rule, here, the same an explicit declaration follows
// over its own kinds; a declaration wins, since it may name what it reaches
// through its bindings and may split an administrative action out of the
// editor, which a derivation never guesses at. A role a module serves nothing
// for (no kind readable: no viewer) is not derived; a module serving nothing
// derives none.
func StandardRoles(m domain.Module) map[string]Scopes {
	out := map[string]Scopes{}
	for _, kind := range scope.Normalize(m.ResourceKinds) {
		served := kind.GetActions()
		any := slices.Contains(served, scope.AnyAction)
		grant := func(role string, actions ...string) {
			var held []string
			for _, action := range actions {
				if any || slices.Contains(served, action) {
					held = append(held, action)
				}
			}
			if len(held) > 0 {
				out[role] = append(out[role], &basev0.WorkScopeV1{ResourceKind: kind.GetResourceKind(), Actions: held})
			}
		}
		grant(ViewerRole, "read")
		grant(EditorRole, "read", "write")
		out[domain.InstallerRole] = append(out[domain.InstallerRole], &basev0.WorkScopeV1{ResourceKind: kind.GetResourceKind(), Actions: slices.Clone(served)})
	}
	for role, scopes := range out {
		out[role] = scope.Normalize(scopes)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// RoleGated reports whether what a person holds at m is the roles granted on
// its installation: a solution's, or a module page's that declares roles.
// Otherwise it is their organization roles within what m serves.
func RoleGated(m domain.Module) bool {
	return m.Kind == domain.KindSolution || len(m.Roles) > 0
}

// Narrowed reports whether next narrows what previous granted: a binding
// removed, readdressed or cut, owner-aware checking withdrawn or adopted, a
// kind no longer shared at a module that checks owners, any of its roles cut,
// or a module moved between organization roles and its own. A narrowing
// invalidates capabilities already issued. Adopting owner checks narrows too:
// what an organization role or a module's role held there unselected is no
// longer held (RBAC-4a, ModuleRoleAt).
func Narrowed(previous, next domain.Module) bool {
	if previous.OwnerAware != next.OwnerAware {
		return true
	}
	if next.OwnerAware {
		for _, kind := range previous.SharedKinds {
			if !slices.Contains(next.SharedKinds, kind) {
				return true
			}
		}
	}
	for id, old := range previous.Bindings {
		b, ok := next.Bindings[id]
		if !ok || old.Audience != b.Audience || !scope.Attenuates(old.InvokeScopes, b.InvokeScopes) ||
			!scope.Attenuates(old.HeadlessScopes, b.HeadlessScopes) || !scope.Attenuates(old.LookupScopes, b.LookupScopes) {
			return true
		}
	}
	if RoleGated(previous) != RoleGated(next) {
		return true
	}
	for name, scopes := range previous.OwnedRoles {
		if !scope.Attenuates(scopes, next.OwnedRoles[name]) {
			return true
		}
	}
	for name, scopes := range previous.Roles {
		if !scope.Attenuates(scopes, next.Roles[name]) {
			return true
		}
	}
	return false
}

// noOwners refuses a delivery naming a resource owner where none belongs: in
// what a module serves, in a binding's scopes, in a role or in a method's
// requirement. An owner is the authority's to select per installation; read
// owner-blind, it would widen to the whole kind, so it is refused by name.
func noOwners(m domain.Module) error {
	check := func(where string, scopes Scopes) error {
		for _, sc := range scopes {
			if sc.GetResourceOwnerId() != "" {
				return domain.Refuse("%s: %s names resource owner %q; a delivery never selects an owner", where, sc.GetResourceKind(), sc.GetResourceOwnerId())
			}
		}
		return nil
	}
	if err := check(m.Name+" serves", m.ResourceKinds); err != nil {
		return err
	}
	for _, id := range slices.Sorted(maps.Keys(m.Bindings)) {
		b := m.Bindings[id]
		for _, scopes := range []Scopes{b.InvokeScopes, b.HeadlessScopes, b.LookupScopes} {
			if err := check(m.Name+" binding "+id, scopes); err != nil {
				return err
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(m.Roles)) {
		if err := check(m.Name+" role "+name, m.Roles[name]); err != nil {
			return err
		}
	}
	for _, name := range slices.Sorted(maps.Keys(m.OwnedRoles)) {
		if err := check(m.Name+" installation-owned role "+name, m.OwnedRoles[name]); err != nil {
			return err
		}
	}
	for _, method := range slices.Sorted(maps.Keys(m.Methods)) {
		if err := check(m.Name+" method "+method, m.Methods[method].Requires); err != nil {
			return err
		}
	}
	return nil
}

// Served is what a module serves: the kinds it declares, joined to every
// (kind, action) its methods require of a call, read from its own method
// declarations.
func Served(m domain.Module) Scopes {
	served := slices.Clone(m.ResourceKinds)
	for _, method := range slices.Sorted(maps.Keys(m.Methods)) {
		for _, required := range m.Methods[method].Requires {
			served = append(served, &basev0.WorkScopeV1{ResourceKind: required.GetResourceKind(), Actions: slices.Clone(required.GetActions())})
		}
	}
	return scope.Normalize(served)
}

// Grantable is what m's roles may name without naming a binding: what m
// serves and what its own bindings consume for a person (invoke, lookup).
func Grantable(m domain.Module) Scopes {
	grantable := Served(m)
	for _, id := range slices.Sorted(maps.Keys(m.Bindings)) {
		grantable = append(grantable, m.Bindings[id].InvokeScopes...)
		grantable = append(grantable, m.Bindings[id].LookupScopes...)
	}
	return grantable
}

// Unselect is scopes as audience receives them: a scope of a kind the
// audience declares shared (SharedKinds) carries no owner selector, since no
// owner holds a resource of it; every other scope is unchanged.
func Unselect(audience domain.Module, scopes Scopes) Scopes {
	if len(audience.SharedKinds) == 0 {
		return scopes
	}
	out := make(Scopes, 0, len(scopes))
	for _, sc := range scopes {
		if sc.GetResourceOwnerId() != "" && slices.Contains(audience.SharedKinds, sc.GetResourceKind()) {
			sc = proto.Clone(sc).(*basev0.WorkScopeV1)
			sc.ResourceOwnerId = ""
		}
		out = append(out, sc)
	}
	return scope.Normalize(out)
}
