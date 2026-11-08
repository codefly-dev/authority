package decide

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The ways a holder reaches a module (domain.ReachRow.Via).
const (
	ReachRole    = "role"    // the role's own scopes, on the target
	ReachBinding = "binding" // the target, then each module it reaches, acting for the holder
	ReachPerson  = "person"  // an edge the target's page reaches on the holder's own session
)

// The confinements of a solution's role on its own target
// (domain.ReachRow.Confinement); a module page's roles have none.
const (
	ConfinedToInstallation = "installation" // the resources the installation's principal owns
	ConfinedToAttached     = "attached"     // the resources attached to the installation
)

// Reach is every place a holder of role on target can cause an operation, as
// a static maximum computed from declarations alone; modules is the
// composition by principal. One row per module, way and confinement:
//
//   - On the target, the role's scopes within what it serves, with their
//     confinement ("role").
//   - Through the target's bindings and onward through each reached module's
//     bindings, self-bindings and re-entries included ("binding"): what a
//     hop acting for the holder can carry, as issuance cuts it (the role
//     within what the module serves, cut to the binding's invoke and lookup
//     scopes and constrained by the chain's limits: scope.ParentLimits,
//     Constrain and Project). The walk is a fixed point over (module, limits)
//     states: limits come from a finite set of declared scopes, so the states
//     are finitely many and the walk ends; a state reached again adds
//     nothing, and a module re-entered under other limits is accounted for.
//     The row's scopes are the union over every state reaching the module;
//     its Path is the shortest way there, a witness.
//   - On an edge dependency of the target, on the holder's own session
//     ("person"): the holder's own grants there decide, so the row carries
//     no scopes and no operations.
//
// Each row lists the operations of its module its scopes are admitted to
// (AdmitMethod), one per operation: a Connect route "POST /pkg.Service/M" is
// the gRPC procedure "/pkg.Service/M". A binding or edge naming a module not
// composed reaches nothing.
//
// It is an upper bound of what issuance admits for the holder: issuance also
// intersects the holder's roles on other solutions on the path, delegation
// ceilings and an installation's consented binding ceilings, and checks
// resources and owners, which binding rows do not carry. A binding's
// headless scopes are its module acting for nobody, which a hop for a holder
// never uses (IssueChild refuses it), so they are no holder's reach.
func Reach(target domain.Module, role string, modules map[string]domain.Module) ([]domain.ReachRow, error) {
	literal, declared := target.Roles[role]
	if !declared {
		return nil, domain.Missing("%s declares no role %q", target.Name, role)
	}
	owned := target.OwnedRoles[role]
	held := scope.Unowned(append(slices.Clone(literal), owned...))
	rows := map[string]*domain.ReachRow{}
	add := func(m domain.Module, path []string, via, confinement string, scopes Scopes) {
		key := m.Name + "\x00" + via + "\x00" + confinement
		row, ok := rows[key]
		if !ok {
			row = &domain.ReachRow{Path: slices.Clone(path), Module: m.Name, Via: via, Confinement: confinement}
			rows[key] = row
		}
		row.Scopes = scope.Normalize(append(row.Scopes, scopes...))
		if via != ReachPerson {
			row.Operations = Operations(m, row.Scopes)
		}
	}
	served := target.ResourceKinds
	root := []string{target.Name}
	if target.Kind != domain.KindSolution {
		if on := scope.Intersect(literal, served); len(on) > 0 {
			add(target, root, ReachRole, "", on)
		}
	} else {
		if on := scope.Intersect(literal, served); len(on) > 0 {
			add(target, root, ReachRole, ConfinedToInstallation, on)
		}
		if on := scope.Intersect(owned, served); len(on) > 0 {
			add(target, root, ReachRole, ConfinedToAttached, on)
		}
	}
	// The holder's capability at the target, as IssueForPerson mints it.
	direct := scope.Intersect(held, served)
	type state struct {
		module domain.Module
		path   []string
		limits scope.Limits
	}
	queue := []state{{target, root, scope.ParentLimits(&basev0.WorkContextV1{AuthorityScopes: scope.Limits{}.Project(direct, direct)})}}
	seen := map[string]bool{target.Name + "\x00" + limitsKey(queue[0].limits): true}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, id := range slices.Sorted(maps.Keys(current.module.Bindings)) {
			b := current.module.Bindings[id]
			next, ok := modules[b.Audience]
			if !ok {
				continue
			}
			invoke, _ := ScopesFor(b, "invoke", "")
			lookup, _ := ScopesFor(b, "lookup", "")
			through := scope.Normalize(append(slices.Clone(invoke), lookup...))
			carried := current.limits.Constrain(scope.Intersect(scope.Intersect(held, next.ResourceKinds), through))
			if len(carried) == 0 {
				continue
			}
			path := append(slices.Clone(current.path), next.Name)
			add(next, path, ReachBinding, "", carried)
			// The child's limits, as IssueChild mints the child: its
			// authority scopes project the binding's kinds onto what it
			// carries, and the hop's grant joins the chain.
			child := scope.ParentLimits(&basev0.WorkContextV1{
				AuthorityScopes: maps.Clone(current.limits).Project(through, carried),
				ActorChain:      []*basev0.WorkActorV1{{GrantedScopes: carried}},
			})
			key := next.Name + "\x00" + limitsKey(child)
			if seen[key] {
				continue
			}
			seen[key] = true
			queue = append(queue, state{next, path, child})
		}
	}
	for _, d := range target.EdgeDependencies {
		if next, ok := modules[d.Module]; ok && next.Name != target.Name {
			add(next, []string{target.Name, next.Name}, ReachPerson, "", nil)
		}
	}
	out := make([]domain.ReachRow, 0, len(rows))
	for _, key := range slices.Sorted(maps.Keys(rows)) {
		out = append(out, *rows[key])
	}
	return out, nil
}

// limitsKey names a chain's limits canonically, a walk state's identity.
func limitsKey(limits scope.Limits) string {
	var b strings.Builder
	for _, kind := range slices.Sorted(maps.Keys(limits)) {
		fmt.Fprintf(&b, "%s=", kind)
		for _, sc := range scope.Normalize(limits[kind]) {
			b.WriteString(scopeText(sc).key())
		}
		b.WriteString(";")
	}
	return b.String()
}

// Operations are m's methods a call holding held is admitted to by m's
// declared policy, as AdmitMethod applies it, one per operation (Operation),
// sorted.
func Operations(m domain.Module, held Scopes) []string {
	set := map[string]bool{}
	for method := range m.Methods {
		if AdmitMethod(m, method, held) == nil {
			set[Operation(method)] = true
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// Operation is the operation a declared method or an incoming call names:
// a Connect call "POST /pkg.Service/Method" is the gRPC procedure
// "/pkg.Service/Method", one operation on two faces; anything else is
// itself.
func Operation(method string) string {
	path, ok := strings.CutPrefix(method, "POST /")
	if !ok {
		return method
	}
	service, name, ok := strings.Cut(path, "/")
	if !ok || !strings.Contains(service, ".") || name == "" || strings.ContainsAny(name, "/{}") {
		return method
	}
	return "/" + path
}

// ReachOf is Reach for every role target declares, by role.
func ReachOf(target domain.Module, modules []domain.Module) (map[string][]domain.ReachRow, error) {
	byPrincipal := map[string]domain.Module{}
	for _, m := range modules {
		byPrincipal[m.Principal] = m
	}
	out := map[string][]domain.ReachRow{}
	for role := range target.Roles {
		rows, err := Reach(target, role, byPrincipal)
		if err != nil {
			return nil, err
		}
		out[role] = rows
	}
	return out, nil
}

// The text a consent records: explicit fields, so its digest moves only
// when the reach does, never with how a generated type marshals.
type reachRowText struct {
	Path        []string    `json:"path"`
	Module      string      `json:"module"`
	Via         string      `json:"via"`
	Confinement string      `json:"confinement,omitempty"`
	Scopes      []scopeLine `json:"scopes,omitempty"`
	Operations  []string    `json:"operations,omitempty"`
}

type scopeLine struct {
	Kind    string   `json:"kind"`
	Actions []string `json:"actions,omitempty"`
	IDs     []string `json:"ids,omitempty"`
	Owner   string   `json:"owner,omitempty"`
}

func scopeText(sc *basev0.WorkScopeV1) scopeLine {
	return scopeLine{Kind: sc.GetResourceKind(), Actions: slices.Sorted(slices.Values(sc.GetActions())),
		IDs: slices.Sorted(slices.Values(sc.GetResourceIds())), Owner: sc.GetResourceOwnerId()}
}

func (l scopeLine) key() string {
	return fmt.Sprintf("%s|%s|%s|%s,", l.Kind, strings.Join(l.Actions, " "), strings.Join(l.IDs, " "), l.Owner)
}

// EncodeReach is reach as the canonical text a consent records, and its
// digest, which the review hands Install with the rest of the consent tuple.
func EncodeReach(reach map[string][]domain.ReachRow) (text, digest string, err error) {
	out := map[string][]reachRowText{}
	for role, rows := range reach {
		lines := []reachRowText{}
		for _, r := range rows {
			line := reachRowText{Path: r.Path, Module: r.Module, Via: r.Via, Confinement: r.Confinement, Operations: r.Operations}
			for _, sc := range scope.Normalize(r.Scopes) {
				line.Scopes = append(line.Scopes, scopeText(sc))
			}
			lines = append(lines, line)
		}
		out[role] = lines
	}
	raw, err := json.Marshal(out) // map keys sorted; rows sorted by Reach
	if err != nil {
		return "", "", err
	}
	return string(raw), fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), nil
}

// DecodeReach reads what EncodeReach wrote.
func DecodeReach(text string) (map[string][]domain.ReachRow, error) {
	out := map[string][]domain.ReachRow{}
	if text == "" {
		return out, nil
	}
	var in map[string][]reachRowText
	if err := json.Unmarshal([]byte(text), &in); err != nil {
		return nil, fmt.Errorf("approved reach: %w", err)
	}
	for role, lines := range in {
		rows := []domain.ReachRow{}
		for _, l := range lines {
			row := domain.ReachRow{Path: l.Path, Module: l.Module, Via: l.Via, Confinement: l.Confinement, Operations: l.Operations}
			for _, s := range l.Scopes {
				row.Scopes = append(row.Scopes, &basev0.WorkScopeV1{ResourceKind: s.Kind, Actions: s.Actions, ResourceIds: s.IDs, ResourceOwnerId: s.Owner})
			}
			rows = append(rows, row)
		}
		out[role] = rows
	}
	return out, nil
}

// ReachWidens lists what next reaches beyond approved, by role: a module,
// way or confinement approved has no row for, scopes that do not attenuate
// the approved row's, or an operation the approved row does not list. Empty
// means next asks nothing new: a narrowing, or nothing moved. A row's path
// is a witness, never compared.
func ReachWidens(approved, next map[string][]domain.ReachRow) []string {
	var out []string
	for _, role := range slices.Sorted(maps.Keys(next)) {
		for _, row := range next[role] {
			at := row.Module
			if row.Via != ReachRole {
				at = strings.Join(row.Path, " > ")
			}
			i := slices.IndexFunc(approved[role], func(a domain.ReachRow) bool {
				return a.Module == row.Module && a.Via == row.Via && a.Confinement == row.Confinement
			})
			switch {
			case i < 0:
				out = append(out, fmt.Sprintf("role %s reaches %s (%s)", role, at, row.Via))
			case !scope.Attenuates(row.Scopes, approved[role][i].Scopes):
				out = append(out, fmt.Sprintf("role %s reaches further at %s", role, at))
			default:
				for _, op := range row.Operations {
					if !slices.Contains(approved[role][i].Operations, op) {
						out = append(out, fmt.Sprintf("role %s reaches %s at %s", role, op, at))
					}
				}
			}
		}
	}
	return out
}

// MethodKey is the method of m's declared policies an incoming call is for:
// method itself, or the one route template an HTTP request matches.
func MethodKey(m domain.Module, method string) (string, bool) {
	if _, ok := m.Methods[method]; ok {
		return method, true
	}
	key, ok, err := routeKey(m.Methods, method)
	return key, ok && err == nil
}
