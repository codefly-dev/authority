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
// composition by principal. On the target, the role's scopes within what it
// serves, with their confinement. Through each binding of the target (the
// target acting for the holder), then through each binding of what that
// reaches: what a person-owned hop is issued (IssueChild), the role's scopes
// within what the module serves, cut to the binding's invoke and lookup
// scopes and to every limit the chain carries so far (scope.ParentLimits,
// Constrain and Project, as issuance applies them). A hop that carries
// nothing ends its path; a module already on the path, or the hop's own
// audience, is not walked again, so the walk ends: attenuation only narrows.
// Through an edge dependency of the target, on the holder's own session,
// the holder's own grants there decide: the row carries no scopes. A binding
// or edge naming a module not composed reaches nothing. Each row lists the
// operations of its module its scopes are admitted to (AdmitMethod); rows
// with one path, way and confinement are one, so the faces of one operation
// are one operation. The result is sorted by path.
//
// It is an upper bound: issuance also intersects the holder's roles on other
// solutions on the path, delegation ceilings and an installation's consented
// binding ceilings, never widens past these, and checks resources and owners.
// A module's headless scopes are the module acting as itself, for nobody, and
// are no holder's reach.
func Reach(target domain.Module, role string, modules map[string]domain.Module) ([]domain.ReachRow, error) {
	literal, declared := target.Roles[role]
	if !declared {
		return nil, domain.Missing("%s declares no role %q", target.Name, role)
	}
	owned := target.OwnedRoles[role]
	held := scope.Unowned(append(slices.Clone(literal), owned...))
	rows := map[string]*domain.ReachRow{}
	add := func(m domain.Module, path []string, via, confinement string, scopes Scopes) {
		key := strings.Join(path, "\x00") + "\x00" + via + "\x00" + confinement
		row, ok := rows[key]
		if !ok {
			row = &domain.ReachRow{Path: slices.Clone(path), Module: m.Name, Via: via, Confinement: confinement}
			rows[key] = row
		}
		row.Scopes = scope.Normalize(append(row.Scopes, scopes...))
		if via != ReachPerson {
			row.Operations = operations(m, row.Scopes)
		}
	}
	served := target.ResourceKinds
	root := []string{target.Name}
	switch {
	case target.Kind != domain.KindSolution:
		if on := scope.Intersect(literal, served); len(on) > 0 {
			add(target, root, ReachRole, "", on)
		}
	default:
		if on := scope.Intersect(literal, served); len(on) > 0 {
			add(target, root, ReachRole, ConfinedToInstallation, on)
		}
		if on := scope.Intersect(owned, served); len(on) > 0 {
			add(target, root, ReachRole, ConfinedToAttached, on)
		}
	}
	// The holder's capability at the target, as IssueForPerson mints it.
	direct := scope.Intersect(held, served)
	start := &basev0.WorkContextV1{AuthorityScopes: scope.Limits{}.Project(direct, direct)}
	var walk func(current domain.Module, path []string, parent *basev0.WorkContextV1)
	walk = func(current domain.Module, path []string, parent *basev0.WorkContextV1) {
		for _, id := range slices.Sorted(maps.Keys(current.Bindings)) {
			b := current.Bindings[id]
			next, ok := modules[b.Audience]
			if !ok || next.Principal == current.Principal || slices.Contains(path, next.Name) {
				continue
			}
			invoke, _ := ScopesFor(b, "invoke", "")
			lookup, _ := ScopesFor(b, "lookup", "")
			through := scope.Normalize(append(slices.Clone(invoke), lookup...))
			carried := scope.ParentLimits(parent).Constrain(scope.Intersect(scope.Intersect(held, next.ResourceKinds), through))
			if len(carried) == 0 {
				continue
			}
			here := append(slices.Clone(path), next.Name)
			add(next, here, ReachBinding, "", carried)
			child := &basev0.WorkContextV1{AuthorityScopes: scope.ParentLimits(parent).Project(through, carried),
				ActorChain: append(slices.Clone(parent.GetActorChain()), &basev0.WorkActorV1{GrantedScopes: carried})}
			walk(next, here, child)
		}
	}
	walk(target, root, start)
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

// operations are m's methods a call holding held is admitted to, by m's
// declared policy as AdmitMethod applies it, sorted.
func operations(m domain.Module, held Scopes) []string {
	var out []string
	for _, method := range slices.Sorted(maps.Keys(m.Methods)) {
		if AdmitMethod(m, method, held) == nil {
			out = append(out, method)
		}
	}
	return out
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

// EncodeReach is reach as the canonical text a consent records, and its
// digest, which the review hands Install with the rest of the consent tuple.
func EncodeReach(reach map[string][]domain.ReachRow) (text, digest string, err error) {
	if reach == nil {
		reach = map[string][]domain.ReachRow{}
	}
	raw, err := json.Marshal(reach) // map keys sorted; rows sorted by Reach
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
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		return nil, fmt.Errorf("approved reach: %w", err)
	}
	return out, nil
}

// ReachWidens lists what next reaches beyond approved, by role: a row on a
// path, way or confinement approved has none of, scopes that do not
// attenuate the approved row's, or an operation the approved row does not
// list. Empty means next asks nothing new: a narrowing, or nothing moved.
func ReachWidens(approved, next map[string][]domain.ReachRow) []string {
	var out []string
	for _, role := range slices.Sorted(maps.Keys(next)) {
		for _, row := range next[role] {
			at := strings.Join(row.Path, " > ")
			i := slices.IndexFunc(approved[role], func(a domain.ReachRow) bool {
				return slices.Equal(a.Path, row.Path) && a.Via == row.Via && a.Confinement == row.Confinement
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
