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
//     within what the module serves, cut to the binding's invoke or lookup
//     scopes, one hop each, and constrained by the chain's limits:
//     scope.ParentLimits, Constrain and Project). Chains start where a
//     holder's can: the capability at the target, the same naming one of its
//     bindings, and a delegation to the target issued through a binding. The
//     walk is a fixed point over (module, limits) states: limits come from a
//     finite set of declared scopes, so the states are finitely many and the
//     walk ends; a module re-entered under other limits is accounted for. A
//     hop carrying nothing for this role is walked through all the same,
//     since another role held with it may keep the chain going: the union of
//     the reaches of the roles a person holds bounds what they hold together.
//     The row's scopes are the union over every state reaching the module;
//     its Path is a shortest way there, a witness.
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
			row.Operations, row.Policies = Operations(m, row.Scopes), Policies(m)
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
	type state struct {
		module domain.Module
		path   []string
		limits scope.Limits
	}
	var queue []state
	seen := map[string]bool{}
	enqueue := func(st state) {
		key := st.module.Name + "\x00" + limitsKey(st.limits)
		if !seen[key] {
			seen[key] = true
			queue = append(queue, st)
		}
	}
	rootAt := func(scopes Scopes) scope.Limits {
		return scope.ParentLimits(&basev0.WorkContextV1{AuthorityScopes: scope.Limits{}.Project(scopes, scopes)})
	}
	// hops are what each hop over b from a capability with limits carries
	// at next, and the child's limits, as IssueChild mints the child: the
	// hop invokes, or looks up, never uses the headless scopes; its
	// authority scopes project the kinds of what it uses onto what it
	// carries, and the hop's grant joins the chain.
	type hopped struct {
		carried Scopes
		limits  scope.Limits
	}
	hops := func(limits scope.Limits, b domain.Binding, next domain.Module) []hopped {
		var out []hopped
		for _, operation := range []string{"invoke", "lookup"} {
			through, _ := ScopesFor(b, operation, "")
			if len(through) == 0 {
				continue
			}
			carried := limits.Constrain(scope.Intersect(scope.Intersect(held, next.ResourceKinds), through))
			out = append(out, hopped{carried, scope.ParentLimits(&basev0.WorkContextV1{
				AuthorityScopes: maps.Clone(limits).Project(through, carried),
				ActorChain:      []*basev0.WorkActorV1{{GrantedScopes: carried}},
			})})
		}
		return out
	}
	// Where a holder's chains start: the capability IssueForPerson mints at
	// the target; the same naming one of the target's bindings, which also
	// carries what the holder holds through it (its invoke scopes there); and
	// a delegation to the target issued through one of its bindings, which
	// starts at the binding's audience with no limit from the target.
	direct := scope.Intersect(held, served)
	enqueue(state{target, root, rootAt(direct)})
	for _, id := range slices.Sorted(maps.Keys(target.Bindings)) {
		b := target.Bindings[id]
		next, ok := modules[b.Audience]
		if !ok {
			continue
		}
		naming := scope.Intersect(scope.Intersect(held, next.ResourceKinds), b.InvokeScopes)
		enqueue(state{target, root, rootAt(scope.Normalize(append(slices.Clone(direct), naming...)))})
		path := []string{target.Name, next.Name}
		for _, h := range hops(scope.Limits{}, b, next) {
			if len(h.carried) > 0 {
				add(next, path, ReachBinding, "", h.carried)
			}
			enqueue(state{next, path, h.limits})
		}
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, id := range slices.Sorted(maps.Keys(current.module.Bindings)) {
			b := current.module.Bindings[id]
			next, ok := modules[b.Audience]
			if !ok {
				continue
			}
			// A hop carrying nothing for this role is still walked: another
			// role held with it may keep the chain going, and each role's
			// walk then follows that chain, so the union of the reaches of
			// the roles a person holds bounds what they hold together.
			path := append(slices.Clone(current.path), next.Name)
			for _, h := range hops(current.limits, b, next) {
				if len(h.carried) > 0 {
					add(next, path, ReachBinding, "", h.carried)
				}
				enqueue(state{next, path, h.limits})
			}
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

// Policies is what each operation of m requires, by operation (Operation),
// as m declares it: on two faces, the gRPC procedure's.
func Policies(m domain.Module) map[string]domain.MethodPolicy {
	out := map[string]domain.MethodPolicy{}
	for _, method := range slices.Sorted(maps.Keys(m.Methods)) {
		if _, ok := out[Operation(method)]; !ok {
			out[Operation(method)] = m.Methods[method]
		}
	}
	return out
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
	Path        []string     `json:"path"`
	Module      string       `json:"module"`
	Via         string       `json:"via"`
	Confinement string       `json:"confinement,omitempty"`
	Scopes      []scopeLine  `json:"scopes,omitempty"`
	Operations  []string     `json:"operations,omitempty"`
	Policies    []policyLine `json:"policies,omitempty"`
}

type policyLine struct {
	Operation        string      `json:"operation"`
	AnyCheckedCaller bool        `json:"any_checked_caller,omitempty"`
	Requires         []scopeLine `json:"requires,omitempty"`
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

func (l scopeLine) scope() *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: l.Kind, Actions: l.Actions, ResourceIds: l.IDs, ResourceOwnerId: l.Owner}
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
			for _, op := range slices.Sorted(maps.Keys(r.Policies)) {
				p := policyLine{Operation: op, AnyCheckedCaller: r.Policies[op].AnyCheckedCaller}
				for _, sc := range scope.Normalize(r.Policies[op].Requires) {
					p.Requires = append(p.Requires, scopeText(sc))
				}
				line.Policies = append(line.Policies, p)
			}
			lines = append(lines, line)
		}
		out[role] = lines
	}
	raw, err := json.Marshal(out) // map keys sorted; rows sorted by Reach
	if err != nil {
		return "", "", err
	}
	return string(raw), DigestReach(string(raw)), nil
}

// DigestReach is the digest of the text EncodeReach wrote.
func DigestReach(text string) string { return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(text))) }

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
				row.Scopes = append(row.Scopes, s.scope())
			}
			for _, p := range l.Policies {
				if row.Policies == nil {
					row.Policies = map[string]domain.MethodPolicy{}
				}
				policy := domain.MethodPolicy{AnyCheckedCaller: p.AnyCheckedCaller}
				for _, s := range p.Requires {
					policy.Requires = append(policy.Requires, s.scope())
				}
				row.Policies[p.Operation] = policy
			}
			rows = append(rows, row)
		}
		out[role] = rows
	}
	return out, nil
}

// ReachWidens lists what next reaches beyond approved, by role: a module,
// way or confinement approved has no row for, scopes that do not attenuate
// the approved row's, an operation the approved row does not list, or an
// operation of the module added, opened to any checked caller or requiring
// less than approved (which roles held together could reach). Empty
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
				was := approved[role][i]
				for _, op := range row.Operations {
					if !slices.Contains(was.Operations, op) {
						out = append(out, fmt.Sprintf("role %s reaches %s at %s", role, op, at))
					}
				}
				for _, op := range slices.Sorted(maps.Keys(row.Policies)) {
					p, before := row.Policies[op], was.Policies[op]
					switch _, ok := was.Policies[op]; {
					case !ok:
						out = append(out, fmt.Sprintf("operation %s added at %s", op, row.Module))
					case p.AnyCheckedCaller && !before.AnyCheckedCaller:
						out = append(out, fmt.Sprintf("operation %s at %s opened to any checked caller", op, row.Module))
					case !p.AnyCheckedCaller && !scope.Attenuates(before.Requires, p.Requires):
						out = append(out, fmt.Sprintf("operation %s at %s requires less", op, row.Module))
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
