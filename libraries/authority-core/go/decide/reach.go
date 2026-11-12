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

// JointRoles is the key of the reach of every role declared, held together,
// beside each role's own in what ReachOf answers: what a person holding
// several roles reaches is within it, and within those roles' scopes.
const JointRoles = ""

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
//     bindings, and a delegation to the target issued through a binding.
//     The walk is a join fixed point: each module keeps one limit, the join
//     of every limit a chain can arrive with (a kind any arrival leaves
//     unconstrained is unconstrained; otherwise the union of what arrives),
//     and is walked again only when its limit grows. Issuance is monotone in
//     the limits, so every chain's limits at a module are within its joined
//     one, and the rows bound what any chain carries; limits only grow and
//     take finitely many values, so the walk ends after polynomially many
//     steps. A hop that carries nothing ends its chain, as issuance refuses
//     it.
//   - On an edge dependency of the target, on the holder's own session
//     ("person"): the holder's own grants there decide, so the row carries
//     no scopes and no operations.
//
// Each row lists the operations of its module its scopes are admitted to
// (AdmitMethod), one per operation whatever face serves it (Operation), and
// the policy of every declared method of the module, each face its own
// (Policies). A binding or edge naming a module not composed reaches
// nothing.
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
	return reach(target, literal, target.OwnedRoles[role], modules), nil
}

func reach(target domain.Module, literal, owned Scopes, modules map[string]domain.Module) []domain.ReachRow {
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
	// One joined limit per module; a module is walked again when it grows.
	limitsAt := map[string]scope.Limits{}
	pathTo := map[string][]string{}
	var queue []string
	queued := map[string]bool{}
	arrive := func(m domain.Module, path []string, limits scope.Limits) {
		was, ok := limitsAt[m.Name]
		if ok {
			joined := joinLimits(was, limits)
			if limitsKey(joined) == limitsKey(was) {
				return
			}
			limits = joined
		} else {
			pathTo[m.Name] = slices.Clone(path)
		}
		limitsAt[m.Name] = limits
		if !queued[m.Name] {
			queued[m.Name] = true
			queue = append(queue, m.Name)
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
	hops := func(from []string, limits scope.Limits, b domain.Binding, next domain.Module) {
		path := append(slices.Clone(from), next.Name)
		for _, operation := range []string{"invoke", "lookup"} {
			through, _ := ScopesFor(b, operation, "")
			carried := limits.Constrain(Through(held, b, operation, next))
			if len(carried) == 0 {
				continue
			}
			add(next, path, ReachBinding, "", carried)
			arrive(next, path, scope.ParentLimits(&basev0.WorkContextV1{
				AuthorityScopes: maps.Clone(limits).Project(through, carried),
				ActorChain:      []*basev0.WorkActorV1{{GrantedScopes: carried}},
			}))
		}
	}
	// Where a holder's chains start: the capability IssueForPerson mints at
	// the target; the same naming one of the target's bindings, which also
	// carries what the holder holds through it (its invoke scopes there); and
	// a delegation to the target issued through one of its bindings, which
	// starts at the binding's audience with no limit from the target.
	direct := scope.Intersect(held, served)
	arrive(target, root, rootAt(direct))
	for _, id := range slices.Sorted(maps.Keys(target.Bindings)) {
		b := target.Bindings[id]
		next, ok := modules[b.Audience]
		if !ok {
			continue
		}
		naming := scope.Intersect(scope.Intersect(held, next.ResourceKinds), b.InvokeScopes)
		arrive(target, root, rootAt(scope.Normalize(append(slices.Clone(direct), naming...))))
		hops(root, scope.Limits{}, b, next)
	}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		queued[name] = false
		current := target
		if name != target.Name {
			current = moduleNamed(modules, name)
		}
		limits := limitsAt[name]
		for _, id := range slices.Sorted(maps.Keys(current.Bindings)) {
			b := current.Bindings[id]
			if next, ok := modules[b.Audience]; ok {
				hops(pathTo[name], limits, b, next)
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
		row := *rows[key]
		if row.Via != ReachPerson {
			m := moduleNamed(modules, row.Module)
			if row.Module == target.Name {
				m = target
			}
			row.Operations, row.Policies = Operations(m, row.Scopes), Policies(m)
		}
		out = append(out, row)
	}
	return out
}

// Through is what a capability holding held carries at next over one
// operation of binding b, before the chain's limits: held within what next
// serves, cut to what the binding may do for that operation. An operation
// the binding does not have carries nothing.
func Through(held Scopes, b domain.Binding, operation string, next domain.Module) Scopes {
	through, _ := ScopesFor(b, operation, "")
	return scope.Intersect(scope.Intersect(held, next.ResourceKinds), through)
}

// moduleNamed is the module of modules (by principal) named name.
func moduleNamed(modules map[string]domain.Module, name string) domain.Module {
	if m, ok := modules[name]; ok && m.Name == name {
		return m
	}
	for _, m := range modules {
		if m.Name == name {
			return m
		}
	}
	return domain.Module{}
}

// joinLimits is the least limit both a and b are within: a kind either
// leaves unconstrained is unconstrained; otherwise what either admits.
func joinLimits(a, b scope.Limits) scope.Limits {
	out := scope.Limits{}
	for kind, rows := range a {
		if other, ok := b[kind]; ok {
			out[kind] = scope.Normalize(append(slices.Clone(rows), other...))
		}
	}
	return out
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

// Policies is what each method m declares requires, by declared method:
// each face of an operation keeps its own policy, as the module checks it.
func Policies(m domain.Module) map[string]domain.MethodPolicy {
	return maps.Clone(m.Methods)
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

// ReachOf is Reach for every role target declares, by role, and, under
// JointRoles, the reach of all of them held together.
func ReachOf(target domain.Module, modules []domain.Module) (map[string][]domain.ReachRow, error) {
	byPrincipal := map[string]domain.Module{}
	for _, m := range modules {
		byPrincipal[m.Principal] = m
	}
	out := map[string][]domain.ReachRow{}
	var literal, owned Scopes
	for _, role := range slices.Sorted(maps.Keys(target.Roles)) {
		rows, err := Reach(target, role, byPrincipal)
		if err != nil {
			return nil, err
		}
		out[role] = rows
		literal = append(literal, target.Roles[role]...)
		owned = append(owned, target.OwnedRoles[role]...)
	}
	if len(target.Roles) > 1 {
		out[JointRoles] = reach(target, scope.Normalize(literal), scope.Normalize(owned), byPrincipal)
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
	return ReachWidensWithin(approved, next, domain.Module{})
}

// ReachWidensWithin is ReachWidens for an installation whose approved
// declaration is declared: the scopes of a row onward through a binding
// that are within what the role names through that binding
// (domain.Module.Through) ask nothing new, whether the row is new or reaches
// further, since the administrator consented to the declaration naming them.
// The operations those scopes open are not part of that declaration: such a
// row still asks every operation the approved row does not list, and every
// operation of its module added, opened to any checked caller or requiring
// less; a row the receipt does not hold lists none. A declared reach a
// delivery left unreached (decide.UnreachedOf) re-converges by itself once a
// later delivery reaches it again only where it opens no operation the
// receipt does not hold; otherwise it offers the upgrade.
func ReachWidensWithin(approved, next map[string][]domain.ReachRow, declared domain.Module) []string {
	var out []string
	for _, role := range slices.Sorted(maps.Keys(next)) {
		who, reaches := "role "+role, "reaches"
		if role == JointRoles {
			who, reaches = "the roles together", "reach"
		}
		for _, row := range next[role] {
			at := row.Module
			if row.Via != ReachRole {
				at = strings.Join(row.Path, " > ")
			}
			i := slices.IndexFunc(approved[role], func(a domain.ReachRow) bool {
				return a.Module == row.Module && a.Via == row.Via && a.Confinement == row.Confinement
			})
			var was domain.ReachRow // a row the receipt does not hold lists nothing
			if i >= 0 {
				was = approved[role][i]
			}
			consented := row.Via == ReachBinding && len(row.Path) > 1 && scope.Attenuates(row.Scopes, declaredThrough(declared, role, row.Path[1]))
			switch {
			case consented: // its scopes; never the operations they open
			case i < 0:
				out = append(out, fmt.Sprintf("%s %s %s (%s)", who, reaches, at, row.Via))
				continue
			case !scope.Attenuates(row.Scopes, was.Scopes):
				out = append(out, fmt.Sprintf("%s %s further at %s", who, reaches, at))
				continue
			}
			for _, op := range row.Operations {
				if !slices.Contains(was.Operations, op) {
					out = append(out, fmt.Sprintf("%s %s %s at %s", who, reaches, op, at))
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
	return out
}

// declaredThrough is what role (every role, for JointRoles) of declared names
// through its bindings addressed to audience, the first module on a path: a
// path names modules, and a module's principal is its name (the render
// refuses a contract claiming another).
func declaredThrough(declared domain.Module, role, audience string) Scopes {
	var out Scopes
	for name, bindings := range declared.Through {
		if role != JointRoles && name != role {
			continue
		}
		for id, scopes := range bindings {
			if b, ok := declared.Bindings[id]; ok && b.Audience == audience {
				out = append(out, scopes...)
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
