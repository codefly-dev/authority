package scenario

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/codefly-dev/authority/libraries/authority-core/go/roleplan"
	"github.com/codefly-dev/authority/libraries/hop/go/policy"
	"github.com/codefly-dev/core/composition"
	"github.com/codefly-dev/core/resources"
)

// Seats are the fixture people who hold a product's roles: the holder of its
// admin role, the holder of its user role and a member holding none. Outsider
// is the administrator of another organisation, who holds no role on any
// installation of theirs; a plan's rows (PlanRows) are the first three's, and
// the outsider is held to tenant isolation (Isolated, Withheld).
type Seats struct{ Admin, User, None, Outsider string }

// Cast is the local authority's shipped fixture, by seat: at Acme, Dana is
// every role-gated target's admin (and the organisation's administrator, who
// installs), Carol its user and Bob a member holding no role; Zoë administers
// Globex, where she is the admin of its own installation of every module page
// the run composes. The ids are the fixture's contract with every composing
// repository; a person's token is still read from the host.
var Cast = Seats{Admin: "dana", User: "carol", None: "bob", Outsider: "zoe"}

// Published is what each composed module publishes of its methods: by
// audience, each procedure "/package.Service/Method" and the permissions it
// requires.
type Published map[string]map[string]policy.Method

// Published reads what every module the composition's workspace composes
// publishes (the procedures its endpoints serve: PublishedIn), each under its
// module's name, which is its audience: from where
// the run resolved the module (Codefly's own resolution: a path, the local
// overlay, or the checkout the run materialized for a pin). A module that
// publishes no protobuf contract is left out.
func (c *Composition) Published(ctx context.Context) (Published, error) {
	workspace, err := resources.FindWorkspaceUpFrom(ctx, c.anchor)
	if err != nil {
		return nil, err
	}
	resolved, err := workspace.ResolveModules(ctx)
	if err != nil {
		return nil, err
	}
	out := Published{}
	for _, module := range resolved {
		if module.Dir == "" {
			return nil, fmt.Errorf("scenario: the run resolved %s to no directory", module.Module)
		}
		if err := out.PublishedIn(module.Module, module.Dir); err != nil && !errors.Is(err, errNoContract) {
			return nil, err
		}
	}
	return out, nil
}

var errNoContract = errors.New("no protobuf contract")

// PublishedIn reads what a module publishes under dir as audience's: the
// procedures its endpoints serve, each with what its published contract (a
// contracts/api/<service>/<endpoint>/contract.binpb, the descriptor sets a
// delivery to the authority is read from) declares for it.
//
// What an endpoint serves is what the module's contract catalog
// (contracts/api/catalog.codefly.json) records for it: the procedures its
// listener registers. A descriptor carries more than that (a protocol the
// module publishes for other modules to serve, its imports' services), which
// the module answers no call to and a delivery leaves out of its method
// table; it is left out here too, so no plan is held to a call to nothing. A
// procedure the catalog routes and its contract does not declare is a stale
// catalog, and an error. A module with no catalog serves every service its
// descriptors declare.
func (p Published) PublishedIn(audience, dir string) error {
	served, err := servedIn(dir)
	if err != nil {
		return fmt.Errorf("%s publishes under %s: %w", audience, dir, err)
	}
	if p[audience] == nil {
		p[audience] = map[string]policy.Method{}
	}
	maps.Copy(p[audience], served)
	return nil
}

// servedIn is the procedures the module at dir serves, each with what its
// contract declares: PublishedIn's rule.
func servedIn(dir string) (map[string]policy.Method, error) {
	contract := func(path string) (map[string]policy.Method, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		methods, err := policy.Contract(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return methods, nil
	}
	out := map[string]policy.Method{}
	catalog, err := composition.LoadAPIContractCatalog(dir)
	if errors.Is(err, fs.ErrNotExist) {
		found, err := filepath.Glob(filepath.Join(dir, "contracts", "api", "*", "*", "contract.binpb"))
		if err != nil {
			return nil, err
		}
		if len(found) == 0 {
			return nil, errNoContract
		}
		for _, path := range found {
			methods, err := contract(path)
			if err != nil {
				return nil, err
			}
			maps.Copy(out, methods)
		}
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	published := false
	for _, endpoint := range catalog.Endpoints {
		if endpoint.Kind != composition.APIContractKindProtobuf {
			continue
		}
		published = true
		methods, err := contract(filepath.Join(dir, filepath.FromSlash(endpoint.Path)))
		if err != nil {
			return nil, err
		}
		for _, service := range endpoint.Services {
			for _, procedure := range service.Procedures {
				declared, ok := methods[procedure]
				if !ok {
					return nil, fmt.Errorf("the catalog routes %s to %s/%s, and %s does not declare it; run codefly generate contracts",
						procedure, endpoint.Service, endpoint.Endpoint, endpoint.Path)
				}
				out[procedure] = declared
			}
		}
	}
	if !published {
		return nil, errNoContract
	}
	return out, nil
}

// PlanRows turns a product's role plan into the calls it speaks of, made for
// real: nothing is listed by hand, so a call the plan and the published
// contracts state is a call the composition is held to.
//
// For a row its page makes through a binding, every procedure the binding's
// audience publishes whose requirement the row's asks cover is called from
// the page, with an empty request, as each seat. For a row naming a route the
// product serves with no path parameter, the route is called the same way,
// on the person's own session.
//
// A seat the plan allows is expected to be let through (Admit: the method may
// refuse the empty request for its own reasons, and a call that failed is not
// let through). A seat the plan refuses is expected to be refused by the
// decision the plan names, read from the refusal's own words, so that a
// refusal for another cause (the audience not installed, the authority
// unreachable, a seat the fixture did not give, a call nobody is served)
// fails the row:
//
//   - refused: no role: the authority says the person "holds no role on
//     <product>". That is the page's root, so it is the same on every call
//     from the page, whatever the method declares.
//   - refused at the product: it says the role "names nothing <product>
//     itself serves".
//   - refused by the method policy (a route): the policy's refusal names, as
//     required and not held, a permission the product's method table requires
//     for the route.
//   - refused at the binding (a page's call): the audience's policy names, as
//     required and not held, a permission of the procedure that no row the
//     plan allows the seat through that binding asks; or, for a seat the plan
//     allows nothing through the binding, the authority says the person
//     "holds nothing at <audience> through binding <binding>".
//   - refused at the binding or onward (a route): the product's handler
//     relays that refusal in words of its own, which the plan does not state;
//     it is held to being a refusal, and not the edge's ("the authority
//     refused this person at"), which the plan says issued.
//
// A page row refused onward is refused past the audience: the first hop,
// which is what is called here, is let through.
//
// A procedure the audience declares open to any checked caller
// (any_checked_caller) requires nothing more than a Work Context at the
// audience, and is called as each seat too. From a page, that Work Context is
// issued from the person's roles on the page's product, through the binding:
// a seat the plan allows something through the binding is a checked caller
// and is let through; the member with no role is issued nothing, and is
// refused for holding no role on the product before the method's declaration
// is read; a seat whose role carries nothing through the binding is refused
// for holding nothing through it. So "nothing more is required" is held to
// mean nothing more than the role, never nothing at all.
//
// A procedure whose requirement no single row's asks cover is not called: the
// plan says nothing of it. A verdict no such call is refused by (the product's
// method policy on a page's call, administration) is an error, not a guess.
//
// This holds the plan's first hop to the real audience: its real method
// policy, whether it checks owners, which kinds it shares, and that the
// composition routes the procedure at all, none of which the plan's stand-in
// for the audience can say. What a call does onward needs a real request,
// which a scenario's own rows give.
func PlanRows(plan roleplan.Plan, seats Seats, published Published) ([]Row, error) {
	product, err := roleplan.Module(plan.Product)
	if err != nil {
		return nil, fmt.Errorf("scenario: the product does not compose: %w", err)
	}
	name := plan.Product.Name
	people := [3]string{seats.Admin, seats.User, seats.None}
	refusal := func(stage string, among, unmet []string) Expect {
		return Expect{verdict: Denied, stage: stage, among: among, unmet: unmet}
	}
	noRole := refusal("for holding no role on "+name, []string{"holds no role on " + name}, nil)
	// route is what the plan's verdict on a route the product serves expects.
	route := func(row roleplan.Row, verdict roleplan.Verdict) (Expect, error) {
		switch verdict {
		case roleplan.Allowed:
			return Admit, nil
		case roleplan.RefusedNoRole:
			return noRole, nil
		case roleplan.RefusedAtProduct:
			return refusal("at "+name+" itself, of which the role names nothing", []string{"names nothing " + name + " itself serves"}, nil), nil
		case roleplan.RefusedByPolicy:
			requires := plan.Product.Methods[row.Method].Requires
			if len(requires) == 0 {
				return Expect{}, fmt.Errorf("the plan says the method policy refuses it, and %s requires nothing for %s", name, row.Method)
			}
			return refusal(fmt.Sprintf("by %s's policy for %s, for one of %v", name, row.Method, requires), nil, requires), nil
		case roleplan.RefusedAtBinding, roleplan.RefusedOnward:
			return Expect{verdict: Denied, stage: fmt.Sprintf("past %s's own policy (%s)", name, verdict),
				not: []string{"the authority refused this person at", "holds no role on " + name}}, nil
		}
		return Expect{}, fmt.Errorf("the plan states %q, which no call to a route is refused by", verdict)
	}
	var rows []Row
	// through is what the plan says of a binding: the asks its page rows
	// cover, those each seat is allowed, and the seats holding no role.
	type through struct {
		covered [][]string
		allowed [3][][]string
		noRole  [3]bool
	}
	bindings := map[string]*through{}
	for _, row := range plan.Rows {
		verdicts := [3]roleplan.Verdict{row.Admin, row.User, row.None}
		switch {
		case row.Method == "" && row.Binding != "":
			if bindings[row.Binding] == nil {
				bindings[row.Binding] = &through{}
			}
			b := bindings[row.Binding]
			b.covered = append(b.covered, row.Asks)
			for i, verdict := range verdicts {
				switch verdict {
				case roleplan.Allowed, roleplan.RefusedOnward:
					b.allowed[i] = append(b.allowed[i], row.Asks)
				case roleplan.RefusedNoRole:
					b.noRole[i] = true
				case roleplan.RefusedAtBinding:
				default:
					return nil, fmt.Errorf("scenario: %q: the plan states %q for %s, which no call a page makes through a binding is refused by", row.Name, verdict, people[i])
				}
			}
		case row.Method != "" && !strings.ContainsAny(row.Method, "{*"):
			want := Want{}
			for i, verdict := range verdicts {
				if want[people[i]], err = route(row, verdict); err != nil {
					return nil, fmt.Errorf("scenario: %q, %s: %w", row.Name, people[i], err)
				}
			}
			rows = append(rows, Row{Name: row.Name, Call: Call{Procedure: row.Method}, Want: want})
		}
	}
	for _, binding := range slices.Sorted(maps.Keys(bindings)) {
		b := bindings[binding]
		audience := product.Bindings[binding].Audience
		methods, ok := published[audience]
		if !ok {
			return nil, fmt.Errorf("scenario: the plan calls %s through binding %q, and no published contract of %s was read", audience, binding, audience)
		}
		nothing := fmt.Sprintf("holds nothing at %s through binding %q", audience, binding)
		for _, procedure := range slices.Sorted(maps.Keys(methods)) {
			var requires []string
			for _, permission := range methods[procedure].Requires {
				requires = append(requires, permission.String())
			}
			covers := func(asks []string) bool {
				return !slices.ContainsFunc(requires, func(p string) bool { return !slices.Contains(asks, p) })
			}
			// open: any checked caller, nothing more required.
			open := methods[procedure].AnyCheckedCaller && len(requires) == 0
			if !open && (len(requires) == 0 || !slices.ContainsFunc(b.covered, covers)) {
				continue
			}
			want := Want{}
			for i, seat := range people {
				switch {
				case len(b.allowed[i]) == 0 && b.noRole[i]:
					want[seat] = noRole
				case len(b.allowed[i]) == 0:
					want[seat] = refusal(fmt.Sprintf("at binding %q, through which the plan lets this role carry nothing", binding), []string{nothing}, requires)
				case open || slices.ContainsFunc(b.allowed[i], covers):
					want[seat] = Admit
				default:
					unmet := slices.DeleteFunc(slices.Clone(requires), func(p string) bool {
						return slices.ContainsFunc(b.allowed[i], func(asks []string) bool { return slices.Contains(asks, p) })
					})
					if len(unmet) == 0 {
						unmet = requires
					}
					want[seat] = refusal(fmt.Sprintf("at binding %q, for one of %v", binding, unmet), nil, unmet)
				}
			}
			rows = append(rows, Row{Name: binding + " " + strings.TrimPrefix(procedure, "/"),
				Call: Call{Page: name, Procedure: strings.TrimPrefix(procedure, "/")}, Want: want})
		}
	}
	return rows, nil
}
