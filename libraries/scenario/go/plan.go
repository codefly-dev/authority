package scenario

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/codefly-dev/authority/libraries/authority-core/go/roleplan"
	"github.com/codefly-dev/authority/libraries/hop/go/policy"
	"github.com/codefly-dev/core/resources"
)

// Seats are the fixture people who hold a product's roles: the holder of its
// admin role, the holder of its user role and a member holding none.
type Seats struct{ Admin, User, None string }

// Published is what each composed module publishes of its methods: by
// audience, each procedure "/package.Service/Method" and the permissions it
// requires.
type Published map[string]map[string]policy.Method

// Published reads what every module the composition's workspace composes
// publishes, each under its module's name, which is its audience: from where
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

// PublishedIn reads the contracts a module publishes under dir (its
// contracts/api/<service>/<endpoint>/contract.binpb, the descriptor sets a
// delivery to the authority is read from) as audience's.
func (p Published) PublishedIn(audience, dir string) error {
	found, err := filepath.Glob(filepath.Join(dir, "contracts", "api", "*", "*", "contract.binpb"))
	if err != nil {
		return err
	}
	if len(found) == 0 {
		return fmt.Errorf("%s publishes under %s: %w", audience, dir, errNoContract)
	}
	if p[audience] == nil {
		p[audience] = map[string]policy.Method{}
	}
	for _, path := range found {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		methods, err := policy.Contract(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		maps.Copy(p[audience], methods)
	}
	return nil
}

// PlanRows turns a product's role plan into the calls it speaks of, made for
// real: nothing is listed by hand, so a call the plan and the published
// contracts state is a call the composition is held to.
//
// For a row its page makes through a binding, every procedure the binding's
// audience publishes whose requirement the row's asks cover is called from
// the page, with an empty request, as each seat. A seat is expected to be let
// through (Admit: the method may refuse the empty request for its own
// reasons) when some row through that binding allows it asks that cover the
// procedure's requirement, and refused, with a reason, otherwise. For a row
// naming a route the product serves with no path parameter, the route is
// called the same way.
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
	expect := func(allowed bool) Expect {
		if allowed {
			return Admit
		}
		return Deny("")
	}
	var rows []Row
	// allows is, per binding, the asks each seat is allowed through it.
	type seatAsks [3][][]string
	allows, covered := map[string]*seatAsks{}, map[string][][]string{}
	for _, row := range plan.Rows {
		verdicts := [3]roleplan.Verdict{row.Admin, row.User, row.None}
		switch {
		case row.Method == "" && row.Binding != "":
			if allows[row.Binding] == nil {
				allows[row.Binding] = &seatAsks{}
			}
			covered[row.Binding] = append(covered[row.Binding], row.Asks)
			for i, v := range verdicts {
				if v == roleplan.Allowed {
					allows[row.Binding][i] = append(allows[row.Binding][i], row.Asks)
				}
			}
		case row.Method != "" && !strings.ContainsAny(row.Method, "{*"):
			rows = append(rows, Row{Name: row.Name, Call: Call{Procedure: row.Method}, Want: Want{
				seats.Admin: expect(row.Admin == roleplan.Allowed), seats.User: expect(row.User == roleplan.Allowed), seats.None: expect(row.None == roleplan.Allowed)}})
		}
	}
	for _, binding := range slices.Sorted(maps.Keys(allows)) {
		audience := product.Bindings[binding].Audience
		methods, ok := published[audience]
		if !ok {
			return nil, fmt.Errorf("scenario: the plan calls %s through binding %q, and no published contract of %s was read", audience, binding, audience)
		}
		for _, procedure := range slices.Sorted(maps.Keys(methods)) {
			var requires []string
			for _, permission := range methods[procedure].Requires {
				requires = append(requires, permission.String())
			}
			covers := func(asks []string) bool {
				return !slices.ContainsFunc(requires, func(p string) bool { return !slices.Contains(asks, p) })
			}
			if len(requires) == 0 || !slices.ContainsFunc(covered[binding], covers) {
				continue
			}
			want := Want{}
			for i, seat := range []string{seats.Admin, seats.User, seats.None} {
				want[seat] = expect(slices.ContainsFunc(allows[binding][i], covers))
			}
			rows = append(rows, Row{Name: binding + " " + strings.TrimPrefix(procedure, "/"),
				Call: Call{Page: plan.Product.Name, Procedure: strings.TrimPrefix(procedure, "/")}, Want: want})
		}
	}
	return rows, nil
}
