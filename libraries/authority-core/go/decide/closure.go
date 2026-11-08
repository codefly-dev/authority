package decide

import (
	"fmt"
	"maps"
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// EdgeOptional is the presence of an edge dependency a target can do without:
// present when composed, never installed with the target. Any other presence
// is required.
const EdgeOptional = "optional"

// Closure is what installing m at an organization brings with it: every
// module m reaches through its bindings and its required edge dependencies,
// transitively through what those reach, that holds no roles of its own,
// sorted by name. Such a module is present wherever it is composed and
// installed with the target that reaches it, holding no standing authority;
// a host that installs modules by its administrators' consent converges these
// with the install. A role-gated target reached (a solution, or a module page
// declaring roles) is chosen by its own review and is neither listed nor
// walked through; m itself is never listed. Bindings and edges name a
// module's principal, resolved in modules, the composition as the store
// answers it: a binding audience or a required edge that is not composed is
// an error, since what the install needs is not there. Optional edges are
// answered apart, never walked, never installed.
func Closure(m domain.Module, modules []domain.Module) (closure, optional []string, err error) {
	byPrincipal := map[string]domain.Module{}
	for _, c := range modules {
		byPrincipal[c.Principal] = c
	}
	seen := map[string]bool{m.Name: true}
	optionals := map[string]bool{}
	queue := []domain.Module{m}
	reach := func(from domain.Module, principal, what string) error {
		c, ok := byPrincipal[principal]
		if !ok {
			return domain.NotNow("%s %s names %q, which is not composed; its closure cannot be installed", from.Name, what, principal)
		}
		if seen[c.Name] {
			return nil
		}
		seen[c.Name] = true
		if RoleGated(c) {
			return nil
		}
		closure = append(closure, c.Name)
		queue = append(queue, c)
		return nil
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, id := range slices.Sorted(maps.Keys(current.Bindings)) {
			if err := reach(current, current.Bindings[id].Audience, "binding "+id); err != nil {
				return nil, nil, err
			}
		}
		for _, d := range current.EdgeDependencies {
			if d.Presence == EdgeOptional {
				if c, ok := byPrincipal[d.Module]; ok && c.Name != m.Name {
					optionals[c.Name] = true
				} else if !ok {
					optionals[d.Module] = true
				}
				continue
			}
			if err := reach(current, d.Module, fmt.Sprintf("edge dependency (%s)", d.Presence)); err != nil {
				return nil, nil, err
			}
		}
	}
	slices.Sort(closure)
	return closure, slices.Sorted(maps.Keys(optionals)), nil
}
