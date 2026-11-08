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

// Closure is what m depends on at an organization: every module m reaches
// through its bindings and its required edge dependencies, transitively
// through what those reach, roles or not, page or not, sorted by name.
// Composition installs every module wherever it is composed, so the closure
// reports what a solution needs present; a host whose composition is per
// organization converges it with the install. A solution reached is
// installed by its own administrator's review and is neither listed nor
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
		if c.Kind == domain.KindSolution {
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
