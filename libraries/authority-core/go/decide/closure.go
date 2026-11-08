package decide

import (
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// Closure is what installing m at an organization brings with it: every
// module m reaches through its bindings and edge dependencies, transitively
// through what those reach, that holds no roles of its own, sorted by name.
// Such a module is present wherever it is composed and installed with the
// target that reaches it, holding no standing authority; a host that installs
// modules by its administrators' consent converges these with the install. A
// role-gated target reached (a solution, or a module page declaring roles) is
// chosen by its own review and is neither listed nor walked through; m itself
// is never listed. modules is the composition, as the store answers it.
func Closure(m domain.Module, modules []domain.Module) []string {
	byName := map[string]domain.Module{}
	byPrincipal := map[string]domain.Module{}
	for _, c := range modules {
		byName[c.Name], byPrincipal[c.Principal] = c, c
	}
	seen := map[string]bool{m.Name: true}
	var out []string
	queue := []domain.Module{m}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		var reached []string
		for _, b := range current.Bindings {
			reached = append(reached, b.Audience)
		}
		for _, d := range current.EdgeDependencies {
			if c, ok := byPrincipal[d.Module]; ok {
				reached = append(reached, c.Name)
			}
		}
		for _, name := range reached {
			c, ok := byName[name]
			if !ok {
				c, ok = byPrincipal[name]
			}
			if !ok || seen[c.Name] {
				continue
			}
			seen[c.Name] = true
			if RoleGated(c) {
				continue
			}
			out = append(out, c.Name)
			queue = append(queue, c)
		}
	}
	slices.Sort(out)
	return out
}
