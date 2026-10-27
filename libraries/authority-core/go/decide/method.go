package decide

import (
	"fmt"
	"slices"
	"strings"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
)

// AdmitMethod applies what the module m (the audience a call is checked for)
// declares for method to the scopes the checked call holds. A method that m
// does not declare is NotFound; a module that declares no method policy, a
// method declaring nothing, or one declaring both that it requires scopes and
// that it requires none, is refused: an absent or ambiguous declaration is
// never read as permission. Method admission checks kinds and actions only:
// the module still checks each resource, and its owner, against the
// unchanged scopes.
//
// method is a full protobuf procedure, or an HTTP request "<VERB> <path>"
// admitted under the one route template "<VERB> <template>" its path is an
// instance of; two matching templates are refused rather than guessed between.
func AdmitMethod(m domain.Module, method string, held Scopes) error {
	audience := m.Principal
	if m.Methods == nil {
		return domain.Refuse("%s's delivery declares no method policy, so %s is refused", audience, method)
	}
	p, ok := m.Methods[method]
	if !ok {
		var err error
		if p, ok, err = routeOf(m.Methods, method); err != nil {
			return domain.Refuse("%s: %v", audience, err)
		}
	}
	switch {
	case !ok:
		return domain.Missing("%s serves no method %s", audience, method)
	case p.AnyCheckedCaller && len(p.Requires) > 0:
		return domain.Refuse("%s declares for %s both that it requires scopes and that it requires none", audience, method)
	case p.AnyCheckedCaller:
		return nil
	case len(p.Requires) == 0:
		return domain.Refuse("%s declares no policy for %s", audience, method)
	}
	var missing []string
	for _, r := range p.Requires {
		for _, action := range r.GetActions() {
			if !scope.HoldsAction(held, r.GetResourceKind(), action) {
				missing = append(missing, r.GetResourceKind()+":"+action)
			}
		}
	}
	if len(missing) > 0 {
		return domain.Refuse("%s requires %s for %s, which the call does not hold (it holds %s)",
			audience, strings.Join(missing, ", "), method, describe(held))
	}
	return nil
}

// routeOf is the route a module declares that an HTTP request "<VERB> <path>"
// is for.
func routeOf(methods map[string]domain.MethodPolicy, request string) (domain.MethodPolicy, bool, error) {
	verb, path, ok := strings.Cut(request, " ")
	if !ok || !strings.HasPrefix(path, "/") {
		return domain.MethodPolicy{}, false, nil
	}
	var found []string
	for declared := range methods {
		if v, template, ok := strings.Cut(declared, " "); ok && v == verb && routing.RouteMatches(template, path) {
			found = append(found, declared)
		}
	}
	switch len(found) {
	case 0:
		return domain.MethodPolicy{}, false, nil
	case 1:
		return methods[found[0]], true, nil
	}
	slices.Sort(found)
	return domain.MethodPolicy{}, false, fmt.Errorf("%s matches more than one declared route (%s)", request, strings.Join(found, ", "))
}

// describe names what a call holds, for a refusal.
func describe(held Scopes) string {
	var out []string
	for _, h := range held {
		for _, a := range h.GetActions() {
			permission := h.GetResourceKind() + ":" + a
			switch {
			case h.GetResourceOwnerId() != "":
				permission += " (owner-selected)"
			case len(h.GetResourceIds()) > 0:
				permission += " (resource-limited)"
			}
			out = append(out, permission)
		}
	}
	if len(out) == 0 {
		return "nothing"
	}
	return strings.Join(out, ", ")
}
