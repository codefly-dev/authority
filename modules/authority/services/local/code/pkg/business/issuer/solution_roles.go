package issuer

import (
	"gateway/pkg/business/state"
	resources "github.com/codefly-dev/authority/libraries/resources/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"slices"
)

// solutionPrincipals reads provenance already verified by Core. A module hop
// retains its predecessors; it cannot drop a solution's permission source.
func solutionPrincipals(wc *basev0.WorkContextV1, current string) []string {
	out := []string{current}
	for _, actor := range wc.GetActorChain() {
		if actor.GetPrincipalKind() == "service" {
			out = append(out, actor.GetPrincipalId())
		}
	}
	return out
}

// solutionCeiling combines the current role of each solution in the verified
// path. The boolean distinguishes no solution from a solution granting nothing.
func (i *Issuer) solutionCeiling(person string, principals []string) ([]*basev0.WorkScopeV1, bool, error) {
	seen := map[string]bool{}
	var ceiling []*basev0.WorkScopeV1
	bounded := false
	for _, principal := range principals {
		if seen[principal] {
			continue
		}
		seen[principal] = true
		m, err := i.state.ModuleByPrincipal(principal)
		if err != nil {
			return nil, false, err
		}
		if m.Kind != "solution" {
			continue
		}
		role, err := i.state.PersonSolutionScopes(person, principal)
		if err != nil {
			return nil, false, err
		}
		if bounded {
			ceiling = state.Intersect(ceiling, role)
		} else {
			ceiling = role
		}
		bounded = true
	}
	return ceiling, bounded, nil
}

// personThroughSolutions selects solution roles instead of organization roles
// when a solution acts. A target solution additionally requires its own grant.
func (i *Issuer) personThroughSolutions(person string, audience state.Manifest, principals []string) (held, ceiling []*basev0.WorkScopeV1, bounded bool, err error) {
	ceiling, bounded, err = i.solutionCeiling(person, principals)
	if err != nil {
		return
	}
	if !bounded {
		held, err = i.state.PersonScopes(person, audience.Principal)
		return
	}
	held = state.Intersect(ceiling, audience.ResourceKinds)
	if audience.Kind == "solution" {
		var target []*basev0.WorkScopeV1
		target, err = i.state.PersonScopes(person, audience.Principal)
		held = state.Intersect(held, target)
	}
	return
}

// roleResources projects only exact IDs or whole-kind grants, as solution roles
// declare them. Organization prefix/pattern grants keep their existing reader.
func roleResources(scopes []*basev0.WorkScopeV1, kind, action string) []resources.Grant {
	var grants []resources.Grant
	for _, scope := range scopes {
		if scope.GetResourceKind() != kind || (!slices.Contains(scope.GetActions(), action) && !slices.Contains(scope.GetActions(), state.AnyAction)) {
			continue
		}
		if len(scope.GetResourceIds()) == 0 {
			return []resources.Grant{{All: true}}
		}
		for _, id := range scope.GetResourceIds() {
			grants = append(grants, resources.Grant{ID: id})
		}
	}
	return grants
}
