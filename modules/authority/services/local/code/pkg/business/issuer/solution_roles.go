package issuer

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"gateway/pkg/business/state"
	resources "github.com/codefly-dev/authority/libraries/resources/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
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

// AttachResource records that the module serving kind created or attached id
// under token, a capability addressed to that module and holding an action on
// kind. The owning installation is read from the capability's verified
// provenance, never named by the caller: an installation owning it, and the
// installation of each solution in its actor chain. The state requires one.
func (i *Issuer) AttachResource(ctx context.Context, token, credential, kind, id string) (string, error) {
	if kind == "" || id == "" {
		return "", fmt.Errorf("%w: an attachment names a resource kind and a resource id", ErrRefused)
	}
	actor, err := i.state.VerifyWorkload(ctx, credential)
	if err != nil {
		return "", err
	}
	if !holdsKind(actor.ResourceKinds, kind) {
		return "", fmt.Errorf("%w: %s does not serve %s, so it attaches none of its resources", ErrRefused, actor.Module, kind)
	}
	verified, err := i.verifier(actor.Principal).Verify(ctx, token)
	if err != nil {
		return "", err
	}
	if !holdsKind(verified.EffectiveScopes(), kind) {
		return "", fmt.Errorf("%w: the capability holds no action on %s, so nothing of it was created under it", ErrRefused, kind)
	}
	wc := verified.Context()
	var candidates []string
	if wc.GetOwnerPrincipalKind() == "agent" {
		candidates = append(candidates, strings.TrimSuffix(wc.GetOwnerPrincipalId(), "/agent"))
	}
	for _, hop := range wc.GetActorChain() {
		if hop.GetPrincipalKind() != "service" {
			continue
		}
		m, err := i.state.ModuleByPrincipal(hop.GetPrincipalId())
		if err != nil {
			return "", err
		}
		if m.Kind == "solution" {
			candidates = append(candidates, state.InstallationID(wc.GetTenantId(), m.Module))
		}
	}
	return i.state.AttachResource(wc.GetTenantId(), candidates, kind, id)
}

// holdsKind reports whether any scope grants an action on kind; a zero-action
// row is a denial, not a grant.
func holdsKind(scopes []*basev0.WorkScopeV1, kind string) bool {
	return slices.ContainsFunc(scopes, func(scope *basev0.WorkScopeV1) bool {
		return scope.GetResourceKind() == kind && len(scope.GetActions()) > 0
	})
}
