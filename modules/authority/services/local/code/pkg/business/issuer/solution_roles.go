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

// AttachResource records that the module serving kind created id under
// token, a capability addressed to that module and holding create on the whole
// kind: attaching is for a resource the installation creates, so a capability
// that only reads, or acts on named ids, attaches nothing. The owning
// installation is read from the capability's verified provenance, never named
// by the caller: an installation owning it, the installation of each solution
// in its actor chain, and the module's own when it is the solution. The state
// requires exactly one, at the capability's authorization revision.
func (i *Issuer) AttachResource(ctx context.Context, token, credential, kind, id string) (string, error) {
	if kind == "" || id == "" {
		return "", fmt.Errorf("%w: an attachment names a resource kind and a resource id", ErrRefused)
	}
	actor, err := i.state.VerifyWorkload(ctx, credential)
	if err != nil {
		return "", err
	}
	// Only the one module serving a kind is trusted to say what it created; a
	// kind two composed modules declare has no such module, so nothing of it
	// is attached.
	switch servers := i.state.ServersOf(kind); {
	case !slices.Contains(servers, actor.Module):
		return "", fmt.Errorf("%w: %s does not serve %s, so it attaches none of its resources", ErrRefused, actor.Module, kind)
	case len(servers) > 1:
		return "", fmt.Errorf("%w: %s is served by %s; an attachment needs the kind's one serving module", ErrRefused, kind, strings.Join(servers, ", "))
	}
	verified, err := i.verifier(actor.Principal).Verify(ctx, token)
	if err != nil {
		return "", err
	}
	if !holdsCreate(verified.EffectiveScopes(), kind) {
		return "", fmt.Errorf("%w: the capability holds no create on the whole of %s; an installation attaches only what it creates", ErrRefused, kind)
	}
	wc := verified.Context()
	tenant := wc.GetTenantId()
	var candidates []string
	if wc.GetOwnerPrincipalKind() == "agent" {
		candidates = append(candidates, strings.TrimSuffix(wc.GetOwnerPrincipalId(), "/agent"))
	}
	if actor.Kind == "solution" {
		candidates = append(candidates, state.InstallationID(tenant, actor.Module))
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
			candidates = append(candidates, state.InstallationID(tenant, m.Module))
		}
	}
	return i.state.AttachResource(tenant, wc.GetAuthorizationRevision(), candidates, kind, id)
}

// CreateAction is the action a creating call holds on the whole kind; it is
// what AttachResource requires of the capability it is presented.
const CreateAction = "create"

// holdsCreate reports whether scopes hold create (or every action) on the
// whole of kind, not on named ids.
func holdsCreate(scopes []*basev0.WorkScopeV1, kind string) bool {
	return slices.ContainsFunc(scopes, func(scope *basev0.WorkScopeV1) bool {
		return scope.GetResourceKind() == kind && len(scope.GetResourceIds()) == 0 &&
			(slices.Contains(scope.GetActions(), CreateAction) || slices.Contains(scope.GetActions(), state.AnyAction))
	})
}
