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

// AttachResource records that id of kind now belongs to the installation the
// presented capability was issued through. The caller is the kind's one
// serving module and the capability is addressed to it, holding either
// create on the whole kind (the module created id) or admin on id itself (an
// administrator of an existing resource attaches it); a capability that only
// reads attaches nothing. The owning installation is read from the
// capability's verified provenance, never named by the caller: an
// installation owning it, the installation of each solution in its actor
// chain, and the module's own when it is the solution. The state requires
// exactly one, at the capability's authorization revision.
func (i *Issuer) AttachResource(ctx context.Context, token, credential, kind, id string) (string, error) {
	actor, err := i.soleServer(ctx, credential, kind, id)
	if err != nil {
		return "", err
	}
	verified, err := i.verifier(actor.Principal).Verify(ctx, token)
	if err != nil {
		return "", err
	}
	if !mayAttach(verified.EffectiveScopes(), kind, id) {
		return "", fmt.Errorf("%w: the capability holds neither %s on the whole of %s nor %s on %q; reading a resource attaches nothing", ErrRefused, CreateAction, kind, AdminAction, id)
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

// DetachResource releases id of kind from whichever installation of org owns
// it, when the kind's one serving module deletes it. Detaching only narrows,
// so it asks the module's word alone; the owner's revision moves, so no
// capability issued before still carries the released id.
func (i *Issuer) DetachResource(ctx context.Context, credential, org, kind, id string) (string, error) {
	if _, err := i.soleServer(ctx, credential, kind, id); err != nil {
		return "", err
	}
	if org == "" {
		return "", fmt.Errorf("%w: a detachment names the organization the resource belongs to", ErrRefused)
	}
	return i.state.DetachResource(org, kind, id)
}

// soleServer authenticates the module and requires it to be the one composed
// module serving kind: only it is trusted with what exists of the kind, and a
// kind two modules declare has no such module, so nothing of it is attached.
func (i *Issuer) soleServer(ctx context.Context, credential, kind, id string) (state.Manifest, error) {
	if kind == "" || id == "" {
		return state.Manifest{}, fmt.Errorf("%w: an ownership change names a resource kind and a resource id", ErrRefused)
	}
	actor, err := i.state.VerifyWorkload(ctx, credential)
	if err != nil {
		return state.Manifest{}, err
	}
	switch servers := i.state.ServersOf(kind); {
	case !slices.Contains(servers, actor.Module):
		return state.Manifest{}, fmt.Errorf("%w: %s does not serve %s, so it attaches none of its resources", ErrRefused, actor.Module, kind)
	case len(servers) > 1:
		return state.Manifest{}, fmt.Errorf("%w: %s is served by %s; an attachment needs the kind's one serving module", ErrRefused, kind, strings.Join(servers, ", "))
	}
	return actor, nil
}

// The actions AttachResource reads, in the serving module's vocabulary:
// create on the whole kind is a creating call; admin on a resource (or on
// the whole kind) administers it.
const (
	CreateAction = "create"
	AdminAction  = "admin"
)

// mayAttach reports whether scopes hold create (or every action) on the whole
// of kind, or admin (or every action) on id, by name or on the whole kind.
func mayAttach(scopes []*basev0.WorkScopeV1, kind, id string) bool {
	return slices.ContainsFunc(scopes, func(scope *basev0.WorkScopeV1) bool {
		if scope.GetResourceKind() != kind {
			return false
		}
		whole, every := len(scope.GetResourceIds()) == 0, slices.Contains(scope.GetActions(), state.AnyAction)
		create := whole && (every || slices.Contains(scope.GetActions(), CreateAction))
		admin := (whole || slices.Contains(scope.GetResourceIds(), id)) && (every || slices.Contains(scope.GetActions(), AdminAction))
		return create || admin
	})
}
