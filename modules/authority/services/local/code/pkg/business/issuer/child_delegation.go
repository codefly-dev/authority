package issuer

import (
	"errors"
	"fmt"
	"gateway/pkg/business/state"

	base "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// delegationCeiling reads durable restrictions from verified provenance.
// Ordinary child hops name parent sessions, not stored Delegate records.
// Revoked records are retained; the final parent recheck fences concurrent
// revocation, so reconstruction cannot refresh an invalidated grant.
func (i *Issuer) delegationCeiling(parent *base.WorkContextV1, ceiling []*base.WorkScopeV1) ([]*base.WorkScopeV1, error) {
	for _, hop := range parent.GetActorChain() {
		d, err := i.state.DelegationByID(hop.GetDelegationId())
		if errors.Is(err, state.ErrUnknown) {
			continue
		}
		if err != nil {
			return nil, err
		}
		module, err := i.state.ModuleByPrincipal(hop.GetPrincipalId())
		if err != nil {
			return nil, err
		}
		if d.Revoked || d.Grantor != parent.GetOwnerPrincipalId() ||
			d.Organization != parent.GetOrganizationId() || d.Module != module.Module {
			return nil, fmt.Errorf("%w: the explicit delegation does not authorize this actor chain", ErrRefused)
		}
		ceiling = state.Intersect(ceiling, d.WorkScopes())
	}
	return ceiling, nil
}
