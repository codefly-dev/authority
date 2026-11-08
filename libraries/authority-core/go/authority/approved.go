package authority

import (
	"context"
	"errors"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// approvedModule is the declaration an installation's holders are decided
// from: the delivered module m while the consent stands at its generation
// (or the installation was never consented to, or its consent predates the
// generation being kept), otherwise the generation the consent approved, as
// the store kept it. A redelivery that asked more than the consent approved
// therefore grants nobody the wider roles until an administrator upgrades.
// A generation the store does not keep is refused by name: a host must keep
// what an active consent names.
func approvedModule(tx Tx, inst domain.Installation, m domain.Module) (domain.Module, error) {
	c := inst.Consent
	if c.OperationID == "" || c.Generation == 0 || c.Generation >= m.Generation || inst.Target != m.Name {
		return m, nil
	}
	approved, err := tx.ApprovedModule(m.Name, c.Generation)
	if errors.Is(err, domain.ErrNotFound) {
		return m, domain.NotNow("the generation %d of %s that installation %s approved is not kept; review and approve the delivered offer", c.Generation, m.Name, inst.ID)
	}
	return approved, err
}

// dropUndeclaredGrants deletes every grant on inst of a role next does not
// declare, when inst's consent advances to next: a grant of a role nobody
// declares any more would otherwise sleep in the store until a later
// generation declared the name again, and its holders would hold whatever
// that generation meant by it, with no administrator having granted that.
// Each deletion is journaled as a revocation by actor.
func (s *Service) dropUndeclaredGrants(ctx context.Context, tx Tx, inst domain.Installation, next domain.Module, actor string) error {
	grants, err := tx.RoleGrants(inst.ID)
	if err != nil {
		return err
	}
	for _, g := range grants {
		if _, declared := next.Roles[g.Role]; declared {
			continue
		}
		if err := tx.DeleteRoleGrant(g); err != nil {
			return err
		}
		r := RoleRequest{Organization: inst.Organization, InstallationID: inst.ID, Role: g.Role, PersonID: g.PersonID, TeamID: g.TeamID}
		if err := s.journal(ctx, tx, r.event(domain.RoleRevoked, actor)); err != nil {
			return err
		}
	}
	return nil
}
