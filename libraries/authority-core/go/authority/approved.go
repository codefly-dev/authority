package authority

import (
	"context"
	"errors"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// ApprovedDeclaration is the declaration that governs what inst's holders
// hold: its target as composed now while inst's consent stands at that
// generation (or the installation was never consented to, or its consent
// predates the generation being kept), otherwise the generation the consent
// approved, as the store keeps it. It is the rule issuance applies, exported
// so a host that states what a holder may hold never restates it. A target no
// longer composed answers domain.ErrNotFound; an approved generation the
// store does not keep, or keeps as something other than what was consented
// to, is refused by name (approvedModule).
func ApprovedDeclaration(tx Tx, inst domain.Installation) (domain.Module, error) {
	m, err := tx.ModuleNamed(inst.Target)
	if err != nil {
		return domain.Module{}, err
	}
	return approvedModule(tx, inst, m)
}

// ApprovedDeclaration is ApprovedDeclaration read in one transaction.
func (s *Service) ApprovedDeclaration(ctx context.Context, inst domain.Installation) (domain.Module, error) {
	var m domain.Module
	err := s.store.Read(ctx, func(tx Tx) (err error) {
		m, err = ApprovedDeclaration(tx, inst)
		return err
	})
	return m, err
}

// approvedModule is ApprovedDeclaration given m, inst's target as composed
// now: m while the consent stands at its generation (or names none),
// otherwise the generation the consent approved, as the store kept it. A
// redelivery that asked more than the consent approved therefore grants
// nobody the wider roles until an administrator upgrades. A generation the
// store does not keep is refused by name: a host must keep what an active
// consent names. So is a kept declaration whose offer digest is not the one
// the consent recorded: whatever wrote that row, it is not what an
// administrator approved. A digest that differs only because the module's
// encoding changed fails the same way, closed: the installation reads as an
// upgrade, and its review records the digest anew.
func approvedModule(tx Tx, inst domain.Installation, m domain.Module) (domain.Module, error) {
	c := inst.Consent
	if c.OperationID == "" || c.Generation == 0 || c.Generation >= m.Generation || inst.Target != m.Name {
		return m, nil
	}
	approved, err := tx.ApprovedModule(m.Name, c.Generation)
	if errors.Is(err, domain.ErrNotFound) {
		return m, domain.NotNow("the generation %d of %s that installation %s approved is not kept; review and approve the delivered offer", c.Generation, m.Name, inst.ID)
	}
	if err != nil {
		return domain.Module{}, err
	}
	if c.Digest != "" {
		digest, err := OfferDigest(approved)
		if err != nil {
			return domain.Module{}, err
		}
		if digest != c.Digest {
			return domain.Module{}, domain.NotNow("the generation %d of %s kept for installation %s is not the offer it approved; review and approve the delivered offer", c.Generation, m.Name, inst.ID)
		}
	}
	return approved, nil
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
