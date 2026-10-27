package authority

import (
	"context"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// CurrentInstallation reads only the authenticated workload's installation
// in its current parent's tenant. A child is sealed to its source actor, so
// the seal is verified but is not the destination installation selector.
func (s *Service) CurrentInstallation(ctx context.Context, parent string, actor Workload) (domain.Installation, error) {
	var module domain.Module
	err := s.store.Read(ctx, func(tx Tx) error {
		var err error
		module, err = tx.ModuleNamed(actor.Module)
		return notFound(err)
	})
	if err != nil {
		return domain.Installation{}, err
	}
	verified, _, err := s.Check(ctx, parent, module.Principal)
	if err != nil {
		return domain.Installation{}, err
	}
	claims := verified.Context()
	var out domain.Installation
	err = s.store.Read(ctx, func(tx Tx) error {
		inst, err := installationOf(tx, claims.GetTenantId(), module.Name)
		if err != nil {
			return err
		}
		if inst.Status != domain.Active || inst.Target != module.Name {
			return domain.Missing("the authenticated module has no active installation in the parent organization")
		}
		out = inst
		return nil
	})
	return out, err
}
