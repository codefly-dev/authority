package authority

import (
	"context"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
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

// CurrentAuthoring is CurrentInstallation and the namespace the parent
// authors artifacts in there: the installation's own, or, for a parent whose
// scopes are owned by a solution installation's principal (a person reaching
// the module through that solution's binding), that owning installation's —
// the namespace DecideArtifact holds such a parent's artifacts to. Scopes
// owned by two owners, or owned beside unowned, are refused; an owner with no
// active installation in the parent's organization has no namespace there.
func (s *Service) CurrentAuthoring(ctx context.Context, parent string, actor Workload) (domain.Installation, string, error) {
	inst, err := s.CurrentInstallation(ctx, parent, actor)
	if err != nil {
		return inst, "", err
	}
	var principal string
	if err := s.store.Read(ctx, func(tx Tx) error {
		module, err := tx.ModuleNamed(actor.Module)
		principal = module.Principal
		return notFound(err)
	}); err != nil {
		return inst, "", err
	}
	verified, _, err := s.Check(ctx, parent, principal)
	if err != nil {
		return inst, "", err
	}
	owner, err := decide.ScopesOwner(verified.EffectiveScopes())
	if err != nil || owner == "" {
		return inst, decide.Namespace(inst), err
	}
	namespace, err := s.ownerNamespace(ctx, verified.Context().GetTenantId(), owner)
	if err == nil && namespace == "" {
		err = domain.Refuse("the owner %s of the parent's scopes holds no installation here, so it has no namespace", owner)
	}
	return inst, namespace, err
}
