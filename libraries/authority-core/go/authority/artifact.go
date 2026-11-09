package authority

import (
	"context"
	"errors"

	"github.com/codefly-dev/core/workcontext"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// DecideArtifact is the one artifact decision every host makes before it
// reads or writes its own approvals (codefly.dev/artifact): actor is the
// module its workload credential proves, parent the Work Context it presents.
// action is decide.ArtifactActivate (approve, revoke) or decide.ArtifactRun
// (authorize); identity is nil for a revoke. It answers the installation the
// approval belongs to, or the named refusal of decide.Artifact.
func (s *Service) DecideArtifact(ctx context.Context, parent string, actor Workload, installation, policy, action string, identity *decide.ArtifactIdentity) (domain.Installation, error) {
	var module domain.Module
	if err := s.store.Read(ctx, func(tx Tx) (err error) {
		module, err = tx.ModuleNamed(actor.Module)
		return notFound(err)
	}); err != nil {
		return domain.Installation{}, err
	}
	// A parent addressed to another module is that module's, not a forgery:
	// refuse it by name before verifying it at this module's audience.
	decoded, err := workcontext.Decode(parent)
	if err != nil {
		return domain.Installation{}, err
	}
	if audience := decoded.Context().GetAudience(); audience != module.Principal {
		return domain.Installation{}, decide.Artifact(decide.ArtifactCaller{Module: module, Audience: audience}, domain.Installation{}, false, installation, policy, action, identity)
	}
	verified, _, err := s.Check(ctx, parent, module.Principal)
	if err != nil {
		return domain.Installation{}, err
	}
	claims := verified.Context()
	if actor.Organization != "" && actor.Organization != claims.GetTenantId() {
		return domain.Installation{}, domain.Refuse("workload %s is bound to organization %s, not %s", actor.Module, actor.Organization, claims.GetTenantId())
	}
	var inst domain.Installation
	found := false
	if err := s.store.Read(ctx, func(tx Tx) error {
		inst, err = tx.Installation(installation)
		switch {
		case errors.Is(err, domain.ErrNotFound):
			return nil
		case err != nil:
			return err
		}
		found = true
		return nil
	}); err != nil {
		return domain.Installation{}, err
	}
	caller := decide.ArtifactCaller{Module: module, Audience: claims.GetAudience(), Tenant: claims.GetTenantId(),
		OwnerKind: claims.GetOwnerPrincipalKind(), Delegated: verified.Actor() != nil, PagePresent: decide.PresentThroughPage(claims.GetActorChain()),
		Held: verified.EffectiveScopes()}
	// An owned parent's artifacts are its owner's, in the namespace of the
	// installation that owner is the principal of, in this organization.
	if caller.Owner, err = decide.ArtifactOwner(caller.Held, policy); err != nil {
		return domain.Installation{}, err
	}
	if caller.Owner != "" {
		if err := s.store.Read(ctx, func(tx Tx) error {
			owning, err := tx.InstallationByPrincipal(caller.Owner)
			if errors.Is(err, domain.ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			if owning.Organization == claims.GetTenantId() && owning.Status == domain.Active {
				caller.OwnerNamespace = decide.Namespace(owning)
			}
			return nil
		}); err != nil {
			return domain.Installation{}, err
		}
	}
	if err := decide.Artifact(caller, inst, found, installation, policy, action, identity); err != nil {
		return domain.Installation{}, err
	}
	return inst, nil
}
