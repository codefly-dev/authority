package authority

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/google/uuid"
)

func administrator(tx Tx, caller Person, org string) error {
	p, err := memberAs(tx, caller, org)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	if err != nil || !decide.IsAdministrator(p) {
		return domain.Refuse("installation administration requires an administrator or owner of organization %q", org)
	}
	return nil
}

// memberAs is the caller as a member of org, read now. The caller acts in the
// organization their session was opened at: a person who belongs to several
// organizations administers or reads another one only from a session there,
// so a session never carries one organization's authority into another.
// Anything else is ErrNotFound, as an absent member is.
func memberAs(tx Tx, caller Person, org string) (domain.Person, error) {
	if caller.ID == "" || org == "" || caller.Organization != org {
		return domain.Person{}, fmt.Errorf("%q acting at %q: %w", caller.ID, org, domain.ErrNotFound)
	}
	return tx.Member(org, caller.ID)
}

// offerDigest covers every authority declaration in the reviewed module. JSON
// sorts map keys; the receipt therefore covers roles, ceilings and bindings too.
func offerDigest(m domain.Module) (string, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), nil
}

// Review reads one consistent offer. It never supplies an operation identity or
// approves anything; the caller must retain the returned values when consenting.
// It is an administrator's read: the consent tuple is what Install takes, and
// a module page, which composition installs, answers none.
func (s *Service) Review(ctx context.Context, caller Person, org, target string) (domain.ConsentApproval, error) {
	offer, err := s.reviewOffer(ctx, caller, org, target, false)
	return offer.Approval, err
}

// ReviewedOffer is one transaction: the displayed declaration and its consent identity.
type ReviewedOffer struct {
	// Approval is empty on a member's read: only an administrator consents.
	Approval     domain.ConsentApproval
	Module       domain.Module
	Installation domain.Installation
	Modules      []domain.Module
}

// ReviewOffer reads one solution's offer, or a module page's that declares
// roles. An administrator of org reads it
// with the consent tuple Install takes. A member of org who holds a role on
// the solution's active installation there (granted to them or to a team of
// theirs) reads the same declaration, roles, ceiling and installation without
// the tuple: what the solution they use grants, never a way to consent. Anyone
// else is refused by one reason, before the target is looked up, so the
// refusal says nothing about what org delivered or installed.
func (s *Service) ReviewOffer(ctx context.Context, caller Person, org, target string) (ReviewedOffer, error) {
	return s.reviewOffer(ctx, caller, org, target, true)
}

func (s *Service) reviewOffer(ctx context.Context, caller Person, org, target string, members bool) (ReviewedOffer, error) {
	var offer ReviewedOffer
	var out domain.ConsentApproval
	err := s.store.Read(ctx, func(tx Tx) error {
		refused := administrator(tx, caller, org)
		if code, ok := domain.CodeOf(refused); refused != nil && (!members || !ok || code != domain.Denied) {
			return refused
		}
		inst, err := tx.Installation(s.cfg.InstallationID(org, target))
		if errors.Is(err, domain.ErrNotFound) && s.cfg.HostInstallsModules {
			// A host that installs modules names a module page's
			// installation itself, so it is found by its target.
			inst, err = installationOf(tx, org, target)
		}
		if errors.Is(err, domain.ErrNotFound) {
			inst, err = domain.Installation{}, nil
		}
		if err != nil {
			return err
		}
		if refused != nil {
			held, err := holdsRoleOn(tx, caller, org, inst)
			if err != nil {
				return err
			}
			if !held {
				return domain.Refuse("reviewing %q requires an administrator or owner of organization %q, or a role on its installation there", target, org)
			}
		}
		m, err := tx.ModuleNamed(target)
		if err != nil {
			return notFound(err)
		}
		// A module page declaring roles is reviewed as a solution is: its
		// roles are what its Setup shows and grants. Its installation is
		// still composition's (Install refuses a module), so its review
		// carries no consent tuple: there is nothing to approve.
		if !decide.RoleGated(m) {
			return domain.Missing("%q is not a composed solution or a module page declaring roles; a module is installed by composition", target)
		}
		if refused == nil && m.Kind == domain.KindSolution {
			digest, err := offerDigest(m)
			if err != nil {
				return err
			}
			out = domain.ConsentApproval{TargetID: m.Principal, Generation: m.Generation, ExpectedRevision: inst.Revision, Digest: digest}
		}
		offer.Module, offer.Installation = m, inst
		offer.Modules, err = tx.Modules()
		return err
	})
	offer.Approval = out
	return offer, err
}

// holdsRoleOn is whether caller, read now as a member of org, holds a role on
// inst, an active installation of org, granted to them or to a team of theirs.
func holdsRoleOn(tx Tx, caller Person, org string, inst domain.Installation) (bool, error) {
	if inst.ID == "" || inst.Organization != org || inst.Status != domain.Active {
		return false, nil
	}
	p, err := memberAs(tx, caller, org)
	if errors.Is(err, domain.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	roles, err := rolesHeld(tx, p, org, inst)
	return len(roles) > 0, err
}

func consentIntent(caller Person, org, target, role, owner string, a *domain.ConsentApproval) (string, error) {
	if a == nil || a.TargetID == "" || a.Generation == 0 || a.Digest == "" || uuid.Validate(a.OperationID) != nil {
		return "", domain.NotNow("INSTALLATION_APPROVAL_REQUIRED: review the offer, supply its target, generation, revision and digest with a fresh UUID operation_id, and preserve the request on retry")
	}
	raw, err := json.Marshal(struct {
		Actor, Organization, Target, Role, Owner string
		Approval                                 *domain.ConsentApproval
	}{caller.ID, org, target, role, owner, a})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

func checkConsent(m domain.Module, existing domain.Installation, a *domain.ConsentApproval, intent string) (bool, error) {
	if a.TargetID != m.Principal || a.Generation != m.Generation {
		return false, domain.NotNow("INSTALLATION_APPROVAL_GENERATION_CHANGED: the reviewed target or generation changed; review and approve again")
	}
	digest, err := offerDigest(m)
	if err != nil {
		return false, err
	}
	if a.Digest != digest {
		return false, domain.NotNow("INSTALLATION_APPROVAL_DIGEST_CHANGED: the reviewed authority offer changed; review and approve again")
	}
	receipt := existing.Consent
	if receipt.OperationID == a.OperationID {
		if receipt.Intent != intent {
			return false, domain.NotNow("INSTALLATION_APPROVAL_OPERATION_CONFLICT: operation_id already names different approval inputs")
		}
		if existing.Status == domain.Revoked || receipt.Revision != existing.Revision {
			return false, domain.NotNow("INSTALLATION_APPROVAL_REVISION_CHANGED: the installation changed after approval; review and approve again")
		}
		return true, nil
	}
	if a.ExpectedRevision != existing.Revision {
		return false, domain.NotNow("INSTALLATION_APPROVAL_REVISION_CHANGED: the reviewed installation revision changed; review and approve again")
	}
	return false, nil
}

// Offers lists what an administrator of org sets up: delivered solutions, and
// module pages declaring roles (composition installs them; their Setup grants
// their roles). A module without roles is the organization's roles' alone.
func (s *Service) Offers(ctx context.Context, caller Person, org string) ([]domain.Module, error) {
	var out []domain.Module
	err := s.store.Read(ctx, func(tx Tx) error {
		if err := administrator(tx, caller, org); err != nil {
			return err
		}
		modules, err := tx.Modules()
		for _, m := range modules {
			if decide.RoleGated(m) {
				out = append(out, m)
			}
		}
		return err
	})
	return out, err
}
