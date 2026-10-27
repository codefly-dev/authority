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
func (s *Service) Review(ctx context.Context, caller Person, org, target string) (domain.ConsentApproval, error) {
	offer, err := s.ReviewOffer(ctx, caller, org, target)
	return offer.Approval, err
}

// ReviewedOffer is one transaction: the displayed declaration and its consent identity.
type ReviewedOffer struct {
	Approval     domain.ConsentApproval
	Module       domain.Module
	Installation domain.Installation
	Modules      []domain.Module
}

func (s *Service) ReviewOffer(ctx context.Context, caller Person, org, target string) (ReviewedOffer, error) {
	var offer ReviewedOffer
	var out domain.ConsentApproval
	err := s.store.Read(ctx, func(tx Tx) error {
		if err := administrator(tx, caller, org); err != nil {
			return err
		}
		m, err := tx.ModuleNamed(target)
		if err != nil {
			return notFound(err)
		}
		if m.Kind != domain.KindSolution {
			return domain.Missing("%q is not a composed solution; a module is installed by composition", target)
		}
		digest, err := offerDigest(m)
		if err != nil {
			return err
		}
		out = domain.ConsentApproval{TargetID: m.Principal, Generation: m.Generation, Digest: digest}
		inst, err := tx.Installation(s.cfg.InstallationID(org, target))
		if err == nil {
			out.ExpectedRevision = inst.Revision
		} else if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		offer.Module, offer.Installation = m, inst
		offer.Modules, err = tx.Modules()
		return err
	})
	offer.Approval = out
	return offer, err
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

// Offers lists delivered solution targets, not composition-installed modules.
func (s *Service) Offers(ctx context.Context, caller Person, org string) ([]domain.Module, error) {
	var out []domain.Module
	err := s.store.Read(ctx, func(tx Tx) error {
		if err := administrator(tx, caller, org); err != nil {
			return err
		}
		modules, err := tx.Modules()
		for _, m := range modules {
			if m.Kind == domain.KindSolution {
				out = append(out, m)
			}
		}
		return err
	})
	return out, err
}
