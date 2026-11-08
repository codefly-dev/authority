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
// It is an administrator's read of a role-gated target (a solution, or a
// module page declaring roles): the consent tuple is what Install takes.
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
	// RolesDeclared: the target declares roles, which its Setup grants.
	// Always true for a solution; a module is offered only when it does.
	RolesDeclared bool
	// Page: the target declares a page a person opens, as the stored
	// declaration knows it. A module declaring roles always has one (a
	// delivery without a page declares no roles); a solution's is read as
	// delivered, and a store that does not keep the flag answers false.
	Page bool
	// Closure is what installing the target brings along: the modules it
	// reaches, transitively, that hold no roles of their own, by name
	// (decide.Closure). A host that installs modules by its administrators'
	// consent converges them with the install; a role-gated target reached
	// is chosen by its own review and is not listed.
	Closure []string
}

// ReviewOffer reads one role-gated target's offer: a solution's, or a module
// page's that declares roles. An administrator of org reads it
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
		var inst domain.Installation
		var err error
		if s.cfg.HostInstallsModules {
			// A host that installs modules names a module page's installation
			// itself, so it is found by its target, as issuance finds it: the
			// active one before any the core retired under its own id.
			inst, err = installationOf(tx, org, target)
		} else {
			inst, err = tx.Installation(s.cfg.InstallationID(org, target))
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
		// A module page declaring roles is reviewed, consented to and
		// installed as a solution is: its roles are what its Setup shows and
		// grants. A module without roles is composition's: nothing to review.
		if !decide.RoleGated(m) {
			return domain.Missing("%q is not a composed solution or a module page declaring roles; a module without roles is installed by composition", target)
		}
		if refused == nil {
			digest, err := offerDigest(m)
			if err != nil {
				return err
			}
			out = domain.ConsentApproval{TargetID: m.Principal, Generation: m.Generation, ExpectedRevision: inst.Revision, Digest: digest}
		}
		offer.Module, offer.Installation = m, inst
		offer.RolesDeclared, offer.Page = len(m.Roles) > 0, m.Page || (m.Kind != domain.KindSolution && len(m.Roles) > 0)
		if offer.Modules, err = tx.Modules(); err != nil {
			return err
		}
		offer.Closure = decide.Closure(m, offer.Modules)
		return nil
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

// Offers lists what an administrator of org sets up: the role-gated targets,
// delivered solutions and module pages declaring roles, each chosen through
// Review and Install. A module without roles is never offered: composition
// installs it, and the organization's roles decide at it.
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
