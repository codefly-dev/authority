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
	return personAs(tx, caller)
}

// OfferDigest is the digest a consent records of the offer it approved
// (ConsentReceipt.Digest), covering every authority declaration in the
// reviewed module. JSON sorts map keys; the receipt therefore covers roles,
// ceilings and bindings too. A host comparing a declaration it holds with
// what a consent approved compares this.
func OfferDigest(m domain.Module) (string, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), nil
}

// Review reads one consistent offer. It never supplies an operation identity or
// approves anything; the caller must retain the returned values when consenting.
// It is an administrator's read of a solution: the consent tuple is what
// Install takes. A module, roles or not, is installed by composition and
// answers none.
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
	// RolesDeclared: the solution declares roles, which its Setup grants.
	RolesDeclared bool
	// Page: the solution declares a page a person opens, as the stored
	// declaration knows it; a store that does not keep the flag answers
	// false.
	Page bool
	// Closure is the modules the solution reaches, transitively, by name
	// (decide.Closure), roles or not. Composition installs every module, so
	// the closure reports what the solution depends on; a host whose
	// composition is per organization converges it with the install.
	Closure []string
	// OptionalEdges are the optional edge dependencies the target and its
	// closure declare, by module name: present when composed, never
	// installed by the install.
	OptionalEdges []string
	// Reach is what each role reaches, directly and transitively
	// (decide.Reach): in the composition now on an administrator's read,
	// which the approval's ReachDigest names; as the installation's consent
	// approved it on a holder's read.
	Reach map[string][]domain.ReachRow
	// UpgradeAvailable: the installation's consent stands behind what is
	// delivered, its declaration or its reach (Service.UpgradeAvailable).
	UpgradeAvailable bool
}

// ReviewOffer reads one solution's offer. An administrator of org reads it
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
		// Only a solution is reviewed, consented to and installed by an
		// administrator. A module, roles or not, is composition's: nothing to
		// review; its roles are granted on its composition installation.
		if m.Kind != domain.KindSolution {
			return domain.Missing("%q is not a composed solution; a module is installed by composition", target)
		}
		if refused == nil {
			digest, err := OfferDigest(m)
			if err != nil {
				return err
			}
			reach, err := reachIn(tx, m)
			if err != nil {
				return err
			}
			out = domain.ConsentApproval{TargetID: m.Principal, Generation: m.Generation, ExpectedRevision: inst.Revision, Digest: digest, ReachDigest: reach.digest}
			offer.Reach = reach.rows
			if inst.ID != "" {
				if offer.UpgradeAvailable, err = upgradeAvailable(tx, inst, m); err != nil {
					return err
				}
			}
		} else {
			// A role holder reads what they hold: the declaration their
			// installation's consent approved, not one delivered since, and
			// the reach it approved, not one a delivery widened since.
			if offer.UpgradeAvailable, err = upgradeAvailable(tx, inst, m); err != nil {
				return err
			}
			if m, err = approvedModule(tx, inst, m); err != nil {
				return err
			}
			if offer.Reach, err = decide.DecodeReach(inst.Consent.Reach); err != nil {
				return err
			}
			if inst.Consent.ReachDigest == "" {
				reach, err := reachIn(tx, m)
				if err != nil {
					return err
				}
				offer.Reach = reach.rows
			}
		}
		offer.Module, offer.Installation = m, inst
		offer.RolesDeclared, offer.Page = len(m.Roles) > 0, m.Page
		if offer.Modules, err = tx.Modules(); err != nil {
			return err
		}
		if !members {
			return nil // Review hands the consent tuple alone
		}
		// The setup read says what the install brings along; a binding or a
		// required edge naming something not composed refuses it, since that
		// install could not converge.
		offer.Closure, offer.OptionalEdges, err = decide.Closure(m, offer.Modules)
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

func checkConsent(m domain.Module, existing domain.Installation, a *domain.ConsentApproval, intent string, reach offeredReach) (bool, error) {
	if a.TargetID != m.Principal || a.Generation != m.Generation {
		return false, domain.NotNow("INSTALLATION_APPROVAL_GENERATION_CHANGED: the reviewed target or generation changed; review and approve again")
	}
	digest, err := OfferDigest(m)
	if err != nil {
		return false, err
	}
	if a.Digest != digest {
		return false, domain.NotNow("INSTALLATION_APPROVAL_DIGEST_CHANGED: the reviewed authority offer changed; review and approve again")
	}
	if a.ReachDigest != reach.digest {
		return false, domain.NotNow("INSTALLATION_APPROVAL_REACH_CHANGED: what the offer's roles reach changed, or the approval names no reach; review and approve again")
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

// Offers lists what an administrator of org sets up: the delivered
// solutions, each installed through Review and Install. A module is never
// offered, roles or not: composition installs it, and its roles, or the
// organization's when it declares none, decide who may use it.
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
