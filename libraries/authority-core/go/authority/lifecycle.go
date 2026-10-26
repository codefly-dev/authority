package authority

import (
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
)

// ApplyModule records a delivered module at a newer generation and holds a
// module installation at every organization (a solution is installed
// explicitly). A narrowing invalidates the capabilities issued before it; a
// withdrawn owner-aware declaration refuses its owner-selected ones for good.
func (s *Service) ApplyModule(ctx context.Context, m domain.Module) ([]string, error) {
	if err := decide.ValidateModule(m); err != nil {
		return nil, err
	}
	var ids []string
	err := s.store.Write(ctx, func(tx Tx) error {
		ids = nil // a retried transaction starts over
		previous, err := tx.ModuleNamed(m.Name)
		exists := err == nil
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		withdrawn := false
		if !exists {
			// A module withdrawn before keeps its principal and its last
			// generation: a redelivery never renames it or rewinds it. Its
			// principal stays its own: no other module claims it. A tombstone
			// is never cleared; a module that must change principal is
			// delivered under a new name.
			if tomb, err := tx.TombstoneByPrincipal(m.Principal); err == nil && tomb.Name != m.Name {
				return domain.Refuse("principal %q is withdrawn %s's for life; %s cannot claim it", m.Principal, tomb.Name, m.Name)
			} else if err != nil && !errors.Is(err, domain.ErrNotFound) {
				return err
			}
			tomb, err := tx.Tombstone(m.Name)
			withdrawn = err == nil
			switch {
			case err == nil && tomb.Principal != m.Principal:
				return domain.Refuse("%s is principal %q for life; a delivery cannot rename it %q", m.Name, tomb.Principal, m.Principal)
			case err == nil && tomb.Generation >= m.Generation:
				return domain.NotNow("%s was withdrawn at %d, got %d", m.Name, tomb.Generation, m.Generation)
			case err != nil && !errors.Is(err, domain.ErrNotFound):
				return err
			}
		}
		if exists && !previous.StandIn && previous.Generation >= m.Generation {
			return domain.NotNow("%s is at %d, got %d", m.Name, previous.Generation, m.Generation)
		}
		if other, err := tx.Module(m.Principal); err == nil && other.Name != m.Name {
			return domain.Refuse("principal %q already belongs to %s", m.Principal, other.Name)
		}
		if exists && previous.Principal != m.Principal {
			return domain.Refuse("%s is principal %q for life; a delivery cannot rename it %q", m.Name, previous.Principal, m.Principal)
		}
		if _, err := tx.Person(m.Principal); err == nil {
			return domain.Refuse("principal %q names a person; a module's principal is its own", m.Principal)
		}
		if _, err := tx.InstallationByPrincipal(m.Principal); err == nil {
			return domain.Refuse("principal %q names an installed solution's principal; a module's principal is its own", m.Principal)
		}
		m.ResourceKinds = scope.Normalize(m.ResourceKinds)
		if exists && decide.Narrowed(previous, m) {
			all, err := tx.Installations("")
			if err != nil {
				return err
			}
			changed := map[string]bool{}
			for _, inst := range all {
				if inst.Target == m.Name && inst.Status == domain.Active {
					inst.Revision++
					if err := tx.PutInstallation(inst); err != nil {
						return err
					}
					changed[inst.Organization] = true
				}
			}
			for _, org := range slices.Sorted(maps.Keys(changed)) {
				if err := tx.BumpAuthorizationRevision(org); err != nil {
					return err
				}
			}
		}
		if exists && previous.OwnerAware && !m.OwnerAware {
			if err := tx.BumpOwnerAwareRevision(m.Principal); err != nil {
				return err
			}
		}
		if err := tx.PutModule(m); err != nil {
			return err
		}
		if m.Kind == domain.KindSolution {
			return nil
		}
		orgs, err := tx.Organizations()
		if err != nil {
			return err
		}
		for _, org := range orgs {
			id := s.cfg.InstallationID(org.ID, m.Name)
			inst, err := tx.Installation(id)
			switch {
			case errors.Is(err, domain.ErrNotFound):
				if err := tx.PutInstallation(domain.Installation{ID: id, Organization: org.ID, Target: m.Name, Status: domain.Active, Revision: 1}); err != nil {
					return err
				}
			case err != nil:
				return err
			case inst.Status == domain.Revoked && withdrawn:
				// A module withdrawn and delivered again is installed again,
				// at a revision above every capability sealed before. Only a
				// withdrawal is undone this way: an installation an
				// administrator uninstalled stays uninstalled (Uninstall
				// refuses a module's anyway).
				inst.Status, inst.Revision = domain.Active, inst.Revision+1
				if err := tx.PutInstallation(inst); err != nil {
					return err
				}
			}
			ids = append(ids, id)
		}
		slices.Sort(ids)
		return nil
	})
	return ids, err
}

// WithdrawModule removes a module: its installations are revoked and the
// delegations granted to it end.
func (s *Service) WithdrawModule(ctx context.Context, name string) error {
	return s.store.Write(ctx, func(tx Tx) error {
		all, err := tx.Installations("")
		if err != nil {
			return err
		}
		for _, inst := range all {
			if inst.Target == name && inst.Status != domain.Revoked {
				if err := s.revoke(tx, inst); err != nil {
					return err
				}
			}
		}
		delegations, err := tx.Delegations()
		if err != nil {
			return err
		}
		for _, d := range delegations {
			if d.Module == name && !d.Revoked {
				d.Revoked = true
				if err := tx.PutDelegation(d); err != nil {
					return err
				}
				if err := tx.BumpAuthorizationRevision(d.Organization); err != nil {
					return err
				}
			}
		}
		m, err := tx.ModuleNamed(name)
		if err != nil {
			return notFound(err)
		}
		if err := tx.PutTombstone(domain.Tombstone{Name: m.Name, Principal: m.Principal, Generation: m.Generation}); err != nil {
			return err
		}
		return tx.DeleteModule(name)
	})
}

// InstallStep converges one installation; a retry may repeat it.
type InstallStep func(ctx context.Context, inst domain.Installation) error

// Install installs a solution at an organization: pending until its step
// converges, then active; the host's own setup asking the same install
// while it is pending resumes it. Its principal is stable per organization and
// target, so a reinstall reuses it; nobody holds a role until granted one,
// the installing person included. The caller must administer the organization.
func (s *Service) Install(ctx context.Context, caller Person, org, target, agentRole, installedBy string, approval *domain.ConsentApproval, step InstallStep) (domain.Installation, error) {
	if approval != nil {
		copy := *approval
		approval = &copy
	}
	return s.install(ctx, func(tx Tx) error { return administrator(tx, caller, org) }, caller, org, target, agentRole, installedBy, approval, step)
}

// InstallAsHost is for trusted host setup, never a request handler. It installs
// a solution without person authorization; an absent person cannot select it.
func (s *Service) InstallAsHost(ctx context.Context, org, target, agentRole, installedBy string, step InstallStep) (domain.Installation, error) {
	return s.install(ctx, func(Tx) error { return nil }, Person{}, org, target, agentRole, installedBy, nil, step)
}

func (s *Service) install(ctx context.Context, authorize func(Tx) error, caller Person, org, target, agentRole, installedBy string, approval *domain.ConsentApproval, step InstallStep) (domain.Installation, error) {
	var inst domain.Installation
	var generation uint64
	var intent string
	var replayed bool
	requestedOwner := installedBy
	if installedBy == "" && caller.ID != "" {
		installedBy = caller.ID
	}
	err := s.store.Write(ctx, func(tx Tx) error {
		replayed = false
		if err := authorize(tx); err != nil {
			return err
		}
		if caller.ID != "" {
			var err error
			intent, err = consentIntent(caller, org, target, agentRole, requestedOwner, approval)
			if err != nil {
				return err
			}
		}
		if _, err := tx.Organization(org); err != nil {
			return notFound(err)
		}
		m, err := tx.ModuleNamed(target)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		if err != nil || m.Kind != domain.KindSolution {
			return domain.Missing("%q is not a composed solution; a module is installed by composition", target)
		}
		generation = m.Generation
		if _, ok := m.Roles[agentRole]; !ok {
			return domain.Missing("role %q is not one %s declares", agentRole, target)
		}
		p, err := tx.Person(installedBy)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		if err != nil || p.Organization != org {
			return domain.Refuse("owner %q is not a member of %s", installedBy, org)
		}
		id := s.cfg.InstallationID(org, target)
		existing, err := tx.Installation(id)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		if approval != nil {
			same, err := checkConsent(m, existing, approval, intent)
			if err != nil {
				return err
			}
			if same && existing.Status == domain.Active {
				inst, replayed = existing, true
				return nil
			}
		}
		if err == nil && existing.Status == domain.Pending {
			if existing.AgentRole != agentRole || existing.InstalledBy != installedBy {
				return domain.NotNow("%s is pending at %s as %s for %s; only that install resumes it", target, org, existing.AgentRole, existing.InstalledBy)
			}
			// The same install asked again resumes its pending attempt: its
			// step converges idempotently, and its revision stays the one the
			// first attempt took, so a revoke or a reinstall since is told apart.
			// A fresh approval supersedes the unfinished attempt instead: checkConsent
			// held it to the current generation, digest and the pending revision, so
			// it consents to exactly what is pending now. The revision moves with its
			// receipt, so the superseded operation can neither resume nor acknowledge.
			if approval != nil && existing.Consent.OperationID != approval.OperationID {
				existing.Revision++
				existing.Consent = domain.ConsentReceipt{OperationID: approval.OperationID, Intent: intent, Revision: existing.Revision}
				if err := tx.DeleteRoleGrants(id); err != nil {
					return err
				}
				inst = existing
				return tx.PutInstallation(existing)
			}
			inst = existing
			return nil
		}
		if err == nil && existing.Status != domain.Revoked {
			return domain.Refuse("%s is already installed at %s", target, org)
		}
		principal := s.cfg.PrincipalID(org, target)
		if _, err := tx.Module(principal); err == nil {
			return domain.Refuse("the principal %q of %s at %s names a module", principal, target, org)
		} else if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		if _, err := tx.Person(principal); err == nil {
			return domain.Refuse("the principal %q of %s at %s names a person", principal, target, org)
		} else if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		if other, err := tx.InstallationByPrincipal(principal); err == nil && other.ID != id {
			return domain.Refuse("the principal %q of %s at %s is another installation's", principal, target, org)
		} else if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		if _, err := tx.TombstoneByPrincipal(principal); err == nil {
			return domain.Refuse("the principal %q of %s at %s is a withdrawn module's", principal, target, org)
		} else if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		inst = domain.Installation{ID: id, Organization: org, Target: target, Status: domain.Pending, Revision: existing.Revision + 1,
			AgentRole: agentRole, PrincipalID: principal, InstalledBy: installedBy}
		if approval != nil {
			inst.Consent = domain.ConsentReceipt{OperationID: approval.OperationID, Intent: intent, Revision: inst.Revision}
		}
		if err := tx.DeleteRoleGrants(id); err != nil {
			return err
		}
		return tx.PutInstallation(inst)
	})
	if err != nil {
		return inst, err
	}
	if replayed {
		return inst, nil
	}
	if step != nil {
		if err := step(ctx, inst); err != nil {
			return inst, err
		}
	}
	err = s.store.Write(ctx, func(tx Tx) error {
		current, err := tx.Installation(inst.ID)
		if err != nil {
			return notFound(err)
		}
		if err := authorize(tx); err != nil {
			return err
		}
		m, err := tx.ModuleNamed(target)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		if err == nil && approval != nil {
			same, err := checkConsent(m, current, approval, intent)
			if err != nil {
				return err
			}
			if !same {
				return domain.NotNow("INSTALLATION_APPROVAL_OPERATION_CONFLICT: approval changed before acknowledgement")
			}
			if current.Status == domain.Active {
				inst = current
				return nil
			}
		}
		if err != nil || m.Generation != generation || current.Status != domain.Pending || current.Revision != inst.Revision {
			return domain.NotNow("installation attempt %s changed before acknowledgement", inst.ID)
		}
		current.Status = domain.Active
		inst = current
		return tx.PutInstallation(current)
	})
	return inst, err
}

// Uninstall disables a solution installation and its principal at once, clears
// its grants and revokes capabilities sealed to it or its organization. The
// caller must currently administer the organization. Module installations
// belong to host composition and cannot be uninstalled by a person.
func (s *Service) Uninstall(ctx context.Context, caller Person, organization, installationID string) error {
	return s.store.Write(ctx, func(tx Tx) error {
		p, err := tx.Person(caller.ID)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		// Authorize before reading the installation: unauthorized callers
		// cannot tell a present installation from an absent one.
		if caller.ID == "" || err != nil || p.Organization != organization || !decide.IsAdministrator(p) {
			return decide.ForeignInstallation(installationID, organization)
		}
		inst, err := installationIn(tx, organization, installationID)
		if err != nil {
			return err
		}
		// This identity survives withdrawal of the module manifest. A
		// solution always has both its own principal and an installer.
		if inst.PrincipalID == "" || inst.InstalledBy == "" {
			return domain.Refuse("%s is a module, installed by composition: it is withdrawn, never uninstalled", inst.Target)
		}
		return s.revoke(tx, inst)
	})
}

// UninstallAsHost retires an installation for trusted host setup and teardown,
// never for a request handler. A module stays retired through routine delivery;
// only host withdrawal and redelivery reactivate it.
func (s *Service) UninstallAsHost(ctx context.Context, organization, installationID string) error {
	return s.store.Write(ctx, func(tx Tx) error {
		inst, err := installationIn(tx, organization, installationID)
		if err != nil {
			return err
		}
		return s.revoke(tx, inst)
	})
}

func installationIn(tx Tx, organization, installationID string) (domain.Installation, error) {
	inst, err := tx.Installation(installationID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && inst.Organization != organization) {
		return inst, decide.ForeignInstallation(installationID, organization)
	}
	return inst, err
}

// revoke disables inst: its revision and its organization's authorization
// revision both move, and its grants are cleared.
func (s *Service) revoke(tx Tx, inst domain.Installation) error {
	inst.Status = domain.Revoked
	inst.Revision++
	if err := tx.PutInstallation(inst); err != nil {
		return err
	}
	if err := tx.BumpAuthorizationRevision(inst.Organization); err != nil {
		return err
	}
	return tx.DeleteRoleGrants(inst.ID)
}

// Installations answers an organization's installations, for its administrator.
func (s *Service) Installations(ctx context.Context, caller Person, org string) ([]domain.Installation, error) {
	var out []domain.Installation
	err := s.store.Read(ctx, func(tx Tx) error {
		p, err := tx.Person(caller.ID)
		if err != nil || p.Organization != org || !decide.IsAdministrator(p) {
			return domain.Refuse("installation administration requires an administrator or owner of organization %q", org)
		}
		out, err = tx.Installations(org)
		return err
	})
	return out, err
}
