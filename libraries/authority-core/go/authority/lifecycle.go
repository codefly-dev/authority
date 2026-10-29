package authority

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
)

// ApplyModule records a delivered module at a newer generation and holds a
// module installation at every organization, unless the host installs
// modules itself (Config.HostInstallsModules; a solution is installed
// explicitly). A narrowing invalidates the capabilities issued before it; a
// withdrawn owner-aware declaration refuses its owner-selected ones for good.
func (s *Service) ApplyModule(ctx context.Context, m domain.Module) ([]string, error) {
	if err := decide.ValidateModule(m); err != nil {
		return nil, err
	}
	m.ResourceKinds = decide.Served(m)
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
		if _, err := tx.Client(m.Principal); err == nil {
			return domain.Refuse("principal %q names an external client; a module's principal is its own", m.Principal)
		} else if !errors.Is(err, domain.ErrNotFound) {
			return err
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
		if err := s.journal(ctx, tx, domain.Event{Kind: domain.ModuleApplied, Subject: m.Name, Detail: map[string]string{"principal": m.Principal, "kind": m.Kind, "generation": fmt.Sprint(m.Generation)}}); err != nil {
			return err
		}
		if m.Kind == domain.KindSolution || s.cfg.HostInstallsModules {
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

// OrganizationAdded holds every composed module installed at an organization
// the host created after those modules were delivered, as ApplyModule holds
// them at every organization that existed then: the order of delivery and
// sign-up never decides whether an organization may use a module. It is
// idempotent, and a module installation an administrator or a withdrawal
// retired stays retired. It answers the organization's module installations.
func (s *Service) OrganizationAdded(ctx context.Context, org string) ([]string, error) {
	var ids []string
	err := s.store.Write(ctx, func(tx Tx) error {
		ids = nil
		if _, err := tx.Organization(org); err != nil {
			return notFound(err)
		}
		if s.cfg.HostInstallsModules {
			return nil // the host installs a module where its administrators consent
		}
		modules, err := tx.Modules()
		if err != nil {
			return err
		}
		for _, m := range modules {
			if m.Kind == domain.KindSolution {
				continue
			}
			id := s.cfg.InstallationID(org, m.Name)
			if _, err := tx.Installation(id); errors.Is(err, domain.ErrNotFound) {
				if err := tx.PutInstallation(domain.Installation{ID: id, Organization: org, Target: m.Name, Status: domain.Active, Revision: 1}); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			ids = append(ids, id)
		}
		slices.Sort(ids)
		return nil
	})
	return ids, err
}

// ReconcileOrganizations holds every composed module at every organization
// (OrganizationAdded at each), and does nothing when the host installs modules: what a host runs when it starts, so an
// organization created while the authority could not record it still holds
// the modules it may use.
func (s *Service) ReconcileOrganizations(ctx context.Context) error {
	if s.cfg.HostInstallsModules {
		return nil // nothing is installed by the core to reconcile
	}
	// One read finds the organizations missing a module installation, so a
	// host with many organizations writes only where something is missing.
	var missing []string
	if err := s.store.Read(ctx, func(tx Tx) error {
		missing = nil
		orgs, err := tx.Organizations()
		if err != nil {
			return err
		}
		modules, err := tx.Modules()
		if err != nil {
			return err
		}
		all, err := tx.Installations("")
		if err != nil {
			return err
		}
		held := map[string]bool{}
		for _, inst := range all {
			held[inst.ID] = true
		}
		for _, org := range orgs {
			for _, m := range modules {
				if m.Kind != domain.KindSolution && !held[s.cfg.InstallationID(org.ID, m.Name)] {
					missing = append(missing, org.ID)
					break
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	for _, org := range missing {
		if _, err := s.OrganizationAdded(ctx, org); err != nil {
			return fmt.Errorf("organization %s: %w", org, err)
		}
	}
	return nil
}

// WithdrawModule removes a module: its installations are revoked and the
// delegations granted to it end.
func (s *Service) WithdrawModule(ctx context.Context, name string) error {
	return s.store.Write(ctx, func(tx Tx) error {
		all, err := tx.Installations("")
		if err != nil {
			return err
		}
		withdrawn, err := tx.ModuleNamed(name)
		if err != nil {
			return notFound(err)
		}
		hostOwned := s.cfg.HostInstallsModules && withdrawn.Kind != domain.KindSolution
		for _, inst := range all {
			if inst.Target == name && inst.Status != domain.Revoked && !hostOwned {
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
		m := withdrawn
		if err := tx.PutTombstone(domain.Tombstone{Name: m.Name, Principal: m.Principal, Generation: m.Generation}); err != nil {
			return err
		}
		if err := s.journal(ctx, tx, domain.Event{Kind: domain.ModuleWithdrawn, Subject: m.Name, Detail: map[string]string{"principal": m.Principal, "generation": fmt.Sprint(m.Generation)}}); err != nil {
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
// A delivered installation-role selector is authoritative: a named role is
// selected unless the caller names that same role, and "none" selects no standing
// authority when the caller supplies no role. A caller may never supply "none".
// With no selector, the caller must name a declared role as before.
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
		selectedRole, err := installationRole(m, agentRole)
		if err != nil {
			return err
		}
		p, err := tx.Member(org, installedBy)
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
			if existing.AgentRole != selectedRole || existing.InstalledBy != installedBy {
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
				if err := tx.PutInstallation(existing); err != nil {
					return err
				}
				return s.journal(ctx, tx, requested(caller, existing))
			}
			inst = existing
			return nil
		}
		if err == nil && existing.Status != domain.Revoked {
			return &domain.Refusal{Code: domain.Denied, Cause: domain.ErrAlreadyInstalled, Reason: fmt.Sprintf("%s is already installed at %s", target, org)}
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
		if _, err := tx.Client(principal); err == nil {
			return domain.Refuse("installation principal %q belongs to an external client", principal)
		} else if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		inst = domain.Installation{ID: id, Organization: org, Target: target, Status: domain.Pending, Revision: existing.Revision + 1,
			AgentRole: selectedRole, PrincipalID: principal, InstalledBy: installedBy}
		if approval != nil {
			inst.Consent = domain.ConsentReceipt{OperationID: approval.OperationID, Intent: intent, Revision: inst.Revision}
		}
		if err := tx.DeleteRoleGrants(id); err != nil {
			return err
		}
		if err := tx.PutInstallation(inst); err != nil {
			return err
		}
		return s.journal(ctx, tx, requested(caller, inst))
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
		if err := tx.PutInstallation(current); err != nil {
			return err
		}
		return s.journal(ctx, tx, domain.Event{Kind: domain.InstallationActivated, Organization: current.Organization, Actor: caller.ID, Subject: current.ID,
			Detail: map[string]string{"target": current.Target, "revision": fmt.Sprint(current.Revision)}})
	})
	return inst, err
}

// installationRole applies the signed declaration, not a preference derived from
// role order, human grants or bindings. The request is left unchanged for consent
// intent and transaction retries. "none" is a stored marker, not a role lookup.
func installationRole(m domain.Module, requested string) (string, error) {
	if requested == domain.NoInstallationRole {
		return "", domain.Refuse("none is an installation_role declaration, not a caller-supplied role")
	}
	selected := m.InstallationRole
	if selected == "" {
		selected = requested
	} else if requested != "" && requested != selected {
		return "", domain.Refuse("role %q cannot override %s's installation_role declaration", requested, m.Name)
	}
	if m.InstallationRole == domain.NoInstallationRole {
		return domain.NoInstallationRole, nil
	}
	if _, ok := m.Roles[selected]; !ok {
		return "", domain.Missing("role %q is not one %s declares", selected, m.Name)
	}
	return selected, nil
}

// requested is the journal entry of an installation attempt recorded pending.
func requested(caller Person, inst domain.Installation) domain.Event {
	return domain.Event{Kind: domain.InstallationRequested, Organization: inst.Organization, Actor: caller.ID, Subject: inst.ID,
		Detail: map[string]string{"target": inst.Target, "role": inst.AgentRole, "principal": inst.PrincipalID, "installed_by": inst.InstalledBy,
			"revision": fmt.Sprint(inst.Revision), "operation": inst.Consent.OperationID}}
}

// Uninstall disables a solution installation and its principal at once, clears
// its grants and revokes capabilities sealed to it or its organization. The
// caller must currently administer the organization. Module installations
// belong to host composition and cannot be uninstalled by a person.
func (s *Service) Uninstall(ctx context.Context, caller Person, organization, installationID string) error {
	return s.store.Write(ctx, func(tx Tx) error {
		p, err := memberAs(tx, caller, organization)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		// Authorize before reading the installation: unauthorized callers
		// cannot tell a present installation from an absent one.
		if err != nil || !decide.IsAdministrator(p) {
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
		if err := s.revoke(tx, inst); err != nil {
			return err
		}
		return s.journal(ctx, tx, uninstalled(caller.ID, inst))
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
		if s.cfg.HostInstallsModules && inst.PrincipalID == "" {
			if m, err := tx.ModuleNamed(inst.Target); err == nil && m.Kind != domain.KindSolution {
				return domain.Refuse("%s is a module installed by its host's consent; the host uninstalls it", inst.Target)
			}
		}
		if err := s.revoke(tx, inst); err != nil {
			return err
		}
		return s.journal(ctx, tx, uninstalled("", inst))
	})
}

func uninstalled(actor string, inst domain.Installation) domain.Event {
	return domain.Event{Kind: domain.InstallationUninstalled, Organization: inst.Organization, Actor: actor, Subject: inst.ID,
		Detail: map[string]string{"target": inst.Target, "revision": fmt.Sprint(inst.Revision + 1)}}
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
	inst.Owned = nil
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
		p, err := memberAs(tx, caller, org)
		if err != nil || !decide.IsAdministrator(p) {
			return domain.Refuse("installation administration requires an administrator or owner of organization %q", org)
		}
		out, err = tx.Installations(org)
		return err
	})
	return out, err
}

// Composed answers a composed module by name, as its delivery declared it.
func (s *Service) Composed(ctx context.Context, name string) (domain.Module, error) {
	var m domain.Module
	err := s.store.Read(ctx, func(tx Tx) (err error) {
		m, err = tx.ModuleNamed(name)
		return notFound(err)
	})
	return m, err
}
