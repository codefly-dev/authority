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
		previous, err := tx.ModuleNamed(m.Name)
		exists := err == nil
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
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
			if _, err := tx.Installation(id); errors.Is(err, domain.ErrNotFound) {
				if err := tx.PutInstallation(domain.Installation{ID: id, Organization: org.ID, Target: m.Name, Status: domain.Active, Revision: 1}); err != nil {
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
		return tx.DeleteModule(name)
	})
}

// InstallStep converges one installation; a retry may repeat it.
type InstallStep func(ctx context.Context, inst domain.Installation) error

// Install installs a solution at an organization: pending until its step
// converges, then active; the host's own setup asking the same install
// while it is pending resumes it. Its principal is stable per organization and
// target, so a reinstall reuses it; nobody holds a role until granted one,
// the installing person included. A caller, when named, must administer the
// organization; a host's own setup names none.
func (s *Service) Install(ctx context.Context, caller *Person, org, target, agentRole, installedBy string, step InstallStep) (domain.Installation, error) {
	var inst domain.Installation
	var generation uint64
	err := s.store.Write(ctx, func(tx Tx) error {
		if caller != nil {
			p, err := tx.Person(caller.ID)
			if err != nil || p.Organization != org || !decide.IsAdministrator(p) {
				return domain.Refuse("installation administration requires an administrator or owner of organization %q", org)
			}
		}
		if _, err := tx.Organization(org); err != nil {
			return notFound(err)
		}
		m, err := tx.ModuleNamed(target)
		if err != nil || m.Kind != domain.KindSolution {
			return domain.Missing("%q is not a composed solution; a module is installed by composition", target)
		}
		generation = m.Generation
		if _, ok := m.Roles[agentRole]; !ok {
			return domain.Missing("role %q is not one %s declares", agentRole, target)
		}
		if p, err := tx.Person(installedBy); err != nil || p.Organization != org {
			return domain.Refuse("owner %q is not a member of %s", installedBy, org)
		}
		id := s.cfg.InstallationID(org, target)
		existing, err := tx.Installation(id)
		if err == nil && caller == nil && existing.Status == domain.Pending && existing.AgentRole == agentRole && existing.InstalledBy == installedBy {
			// The host's own setup asking the same install again (a delivery
			// replayed) resumes its pending attempt: its step converges
			// idempotently, and its revision stays the one the first attempt
			// took, so a revoke or a reinstall since is told apart. A person's
			// second install while one is pending is refused below.
			inst = existing
			return nil
		}
		if err == nil && existing.Status != domain.Revoked {
			return domain.Refuse("%s is already installed at %s", target, org)
		}
		inst = domain.Installation{ID: id, Organization: org, Target: target, Status: domain.Pending, Revision: existing.Revision + 1,
			AgentRole: agentRole, PrincipalID: s.cfg.PrincipalID(org, target), InstalledBy: installedBy}
		if err := tx.DeleteRoleGrants(id); err != nil {
			return err
		}
		return tx.PutInstallation(inst)
	})
	if err != nil {
		return inst, err
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
		m, err := tx.ModuleNamed(target)
		if err != nil || m.Generation != generation || current.Status != domain.Pending || current.Revision != inst.Revision {
			return domain.NotNow("installation attempt %s changed before acknowledgement", inst.ID)
		}
		current.Status = domain.Active
		inst = current
		return tx.PutInstallation(current)
	})
	return inst, err
}

// Uninstall disables an installation and its principal at once: every
// capability sealed to it is refused, every capability of its organization
// minted before is refused (a hop through the solution sealed elsewhere
// included), its role grants are cleared, and the data its principal owns
// stays owned. A caller, when named, must administer organization; a host's
// own setup names none. Another organization's installation answers as an
// absent one.
func (s *Service) Uninstall(ctx context.Context, caller *Person, organization, installationID string) error {
	return s.store.Write(ctx, func(tx Tx) error {
		inst, err := tx.Installation(installationID)
		if errors.Is(err, domain.ErrNotFound) || (err == nil && inst.Organization != organization) {
			return decide.ForeignInstallation(installationID, organization)
		}
		if err != nil {
			return err
		}
		if caller != nil {
			p, err := tx.Person(caller.ID)
			if err != nil || p.Organization != organization || !decide.IsAdministrator(p) {
				return domain.Refuse("installation administration requires an administrator or owner of organization %q", organization)
			}
		}
		return s.revoke(tx, inst)
	})
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
