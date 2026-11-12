package authority

import (
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// ConventionalTeamName is the team a role-gated target's role goes to by
// convention, `<target>-<role>`: the three teams of a target declaring
// installer, editor and viewer are `<target>-installer`, `<target>-editor`
// and `<target>-viewer`. Every host seats the same fixture onto these, so a
// journey through "act as this team" names one team wherever it runs.
func ConventionalTeamName(target, role string) string { return target + "-" + role }

// RoleTeams is, per role a role-gated target declares, the conventional
// team holding it; nil for a target that is role-gated by nothing (a module
// without a page's roles), which has no team to seed.
func RoleTeams(m domain.Module) map[string]string {
	if !decide.RoleGated(m) {
		return nil
	}
	teams := make(map[string]string, len(m.Roles))
	for role := range m.Roles {
		teams[role] = ConventionalTeamName(m.Name, role)
	}
	return teams
}

// RoleTeamsOf answers the conventional teams of an installation: one per
// role its target declares, read from the declaration the installation's
// consent approved (never the delivered one past it). A host creates each
// team in its directory from this, then grants with GrantRoleTeamsAsHost.
func (s *Service) RoleTeamsOf(ctx context.Context, installationID string) (map[string]string, error) {
	var teams map[string]string
	err := s.store.Read(ctx, func(tx Tx) error {
		_, m, err := installedDeclaration(tx, installationID)
		if err != nil {
			return err
		}
		teams = RoleTeams(m)
		return nil
	})
	return teams, err
}

// GrantRoleTeamsAsHost is for trusted host setup (a fixture's standing
// people on every role-gated target), never a request handler: it grants, on
// an active installation, each role its target declares to that role's
// conventional team, decided as GrantRoleAsHost decides each grant for the
// organization's administrator. The host's directory holds every team
// already (RoleTeamsOf); one it does not hold is refused by name and nothing
// is granted. A grant that stands already is left as it is, so a pass over a
// converged installation changes nothing. It answers role → team.
func (s *Service) GrantRoleTeamsAsHost(ctx context.Context, installationID string) (map[string]string, error) {
	var teams map[string]string
	err := s.store.Write(ctx, func(tx Tx) error {
		inst, m, err := installedDeclaration(tx, installationID)
		if err != nil {
			return err
		}
		if inst.Status != domain.Active {
			return domain.NotNow("installation %s of %s is %s, so its roles go to no team yet", inst.ID, inst.Target, inst.Status)
		}
		teams = RoleTeams(m)
		for _, role := range slices.Sorted(maps.Keys(teams)) {
			r := RoleRequest{Organization: inst.Organization, InstallationID: inst.ID, Role: role, TeamID: teams[role]}
			if _, err := decideRoleChange(tx, nil, r, false, false); err != nil {
				return err
			}
			if err := tx.PutRoleGrant(r.grant()); err != nil {
				return err
			}
			if err := s.journal(ctx, tx, r.event(domain.RoleGranted, "")); err != nil {
				return err
			}
		}
		return nil
	})
	return teams, err
}

// installedDeclaration is an installation and the declaration of its target
// that its consent approved.
func installedDeclaration(tx Tx, installationID string) (domain.Installation, domain.Module, error) {
	inst, err := tx.Installation(installationID)
	if err != nil {
		return inst, domain.Module{}, notFound(err)
	}
	m, err := tx.ModuleNamed(inst.Target)
	if errors.Is(err, domain.ErrNotFound) {
		return inst, m, domain.Missing("%q, the target of installation %s, is not composed", inst.Target, inst.ID)
	}
	if err != nil {
		return inst, m, err
	}
	m, err = approvedModule(tx, inst, m)
	return inst, m, err
}
