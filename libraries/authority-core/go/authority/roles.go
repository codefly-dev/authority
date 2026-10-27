package authority

import (
	"context"
	"errors"
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// RoleRequest names a role grant: the organization the caller acts in, the
// installation, the role and exactly one person or team.
type RoleRequest struct {
	Organization, InstallationID, Role, PersonID, TeamID string
}

func (r RoleRequest) grant() domain.RoleGrant {
	return domain.RoleGrant{InstallationID: r.InstallationID, Role: r.Role, PersonID: r.PersonID, TeamID: r.TeamID}
}

// decideRoleChange reads what decide.ChangeRole needs. A nil caller is the
// host's own setup, deciding as the organization's administrator would.
func decideRoleChange(tx Tx, caller *Person, r RoleRequest, list, revoke bool) (domain.Installation, error) {
	// A caller of another organization than the one named learns nothing of
	// it: the foreign answer comes before any installation is read. Then the
	// installation is resolved by (organization, id): another organization's
	// and an absent one answer alike, having done the same work.
	c := domain.Person{Organization: r.Organization, Roles: []string{"admin"}}
	if caller != nil {
		var err error
		c, err = memberAs(tx, *caller, r.Organization)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return domain.Installation{}, err
		}
		if err != nil {
			return domain.Installation{}, decide.ForeignInstallation(r.InstallationID, r.Organization)
		}
	}
	inst, err := tx.Installation(r.InstallationID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && inst.Organization != r.Organization) {
		return inst, decide.ForeignInstallation(r.InstallationID, r.Organization)
	}
	if err != nil {
		return inst, err
	}
	grants, err := tx.RoleGrants(inst.ID)
	if err != nil {
		return inst, err
	}
	solution, err := tx.ModuleNamed(inst.Target)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return inst, err
	}
	change := decide.RoleChange{RequestOrganization: r.Organization, RequestedID: r.InstallationID, Installation: inst, Solution: solution,
		Caller: c, CallerRoles: decide.HeldRoles(c, inst, grants), List: list, Revoke: revoke, Role: r.Role, PersonID: r.PersonID, TeamID: r.TeamID}
	if r.PersonID != "" {
		if p, err := tx.Member(inst.Organization, r.PersonID); err == nil {
			change.Subject = &p
		}
	}
	if r.TeamID != "" {
		people, err := tx.People(inst.Organization)
		if err != nil {
			return inst, err
		}
		change.TeamOfOrganization = slices.ContainsFunc(people, func(p domain.Person) bool { return slices.Contains(p.Teams, r.TeamID) })
	}
	return inst, decide.ChangeRole(change)
}

// GrantRole grants a person or a team a role: the access. It moves no
// revision, so every existing capability stays valid.
func (s *Service) GrantRole(ctx context.Context, caller Person, r RoleRequest) (domain.Installation, error) {
	var inst domain.Installation
	err := s.store.Write(ctx, func(tx Tx) error {
		var err error
		if inst, err = decideRoleChange(tx, &caller, r, false, false); err != nil {
			return err
		}
		if err := tx.PutRoleGrant(r.grant()); err != nil {
			return err
		}
		return s.journal(ctx, tx, r.event(domain.RoleGranted, caller.ID))
	})
	return inst, err
}

func (r RoleRequest) event(kind domain.EventKind, actor string) domain.Event {
	return domain.Event{Kind: kind, Organization: r.Organization, Actor: actor, Subject: r.InstallationID,
		Detail: map[string]string{"role": r.Role, "person": r.PersonID, "team": r.TeamID}}
}

// GrantRoleAsHost is for trusted host setup (a fixture's installations),
// never a request handler: it grants a role with no caller, decided as
// GrantRole decides it for the organization's administrator.
func (s *Service) GrantRoleAsHost(ctx context.Context, r RoleRequest) (domain.Installation, error) {
	var inst domain.Installation
	err := s.store.Write(ctx, func(tx Tx) error {
		var err error
		if inst, err = decideRoleChange(tx, nil, r, false, false); err != nil {
			return err
		}
		if err := tx.PutRoleGrant(r.grant()); err != nil {
			return err
		}
		return s.journal(ctx, tx, r.event(domain.RoleGranted, ""))
	})
	return inst, err
}

// RevokeRole ends one grant. Its subject's capabilities through that
// installation are refused at once (their grant epoch on it moves): a
// person's, or every member's of a team. Nobody else's are touched.
func (s *Service) RevokeRole(ctx context.Context, caller Person, r RoleRequest) (domain.Installation, error) {
	var inst domain.Installation
	err := s.store.Write(ctx, func(tx Tx) error {
		var err error
		if inst, err = decideRoleChange(tx, &caller, r, false, true); err != nil {
			return err
		}
		if err := tx.DeleteRoleGrant(r.grant()); err != nil {
			return err
		}
		subjects := []string{r.PersonID}
		if r.TeamID != "" {
			people, err := tx.People(inst.Organization)
			if err != nil {
				return err
			}
			subjects = nil
			for _, p := range people {
				if slices.Contains(p.Teams, r.TeamID) {
					subjects = append(subjects, p.ID)
				}
			}
		}
		for _, person := range subjects {
			if err := tx.BumpGrantEpoch(person, inst.ID); err != nil {
				return err
			}
		}
		return s.journal(ctx, tx, r.event(domain.RoleRevoked, caller.ID))
	})
	return inst, err
}

// ListRoleGrants answers who holds which role on an installation.
func (s *Service) ListRoleGrants(ctx context.Context, caller Person, organization, installationID string) ([]domain.RoleGrant, error) {
	var out []domain.RoleGrant
	err := s.store.Read(ctx, func(tx Tx) error {
		if _, err := decideRoleChange(tx, &caller, RoleRequest{Organization: organization, InstallationID: installationID}, true, false); err != nil {
			return err
		}
		var err error
		out, err = tx.RoleGrants(installationID)
		return err
	})
	return out, err
}

// PersonChanged is what a host calls once it changed a person's identity (a
// team left, the organization left): every capability the person holds is
// refused at once.
func (s *Service) PersonChanged(ctx context.Context, person string) error {
	return s.store.Write(ctx, func(tx Tx) error { return tx.BumpPersonEpoch(person) })
}
