package authority

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// HeldInstallation is one installation a person may use, with the roles they
// hold on it.
type HeldInstallation struct {
	Installation domain.Installation
	// Roles are the roles granted on it to the person or to a team of
	// theirs, sorted.
	Roles []string
}

// HeldInstallations is a member's navigation: each active installation of org
// on which caller, read now as a member of org, holds a role, granted to them
// or to a team of theirs, sorted by id. It answers the caller's own holdings
// alone, never who else holds what. A member holding nothing reads an empty
// list; a caller who is not a member of org acting there is refused.
func (s *Service) HeldInstallations(ctx context.Context, caller Person, org string) ([]HeldInstallation, error) {
	var out []HeldInstallation
	err := s.store.Read(ctx, func(tx Tx) error {
		p, err := memberAs(tx, caller, org)
		if errors.Is(err, domain.ErrNotFound) {
			return domain.Refuse("the installations held at organization %q are read by a member of it, signed in there", org)
		}
		if err != nil {
			return err
		}
		all, err := tx.Installations(org)
		if err != nil {
			return err
		}
		for _, inst := range all {
			roles, err := rolesHeld(tx, p, org, inst)
			if err != nil {
				return err
			}
			if len(roles) > 0 {
				out = append(out, HeldInstallation{Installation: inst, Roles: roles})
			}
		}
		return nil
	})
	slices.SortFunc(out, func(a, b HeldInstallation) int { return strings.Compare(a.Installation.ID, b.Installation.ID) })
	return out, err
}

// rolesHeld are the roles p, a member of org, holds on inst when it is an
// active installation of org: granted on it to them or to a team of theirs.
func rolesHeld(tx Tx, p domain.Person, org string, inst domain.Installation) ([]string, error) {
	if inst.ID == "" || inst.Organization != org || inst.Status != domain.Active {
		return nil, nil
	}
	grants, err := tx.RoleGrants(inst.ID)
	if err != nil {
		return nil, err
	}
	return decide.HeldRoles(p, inst, grants), nil
}

// ComposedInstallations are org's active installations by composition of the
// modules that declare no roles, sorted by id, read by a member of org signed
// in there. Nobody holds a role on one, so HeldInstallations never lists it;
// a page that consumes such a module through its binding names the module's
// installation by it. Naming it grants nothing: a module that checks owners
// answers a person's own session nothing, and the page's call is issued
// through the page's binding.
func (s *Service) ComposedInstallations(ctx context.Context, caller Person, org string) ([]domain.Installation, error) {
	var out []domain.Installation
	err := s.store.Read(ctx, func(tx Tx) error {
		if _, err := memberAs(tx, caller, org); errors.Is(err, domain.ErrNotFound) {
			return domain.Refuse("the installations composed at organization %q are read by a member of it, signed in there", org)
		} else if err != nil {
			return err
		}
		all, err := tx.Installations(org)
		if err != nil {
			return err
		}
		for _, inst := range all {
			if inst.ID == "" || inst.Organization != org || inst.Status != domain.Active {
				continue
			}
			m, err := tx.ModuleNamed(inst.Target)
			if errors.Is(err, domain.ErrNotFound) {
				continue
			} else if err != nil {
				return err
			}
			if m.Kind != domain.KindSolution && !decide.RoleGated(m) {
				out = append(out, inst)
			}
		}
		return nil
	})
	slices.SortFunc(out, func(a, b domain.Installation) int { return strings.Compare(a.ID, b.ID) })
	return out, err
}
