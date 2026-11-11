package authority

import (
	"context"
	"errors"
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// TeamCastRequest asks to fix a new session to act as a member of one team,
// and of nothing else. SessionID is the session the host has minted for the
// cast; the host never takes it from a client.
type TeamCastRequest struct {
	Organization, Team, SessionID string
}

// OpenTeamCast records a cast for a new session: who, signed in at
// r.Organization, acts there as a member of r.Team and of nothing else —
// no direct grant of their own, no other team of theirs, no organisation
// role, no platform role.
//
// It answers "what does a member of this team actually see". An
// administrator who checks a journey as themselves proves nothing, because
// their own reach answers everything; the same journey through a cast proves
// the grant path, because the cast holds the team's grants and only those.
//
// THE ONE RULE: a person may cast onto any team whose grants are within what
// they already hold. Membership is NOT the rule and is never consulted — that
// is deliberate, and it is what lets a platform administrator be a team they
// do not belong to. The three familiar cases fall out of the one rule rather
// than being tiers in it: an ordinary person holds the grants of their own
// teams, so those are within what they hold; an organisation administrator
// holds every kind and action in their organisation, so any team of it is;
// a platform administrator's baseline covers every organisation, so any team
// anywhere is. Deciding by role name instead would be a decision by tier,
// the pattern being removed, and would drift the moment a role's reach moves.
//
// A cast is never wider than the person, by construction of that rule, so it
// only narrows. It composes with a role view, which may narrow it further.
func (s *Service) OpenTeamCast(ctx context.Context, who Person, r TeamCastRequest) (domain.RoleView, error) {
	var cast domain.RoleView
	err := s.store.Write(ctx, func(tx Tx) error {
		if who.SessionID == "" || r.SessionID == "" || r.SessionID == who.SessionID {
			return domain.Malformed("a cast is opened from a session, for a new one")
		}
		if r.Team == "" {
			return domain.Malformed("a cast names the team to act as")
		}
		p, err := personAs(tx, who)
		if err != nil || p.Organization != r.Organization {
			return domain.Refuse("a cast is opened by a member of %q, signed in there", r.Organization)
		}
		if p.Cast != "" {
			return domain.Refuse("this session is already cast onto team %q; a cast is never changed or widened", p.Cast)
		}
		if _, err := tx.RoleView(r.SessionID); err == nil {
			return domain.Refuse("session %s already has a view or cast, which is never changed", r.SessionID)
		} else if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		within, reaches, err := teamIsWithin(tx, p, r.Organization, r.Team)
		if err != nil {
			return err
		}
		if !reaches {
			return domain.Missing("team %q holds no role on anything installed at organization %q, so there is nothing to act as", r.Team, r.Organization)
		}
		if !within {
			return domain.Refuse("team %q is granted more than you hold, so acting as it would widen you, which a cast never does", r.Team)
		}
		cast = domain.RoleView{SessionID: r.SessionID, Parent: who.SessionID, Person: p.ID, Organization: p.Organization, Team: r.Team, Roles: map[string][]string{}}
		for id, roles := range p.View {
			cast.Roles[id] = slices.Clone(roles)
		}
		if err := tx.PutRoleView(cast); err != nil {
			return err
		}
		return s.journal(ctx, tx, domain.Event{Kind: domain.RoleViewOpened, Organization: p.Organization, Actor: p.ID, Subject: r.Team,
			Detail: map[string]string{"cast_team": r.Team, "session": r.SessionID}})
	})
	return cast, err
}

// teamIsWithin answers whether every role the team is granted, on every
// installation of the organization, is a role the person already acts as
// there — and whether the team is granted anything at all.
//
// This is the subset rule read through roles held rather than scopes
// compared: HeldRoles is the one place a person's reach on an installation is
// decided, so asking it is asking the same question the rest of the authority
// asks, and it cannot drift from it. A person whose organisation role already
// answers every role on an installation covers any team there; one who holds
// nothing there covers no team that is granted something there.
func teamIsWithin(tx Tx, p domain.Person, org, team string) (within, reaches bool, err error) {
	installs, err := tx.Installations(org)
	if err != nil {
		return false, false, err
	}
	within = true
	for _, inst := range installs {
		if inst.Status != domain.Active {
			continue
		}
		grants, err := tx.RoleGrants(inst.ID)
		if err != nil {
			return false, false, err
		}
		var teamRoles []string
		for _, g := range grants {
			if g.TeamID == team {
				teamRoles = append(teamRoles, g.Role)
			}
		}
		if len(teamRoles) == 0 {
			continue
		}
		reaches = true
		held := decide.HeldRoles(p, inst, grants)
		for _, role := range teamRoles {
			if !slices.Contains(held, role) {
				within = false
			}
		}
	}
	return within, reaches, nil
}
