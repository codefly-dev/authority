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
		within, reaches, err := teamIsWithin(tx, who, p, r.Organization, r.Team)
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

// teamIsWithin answers whether the person may act as this team — and whether
// the team is granted anything at all.
//
// THE RULE: you may act as a team whose roles you could GRANT.
//
// `decideRoleChange` is the authority's own answer to "may this caller grant
// this role on this installation", already a predicate in the core, reachable
// without performing a grant. Asking it is asking the same question the rest
// of the authority asks, so casting cannot drift from granting: when who may
// grant a role changes, who may act as it follows.
//
// The three familiar cases fall out of the one rule rather than being tiers
// in it: an ordinary member may grant nothing, so they cast only onto teams
// they belong to (the membership arm below); an organisation administrator
// may grant anything in their organisation, so any team of it; a platform
// administrator may grant anywhere, so any team anywhere.
//
// WHY NOT A SCOPE COMPARISON. It was built and measured first. On an
// installation where the team's roles gave 3 scopes, the person's
// organisation baseline computed 0 — because decide.OrgScopes deliberately
// skips any kind an owner-aware module does not share. An organisation role
// reaches none of a module's owned data; that is the owner-aware rule
// working, not a defect. So no baseline expressed in scopes can cover a
// team's roles at an owner-aware module, and forcing one would admit a cast
// that then holds nothing. Granting is the capability an administrator
// actually has, and owner-awareness does not erase it.
func teamIsWithin(tx Tx, caller Person, p domain.Person, org, team string) (within, reaches bool, err error) {
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

		// Already acts as them here: an ordinary member of the team.
		held := decide.HeldRoles(p, inst, grants)
		covered := true
		for _, role := range teamRoles {
			if !slices.Contains(held, role) {
				covered = false
			}
		}
		if covered {
			continue
		}

		// Otherwise: could they grant them here?
		for _, role := range teamRoles {
			c := caller
			if _, err := decideRoleChange(tx, &c, RoleRequest{
				Organization: org, InstallationID: inst.ID, Role: role, TeamID: team,
			}, false, false); err != nil {
				if errors.Is(err, domain.ErrNotFound) {
					return false, false, err
				}
				within = false
			}
		}
	}
	return within, reaches, nil
}
