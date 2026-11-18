package authority

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

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
// THE ONE RULE: a person may act as a team only if they are a MEMBER of it
// or could GRANT every role it holds (teamIsWithin). A member is the team
// already. Could-grant is what lets an administrator be a team they do not
// belong to: an organisation administrator may grant any role in their
// organisation, so any team of it; an administrator of an installation may
// grant its roles, so a team holding roles there alone. Holding the same role
// names by another route (a direct grant, another team) is neither: it would
// attribute work to a team the person is not in and could not have seated,
// so it is refused.
//
// A cast is therefore not simply "a subset of the person". An organisation
// administrator may grant a role at an owner-aware module whose data their own
// session reaches not at all, so a cast can hold what their own session
// computes as nothing there. That is deliberate: granting is the authority an
// administrator actually has, and it is what makes "be this team and see what
// it sees" answer honestly. It composes with a role view, which narrows it
// further; the order never widens.
//
// The rule is live. It is decided here, and again at every read of the cast
// session (personFor, castHolds): a cast whose person is no member of the
// team and could no longer grant what it holds, or whose team was granted
// what they could not grant, is refused from then on.
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
			return domain.Refuse("team %q holds roles you could not grant, so you may not act as it", r.Team)
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
// THE RULE: you may act as a team only if you are a member of it or could
// GRANT every role it holds.
//
// Membership is read from the person as the store holds them (p.Teams), never
// from the roles they hold: a person holding the team's role names by a direct
// grant is not in the team. `decideRoleChange` is the authority's own answer
// to "may this caller grant this role on this installation", already a
// predicate in the core, reachable without performing a grant. Asking it is
// asking the same question the rest of the authority asks, so casting cannot
// drift from granting: when who may grant a role changes, who may act as it
// follows.
//
// WHY NOT A SCOPE COMPARISON. An organisation role reaches no module: it
// decides administration only. So an administrator's own session holds
// nothing to compare a team's roles against, and granting is the capability
// an administrator actually has.
func teamIsWithin(tx Tx, caller Person, p domain.Person, org, team string) (within, reaches bool, err error) {
	installs, err := tx.Installations(org)
	if err != nil {
		return false, false, err
	}
	within = true
	// A member of the team is the team already.
	member := slices.Contains(p.Teams, team)
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

		if member {
			continue
		}

		// Not a member: could they grant every role it holds here?
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

// TeamHolding is one role a team holds on one active installation.
type TeamHolding struct {
	InstallationID, Target, Role string
}

// CastableTeam is a team a person may act as now, and what a cast onto it
// holds.
type CastableTeam struct {
	Team  string
	Holds []TeamHolding
}

// CastableTeams answers the teams of org that who may act as now, sorted by
// team, each with its holdings sorted by installation then role: the choice
// OpenTeamCast decides, listed by the same rule (teamIsWithin), so a team it
// would refuse is not listed — a team who is no member of and whose roles
// they could not grant, and a team granted nothing. A cast acts as one team and opens no other, so it
// answers that team alone. Nothing is opened: each OpenTeamCast decides again.
func (s *Service) CastableTeams(ctx context.Context, who Person, org string) ([]CastableTeam, error) {
	var out []CastableTeam
	err := s.store.Read(ctx, func(tx Tx) error {
		p, err := personAs(tx, who)
		if err != nil || p.Organization != org {
			return domain.Refuse("the teams to act as at %q are read by a member of it, signed in there", org)
		}
		holds, err := teamHoldings(tx, org)
		if err != nil {
			return err
		}
		for _, team := range slices.Sorted(maps.Keys(holds)) {
			if p.Cast != "" && team != p.Cast {
				continue
			}
			if p.Cast == "" {
				within, reaches, err := teamIsWithin(tx, who, p, org, team)
				if err != nil {
					return err
				}
				if !within || !reaches {
					continue
				}
			}
			out = append(out, CastableTeam{Team: team, Holds: holds[team]})
		}
		return nil
	})
	return out, err
}

// teamHoldings is every role granted to a team on an active installation of
// org, by team, each team's sorted by installation then role.
func teamHoldings(tx Tx, org string) (map[string][]TeamHolding, error) {
	installs, err := tx.Installations(org)
	if err != nil {
		return nil, err
	}
	out := map[string][]TeamHolding{}
	for _, inst := range installs {
		if inst.Status != domain.Active {
			continue
		}
		grants, err := tx.RoleGrants(inst.ID)
		if err != nil {
			return nil, err
		}
		for _, g := range grants {
			if g.TeamID != "" {
				out[g.TeamID] = append(out[g.TeamID], TeamHolding{InstallationID: inst.ID, Target: inst.Target, Role: g.Role})
			}
		}
	}
	for _, holds := range out {
		slices.SortFunc(holds, func(a, b TeamHolding) int {
			return cmp.Or(strings.Compare(a.InstallationID, b.InstallationID), strings.Compare(a.Role, b.Role))
		})
	}
	return out, nil
}
