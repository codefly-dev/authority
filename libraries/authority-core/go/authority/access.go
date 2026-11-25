package authority

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"
)

// AccessParty is one principal an access decision must hold the resource
// for: the capability's owner, or one actor of its chain. Everything is read
// live from the store, never from the capability, but the scopes.
type AccessParty struct {
	// Principal is the party as the capability names it.
	Principal string
	// Subjects are whose access grants count for the party. A person counts
	// themselves and the teams they belong to now that the host still holds;
	// a session cast onto a team counts that team and nothing of the
	// person's own. An installation's principal, and a module acting through
	// its installation at the organization, count that installation while it
	// is active. A principal the host no longer knows counts nothing.
	Subjects []domain.AccessSubject
	// Owns is the principal whose data is the party's own: an installation's
	// principal, for its agent and for a capability acting through it. Empty
	// for a person, who owns nothing by being its author.
	Owns string
	// Scopes are what the party contributes to the capability: the
	// capability's effective scopes for its owner, the hop's granted scopes
	// for an actor.
	Scopes Scopes
}

// AccessCaller is a capability verified for the module asking an access
// question (access.Service), and who the decision is made for.
type AccessCaller struct {
	// Server is the module asking: the one module serving every kind named.
	Server domain.Module
	// Organization is the capability's tenant.
	Organization string
	// Claims are the verified capability's.
	Claims *basev1.WorkContextV1
	// Effective are its effective scopes, after every hop.
	Effective Scopes
	// Owner is the capability's owner, Actors its chain in order.
	Owner  AccessParty
	Actors []AccessParty
	// ExpiresAt is when the capability ends.
	ExpiresAt time.Time
}

// AccessCaller verifies token for the module actor's workload proves, which
// must be the one module serving every kind of kinds (the rule AttachResource
// holds its caller to), and reads who an access decision is made for. The
// capability is checked as every callee checks one (Check): current, sealed,
// its session live and its cast still holding. A capability addressed to
// another module is refused by its audience.
func (s *Service) AccessCaller(ctx context.Context, token string, actor Workload, kinds []string) (AccessCaller, error) {
	if len(kinds) == 0 {
		return AccessCaller{}, domain.Malformed("an access question names a resource kind")
	}
	var server domain.Module
	err := s.store.Read(ctx, func(tx Tx) (err error) {
		server, err = accessServer(tx, actor, kinds)
		return err
	})
	if err != nil {
		return AccessCaller{}, err
	}
	verified, _, err := s.Check(ctx, token, server.Principal)
	if err != nil {
		return AccessCaller{}, err
	}
	wc := verified.Context()
	if actor.Organization != "" && actor.Organization != wc.GetTenantId() {
		return AccessCaller{}, domain.Refuse("workload %s is bound to organization %s, not %s", actor.Module, actor.Organization, wc.GetTenantId())
	}
	caller := AccessCaller{Server: server, Organization: wc.GetTenantId(), Claims: wc, Effective: verified.EffectiveScopes(),
		ExpiresAt: time.Unix(wc.GetExpiresAtUnix(), 0)}
	err = s.store.Read(ctx, func(tx Tx) error {
		// The serving module is read again in the snapshot the parties are:
		// a redelivery between the two reads is refused, not decided across.
		current, err := accessServer(tx, actor, kinds)
		if err != nil {
			return err
		}
		if current.Principal != server.Principal || current.Generation != server.Generation {
			return domain.Refuse("serving module changed during the access question")
		}
		caller.Actors = nil
		if caller.Owner, err = accessOwner(tx, wc); err != nil {
			return err
		}
		caller.Owner.Scopes = caller.Effective
		for _, hop := range wc.GetActorChain() {
			party, err := accessPrincipal(tx, wc.GetTenantId(), hop.GetPrincipalId())
			if err != nil {
				return err
			}
			party.Scopes = hop.GetGrantedScopes()
			caller.Actors = append(caller.Actors, party)
		}
		return nil
	})
	if err != nil {
		return AccessCaller{}, err
	}
	return caller, nil
}

// AccessSubjectExists is whether subject is one an access grant may be made
// to at org now: a member, a team the host holds, or an active installation.
// A subject of another organization answers as an absent one does.
func (s *Service) AccessSubjectExists(ctx context.Context, org string, subject domain.AccessSubject) (bool, error) {
	exists := false
	err := s.store.Read(ctx, func(tx Tx) error {
		switch subject.Kind {
		case domain.AccessPerson:
			_, err := memberRecord(tx, org, subject.ID)
			if errors.Is(err, domain.ErrNotFound) {
				return nil
			}
			exists = err == nil
			return err
		case domain.AccessTeam:
			var err error
			exists, err = tx.TeamExists(org, subject.ID)
			return err
		case domain.AccessInstallation:
			inst, err := tx.Installation(subject.ID)
			if errors.Is(err, domain.ErrNotFound) {
				return nil
			}
			exists = err == nil && inst.Organization == org && inst.Status == domain.Active
			return err
		}
		return nil
	})
	return exists, err
}

// AccessSubjectsOf are whose access grants count for principal at org now: a
// member counts themselves and the teams they belong to that the host still
// holds; an installation's principal, or a module acting through its
// installation there, counts that installation while it is active. A
// principal the host no longer knows counts nothing. It is how a share made
// on by a grantee is held to the grants its grantor still holds
// (domain.AccessGrant.Sources).
func (s *Service) AccessSubjectsOf(ctx context.Context, org, principal string) ([]domain.AccessSubject, error) {
	var subjects []domain.AccessSubject
	err := s.store.Read(ctx, func(tx Tx) error {
		subjects = nil
		p, err := memberRecord(tx, org, principal)
		if errors.Is(err, domain.ErrNotFound) {
			party, err := accessPrincipal(tx, org, principal)
			subjects = party.Subjects
			return err
		}
		if err != nil {
			return err
		}
		subjects = append(subjects, domain.AccessSubject{Kind: domain.AccessPerson, ID: p.ID})
		for _, team := range sortedTeams(p.Teams) {
			held, err := tx.TeamExists(org, team)
			if err != nil {
				return err
			}
			if held {
				subjects = append(subjects, domain.AccessSubject{Kind: domain.AccessTeam, ID: team})
			}
		}
		return nil
	})
	return subjects, err
}

// accessServer is the module caller proves, which must be the one module
// serving every kind of kinds.
func accessServer(tx Tx, caller Workload, kinds []string) (domain.Module, error) {
	m, err := tx.ModuleNamed(caller.Module)
	if err != nil {
		return m, notFound(err)
	}
	for _, kind := range kinds {
		servers, err := servingModules(tx, kind)
		if err != nil {
			return m, err
		}
		slices.Sort(servers)
		if !slices.Contains(servers, m.Name) {
			return m, domain.Refuse("%s does not serve %s, so it asks nothing about its resources", m.Name, kind)
		}
		if len(servers) != 1 {
			return m, domain.Refuse("%s is served by %s; an access question needs the kind's one serving module", kind, strings.Join(servers, ", "))
		}
	}
	return m, nil
}

// accessOwner is the capability's owner as a party: a person under the role
// view or cast of the session the capability descends from, or a principal.
func accessOwner(tx Tx, wc *basev1.WorkContextV1) (AccessParty, error) {
	if wc.GetOwnerPrincipalKind() != "human" {
		return accessPrincipal(tx, wc.GetTenantId(), wc.GetOwnerPrincipalId())
	}
	p, err := personOfClaims(tx, wc)
	if err != nil {
		return AccessParty{}, ownerGone(err, wc.GetOwnerPrincipalId())
	}
	party := AccessParty{Principal: p.ID}
	teams := p.Teams
	if p.Cast != "" {
		// A cast holds what is granted to that team and nothing of the
		// person's own: no direct grant, no other team.
		teams = []string{p.Cast}
	} else {
		party.Subjects = append(party.Subjects, domain.AccessSubject{Kind: domain.AccessPerson, ID: p.ID})
	}
	for _, team := range sortedTeams(teams) {
		held, err := tx.TeamExists(p.Organization, team)
		if err != nil {
			return AccessParty{}, err
		}
		if held {
			party.Subjects = append(party.Subjects, domain.AccessSubject{Kind: domain.AccessTeam, ID: team})
		}
	}
	return party, nil
}

// accessPrincipal is a principal that is no person as a party: an
// installation's principal counts that installation, a module's the
// installation it acts through at org. Either counts only while the
// installation is active there, and owns what its principal owns.
func accessPrincipal(tx Tx, org, principal string) (AccessParty, error) {
	party := AccessParty{Principal: principal}
	inst, err := tx.InstallationByPrincipal(principal)
	if errors.Is(err, domain.ErrNotFound) {
		var m domain.Module
		if m, err = tx.Module(principal); err == nil {
			inst, err = installationOf(tx, org, m.Name)
		}
	}
	if errors.Is(err, domain.ErrNotFound) {
		return party, nil
	}
	if err != nil {
		return party, err
	}
	if inst.Organization != org || inst.Status != domain.Active {
		return party, nil
	}
	party.Subjects = []domain.AccessSubject{{Kind: domain.AccessInstallation, ID: inst.ID}}
	party.Owns = inst.PrincipalID
	return party, nil
}
