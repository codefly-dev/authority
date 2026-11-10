package authority

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// RoleViewRequest asks to fix a new session to act as some of the roles the
// caller holds on one installation. SessionID is the session the host has
// minted for the view; the host never takes it from a client.
type RoleViewRequest struct {
	Organization, InstallationID, SessionID string
	Roles                                   []string
}

// OpenRoleView records a role view for a new session: who, signed in at
// r.Organization, acts there as exactly r.Roles on r.InstallationID, and as
// every session they are on elsewhere. It only narrows: each role must be one
// the caller holds on the installation now, through the view of the session
// they call from, so a viewing session never widens and one installation's view
// never reaches another's. The record is the authority's; the host creates the
// session it names after this succeeds, and presents it as the person's own.
// A session's view is written once. Only an interactive session of a person
// calls this: a Work Context, a page and an impersonated session hold no
// Person to call with.
func (s *Service) OpenRoleView(ctx context.Context, who Person, r RoleViewRequest) (domain.RoleView, error) {
	var view domain.RoleView
	err := s.store.Write(ctx, func(tx Tx) error {
		if who.SessionID == "" || r.SessionID == "" || r.SessionID == who.SessionID {
			return domain.Malformed("a role view is opened from a session, for a new one")
		}
		if len(r.Roles) == 0 {
			return domain.Malformed("a role view names the roles to act as")
		}
		p, err := personAs(tx, who)
		if err != nil || p.Organization != r.Organization {
			return domain.Refuse("a role view is opened by a member of %q, signed in there", r.Organization)
		}
		inst, err := tx.Installation(r.InstallationID)
		if errors.Is(err, domain.ErrNotFound) || (err == nil && (inst.Organization != r.Organization || inst.Status != domain.Active)) {
			return domain.Missing("installation %q at organization %q", r.InstallationID, r.Organization)
		}
		if err != nil {
			return err
		}
		if _, err := tx.RoleView(r.SessionID); err == nil {
			return domain.Refuse("session %s already has a role view, which is never changed", r.SessionID)
		} else if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		grants, err := tx.RoleGrants(inst.ID)
		if err != nil {
			return err
		}
		held := decide.HeldRoles(p, inst, grants)
		chosen := slices.Clone(r.Roles)
		slices.Sort(chosen)
		chosen = slices.Compact(chosen)
		for _, role := range chosen {
			if !slices.Contains(held, role) {
				return domain.Refuse("role %q is not one you act as on %s: %s", role, inst.Target, heldSentence(held))
			}
		}
		view = domain.RoleView{SessionID: r.SessionID, Parent: who.SessionID, Person: p.ID, Organization: p.Organization, Roles: map[string][]string{}}
		for id, roles := range p.View {
			view.Roles[id] = slices.Clone(roles)
		}
		view.Roles[inst.ID] = chosen
		if err := tx.PutRoleView(view); err != nil {
			return err
		}
		return s.journal(ctx, tx, domain.Event{Kind: domain.RoleViewOpened, Organization: p.Organization, Actor: p.ID, Subject: inst.ID,
			Detail: map[string]string{"roles": strings.Join(chosen, ","), "session": r.SessionID}})
	})
	return view, err
}

func heldSentence(held []string) string {
	if len(held) == 0 {
		return "you hold none there"
	}
	return "you act as " + strings.Join(held, ", ")
}

// RoleViewOf is the role view session was opened with, or domain.ErrNotFound
// for a session that has none. A host reads it to say what a session views and
// to refuse, by name, a mint of its own that the view does not govern.
func (s *Service) RoleViewOf(ctx context.Context, session string) (domain.RoleView, error) {
	var v domain.RoleView
	err := s.store.Read(ctx, func(tx Tx) (err error) { v, err = tx.RoleView(session); return err })
	return v, err
}

// personAs is the person a session acts as, read now: a member of the
// organization their session was opened at, narrowed to the role view the
// session was fixed to, if any. It and personFor are the only readers of a
// person who acts (TestEveryActingPersonIsReadThroughTheirView): a new call
// that read tx.Member directly would act as every role they hold.
func personAs(tx Tx, caller Person) (domain.Person, error) {
	return personFor(tx, caller.Organization, caller.ID, caller.SessionID)
}

// personFor is id as a member of org acting from session, under that
// session's role view. A view that belongs to another person is refused, not
// ignored: ignoring it would widen.
func personFor(tx Tx, org, id, session string) (domain.Person, error) {
	p, err := tx.Member(org, id)
	if err != nil || session == "" {
		// No session, no view: a capability whose root names none (a delegation's)
		// or a host that authenticated no session. Nothing here can be narrowed.
		return p, err
	}
	v, err := tx.RoleView(session)
	if errors.Is(err, domain.ErrNotFound) {
		return p, nil
	}
	if err != nil {
		return domain.Person{}, err
	}
	if v.Person != p.ID || v.Organization != p.Organization {
		return domain.Person{}, domain.Refuse("session %s holds another person's role view", session)
	}
	p.View = v.Roles
	// A view narrows everything above the roles it names. The organization roles
	// are the person's own, not the viewed roles': an administrator who views as a
	// viewer must hold what a viewer holds, so the administrator's reach (every
	// kind and action of the organization, installation administration, granting
	// a role) is cleared here, at the one reader of an acting person.
	p.Roles = nil
	return p, nil
}

// personOfClaims is the human a verified capability's owner is, under the
// role view of the session the capability descends from.
func personOfClaims(tx Tx, wc *basev0.WorkContextV1) (domain.Person, error) {
	return personFor(tx, wc.GetTenantId(), wc.GetOwnerPrincipalId(), rootSession(wc))
}

// rootSession is the session a person's capability descends from: a root
// carries it as its own, and every hop keeps it as the delegation of the first
// hop, which no later hop rewrites (derive). A capability issued for a
// delegation instead names the delegation there, not a session: its grantor is
// read under no view, and what it holds is bounded by the scopes the
// delegation was made with, which Delegate cut to the view of the session that
// made it (TestADelegationMadeUnderARoleViewHoldsWhatTheViewHolds).
func rootSession(wc *basev0.WorkContextV1) string {
	if chain := wc.GetActorChain(); len(chain) > 0 {
		return chain[0].GetDelegationId()
	}
	return wc.GetSessionId()
}

// memberRecord is a person as the store holds them, under no role view: for a
// person who is the subject of a step, never the one acting (a grantee, a
// transfer's source, an installation's recorded owner, a delegation's grantor,
// whose delegation already carries the scopes it was made with), and for
// existence checks. Whoever acts is read by personAs or personOfClaims.
func memberRecord(tx Tx, org, id string) (domain.Person, error) { return tx.Member(org, id) }

// viewNote says what a refusal under p's role view is the view's doing:
// "viewing as viewer on wiki"; empty without a view.
func viewNote(tx Tx, p domain.Person) string {
	var parts []string
	for _, id := range slices.Sorted(maps.Keys(p.View)) {
		target := id
		if inst, err := tx.Installation(id); err == nil {
			target = inst.Target
		}
		parts = append(parts, strings.Join(p.View[id], ", ")+" on "+target)
	}
	return strings.Join(parts, "; ")
}

// underView names the role view in a refusal it caused or shaped: a person
// who sees a viewer's refusal learns it is the viewer they chose to be, and
// how to leave (the session the view was opened from). Any other error, and
// every refusal without a view, passes unchanged.
func underView(note string, err error) error {
	var r *domain.Refusal
	if note == "" || !errors.As(err, &r) {
		return err
	}
	return &domain.Refusal{Code: r.Code, Reason: fmt.Sprintf("%s (this session views as %s; sign in without the role view to act as all your roles)", r.Reason, note)}
}
