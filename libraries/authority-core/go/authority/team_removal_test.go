package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// removal is tam, a member of the team holding user on a and holding admin on
// b by a grant of their own, with everything they were issued before leaving
// the team: a call through a, the store's own hop on it (sealed to the
// store's installation), a call through b, and a session cast onto the team
// with a call of its own.
type removal struct {
	h                                *harness
	throughTeam, deeper, own, asCast authority.Issued
	cast                             authority.Person
}

func newRemoval(t *testing.T) removal {
	t.Helper()
	h := newHarness(t)
	h.grantTeam("a", "user", "team")
	h.grant("b", "admin", "tam")
	cast, err := h.casting("tam", "team")
	if err != nil {
		t.Fatal(err)
	}
	asCast, err := h.svc.IssueForPerson(h.ctx, cast, authority.IssueRequest{Audience: "a"})
	if err != nil {
		t.Fatal(err)
	}
	return removal{h: h, throughTeam: h.must(h.through("tam", "a", "store")), deeper: h.deeper("tam"),
		own: h.must(h.through("tam", "b", "store")), asCast: asCast, cast: cast}
}

// leave is the host's directory dropping tam from the team; told is whether
// it then tells the authority the person changed.
func (r removal) leave(told bool) {
	r.h.t.Helper()
	r.h.store.PutPerson(domain.Person{ID: "tam", Organization: acme})
	if !told {
		return
	}
	if err := r.h.svc.PersonChanged(r.h.ctx, "tam"); err != nil {
		r.h.t.Fatal(err)
	}
}

// A member removed from a team loses, by the next check, what only the
// team's role gave them, wherever the capability is sealed; acting as the
// team is refused; what a grant of their own gives is issued again.
func TestAMemberRemovedFromATeamLosesWhatOnlyTheTeamGave(t *testing.T) {
	t.Parallel()
	r := newRemoval(t)
	h := r.h
	r.leave(true)
	for name, c := range map[string]authority.Issued{
		"the call through the team's role":                r.throughTeam,
		"the store's hop on it, sealed elsewhere":         r.deeper,
		"the call made as the team":                       r.asCast,
		"the call through their own grant, issued before": r.own,
	} {
		if err := h.check(c); err == nil {
			t.Errorf("%s is still admitted", name)
		}
		if _, _, refusal, err := h.svc.CheckMethod(h.ctx, c.Token, c.Context.GetAudience(), "", false); err == nil && refusal == nil {
			t.Errorf("%s is still admitted by the hop's check", name)
		}
	}
	if _, err := h.svc.ListResources(h.ctx, r.throughTeam.Token, "store", kind, "read"); err == nil {
		t.Error("the removed member is still answered the team's resources")
	}
	_, err := h.root("tam", "a")
	refused(t, err, "holds no role")
	_, err = h.through("tam", "a", "store")
	refused(t, err, "holds no role")
	// What only the team gave is gone; a grant of their own is issued again.
	exactly(t, h.must(h.through("tam", "b", "store")), kind, h.principal(acme, "b"), []string{"create", "read", "write"})

	_, err = h.svc.OpenTeamCast(h.ctx, h.person("tam"), authority.TeamCastRequest{Organization: acme, Team: "team", SessionID: "a-second-cast"})
	refused(t, err, "you could not grant")
	_, err = h.svc.IssueForPerson(h.ctx, r.cast, authority.IssueRequest{Audience: "a"})
	refused(t, err, "the cast has ended")
	teams, err := h.svc.CastableTeams(h.ctx, h.person("tam"), acme)
	if err != nil || len(teams) != 0 {
		t.Fatalf("the removed member is still offered %v to act as (%v)", teams, err)
	}
	// Another member of the team is untouched.
	if _, err := h.through("tal", "a", "store"); err != nil {
		t.Fatalf("removing tam ended tal's access: %v", err)
	}
}

// The authority reads a person's teams from the host's directory at every
// decision, so a removal the host never announced (PersonChanged) still
// narrows everything decided from then on: issuance, a hop, the cast, the
// resources a capability covers. What it cannot end is a capability already
// issued, which carries its scopes and whose epoch nothing moved: Check
// admits it until it expires. PersonChanged is the host's to call, and the
// conformance suite holds every host to the result.
func TestARemovalTheHostNeverAnnouncedNarrowsEveryDecisionButNoIssuedCapability(t *testing.T) {
	t.Parallel()
	r := newRemoval(t)
	h := r.h
	r.leave(false)
	_, err := h.root("tam", "a")
	refused(t, err, "holds no role")
	_, err = h.hop(r.throughTeam, "self")
	refused(t, err, "holds nothing")
	_, err = h.svc.IssueForPerson(h.ctx, r.cast, authority.IssueRequest{Audience: "a"})
	refused(t, err, "the cast has ended")
	if err := h.check(r.asCast); err == nil {
		t.Error("the call made as the team outlived the membership the cast stood on")
	}
	grants, err := h.svc.ListResources(h.ctx, r.throughTeam.Token, "store", kind, "read")
	if err != nil || len(grants) != 0 {
		t.Errorf("an unannounced removal is still answered resources: %v (%v)", grants, err)
	}
	for name, c := range map[string]authority.Issued{"the call through the team's role": r.throughTeam, "the store's hop on it": r.deeper} {
		if err := h.check(c); err != nil {
			t.Errorf("%s was refused with no PersonChanged: the core now ends it itself, and this test and the README say otherwise: %v", name, err)
		}
	}
	// Told late, it ends.
	if err := h.svc.PersonChanged(h.ctx, "tam"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []authority.Issued{r.throughTeam, r.deeper} {
		if err := h.check(c); err == nil {
			t.Error("a capability survived PersonChanged")
		}
	}
}
