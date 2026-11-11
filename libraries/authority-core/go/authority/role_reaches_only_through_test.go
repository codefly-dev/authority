package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// pageWithSteward is the module page reaching the store, with a role that
// names nothing the page itself serves: steward writes at the store, through
// the page's binding, and holds none of pages.note. It is the shape of a role
// whose whole reach is another module's kind (a type editor's "define" at a
// record store, on a page whose own kind is its entries).
func pageWithSteward(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	m := pageReachingStore(1, "read")
	m.Roles["steward"] = []*basev0.WorkScopeV1{sc(kind, "write")}
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	return h
}

// A person in a team, the team holding a module page's role: the page's call
// is issued a Work Context carrying it. The role here names only what the
// page reaches through its binding, and it was refused whole as "tam holds
// no role on pages", for a team's grant and a person's alike: what a role
// names of the page's own kinds was read as whether the role is held at all.
func TestATeamsRoleReachingOnlyThroughABindingIsIssued(t *testing.T) {
	for name, grant := range map[string]func(*harness){
		"granted to the person's team": func(h *harness) { h.grantTeam("pages", "steward", "team") },
		"granted to the person":        func(h *harness) { h.grant("pages", "steward", "tam") },
	} {
		t.Run(name, func(t *testing.T) {
			h := pageWithSteward(t)
			grant(h)
			// Write alone, on the page's installation's data: the role cut to
			// the binding, which carries read and write.
			got := h.must(h.page("tam", "pages", "store"))
			exactly(t, got, kind, h.principal(acme, "pages"), []string{"write"})
			// The store checks it as it checks any page's call.
			if _, _, err := h.svc.Check(h.ctx, got.Token, "store"); err != nil {
				t.Fatalf("the store refuses the capability the page's call was issued: %v", err)
			}
		})
	}
}

// The other team member holds it too, and someone outside the team does not:
// membership decides, read when the call is issued.
func TestATeamsRoleReachingOnlyThroughABindingFollowsMembership(t *testing.T) {
	h := pageWithSteward(t)
	h.grantTeam("pages", "steward", "team")
	exactly(t, h.must(h.page("tal", "pages", "store")), kind, h.principal(acme, "pages"), []string{"write"})
	_, err := h.page("maya", "pages", "store")
	refused(t, err, "maya holds no role on pages")
	h.revoke("pages", "steward", "", "team")
	_, err = h.page("tam", "pages", "store")
	refused(t, err, "tam holds no role on pages")
}

// Such a role still holds nothing at the page itself, and the refusal says
// so: it names the role held and why it carries nothing there, never "holds
// no role", which sends an administrator to grant what is already granted.
// No capability with no scope is handed to anyone: the root that carries
// nothing is the page hop's own step.
func TestARoleReachingOnlyThroughABindingHoldsNothingAtThePageItself(t *testing.T) {
	h := pageWithSteward(t)
	h.grantTeam("pages", "steward", "team")
	_, err := h.root("tam", "pages")
	refused(t, err, "tam holds steward on pages, which names nothing pages itself serves")
	_, err = h.root("tam", "pages", sc("pages.note", "read"))
	refused(t, err, "tam holds steward on pages, which names nothing pages itself serves")
	// The page calling its own module is the person's own ask there.
	_, err = h.page("tam", "pages", "pages")
	refused(t, err, "tam holds steward on pages, which names nothing pages itself serves")
	// Beyond the role, through the binding, is refused as any ask beyond is.
	if _, err = h.page("tam", "pages", "store", sc(kind, "read")); err == nil {
		t.Fatal("a steward was issued read at the store, which the role does not name")
	}
	// Holding a role that does name the page's kind beside it, the person is
	// issued that role's part at the page, as ever.
	h.grantTeam("pages", "viewer", "team")
	exactly(t, h.must(h.svc.IssueForPerson(h.ctx, h.person("tam"), authority.IssueRequest{Audience: "pages"})), "pages.note", "", []string{"read"})
}
