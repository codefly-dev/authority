package authority_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// viewing opens a role view for person on installation target, as a new session
// "<person>-as-<roles>", and returns that session's person.
func (h *harness) viewing(person, target string, roles ...string) (authority.Person, error) {
	h.t.Helper()
	parent := h.person(person)
	session := person + "-as"
	for _, r := range roles {
		session += "-" + r
	}
	_, err := h.svc.OpenRoleView(h.ctx, parent, authority.RoleViewRequest{
		Organization: parent.Organization, InstallationID: h.inst(parent.Organization, target).ID, SessionID: session, Roles: roles})
	parent.SessionID = session
	return parent, err
}

func (h *harness) rootAs(who authority.Person, target string, scopes ...*basev0.WorkScopeV1) (authority.Issued, error) {
	return h.svc.IssueForPerson(h.ctx, who, authority.IssueRequest{Audience: target, Scopes: scopes})
}

func holds(i authority.Issued, kind, action string) bool {
	return scope.HoldsAction(effective(i), kind, action)
}

// The sharpest case of the whole feature: a person holding admin and user
// who acts as user is admitted, at the root and at every hop below it,
// exactly what a person holding only user is. Before the view was decided in
// the core this was admitted, because roles are unioned at every hop; it also
// proves the session a view is recorded under is recoverable from the
// capability at the first, second and third hop.
func TestARoleViewHoldsAtEveryHopWhatTheViewedRolesHold(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "admin", "maya")
	h.grant("a", "user", "maya")
	user, err := h.viewing("maya", "a", "user")
	if err != nil {
		t.Fatal(err)
	}

	full := h.must(h.through("maya", "a", "store"))
	if !holds(full, kind, "write") {
		t.Fatalf("setup: without a view maya holds admin, so writes at the store: %v", effective(full))
	}

	root := h.must(h.rootAs(user, "a"))
	if holds(root, "a.note", "write") {
		t.Fatalf("a user's root at the solution writes: %v", effective(root))
	}
	_, err = h.svc.IssueChild(h.ctx, root.Token, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store", Scopes: []*basev0.WorkScopeV1{sc(kind, "write")}})
	refused(t, err, "widens")

	hop := h.must(h.svc.IssueChild(h.ctx, root.Token, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store"}))
	for depth := 1; depth <= 3; depth++ {
		if holds(hop, kind, "write") || !holds(hop, kind, "read") {
			t.Fatalf("hop %d of a user's session holds %v, want read and no write", depth, effective(hop))
		}
		_, err = h.hop(hop, "self", sc(kind, "write"))
		if err == nil {
			t.Fatalf("hop %d: a user's session asked kind:write at the store and was admitted", depth)
		}
		hop = h.must(h.hop(hop, "self"))
	}
}

func shape(i authority.Issued) string {
	var rows []string
	for _, s := range effective(i) {
		rows = append(rows, fmt.Sprintf("%s/%s:%v@%v", s.GetResourceKind(), s.GetResourceOwnerId(), s.GetActions(), s.GetResourceIds()))
	}
	slices.Sort(rows)
	return strings.Join(rows, " ")
}

// The session a view is keyed by is the one every hop of the chain carries as the
// first hop's delegation, at any depth: a hop reads it back from its parent token,
// so a view cannot be shed by hopping.
func TestARoleViewSessionIsCarriedBelowTheFirstHop(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "admin", "maya")
	h.grant("a", "user", "maya")
	user, err := h.viewing("maya", "a", "user")
	if err != nil {
		t.Fatal(err)
	}
	hop := h.must(h.hopOf(h.must(h.rootAs(user, "a")), "a", "store"))
	for depth := 1; depth <= 3; depth++ {
		chain := hop.Context.GetActorChain()
		if len(chain) != depth || chain[0].GetDelegationId() != user.SessionID {
			t.Fatalf("depth %d: chain of %d hops, first delegation %q, want the view's session %q", depth, len(chain), chain[0].GetDelegationId(), user.SessionID)
		}
		hop = h.must(h.hop(hop, "self"))
	}
}

// A delegation made under a view is cut to the view when it is made, and what
// it holds when exercised is bounded by that, whatever its grantor holds
// beside it: a delegation names no session, so the grantor is read in full
// then.
func TestADelegationMadeUnderARoleViewHoldsWhatTheViewHolds(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "admin", "maya")
	h.grant("a", "user", "maya")
	user, err := h.viewing("maya", "a", "user")
	if err != nil {
		t.Fatal(err)
	}
	mine := func(action string) authority.Scopes {
		return authority.Scopes{owned(kind, h.principal(acme, "a"), []string{action})}
	}
	if _, err := h.svc.Delegate(h.ctx, h.person("maya"), "a", mine("write"), "a job", 0); err != nil {
		t.Fatalf("setup: maya delegates a write as admin: %v", err)
	}
	_, err = h.svc.Delegate(h.ctx, user, "a", mine("write"), "a job", 0)
	refused(t, err, "delegates what they do not hold")
	d, err := h.svc.Delegate(h.ctx, user, "a", mine("read"), "a job", 0)
	if err != nil {
		t.Fatal(err)
	}
	// The grantor, read in full, holds admin: the delegation is still what
	// the view held.
	got, err := h.svc.IssueForDelegation(h.ctx, d.ID, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store"})
	if err != nil {
		t.Fatal(err)
	}
	if holds(got, kind, "write") || !holds(got, kind, "read") {
		t.Fatalf("a delegation made as user holds %v", effective(got))
	}
}

// T1, T2, T5: a view names roles the caller holds on that installation now,
// through the view they call from, and nothing else.
func TestARoleViewOnlyNarrows(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "user", "maya")
	h.grant("b", "admin", "maya")

	_, err := h.viewing("maya", "a", "admin")
	refused(t, err, `role "admin" is not one you act as on a: you act as user`) // T1
	_, err = h.viewing("maya", "a", "user", "admin")
	refused(t, err, `"admin"`)
	_, err = h.viewing("maya", "a", "owner")
	refused(t, err, `"owner"`)
	_, err = h.svc.OpenRoleView(h.ctx, h.person("maya"), authority.RoleViewRequest{Organization: acme, InstallationID: h.inst(acme, "a").ID, SessionID: "nope"})
	refused(t, err, "names the roles to act as")

	// A role held on another installation is not one held on this (T2), and
	// another organization's installation is not found, however it is named.
	_, err = h.viewing("maya", "b", "user")
	refused(t, err, `role "user" is not one you act as on b: you act as admin`)
	_, err = h.svc.OpenRoleView(h.ctx, h.person("maya"), authority.RoleViewRequest{Organization: acme, InstallationID: h.inst(globex, "a").ID, SessionID: "x", Roles: []string{"user"}})
	code(t, err, domain.NotFound)
	_, err = h.svc.OpenRoleView(h.ctx, h.person("maya"), authority.RoleViewRequest{Organization: globex, InstallationID: h.inst(globex, "a").ID, SessionID: "y", Roles: []string{"user"}})
	refused(t, err, `member of "globex", signed in there`)

	// A viewing session never widens (T5): a role granted after it was
	// opened is not one it acts as, and it opens a subset of its own view.
	one, err := h.viewing("maya", "a", "user")
	if err != nil {
		t.Fatal(err)
	}
	h.grant("a", "admin", "maya")
	_, err = h.svc.OpenRoleView(h.ctx, one, authority.RoleViewRequest{Organization: acme, InstallationID: h.inst(acme, "a").ID, SessionID: "granted-since", Roles: []string{"admin"}})
	refused(t, err, `role "admin" is not one you act as on a: you act as user`)
	two, err := h.viewing("maya", "a", "admin", "user")
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.svc.OpenRoleView(h.ctx, two, authority.RoleViewRequest{Organization: acme, InstallationID: h.inst(acme, "a").ID, SessionID: "narrower", Roles: []string{"user"}})
	if err != nil {
		t.Fatal(err)
	}
	narrower := two
	narrower.SessionID = "narrower"
	_, err = h.svc.OpenRoleView(h.ctx, narrower, authority.RoleViewRequest{Organization: acme, InstallationID: h.inst(acme, "a").ID, SessionID: "wider", Roles: []string{"admin"}})
	refused(t, err, `role "admin" is not one you act as on a: you act as user`)
	_, err = h.svc.OpenRoleView(h.ctx, narrower, authority.RoleViewRequest{Organization: acme, InstallationID: h.inst(acme, "a").ID, SessionID: "wider", Roles: []string{"admin", "user"}})
	refused(t, err, `"admin"`)

	// The view of a session is written once, from a session, for a new one (T6).
	_, err = h.svc.OpenRoleView(h.ctx, h.person("maya"), authority.RoleViewRequest{Organization: acme, InstallationID: h.inst(acme, "a").ID, SessionID: "narrower", Roles: []string{"user"}})
	refused(t, err, "already has a role view, which is never changed")
	for _, bad := range []authority.Person{{ID: "maya", Organization: acme}, h.person("maya")} {
		r := authority.RoleViewRequest{Organization: acme, InstallationID: h.inst(acme, "a").ID, SessionID: "session-maya", Roles: []string{"user"}}
		if bad.SessionID == "" {
			r.SessionID = "z"
		}
		_, err = h.svc.OpenRoleView(h.ctx, bad, r)
		code(t, err, domain.Invalid)
	}
}

// T3, T4: a view is re-intersected with the live grants at every issue, never
// copied at selection.
func TestARoleViewDiesWithItsGrant(t *testing.T) {
	h := newHarness(t)
	h.grantTeam("b", "user", "team")
	h.grant("b", "admin", "tam")
	tam, err := h.viewing("tam", "b", "user")
	if err != nil {
		t.Fatal(err)
	}
	issued := h.must(h.rootAs(tam, "b"))
	if holds(issued, "b.note", "write") {
		t.Fatal("tam as user writes")
	}

	// The team grant leaves with the team: the view holds nothing, rather
	// than keeping the role it was chosen from.
	h.store.PutPerson(domain.Person{ID: "tam", Organization: acme})
	_, err = h.rootAs(tam, "b")
	refused(t, err, "holds no role on b")
	refused(t, err, "this session views as user on b")

	// A role revoked while viewing stops the session at the next issue.
	h.store.PutPerson(domain.Person{ID: "tam", Organization: acme, Teams: []string{"team"}})
	h.must(h.rootAs(tam, "b"))
	h.revoke("b", "user", "", "team")
	_, err = h.rootAs(tam, "b")
	refused(t, err, "holds no role on b")
	if err := h.check(issued); err == nil {
		t.Fatal("a capability minted under a revoked role still checks")
	}
}

// T8, T9, T10, T11, T14: the view is what a person holding only those roles
// holds, at the root and at a hop; nothing else of theirs changes.
func TestARoleViewIsWhatTheViewedRolesHold(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "admin", "maya")
	h.grant("a", "user", "maya")
	h.grant("a", "user", "tal")
	h.grant("a", "admin", "ines")
	h.grant("a", "user", "ines")
	h.grant("b", "admin", "maya")

	user, err := h.viewing("maya", "a", "user")
	if err != nil {
		t.Fatal(err)
	}
	// Equivalence with a person who really holds only user (T9): the root
	// and the hop through the store.
	real := h.must(h.root("tal", "a"))
	as := h.must(h.rootAs(user, "a"))
	if shape(as) != shape(real) {
		t.Fatalf("view=user holds %s, a user holds %s", shape(as), shape(real))
	}
	realHop := h.must(h.hopOf(real, "a", "store"))
	asHop := h.must(h.hopOf(as, "a", "store"))
	if shape(asHop) != shape(realHop) {
		t.Fatalf("view=user hop holds %s, a user's %s", shape(asHop), shape(realHop))
	}

	// Several roles are the union of only those (T10).
	both, err := h.viewing("ines", "a", "admin", "user")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := shape(h.must(h.rootAs(both, "a"))), shape(h.must(h.root("ines", "a"))); got != want {
		t.Fatalf("view={admin,user} holds %s, holding both holds %s", got, want)
	}
	admin := h.must(h.root("maya", "a"))
	if shape(admin) == shape(as) {
		t.Fatal("setup: admin and user hold the same")
	}

	// Another installation of the same person is not narrowed (T11), nor is
	// another session of theirs (T14): both still hold admin.
	if !holds(h.must(h.root("maya", "b")), "b.note", "write") || !holds(h.must(h.rootAs(user, "b")), "b.note", "write") {
		t.Fatal("a view on a narrowed b")
	}
	if shape(h.must(h.root("maya", "a"))) != shape(admin) || !holds(admin, "a.note", "write") {
		t.Fatal("a view narrowed another session of the same person")
	}
}

// T15: the navigation under a view lists what the view issues; another session
// of the person still lists all of theirs.
func TestTheMenuUnderARoleViewIsWhatItIssues(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "admin", "maya")
	h.grant("a", "user", "maya")
	h.grant("b", "user", "maya")
	user, err := h.viewing("maya", "a", "user")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		who  authority.Person
		want string
	}{{user, "[a:[user] b:[user]]"}, {h.person("maya"), "[a:[admin user] b:[user]]"}} {
		who, want := c.who, c.want
		got := h.heldBy(who, acme)
		slices.Sort(got)
		if fmt.Sprint(got) != want {
			t.Fatalf("%s (%s) holds %v, want %s", who.ID, who.SessionID, got, want)
		}
	}
	// Role administration reads the same: a user-view of an administrator
	// administers nothing it does not view.
	h.grant("a", "admin", "remi")
	h.grant("a", "user", "remi")
	req := authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, "a").ID, Role: "user", PersonID: "ines"}
	if _, err := h.svc.GrantRole(h.ctx, h.person("remi"), req); err != nil {
		t.Fatalf("an admin grants: %v", err)
	}
	lesser, err := h.viewing("remi", "a", "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.GrantRole(h.ctx, lesser, req); err == nil {
		t.Fatal("an admin viewing as user granted a role")
	}
}

// T16: a refusal under a view says so, and what to do.
func TestARoleViewRefusalNamesTheView(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "admin", "maya")
	h.grant("a", "user", "maya")
	user, _ := h.viewing("maya", "a", "user")
	root := h.must(h.rootAs(user, "a"))
	_, err := h.svc.IssueChild(h.ctx, root.Token, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store", Scopes: []*basev0.WorkScopeV1{sc(kind, "write")}})
	refused(t, err, "this session views as user on a")
	_, err = h.rootAs(user, "a", sc("a.note", "write"))
	refused(t, err, "this session views as user on a")
	code(t, err, domain.Denied)
}

// T13: nothing a caller sends picks the view; the record is the session's.
// A view that belongs to another person is refused, never ignored.
func TestARoleViewBelongsToItsSession(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "admin", "maya")
	h.grant("a", "user", "maya")
	h.grant("a", "admin", "remi")
	user, _ := h.viewing("maya", "a", "user")
	stolen := authority.Person{ID: "remi", Organization: acme, SessionID: user.SessionID}
	_, err := h.rootAs(stolen, "a")
	refused(t, err, "holds another person's role view")
}

// T17: every person who acts is read through personAs or personOfClaims, which
// apply the session's role view. A direct tx.Member in the package, outside
// view.go, would act as every role the person holds.
func TestEveryActingPersonIsReadThroughTheirView(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			if name == "view.go" {
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Member" {
						t.Errorf("%s: a direct Member read; read an acting person with personAs or personOfClaims, a subject with memberRecord", fset.Position(call.Pos()))
					}
				}
				return true
			})
		}
	}
}

func (h *harness) hopOf(parent authority.Issued, module, binding string) (authority.Issued, error) {
	return h.svc.IssueChild(h.ctx, parent.Token, authority.Workload{Module: module}, authority.IssueRequest{Binding: binding})
}

// A role view narrows EVERYTHING above the roles it names: an organization
// administrator who views as a user holds no administrator reach, because a
// real user has none. Before the view cleared the person's organization roles
// the administrator kept every administration power inside it (installation
// administration, granting a role to themselves), so a pass through the view
// proved nothing about what a user sees.
func TestARoleViewHoldsNoOrganizationRole(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "user", "alex") // alex is an organization administrator who also holds user

	// Outside the view the administrator administers.
	if _, err := h.svc.Installations(h.ctx, h.person("alex"), acme); err != nil {
		t.Fatalf("setup: the administrator cannot list installations: %v", err)
	}

	as, err := h.viewing("alex", "a", "user")
	if err != nil {
		t.Fatal(err)
	}
	// Inside it they are a user: no administration of the organization...
	if _, err := h.svc.Installations(h.ctx, as, acme); err == nil {
		t.Fatal("an administrator viewing as a user still administers the organization's installations")
	}
	// ...and no granting themselves a role they did not choose to act as.
	if _, err := h.svc.GrantRole(h.ctx, as, authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, "a").ID, Role: "admin", PersonID: "alex"}); err == nil {
		t.Fatal("an administrator viewing as a user granted themselves a role")
	}
	// The session the view was opened from still administers (the view is not a demotion).
	if _, err := h.svc.Installations(h.ctx, h.person("alex"), acme); err != nil {
		t.Fatalf("the session the view was opened from lost its administration: %v", err)
	}
}
