package conformance

import (
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
)

// roleView is SessionService.OpenRoleView: a person holding several roles on
// an installation fixes a session to act as some of them, and every thing that
// session does, at the solution, through its hops, in the navigation, is what a
// person holding only those roles does. The record is the authority's and the
// view only narrows:
//   - a role the caller does not act as, on that installation, is refused naming
//     it; a viewing session opens only narrower ones;
//   - the capability a view session is issued holds exactly a reader's scopes, at
//     the solution and at the store through its binding, and an ask beyond them is
//     refused "widens" however the ask is made;
//   - the session it was opened from is untouched: it still holds every role;
//   - the navigation lists the view's roles, and the session says what it views.
func (sp *principalSuite) roleView(t *testing.T) {
	t.Helper()
	if !sp.c.hasElement("host.session.v1.SessionService", "OpenRoleView") {
		t.Fatal("the published contract lacks host.session.v1.SessionService.OpenRoleView: a person's session fixed to act as roles they hold")
	}
	f := sp.f
	A := f.A
	a := str(sp.ensure(t, f.Organization, A), "id")
	u := sp.principal(t, f.Organization, A)
	member := sp.person(t, f.Member)
	sp.grant(t, A, "author", member)
	sp.grant(t, A, "reader", member)
	defer sp.revoke(t, A, "author", member)
	defer sp.revoke(t, A, "reader", member)

	open := func(t *testing.T, from string, roles ...string) (string, error) {
		t.Helper()
		asked := []any{}
		for _, r := range roles {
			asked = append(asked, r)
		}
		out, err := sp.c.call(sp.as(t, from), "host.session.v1.SessionService", "OpenRoleView", map[string]any{"installation_id": a, "roles": asked})
		if err != nil {
			return "", err
		}
		name := "role-view:" + str(out, "session_id")
		sp.sessions[name] = out
		return name, nil
	}
	reads := func(t *testing.T, token string) {
		t.Helper()
		exactOwnedScope(t, msg(sp.must(t)(sp.root(t, token, A)), "context"), A.Solution+".note", []string{"read"}, u)
		exactOwnedScope(t, msg(sp.must(t)(sp.through(t, token, A, "store")), "context"), f.Kind, []string{"read"}, u)
	}

	sp.must(t)(sp.through(t, f.Member, A, "store")) // author, before any view
	reader, err := open(t, f.Member, "reader")
	if err != nil {
		t.Fatal(err)
	}
	reads(t, reader)
	for name, ask := range map[string]any{"a write at the store": sp.owned(f.Kind, []string{"write"}, u), "a create at the store": sp.owned(f.Kind, []string{"create"}, u)} {
		_, err := sp.through(t, reader, A, "store", ask)
		t.Run(name, func(t *testing.T) { refused(t, err, codes.PermissionDenied, "widens") })
	}
	wc := msg(sp.must(t)(sp.through(t, f.Member, A, "store")), "context")
	exactOwnedScope(t, wc, f.Kind, []string{"create", "read", "write"}, u) // the session it was opened from is untouched

	// Only a role the caller acts as; a viewing session opens only narrower.
	_, err = open(t, f.Member, "user")
	refused(t, err, codes.PermissionDenied, `"user"`)
	_, err = open(t, reader, "author")
	refused(t, err, codes.PermissionDenied, `"author"`)
	_, err = open(t, f.Member)
	if err == nil {
		t.Fatal("a role view naming no role was opened")
	}
	_, err = sp.c.call(sp.as(t, f.OtherMember), "host.session.v1.SessionService", "OpenRoleView", map[string]any{"installation_id": a, "roles": []any{"reader"}})
	if err == nil {
		t.Fatal("a member of another organization opened a role view on this organization's installation")
	}
	both, err := open(t, f.Member, "author", "reader")
	if err != nil {
		t.Fatal(err)
	}
	exactOwnedScope(t, msg(sp.must(t)(sp.through(t, both, A, "store")), "context"), f.Kind, []string{"create", "read", "write"}, u)
	narrower, err := open(t, both, "reader")
	if err != nil {
		t.Fatal(err)
	}
	reads(t, narrower)

	// The navigation and the session say what is viewed.
	held := sp.must(t)(sp.c.call(sp.as(t, reader), "host.installation.v1.InstallationService", "ListHeld", map[string]any{"organization_id": f.Organization}))
	for _, h := range listMsgs(held, "installations") {
		if str(msg(h, "installation"), "id") == a && !slices.Equal(listStrings(h, "roles"), []string{"reader"}) {
			t.Fatalf("the viewing session lists roles %v on A, want [reader]", listStrings(h, "roles"))
		}
	}
	current := sp.must(t)(sp.c.call(sp.as(t, reader), "host.session.v1.SessionService", "Current", nil))
	views := listMsgs(current, "role_view")
	if len(views) != 1 || str(views[0], "installation_id") != a || !slices.Equal(listStrings(views[0], "roles"), []string{"reader"}) {
		t.Fatalf("Current says the session views %v, want reader on %s", views, a)
	}
}
