package state_test

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
)

// These identities belong to the test-only authority matrix. The shipped
// sign-in choices are covered by TestTheShippedFixtureIsTheCastAndNobodyElse.
func TestAuthorityMatrixFixtureIdentities(t *testing.T) {
	k := testkit.New(t)
	people := k.State.FixturePeople()
	want := []state.Person{
		{ID: "sarah", Name: "Sarah Chen", Email: "admin@acme.com", FixtureToken: "dev-admin", Organization: "acme", Roles: []string{"admin"}, Teams: []string{}},
		{ID: "alice", Name: "Alice Johnson", Email: "alice@acme.com", FixtureToken: "dev-alice", Organization: "acme", Roles: []string{"admin"}, Teams: []string{}},
		{ID: "bob", Name: "Bob Williams", Email: "bob@acme.com", FixtureToken: "dev-bob", Organization: "acme", Roles: []string{}},
		{ID: "carol", Name: "Carol Davis", Email: "carol@acme.com", FixtureToken: "dev-carol", Organization: "acme", Roles: []string{}},
		{ID: "dana", Name: "Dana Lee", Email: "dana@example.com", FixtureToken: "dev-dana", Organization: "acme", Roles: []string{}},
	}
	if len(people) < 5 {
		t.Fatalf("the fixture lists %d people", len(people))
	}
	for i, w := range want {
		got := people[i]
		got.Teams = nil
		w.Teams = nil
		if !reflect.DeepEqual(got, w) {
			t.Fatalf("person %d = %+v, want %+v", i, got, w)
		}
	}
}

// Every role-gated target the run composes has one team per role it
// declares, `<target>-<role>`, holding that role on the installation, with
// Dana seated in the admin team and Carol in the user team, and Bob in
// neither: the wiki the test kit's composition installs by a row of its own,
// and a module page applied later, which is seated the moment it is composed.
func TestEveryRoleGatedTargetSeatsTheAdminAndUserTeams(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	page := testkit.OrgDirectory(2)
	page.Page = true
	page.Roles = map[string][]*basev0.WorkScopeV1{
		state.AdminRole: {testkit.Scope("directory.entry", "read", "write")},
		state.UserRole:  {testkit.Scope("directory.entry", "read", "write")},
	}
	if _, err := k.State.ApplyManifest(page); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"wiki", "org-directory"} {
		inst := state.InstallationID("acme", target)
		grants, err := k.State.Service().ListRoleGrants(ctx, caller(k, t, "dev-alice"), "acme", inst)
		if err != nil {
			t.Fatal(err)
		}
		for role, member := range map[string]string{state.UserRole: "carol", state.AdminRole: "dana"} {
			team := authority.ConventionalTeamName(target, role)
			if !slices.ContainsFunc(grants, func(g domain.RoleGrant) bool { return g.TeamID == team && g.Role == role }) {
				t.Fatalf("%s: team %s does not hold %s; grants %+v", target, team, role, grants)
			}
			if p := person(k, member); !slices.Contains(p.Teams, team) {
				t.Fatalf("%s is not seated in %s: %v", member, team, p.Teams)
			}
		}
		if p := person(k, "bob"); slices.ContainsFunc(p.Teams, func(team string) bool { return strings.HasPrefix(team, target+"-") }) {
			t.Fatalf("bob, who holds no role on a page, is seated on %s: %v", target, p.Teams)
		}
	}
	// A roleless module seats nobody, and a person of another organisation
	// is seated nowhere.
	if p := person(k, "carol"); slices.ContainsFunc(p.Teams, func(team string) bool { return strings.HasPrefix(team, "documents-") }) {
		t.Fatalf("carol is seated on a module that declares no roles: %v", p.Teams)
	}
	if p := person(k, "omar"); len(p.Teams) != 1 {
		t.Fatalf("omar's teams = %v", p.Teams)
	}
}

// Signed in as Alice, "act as this team" opens a session that holds the
// team's role on the wiki and nothing of her own; the session she came from
// is untouched. Bob holds no role on the page: he is refused it, and refused
// the users' team by name. Carol, the user, reads and does not write; Dana,
// the admin, writes, publishes and administers the installation's grants,
// which Carol may not.
func TestAliceCastsOntoATeamAndBobIsRefusedThePage(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	wiki := state.InstallationID("acme", "wiki")
	alice, err := k.State.SignIn("dev-alice")
	if err != nil {
		t.Fatal(err)
	}
	cast, err := k.State.OpenTeamCast(ctx, alice.ID, "wiki-user")
	if err != nil {
		t.Fatalf("alice onto wiki-user: %v", err)
	}
	if cast.CastTeam != "wiki-user" || len(cast.Roles) != 0 || !reflect.DeepEqual(cast.Teams, []string{"wiki-user"}) {
		t.Fatalf("the cast session = %+v", cast)
	}
	issued, err := k.State.Service().IssueForPerson(ctx, must(k.State.Caller(cast.ID)), authority.IssueRequest{Audience: "wiki"})
	if err != nil {
		t.Fatal(err)
	}
	if !holds(issued, "wiki.page", "read") || holds(issued, "wiki.page", "write") {
		t.Fatalf("the cast holds %v, want a user's read alone", issued.Context.GetAuthorityScopes())
	}
	// Back: her own session is what it was, an administrator who grants.
	own, err := k.State.Session(alice.ID)
	if err != nil || own.CastTeam != "" || !reflect.DeepEqual(own.Roles, []string{"admin"}) {
		t.Fatalf("alice's own session = %+v, %v", own, err)
	}
	if _, err := k.State.Service().GrantRole(ctx, must(k.State.Caller(alice.ID)), authority.RoleRequest{Organization: "acme", InstallationID: wiki, Role: state.UserRole, TeamID: "finance"}); err != nil {
		t.Fatalf("alice grants from her own session: %v", err)
	}
	bob, _ := k.State.SignIn("dev-bob")
	if _, err := k.State.Service().IssueForPerson(ctx, must(k.State.Caller(bob.ID)), authority.IssueRequest{Audience: "wiki"}); err == nil {
		t.Fatal("bob, who holds no role on the wiki, was issued its authority")
	}
	if _, err := k.State.OpenTeamCast(ctx, bob.ID, "wiki-user"); err == nil || !strings.Contains(err.Error(), "could not grant") {
		t.Fatalf("bob onto wiki-user: want a refusal naming what he could not grant, got %v", err)
	}
	carol, _ := k.State.SignIn("dev-carol")
	if issued, err := k.State.Service().IssueForPerson(ctx, must(k.State.Caller(carol.ID)), authority.IssueRequest{Audience: "wiki"}); err != nil || !holds(issued, "wiki.page", "read") || holds(issued, "wiki.page", "write") {
		t.Fatalf("carol, the user: %v %v", err, issued.Context.GetAuthorityScopes())
	}
	dana, _ := k.State.SignIn("dev-dana")
	if issued, err := k.State.Service().IssueForPerson(ctx, must(k.State.Caller(dana.ID)), authority.IssueRequest{Audience: "wiki"}); err != nil || !holds(issued, "wiki.page", "write") || !holds(issued, "wiki.page", "publish") {
		t.Fatalf("dana, the admin: %v %v", err, issued.Context.GetAuthorityScopes())
	}
	if _, err := k.State.Service().GrantRole(ctx, must(k.State.Caller(dana.ID)), authority.RoleRequest{Organization: "acme", InstallationID: wiki, Role: state.UserRole, PersonID: "bob"}); err != nil {
		t.Fatalf("dana, the admin, administers the wiki's grants: %v", err)
	}
	_, err = k.State.Service().GrantRole(ctx, must(k.State.Caller(carol.ID)), authority.RoleRequest{Organization: "acme", InstallationID: wiki, Role: state.AdminRole, PersonID: "carol"})
	if code, ok := domain.CodeOf(err); !ok || code != domain.Denied || !strings.Contains(err.Error(), "carol is neither an administrator of acme nor a holder of the admin role on installation "+wiki) {
		t.Fatalf("carol, a user, granting herself admin: want Denied, told she is no administrator, got %v", err)
	}
}

func caller(k *testkit.Kit, t *testing.T, token string) authority.Person {
	t.Helper()
	sess, err := k.State.SignIn(token)
	if err != nil {
		t.Fatal(err)
	}
	return must(k.State.Caller(sess.ID))
}

func must(p authority.Person, err error) authority.Person {
	if err != nil {
		panic(err)
	}
	return p
}

func person(k *testkit.Kit, id string) state.Person {
	for _, p := range k.State.FixturePeople() {
		if p.ID == id {
			return p
		}
	}
	return state.Person{}
}

func holds(i authority.Issued, kind, action string) bool {
	for _, sc := range i.Context.GetAuthorityScopes() {
		if sc.GetResourceKind() == kind && slices.Contains(sc.GetActions(), action) {
			return true
		}
	}
	return false
}
