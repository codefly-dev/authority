package state_test

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
)

// shipped is a bare kit on the fixture a run is given.
func shipped(t *testing.T) *testkit.Kit {
	t.Helper()
	k := testkit.Bare(t)
	data, err := os.ReadFile(testkit.ShippedFixturePath())
	if err != nil {
		t.Fatal(err)
	}
	if err := k.State.LoadFixture(context.Background(), data); err != nil {
		t.Fatalf("the shipped fixture does not load: %v", err)
	}
	return k
}

// The fixture a run is given is the cast a walk needs and nobody else: at
// Acme, Dana the admin, Carol the user, Bob refused (handbook: a page has two
// roles, admin and user); at Globex, Zoë, its one administrator, the outsider
// every composed suite holds Acme's rows against. The sign-in page lists
// FixturePeople unless a composition chooses, so a person added here is a
// person an unconfigured edge offers; the test kit's matrix of other people
// and refusal cases lives in testkit/fixture.yaml instead.
func TestTheShippedFixtureIsTheCastAndNobodyElse(t *testing.T) {
	k := shipped(t)
	var ids []string
	byID := map[string]state.Person{}
	for _, person := range k.State.FixturePeople() {
		ids = append(ids, person.ID)
		byID[person.ID] = person
		if len(person.Teams) != 0 {
			t.Errorf("%s is seated on %v by hand: the `*` rows seat the target teams", person.ID, person.Teams)
		}
	}
	if !slices.Equal(ids, []string{"dana", "carol", "bob", "zoe"}) {
		t.Fatalf("the shipped fixture lists %v; a walk needs dana, carol and bob, a cross-organisation refusal zoe, and nobody else", ids)
	}
	for id, org := range map[string]string{"dana": "acme", "carol": "acme", "bob": "acme", "zoe": "globex"} {
		if byID[id].Organization != org {
			t.Errorf("%s belongs to %q, want %s: the shipped fixture is Acme's three people and Globex's one", id, byID[id].Organization, org)
		}
	}
	if !slices.Equal(byID["dana"].Roles, []string{"admin"}) || len(byID["carol"].Roles) != 0 || len(byID["bob"].Roles) != 0 || !slices.Equal(byID["zoe"].Roles, []string{"admin"}) {
		t.Fatalf("organisation roles: dana %v, carol %v, bob %v, zoe %v; only Dana administers Acme and only Zoë Globex",
			byID["dana"].Roles, byID["carol"].Roles, byID["bob"].Roles, byID["zoe"].Roles)
	}
	if zoe := byID["zoe"]; zoe.Email != "zoe@globex.test" || zoe.FixtureToken != "fixture-zoe" {
		t.Fatalf("zoe is %s by %s; the host's fixture and every composed suite sign her in as zoe@globex.test by fixture-zoe", zoe.Email, zoe.FixtureToken)
	}
	if k.State.OrganizationDisplayName("acme") != "Acme" || k.State.OrganizationDisplayName("globex") != "Globex" {
		t.Fatalf("the organisations are %q and %q, want Acme and Globex", k.State.OrganizationDisplayName("acme"), k.State.OrganizationDisplayName("globex"))
	}
	for _, token := range []string{"dev-dana", "dev-carol", "dev-bob", "fixture-zoe"} {
		if _, err := k.State.SignIn(token); err != nil {
			t.Errorf("%s cannot sign in: %v", token, err)
		}
	}
	for _, gone := range []string{"dev-admin", "dev-alice", "dev-zoe", "fixture-dev", "fixture-maya", "fixture-no-roles", "fixture-omar"} {
		if _, err := k.State.SignIn(gone); err == nil {
			t.Errorf("%s still signs in from the shipped fixture", gone)
		}
	}
}

// Zoë administers Globex and nothing of Acme's. A module page the run
// composes is installed at both organisations: each row standing for every
// target seats its own organisation's people on its own installation, so Zoë
// is the admin of Globex's page and holds no team of Acme's, and Dana and
// Carol none of Globex's. What each is issued is her own organisation's, and
// an ask for the other's, or an act on the other's installation, is refused.
func TestTheShippedFixtureKeepsEachOrganisationToItsOwn(t *testing.T) {
	for name, fragment := range map[string]string{
		"the fixture alone": "",
		// A composition naming who administers the page at Globex, beside the
		// fixture's own row standing for every target there, changes nothing.
		"a composition's row for the page at globex": "installations:\n  - {organization: globex, target: org-directory, owner: zoe}\n",
	} {
		t.Run(name, func(t *testing.T) { eachOrganisationKeepsItsOwn(t, fragment) })
	}
}

func eachOrganisationKeepsItsOwn(t *testing.T, fragment string) {
	k := shipped(t)
	ctx := context.Background()
	if fragment != "" {
		if _, err := k.State.ApplyComposition(ctx, []byte("schema: "+state.CompositionSchema+"\n"+fragment)); err != nil {
			t.Fatal(err)
		}
	}
	page := testkit.OrgDirectory(1)
	page.Page = true
	page.Roles = map[string][]*basev1.WorkScopeV1{
		state.AdminRole: {testkit.Scope("directory.entry", "read", "write")},
		state.UserRole:  {testkit.Scope("directory.entry", "read")},
	}
	if _, err := k.State.ApplyManifest(page); err != nil {
		t.Fatal(err)
	}
	if _, err := k.State.SeatRoleTeams(ctx); err != nil {
		t.Fatal(err)
	}
	admin, user := authority.ConventionalTeamName(page.Name, state.AdminRole), authority.ConventionalTeamName(page.Name, state.UserRole)
	for id, want := range map[string][]string{"dana": {admin}, "carol": {user}, "bob": nil, "zoe": {admin}} {
		if got := person(k, id).Teams; !slices.Equal(got, want) {
			t.Errorf("%s is seated in %v, want %v", id, got, want)
		}
	}
	acme, globex := state.InstallationID("acme", page.Name), state.InstallationID("globex", page.Name)
	if acme == globex {
		t.Fatalf("both organisations hold installation %s", acme)
	}
	zoe, dana := caller(k, t, "fixture-zoe"), caller(k, t, "dev-dana")
	for _, tc := range []struct {
		who                 authority.Person
		own, foreign, other string
	}{{zoe, "globex", "acme", acme}, {dana, "acme", "globex", globex}} {
		issued, err := k.State.Service().IssueForPerson(ctx, tc.who, authority.IssueRequest{Audience: page.Name})
		if err != nil || issued.Context.GetOrganizationId() != tc.own || !holds(issued, "directory.entry", "write") {
			t.Fatalf("%s at her own %s: %v, %v", tc.who.ID, tc.own, issued.Context, err)
		}
		if out, err := k.State.Service().IssueForPerson(ctx, tc.who, authority.IssueRequest{Audience: page.Name, Organization: tc.foreign}); err == nil {
			t.Fatalf("%s of %s was issued %s's %s: %v", tc.who.ID, tc.own, tc.foreign, page.Name, out.Context)
		}
		_, err = k.State.Service().ListRoleGrants(ctx, tc.who, tc.foreign, tc.other)
		if code, ok := domain.CodeOf(err); !ok || code != domain.Denied {
			t.Fatalf("%s of %s reading the grants of %s's installation: want Denied, got %v", tc.who.ID, tc.own, tc.foreign, err)
		}
		_, err = k.State.Service().GrantRole(ctx, tc.who, authority.RoleRequest{Organization: tc.foreign, InstallationID: tc.other, Role: state.UserRole, PersonID: tc.who.ID})
		if code, ok := domain.CodeOf(err); !ok || code != domain.Denied {
			t.Fatalf("%s of %s granting herself a role on %s's installation: want Denied, got %v", tc.who.ID, tc.own, tc.foreign, err)
		}
		// Named as her own organisation's, the other's installation does not exist.
		if _, err = k.State.Service().ListRoleGrants(ctx, tc.who, tc.own, tc.other); err == nil {
			t.Fatalf("%s read %s's installation by naming it as %s's", tc.who.ID, tc.foreign, tc.own)
		}
	}
	grants, err := k.State.Service().ListRoleGrants(ctx, dana, "acme", acme)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range grants {
		if g.PersonID == "zoe" || strings.Contains(g.TeamID, "globex") {
			t.Fatalf("Acme's installation grants Globex's %+v", g)
		}
	}
}

// A composition's fragment names the shipped fixture's ids (its contract with
// every composing repository): a row for Globex owned by Zoë is accepted, and
// a row that would seat her on an installation of Acme's, or Dana on one of
// Globex's, is refused by name, so no fragment makes the outsider an insider.
func TestACompositionSeatsTheShippedPeopleInTheirOwnOrganisationOnly(t *testing.T) {
	const head = "schema: " + state.CompositionSchema + "\n"
	for name, tc := range map[string]struct{ doc, refusal string }{
		"zoe owns a globex installation":     {doc: "installations:\n  - {organization: globex, target: documents, owner: zoe}\n"},
		"zoe owns an acme installation":      {"installations:\n  - {organization: acme, target: documents, owner: zoe}\n", `"zoe" is not a person of acme`},
		"zoe is seated on acme's":            {"installations:\n  - {organization: acme, target: documents, owner: dana, members: {user: [zoe]}}\n", `"zoe", who is not a person of acme`},
		"dana is seated on globex's":         {"installations:\n  - {organization: globex, target: documents, owner: zoe, members: {admin: [dana]}}\n", `"dana", who is not a person of globex`},
		"an organisation nobody defines":     {"installations:\n  - {organization: initech, target: documents, owner: zoe}\n", `"initech" is not an organisation the fixture defines`},
		"a person only the kit's matrix has": {"installations:\n  - {organization: globex, target: documents, owner: omar}\n", `"omar" is not a person of globex`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := shipped(t).State.ApplyComposition(context.Background(), []byte(head+tc.doc))
			switch {
			case tc.refusal == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tc.refusal != "" && (err == nil || !strings.Contains(err.Error(), tc.refusal)):
				t.Fatalf("want a refusal saying %s, got %v", tc.refusal, err)
			}
		})
	}
}
