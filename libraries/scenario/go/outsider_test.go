package scenario

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
)

// shippedCast is the local authority's shipped fixture as the host lists it.
func shippedCast() []*sessionv1.FixturePerson {
	return []*sessionv1.FixturePerson{
		{PersonId: "dana", OrganizationId: "acme", Roles: []string{"admin"}, FixtureToken: "dev-dana"},
		{PersonId: "carol", OrganizationId: "acme", FixtureToken: "dev-carol"},
		{PersonId: "bob", OrganizationId: "acme", FixtureToken: "dev-bob"},
		{PersonId: "zoe", OrganizationId: "globex", Roles: []string{"admin"}, FixtureToken: "fixture-zoe"},
	}
}

// tenants answers as an edge in front of a module that keeps each
// organisation's rows: a person's session is their token, and serve answers
// for the organisation that session is signed into.
func tenants(t *testing.T, people []*sessionv1.FixturePerson, serve func(organization string, w http.ResponseWriter, r *http.Request)) *Composition {
	t.Helper()
	organizations := map[string]string{}
	c := &Composition{signed: map[string]*Person{}, people: map[string]*sessionv1.FixturePerson{}}
	for _, person := range people {
		organizations[person.GetFixtureToken()] = person.GetOrganizationId()
		c.people[person.GetPersonId()] = person
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/sign-in" {
			var in struct{ FixtureToken string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			_, _ = io.WriteString(w, `{"bearer":"`+in.FixtureToken+`"}`)
			return
		}
		serve(organizations[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")], w, r)
	}))
	t.Cleanup(server.Close)
	c.origin, c.client = server.URL, server.Client()
	c.home = homeOrganization("", people)
	return c
}

// The setup administrator and the outsider are read from the fixture: the
// one administrator of the organisation it lists first, and the one
// administrator of another. A second organisation's administrator does not
// make the first ambiguous.
func TestTheOutsiderAdministersAnotherOrganisation(t *testing.T) {
	cast := shippedCast()
	if got, err := fixtureAdministrator(Options{Install: []string{"wiki"}}, cast); err != nil || got != Cast.Admin {
		t.Fatalf("the administrator of the shipped cast = %q, %v", got, err)
	}
	c := tenants(t, cast, nil)
	if c.Home() != "acme" {
		t.Fatalf("home = %q", c.Home())
	}
	zoe := c.Outsider(t)
	if zoe.ID != Cast.Outsider || zoe.Organization != "globex" || zoe != c.As(t, Cast.Outsider) {
		t.Fatalf("the outsider = %+v", zoe)
	}
	// Named as the administrator, Zoë's organisation is the composition's
	// own, and Dana is the outsider.
	c.home = homeOrganization("zoe", cast)
	if got, err := c.outsider(); err != nil || got != "dana" {
		t.Fatalf("the outsider of globex = %q, %v", got, err)
	}
	for name, people := range map[string][]*sessionv1.FixturePerson{
		"one organisation":   cast[:3],
		"two outsiders":      append(shippedCast(), &sessionv1.FixturePerson{PersonId: "omar", OrganizationId: "initech", Roles: []string{"admin"}}),
		"no administrator":   {cast[0], {PersonId: "omar", OrganizationId: "globex"}},
		"nobody is listed":   nil,
		"a second of acme's": {cast[0], {PersonId: "alex", OrganizationId: "acme", Roles: []string{"admin"}}},
	} {
		if got, err := tenants(t, people, nil).outsider(); err == nil || !strings.Contains(err.Error(), "an outsider is exactly one") {
			t.Errorf("%s: the outsider = %q, %v", name, got, err)
		}
	}
}

// Withheld is satisfied by a refusal for who calls and by the method's own
// not found, and by nothing that leaves the row's fate unshown.
func TestWithheldIsARefusalOrNotFound(t *testing.T) {
	for name, tc := range map[string]struct {
		got     Outcome
		problem string
	}{
		"refused":              {Outcome{Verdict: Denied, Status: 403, Code: "permission_denied", Reason: "zoe holds no role on installation i-acme"}, ""},
		"not found":            {Outcome{Verdict: Admitted, Status: 404, Code: "not_found", Reason: "no such note"}, ""},
		"answered":             {Outcome{Verdict: Allowed, Status: 200, Body: []byte(`{"note":"dana's"}`)}, "to be withheld"},
		"another refusal":      {Outcome{Verdict: Admitted, Status: 400, Code: "invalid_argument", Reason: "an id is required"}, "to be withheld"},
		"unserved":             {Outcome{Verdict: Unserved, Status: 404, Reason: "no module serves /a.v1.A/Get"}, "to be withheld"},
		"failed":               {Outcome{Verdict: Failed, Status: 502, Reason: "the module did not answer"}, "failed before any verdict"},
		"refused, no reason":   {Outcome{Verdict: Denied, Status: 403, Code: "permission_denied"}, "denied with no reason"},
		"not found, but leaks": {Outcome{Verdict: Admitted, Status: 404, Code: "not_found", Reason: "no such note", Body: []byte(`{"message":"n-1 is acme's"}`)}, "is not the caller's to read"},
	} {
		problem := Withheld.And(HoldsNone("acme")).problem(tc.got)
		if (tc.problem == "") != (problem == "") || !strings.Contains(problem, tc.problem) {
			t.Errorf("%s: problem %q, want %q", name, problem, tc.problem)
		}
	}
	if problem := Allow.And(Holds("n-1", "n-2")).problem(Outcome{Verdict: Allowed, Body: []byte(`{"notes":["n-1"]}`)}); !strings.Contains(problem, `does not carry "n-2"`) {
		t.Errorf("Holds: %q", problem)
	}
}

// Isolated holds a read to each organisation's own rows, both ways, and
// refuses a table that could show nothing.
func TestIsolatedHoldsAReadToItsOwnOrganisationsRows(t *testing.T) {
	rows := map[string]string{"acme": `{"notes":[{"id":"n-acme"}]}`, "globex": `{"notes":[{"id":"n-globex"}]}`}
	list := Call{Page: "notes", Procedure: "notes.v1.NotesService/List"}
	own := Own{Cast.Admin: {"n-acme"}, Cast.User: {"n-acme"}, Cast.Outsider: {"n-globex"}}
	c := tenants(t, shippedCast(), func(organization string, w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, rows[organization])
	})
	c.Isolated(t, "list the notes", list, own)

	organizations := map[string]string{"dana": "acme", "carol": "acme", "zoe": "globex"}
	for name, tc := range map[string]struct {
		who     string
		got     Outcome
		problem string
	}{
		"her own rows alone":       {"zoe", Outcome{Verdict: Allowed, Status: 200, Body: []byte(rows["globex"])}, ""},
		"another organisation's":   {"zoe", Outcome{Verdict: Allowed, Status: 200, Body: []byte(`{"notes":[{"id":"n-globex"},{"id":"n-acme"}]}`)}, `carries "n-acme", a row of`},
		"the outsider's, to dana":  {"dana", Outcome{Verdict: Allowed, Status: 200, Body: []byte(`{"notes":[{"id":"n-globex"},{"id":"n-acme"}]}`)}, `carries "n-globex", a row of zoe's organisation globex, to a person of acme`},
		"nothing at all":           {"zoe", Outcome{Verdict: Allowed, Status: 200, Body: []byte(`{}`)}, `lacks "n-globex"`},
		"a colleague's row lacked": {"carol", Outcome{Verdict: Allowed, Status: 200, Body: []byte(`{}`)}, `lacks "n-acme"`},
		"refused":                  {"zoe", Outcome{Verdict: Denied, Status: 403, Code: "permission_denied", Reason: "zoe holds no role on notes"}, "shows no isolation"},
		"failed":                   {"zoe", Outcome{Verdict: Failed, Status: 502, Reason: "the module did not answer"}, "shows no isolation"},
	} {
		problems := strings.Join(isolation(tc.who, organizations, own, tc.got), "; ")
		if (tc.problem == "") != (problems == "") || !strings.Contains(problems, tc.problem) {
			t.Errorf("%s: problems %q, want %q", name, problems, tc.problem)
		}
	}
	if err := twoOrganizations(map[string]string{"dana": "acme", "carol": "acme"}); err == nil || !strings.Contains(err.Error(), "between two organisations") {
		t.Errorf("a table of one organisation: %v", err)
	}
	if err := twoOrganizations(organizations); err != nil {
		t.Error(err)
	}
}
