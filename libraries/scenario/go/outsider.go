package scenario

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// Outsider is the fixture's administrator of another organisation than the
// composition's own, signed in: on the local authority's fixture, Zoë of
// Globex (Cast.Outsider). She administers her organisation and holds no role
// on any installation of the composition's own, so she is who a scenario
// holds its organisation's rows against: what she reads is her own
// organisation's (Isolated), and what she names of the other's is withheld
// (Withheld). She is read from the host, never written down: the one person
// holding the organisation role admin in an organisation that is not the
// administrator's. A fixture with none, or with several, fails the test
// saying so; name the person with As then.
func (c *Composition) Outsider(t testing.TB) *Person {
	t.Helper()
	id, err := c.outsider()
	if err != nil {
		t.Fatal(err)
	}
	return c.As(t, id)
}

func (c *Composition) outsider() (string, error) {
	var outsiders []string
	for id, person := range c.people {
		if person.GetOrganizationId() != c.home && slices.Contains(person.GetRoles(), "admin") {
			outsiders = append(outsiders, id)
		}
	}
	slices.Sort(outsiders)
	if len(outsiders) != 1 {
		return "", fmt.Errorf("scenario: the fixture lists %d administrators of an organisation other than %q %v, and an outsider is exactly one: name the person (As)", len(outsiders), c.home, outsiders)
	}
	return outsiders[0], nil
}

// Home is the composition's own organisation: the administrator's
// (Options.Administrator), or the one the fixture lists first.
func (c *Composition) Home() string { return c.home }

// Holds holds an answer to carrying every one of texts, as its JSON spells
// them: an id or a title a scenario wrote.
func Holds(texts ...string) func(Outcome) error {
	return func(got Outcome) error {
		for _, text := range texts {
			if !strings.Contains(string(got.Body), text) {
				return fmt.Errorf("the answer does not carry %q: %s", text, got.Body)
			}
		}
		return nil
	}
}

// HoldsNone holds an answer to carrying none of texts: what another
// organisation's rows carry and this caller's answer must not.
func HoldsNone(texts ...string) func(Outcome) error {
	return func(got Outcome) error {
		for _, text := range texts {
			if text != "" && strings.Contains(string(got.Body), text) {
				return fmt.Errorf("the answer carries %q, which is not the caller's to read: %s", text, got.Body)
			}
		}
		return nil
	}
}

// Own names, by fixture person, text that only the rows of that person's
// organisation carry in the answer to one read, as its JSON spells it: the id
// or the title of a row a scenario wrote there.
type Own map[string][]string

// Isolated holds one read to tenant isolation, both ways. Each person own
// names makes the call on their own seat and must be answered; the answer
// carries every text named for the people of their own organisation and none
// named for a person of another. So a read that answers nothing proves
// nothing and fails, as does a run whose people are all of one organisation,
// or a person named with no text: isolation is shown only against a row that
// is really there on the other side.
//
//	composed.Isolated(t, "list the notes", scenario.Call{Page: "notes", Procedure: "notes.v1.NotesService/List"},
//		scenario.Own{scenario.Cast.Admin: {danasNote}, scenario.Cast.Outsider: {zoesNote}})
//
// Each person is their own subtest, "<name>/<person>".
func (c *Composition) Isolated(t *testing.T, name string, read Call, own Own) {
	t.Helper()
	people := make([]string, 0, len(own))
	organizations := map[string]string{}
	for id, texts := range own {
		if len(texts) == 0 || slices.Contains(texts, "") {
			t.Fatalf("%s: %s is named with no text of a row of theirs: isolation is shown against a row that is there", name, id)
		}
		people = append(people, id)
		organizations[id] = c.As(t, id).Organization
	}
	slices.Sort(people)
	if err := twoOrganizations(organizations); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	for _, id := range people {
		t.Run(name+"/"+id, func(t *testing.T) {
			got := c.As(t, id).Do(t, read)
			for _, problem := range isolation(id, organizations, own, got) {
				t.Errorf("%s, %s (%s): %s", id, name, read.Procedure, problem)
			}
		})
	}
}

// twoOrganizations refuses a table whose people are all of one organisation.
func twoOrganizations(organizations map[string]string) error {
	var distinct []string
	for _, organization := range organizations {
		if !slices.Contains(distinct, organization) {
			distinct = append(distinct, organization)
		}
	}
	slices.Sort(distinct)
	if len(distinct) < 2 {
		return fmt.Errorf("the people named are all of %v: isolation is shown between two organisations (name the outsider's row too)", distinct)
	}
	return nil
}

// isolation is how got, id's answer to the read, falls short of isolation:
// Isolated's rule.
func isolation(id string, organizations map[string]string, own Own, got Outcome) []string {
	if problem := Allow.problem(got); problem != "" {
		return []string{problem + ": a read that is not answered shows no isolation"}
	}
	var problems []string
	people := make([]string, 0, len(own))
	for other := range own {
		people = append(people, other)
	}
	slices.Sort(people)
	for _, other := range people {
		mine := organizations[other] == organizations[id]
		for _, text := range own[other] {
			carried := strings.Contains(string(got.Body), text)
			switch {
			case mine && !carried:
				problems = append(problems, fmt.Sprintf("the answer lacks %q, a row of their own organisation %s (named for %s): %s", text, organizations[id], other, got.Body))
			case !mine && carried:
				problems = append(problems, fmt.Sprintf("the answer carries %q, a row of %s's organisation %s, to a person of %s", text, other, organizations[other], organizations[id]))
			}
		}
	}
	return problems
}
