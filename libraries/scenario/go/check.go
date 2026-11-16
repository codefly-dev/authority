package scenario

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// Expect is what a scenario expects of one person on one call.
type Expect struct {
	verdict Verdict
	reason  string
	holds   []func(Outcome) error
}

var (
	// Allow: the call answers.
	Allow = Expect{verdict: Allowed}
	// Admit: the person may make the call: it answers, or the method refuses
	// it for a reason of its own. For a call made with no real argument.
	Admit = Expect{verdict: Admitted}
)

// Deny: the call is refused for who makes it, and the refusal says reason
// (a part of it). A refusal that names no reason fails whatever is expected.
func Deny(reason string) Expect { return Expect{verdict: Denied, reason: reason} }

// And adds what the answer must hold: holds answers what it lacks.
func (e Expect) And(holds func(Outcome) error) Expect {
	e.holds = append(slices.Clone(e.holds), holds)
	return e
}

// Want is what a row expects, by fixture person.
type Want map[string]Expect

// Row is one call and what becomes of it for each person named.
type Row struct {
	// Name is the call in a person's words: "rate an answer".
	Name string
	Call
	// For builds the request for one person, when it differs by person or
	// comes from an earlier answer; it replaces Call.Request.
	For  func(t *testing.T, p *Person) any
	Want Want
}

// Check makes every row's call as each person it names, in the order given
// (rows) and by name (people), and holds each outcome to what the row
// expects. Each is its own subtest, "<row>/<person>".
func (c *Composition) Check(t *testing.T, rows ...Row) {
	t.Helper()
	for _, row := range rows {
		people := make([]string, 0, len(row.Want))
		for id := range row.Want {
			people = append(people, id)
		}
		slices.Sort(people)
		for _, id := range people {
			t.Run(row.Name+"/"+id, func(t *testing.T) {
				p := c.As(t, id)
				call := row.Call
				if row.For != nil {
					call.Request = row.For(t, p)
				}
				if problem := row.Want[id].problem(p.Do(t, call)); problem != "" {
					t.Errorf("%s, %s (%s): %s", id, row.Name, call.Procedure, problem)
				}
			})
		}
	}
}

// problem is how got falls short of the expectation, in words; empty when it
// does not.
func (e Expect) problem(got Outcome) string {
	said := fmt.Sprintf("%s (%d %s): %s", got.Verdict, got.Status, got.Code, got.Reason)
	switch {
	case e.verdict == 0:
		return "the row states no expectation"
	case got.Verdict == Denied && strings.TrimSpace(got.Reason) == "":
		return "denied with no reason"
	case got.Verdict == Unserved && (e.verdict != Denied || e.reason != ""):
		// A call nobody is served is refused to everyone, which satisfies a
		// refusal expected for no stated reason, and nothing else.
		return "the composition serves no such call: " + said
	case got.Verdict == Unserved:
		return ""
	case e.verdict == Denied && got.Verdict != Denied:
		return "expected a refusal, got " + said
	case e.verdict == Denied && !strings.Contains(got.Reason, e.reason):
		return fmt.Sprintf("refused, but not for %q: %s", e.reason, got.Reason)
	case e.verdict == Allowed && got.Verdict != Allowed:
		return "expected an answer, got " + said
	case e.verdict == Admitted && got.Verdict == Denied:
		return "expected the call to be let through, got " + said
	}
	for _, holds := range e.holds {
		if err := holds(got); err != nil {
			return err.Error()
		}
	}
	return ""
}
