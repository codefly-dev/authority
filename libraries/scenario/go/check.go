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
	// A refusal derived from a plan (PlanRows) is held to the decision the
	// plan names, stage in words: the refusal says one of among, or names one
	// of unmet as a permission the call requires and does not hold, and says
	// none of not, which are an earlier decision's words.
	among, unmet, not []string
	stage             string
	// withheld: the expectation is Withheld, which a refusal for who makes
	// the call or the method's own "not found" each satisfy.
	withheld bool
	holds    []func(Outcome) error
}

// staged: the expectation is a refusal by one named decision.
func (e Expect) staged() bool { return len(e.among)+len(e.unmet)+len(e.not) > 0 }

// refusedBy answers whether reason is the refusal of the decision a staged
// expectation names.
func (e Expect) refusedBy(reason string) bool {
	if slices.ContainsFunc(e.not, func(words string) bool { return strings.Contains(reason, words) }) {
		return false
	}
	if len(e.among)+len(e.unmet) == 0 {
		return true
	}
	return slices.ContainsFunc(e.among, func(words string) bool { return strings.Contains(reason, words) }) || unmetNamed(reason, e.unmet)
}

// unmetNamed answers whether a method policy's refusal ("<module> requires
// <permissions> for <method>, which the call does not hold (it holds …)")
// names one of permissions as unmet. What the call holds is not what it lacks.
func unmetNamed(reason string, permissions []string) bool {
	_, after, ok := strings.Cut(reason, "requires ")
	if !ok {
		return false
	}
	lacks, _, ok := strings.Cut(after, "which the call does not hold")
	if !ok {
		return false
	}
	named := strings.FieldsFunc(lacks, func(r rune) bool { return r == ',' || r == ' ' })
	return slices.ContainsFunc(permissions, func(p string) bool { return slices.Contains(named, p) })
}

var (
	// Allow: the call answers.
	Allow = Expect{verdict: Allowed}
	// Admit: the person may make the call: it answers, or it reached its
	// method and the method refuses the request for a reason of its own
	// (Admitted, as Do reads it). For a call made with no real argument. A
	// call that failed (Failed: the module down, a fault, a timeout) reached
	// no method and does not satisfy it.
	Admit = Expect{verdict: Admitted}
)

// Withheld: the call names something of another organisation's (a row, an
// installation) and its caller is not given it: the call is refused for who
// makes it, or it reached its method and the method answers that no such
// thing exists (Connect not_found), which is what a store scoped to the
// caller's own organisation says of another's row. Nothing else satisfies it:
// an answer gave the row away; a request refused for another reason of the
// method's own (an argument), a call nobody is served and a call that failed
// prove nothing about the row. A route's plain 404 is read as unserved (Do),
// so hold a route to Deny or to what its answer lacks (HoldsNone).
var Withheld = Expect{verdict: Denied, withheld: true}

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
	case got.Verdict == Failed:
		// Nobody was let through and nobody was refused: no expectation holds.
		return "the call failed before any verdict: " + said
	case got.Verdict == Denied && strings.TrimSpace(got.Reason) == "":
		return "denied with no reason"
	case e.withheld && got.Verdict != Denied && (got.Verdict != Admitted || got.Code != "not_found"):
		return "expected another organisation's to be withheld (a refusal, or not found), got " + said
	case e.withheld:
		// Withheld: refused, or not found.
	case got.Verdict == Unserved && (e.verdict != Denied || e.reason != "" || e.staged()):
		// A call nobody is served is refused to everyone, which satisfies a
		// refusal expected for no stated reason, and nothing else: never a
		// refusal a plan attributes to a decision.
		return "the composition serves no such call: " + said
	case got.Verdict == Unserved:
		return ""
	case e.verdict == Denied && got.Verdict != Denied:
		return "expected a refusal, got " + said
	case e.verdict == Denied && e.staged() && !e.refusedBy(got.Reason):
		return fmt.Sprintf("refused, but not %s: %s", e.stage, got.Reason)
	case e.verdict == Denied && !strings.Contains(got.Reason, e.reason):
		return fmt.Sprintf("refused, but not for %q: %s", e.reason, got.Reason)
	case e.verdict == Allowed && got.Verdict != Allowed:
		return "expected an answer, got " + said
	case e.verdict == Admitted && got.Verdict != Allowed && got.Verdict != Admitted:
		return "expected the call to be let through, got " + said
	}
	for _, holds := range e.holds {
		if err := holds(got); err != nil {
			return err.Error()
		}
	}
	return ""
}

// Session is the person's session as the edge answers it to their browser:
// who they are and the pages they may use.
var Session = Call{Procedure: "GET /auth/session"}

// Uses holds a Session answer to listing target among the pages the person
// may use; UsesNothing holds it to listing none.
func Uses(target string) func(Outcome) error {
	return func(got Outcome) error {
		installations, _ := got.Value("installations").([]any)
		for i := range installations {
			if got.Text(fmt.Sprintf("installations.%d.target", i)) == target {
				return nil
			}
		}
		refused, _ := got.Value("refused").(map[string]any)
		return fmt.Errorf("the session lists %s among no page the person may use (refused: %v)", target, refused)
	}
}

// UsesNothing: the session lists no page.
func UsesNothing(got Outcome) error {
	if installations, _ := got.Value("installations").([]any); len(installations) > 0 {
		return fmt.Errorf("the session lists pages for a person who holds no role: %s", got.Body)
	}
	return nil
}
