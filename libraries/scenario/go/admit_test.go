package scenario

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// Admit says the call reached its method. A module that is down, a hop that
// could not reach it, a fault and a deadline are no answer of the method: each
// fails whatever the row expects, and says its cause. What the method answers
// of the request itself (an argument, a record, a state) is still admitted.
func TestACallThatFailedIsNoVerdict(t *testing.T) {
	answers := map[string]struct {
		status int
		body   string
	}{
		"/a.v1.A/Down":         {502, `{"error":"the module did not answer"}`},
		"/a.v1.A/Unavailable":  {503, `{"code":"unavailable","message":"the module did not answer"}`},
		"/a.v1.A/Fault":        {500, `{"code":"internal","message":"nil pointer"}`},
		"/a.v1.A/Unknown":      {500, `{"code":"unknown","message":"boom"}`},
		"/a.v1.A/Late":         {504, `{"code":"deadline_exceeded","message":"too slow"}`},
		"/a.v1.A/Gone":         {499, `{"code":"canceled","message":"the caller left"}`},
		"/a.v1.A/Busy":         {429, `{"code":"resource_exhausted","message":"too many"}`},
		"/a.v1.A/Page":         {500, `<html>oops</html>`},
		"/a.v1.A/StreamDown":   {200, string(end(`{"error":{"code":"unavailable","message":"the module did not answer"}}`))},
		"/a.v1.A/Undecided":    {404, `{"code":"not_found","message":"the authority refused the call to a: module \"a\" not found"}`},
		"/a.v1.A/NotInstalled": {400, `{"code":"failed_precondition","message":"the authority refused the call to a: a is not installed at acme"}`},
		"/a.v1.A/NotFound":     {404, `{"code":"not_found","message":"no such note"}`},
		"/a.v1.A/Exists":       {409, `{"code":"already_exists","message":"a note of that name exists"}`},
		"/a.v1.A/NotNow":       {400, `{"code":"failed_precondition","message":"the note is archived"}`},
		"/a.v1.A/Range":        {400, `{"code":"out_of_range","message":"page 9 of 2"}`},
		"/v1/notes/missing":    {400, `{"error":"a name is required"}`},
		"/v1/notes/conflict":   {409, `{"error":"a note of that name exists"}`},
	}
	c := front(t, func(w http.ResponseWriter, r *http.Request) {
		answer := answers[r.URL.Path]
		w.WriteHeader(answer.status)
		_, _ = io.WriteString(w, answer.body)
	})
	for _, tc := range []struct {
		call    Call
		verdict Verdict
		cause   string
	}{
		{Call{Procedure: "a.v1.A/Down"}, Failed, "the module did not answer"},
		{Call{Procedure: "a.v1.A/Unavailable"}, Failed, "the module did not answer"},
		{Call{Procedure: "a.v1.A/Fault"}, Failed, "nil pointer"},
		{Call{Procedure: "a.v1.A/Unknown"}, Failed, "boom"},
		{Call{Procedure: "a.v1.A/Late"}, Failed, "too slow"},
		{Call{Procedure: "a.v1.A/Gone"}, Failed, "the caller left"},
		{Call{Procedure: "a.v1.A/Busy"}, Failed, "too many"},
		{Call{Procedure: "a.v1.A/Page"}, Failed, "oops"},
		{Call{Procedure: "a.v1.A/StreamDown", Stream: true}, Failed, "the module did not answer"},
		{Call{Procedure: "a.v1.A/Undecided"}, Failed, "the authority refused the call"},
		{Call{Procedure: "a.v1.A/NotInstalled"}, Failed, "is not installed"},
		{Call{Procedure: "a.v1.A/NotFound"}, Admitted, ""},
		{Call{Procedure: "a.v1.A/Exists"}, Admitted, ""},
		{Call{Procedure: "a.v1.A/NotNow"}, Admitted, ""},
		{Call{Procedure: "a.v1.A/Range"}, Admitted, ""},
		{Call{Procedure: "POST /v1/notes/missing"}, Admitted, ""},
		{Call{Procedure: "POST /v1/notes/conflict"}, Admitted, ""},
	} {
		got := c.As(t, "carol").Do(t, tc.call)
		if got.Verdict != tc.verdict {
			t.Errorf("%s: %s (%d %s), want %s", tc.call.Procedure, got.Verdict, got.Status, got.Code, tc.verdict)
		}
		for name, want := range map[string]Expect{"Admit": Admit, "Allow": Allow, "Deny": Deny(""), "Deny for a reason": Deny("holds no role")} {
			problem := want.problem(got)
			switch {
			case tc.verdict == Failed && (!strings.Contains(problem, "failed before any verdict") || !strings.Contains(problem, tc.cause)):
				t.Errorf("%s expecting %s: problem %q, want the failure and its cause %q", tc.call.Procedure, name, problem, tc.cause)
			case tc.verdict == Admitted && (problem == "") != (name == "Admit"):
				t.Errorf("%s expecting %s: problem %q", tc.call.Procedure, name, problem)
			}
		}
	}
}
