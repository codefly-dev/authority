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

// front answers as the edge does on the wire, for the harness's own
// mechanics: how a call is addressed and how its answer is read. What the
// authority decides is never tested against it.
func front(t *testing.T, serve http.HandlerFunc) *Composition {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/sign-in" {
			var in struct{ FixtureToken string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			if r.Header.Get("Origin") == "" || in.FixtureToken != "token-carol" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"error":"the authority refused the sign-in"}`)
				return
			}
			_, _ = io.WriteString(w, `{"bearer":"session-carol"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer session-carol" {
			t.Errorf("%s carries %q, not the person's session", r.URL.Path, r.Header.Get("Authorization"))
		}
		serve(w, r)
	}))
	t.Cleanup(server.Close)
	return &Composition{origin: server.URL, client: server.Client(), signed: map[string]*Person{},
		people: map[string]*sessionv1.FixturePerson{"carol": {PersonId: "carol", FixtureToken: "token-carol"}, "mallory": {PersonId: "mallory", FixtureToken: "unknown"}}}
}

func TestACallIsAddressedAsAPageMakesIt(t *testing.T) {
	var paths []string
	c := front(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		body, _ := io.ReadAll(r.Body)
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/") && (string(body) != `{"name":"n"}` || r.Header.Get("Connect-Protocol-Version") != "1") {
			t.Errorf("a page call sent %q, protocol %q", body, r.Header.Get("Connect-Protocol-Version"))
		}
		_, _ = io.WriteString(w, `{"items":[{"text":"first"}]}`)
	})
	carol := c.As(t, "carol")
	got := carol.Do(t, Call{Page: "notes", Procedure: "notes.v1.Notes/List", Request: map[string]string{"name": "n"}})
	if got.Verdict != Allowed || got.Text("items.0.text") != "first" || got.Value("items.1") != nil {
		t.Fatalf("got %+v", got)
	}
	carol.Do(t, Call{Procedure: "notes.v1.Notes/List"})
	carol.Do(t, Call{Page: "notes", Procedure: "GET /v1/notes/settings"})
	want := []string{"POST /api/solutions/notes/proxy/_browser/notes.v1.Notes/List", "POST /notes.v1.Notes/List", "GET /v1/notes/settings"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("called %v, want %v", paths, want)
	}
	if c.As(t, "carol") != carol {
		t.Fatal("a person is signed in twice")
	}
	if _, err := c.person("mallory"); err == nil || !strings.Contains(err.Error(), "refused the sign-in") {
		t.Fatalf("a refused sign-in: %v", err)
	}
	if _, err := c.person("nobody"); err == nil {
		t.Fatal("a person the fixture does not name signs in")
	}
}

func TestAnAnswerIsReadAsItsVerdict(t *testing.T) {
	answers := map[string]struct {
		status int
		body   string
	}{
		"/a.v1.A/Answers":      {200, `{}`},
		"/a.v1.A/Invalid":      {400, `{"code":"invalid_argument","message":"a name is required"}`},
		"/a.v1.A/Denied":       {403, `{"code":"permission_denied","message":"carol holds no role on notes"}`},
		"/a.v1.A/SignedOut":    {401, `{"code":"unauthenticated","message":"no session"}`},
		"/a.v1.A/Unreasoned":   {403, `{"code":"permission_denied","message":""}`},
		"/a.v1.A/Unrouted":     {404, `{"error":"no module serves /a.v1.A/Unrouted"}`},
		"/v1/notes/settings":   {403, `{"error":"a write must come from this origin"}`},
		"/a.v1.A/StreamDenied": {200, string(envelope([]byte(`{"n":1}`))) + string(end(`{"error":{"code":"permission_denied","message":"refused late"}}`))},
	}
	c := front(t, func(w http.ResponseWriter, r *http.Request) {
		answer := answers[r.URL.Path]
		w.WriteHeader(answer.status)
		_, _ = io.WriteString(w, answer.body)
	})
	for _, tc := range []struct {
		call    Call
		want    Expect
		problem string
	}{
		{Call{Procedure: "a.v1.A/Answers"}, Allow, ""},
		{Call{Procedure: "a.v1.A/Answers"}, Deny("no role"), "expected a refusal"},
		{Call{Procedure: "a.v1.A/Answers"}, Allow.And(func(Outcome) error { return io.EOF }), "EOF"},
		{Call{Procedure: "a.v1.A/Invalid"}, Admit, ""},
		{Call{Procedure: "a.v1.A/Invalid"}, Allow, "expected an answer"},
		{Call{Procedure: "a.v1.A/Denied"}, Deny("holds no role on notes"), ""},
		{Call{Procedure: "a.v1.A/Denied"}, Deny("another reason"), "but not for"},
		{Call{Procedure: "a.v1.A/Denied"}, Admit, "expected the call to be let through"},
		{Call{Procedure: "a.v1.A/SignedOut"}, Deny("no session"), ""},
		{Call{Procedure: "a.v1.A/Unreasoned"}, Deny(""), "denied with no reason"},
		{Call{Procedure: "POST /v1/notes/settings"}, Deny("this origin"), ""},
		{Call{Procedure: "a.v1.A/Unrouted"}, Admit, "serves no such call"},
		{Call{Procedure: "a.v1.A/Unrouted"}, Deny("holds no role"), "serves no such call"},
		{Call{Procedure: "a.v1.A/Unrouted"}, Deny(""), ""},
		{Call{Procedure: "a.v1.A/StreamDenied", Stream: true}, Deny("refused late"), ""},
		{Call{Procedure: "a.v1.A/Answers"}, Expect{}, "states no expectation"},
	} {
		got := c.As(t, "carol").Do(t, tc.call)
		problem := tc.want.problem(got)
		if (tc.problem == "") != (problem == "") || !strings.Contains(problem, tc.problem) {
			t.Errorf("%s expecting %v: problem %q, want %q", tc.call.Procedure, tc.want.verdict, problem, tc.problem)
		}
	}
	if got := c.As(t, "carol").Do(t, Call{Procedure: "a.v1.A/StreamDenied", Stream: true}); got.Text("0.n") != "" || got.Value("0.n") != float64(1) {
		t.Fatalf("a stream's messages: %s", got.Body)
	}
}

// end frames a stream's last message, as Connect marks it.
func end(message string) []byte {
	frame := envelope([]byte(message))
	frame[0] = 2
	return frame
}
