package scenario

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Person is a fixture person signed in at the edge: every call carries their
// session and nothing else, as their browser's would.
type Person struct {
	ID string
	// Organization is the organisation the fixture signs them into.
	Organization string
	c            *Composition
	// bearer is the session the edge opened; the edge issues the person's
	// Work Context for each module a call is for.
	bearer string
}

// As is the fixture person named id, signed in at the edge by the fixture's
// own token for them (read from the host, never written down). A person is
// signed in once per composition.
func (c *Composition) As(t testing.TB, id string) *Person {
	t.Helper()
	p, err := c.person(id)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (c *Composition) person(id string) (*Person, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p, ok := c.signed[id]; ok {
		return p, nil
	}
	fixture, ok := c.people[id]
	if !ok {
		return nil, fmt.Errorf("scenario: %q is not a fixture person of this host", id)
	}
	body, _ := json.Marshal(map[string]string{"fixtureToken": fixture.GetFixtureToken()})
	req, _ := http.NewRequest(http.MethodPost, c.origin+"/auth/sign-in", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", c.origin)
	res, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scenario: sign in %s: %w", id, err)
	}
	defer res.Body.Close()
	var session struct{ Bearer, Error string }
	if err := json.NewDecoder(res.Body).Decode(&session); err != nil || session.Bearer == "" {
		return nil, fmt.Errorf("scenario: sign in %s: %d %s %v", id, res.StatusCode, session.Error, err)
	}
	p := &Person{ID: id, Organization: fixture.GetOrganizationId(), c: c, bearer: session.Bearer}
	c.signed[id] = p
	return p, nil
}

// Call is one call a person makes.
type Call struct {
	// Page is the page the call is made from: a solution's or a module
	// page's route alias. The edge names it to the authority, which issues
	// through the page's binding to the module. Empty is a call on the
	// person's own session, with no page.
	Page string
	// Procedure is "<package.Service>/<Method>" for a module's method, or
	// "<VERB> <path>" for a route the edge serves ("GET /v1/wiki/pages").
	Procedure string
	// Request is the request message as JSON marshals it; nil is empty.
	Request any
	// Stream: the method streams its answer; every message is kept.
	Stream bool
}

// Verdict is what became of a call.
type Verdict int

const (
	// Allowed: every decision let the call through and it answered.
	Allowed Verdict = iota + 1
	// Admitted: the authority and the hop let the call through, it reached
	// its method, and the method refused the request for a reason of its own
	// (an argument it requires, a record that does not exist). It says the
	// caller may make the call. See Do for the exact rule.
	Admitted
	// Denied: the call was refused for who makes it, by the edge's issuance,
	// the hop's admission or a module on the way.
	Denied
	// Unserved: the composition serves no such call to anyone: the edge
	// routes the procedure to no module, or no module implements it.
	Unserved
	// Failed: the call reached no verdict: the module did not answer, the hop
	// or the authority could not decide, a fault, a deadline. Nobody was let
	// through and nobody was refused, so it satisfies no expectation.
	Failed
)

func (v Verdict) String() string {
	return [...]string{"no verdict", "allowed", "admitted", "denied", "unserved", "failed"}[v]
}

// Outcome is a call's answer.
type Outcome struct {
	Verdict Verdict
	// Status is the HTTP status; Code the Connect code of a refusal or an
	// error, empty when the call answered.
	Status int
	Code   string
	// Reason is the refusal's or the error's message, as the caller reads it.
	Reason string
	// Body is the answer: the message, or a stream's messages as a JSON array.
	Body json.RawMessage
}

// Value is the answer's value at a dotted path ("traces.0.detail.question.text"),
// nil when the answer holds none there.
func (o Outcome) Value(path string) any {
	var at any
	if json.Unmarshal(o.Body, &at) != nil {
		return nil
	}
	for _, step := range strings.Split(path, ".") {
		switch node := at.(type) {
		case map[string]any:
			at = node[step]
		case []any:
			var i int
			if _, err := fmt.Sscanf(step, "%d", &i); err != nil || i < 0 || i >= len(node) {
				return nil
			}
			at = node[i]
		default:
			return nil
		}
	}
	return at
}

// Text is Value as text, empty when it is none.
func (o Outcome) Text(path string) string {
	text, _ := o.Value(path).(string)
	return text
}

// Do makes the call as the person and answers what became of it. A call
// that cannot be made at all (the edge unreachable) is the test's failure.
//
// The verdict is read from the answer alone, first match:
//
//   - Unserved: the edge's own "no module serves <procedure>": it routes the
//     procedure for no module. On the page route it says so as a Connect
//     refusal (403 permission_denied), which is no decision on the person.
//   - Denied: Connect permission_denied or unauthenticated, or HTTP 403 or 401.
//   - Failed: an error that says "the authority refused" and is no denial: the
//     hop relaying that the authority reached no decision on the caller (a
//     module it does not hold, an installation that is not active).
//   - Unserved: Connect unimplemented, or HTTP 404 with no Connect code.
//   - Allowed: HTTP 200 with no error (a stream: no error in its last frame).
//   - Admitted: an error only the method itself gives of a request it was
//     handed: Connect invalid_argument, not_found, already_exists,
//     failed_precondition, out_of_range or aborted; or, with no Connect code
//     (a route), HTTP 400 to 499 other than 408, 429 and 499.
//   - Failed: everything else: HTTP 5xx (the edge's 502 "the module did not
//     answer"), a redirect, Connect unavailable, internal, unknown,
//     deadline_exceeded, canceled, resource_exhausted, data_loss, and a code
//     this list does not know.
//
// So "admitted" is never inferred from the absence of a refusal: a module
// that is down, a hop that could not reach it or the authority, a fault and a
// timeout are Failed, which satisfies no expectation (Expect).
func (p *Person) Do(t testing.TB, call Call) Outcome {
	t.Helper()
	out, err := p.do(call)
	if err != nil {
		t.Fatalf("scenario: %s calling %s: %v", p.ID, call.Procedure, err)
	}
	return out
}

func (p *Person) do(call Call) (Outcome, error) {
	// The seating the run asked for is what the call is decided on: the host
	// may have seated its people again since the last call.
	if err := p.c.holdSeats(context.Background()); err != nil {
		return Outcome{}, err
	}
	payload := []byte("{}")
	if call.Request != nil {
		var err error
		if payload, err = json.Marshal(call.Request); err != nil {
			return Outcome{}, err
		}
	}
	method, path, rest := http.MethodPost, "/"+call.Procedure, false
	if verb, route, ok := strings.Cut(call.Procedure, " "); ok {
		method, path, rest = verb, route, true
	}
	if call.Page != "" && !rest {
		path = "/api/solutions/" + call.Page + "/proxy/_browser" + path
	}
	content := "application/json"
	if call.Stream {
		content, payload = "application/connect+json", envelope(payload)
	}
	var body io.Reader
	if method != http.MethodGet && method != http.MethodHead {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, p.c.origin+path, body)
	if err != nil {
		return Outcome{}, err
	}
	req.Header.Set("Authorization", "Bearer "+p.bearer)
	req.Header.Set("Content-Type", content)
	if !rest {
		req.Header.Set("Connect-Protocol-Version", "1")
	}
	res, err := p.c.client.Do(req)
	if err != nil {
		return Outcome{}, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return Outcome{}, err
	}
	out := Outcome{Status: res.StatusCode, Body: raw}
	if call.Stream && res.StatusCode == http.StatusOK {
		out.Body, out.Code, out.Reason = frames(raw)
	} else if res.StatusCode != http.StatusOK {
		// A Connect refusal says code and message; the edge's own says error.
		var refusal struct{ Code, Message, Error string }
		if json.Unmarshal(raw, &refusal) != nil {
			refusal.Message = strings.TrimSpace(string(raw))
		}
		out.Code, out.Reason = refusal.Code, refusal.Message+refusal.Error
	}
	out.Verdict = verdictOf(res.StatusCode, out.Code, out.Reason)
	return out, nil
}

// verdictOf reads a verdict from an answer's HTTP status, Connect code and
// message: the rule Do states.
func verdictOf(status int, code, reason string) Verdict {
	switch {
	case strings.HasPrefix(reason, "no module serves "):
		return Unserved
	case code == "permission_denied" || code == "unauthenticated" || status == http.StatusForbidden || status == http.StatusUnauthorized:
		return Denied
	case strings.Contains(reason, "the authority refused"):
		return Failed
	case code == "unimplemented" || code == "" && status == http.StatusNotFound:
		return Unserved
	case code == "" && status == http.StatusOK:
		return Allowed
	}
	switch code {
	case "invalid_argument", "not_found", "already_exists", "failed_precondition", "out_of_range", "aborted":
		return Admitted
	case "":
		// 499 is a request whose caller left before it was answered.
		if status >= 400 && status < 500 && status != http.StatusRequestTimeout && status != http.StatusTooManyRequests && status != 499 {
			return Admitted
		}
	}
	return Failed
}

// envelope frames one message as Connect's streaming protocol sends it.
func envelope(message []byte) []byte {
	head := make([]byte, 5)
	binary.BigEndian.PutUint32(head[1:], uint32(len(message)))
	return append(head, message...)
}

// frames reads a Connect stream: its messages as a JSON array, and the code
// and message of the error its last frame carries, when it carries one.
func frames(raw []byte) (messages json.RawMessage, code, reason string) {
	var out []json.RawMessage
	for len(raw) >= 5 {
		size := int(binary.BigEndian.Uint32(raw[1:5]))
		if len(raw) < 5+size {
			break
		}
		frame := raw[5 : 5+size]
		if raw[0]&2 != 0 {
			var end struct {
				Error struct{ Code, Message string }
			}
			_ = json.Unmarshal(frame, &end)
			code, reason = end.Error.Code, end.Error.Message
		} else {
			out = append(out, frame)
		}
		raw = raw[5+size:]
	}
	messages, _ = json.Marshal(out)
	return messages, code, reason
}
