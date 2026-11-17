package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	installationv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/installation/v1"
	"github.com/codefly-dev/sdk-go/receipts"
	"google.golang.org/grpc"
)

// changingRoles is an authority whose person's roles change: each change is a
// new revision, a Work Context is issued at the revision it was asked at, and
// the module (its hop) answers only a context of the current revision, as a
// hop refuses one sealed before a revoke or lacking a role granted since.
type changingRoles struct {
	*standIn
	mu       sync.Mutex
	revision int
	// refuseAll: the module refuses every context, the current one included.
	refuseAll bool
	issues    int
	calls     []moduleCall
	module    *httptest.Server
}

type moduleCall struct{ token, effect, body string }

func (c *changingRoles) Issue(ctx context.Context, in *authorityv1.IssueRequest, opts ...grpc.CallOption) (*authorityv1.IssueResponse, error) {
	out, err := c.standIn.Issue(ctx, in, opts...)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.issues++
	out.Token = fmt.Sprintf("wc-%s-r%d", in.GetAudience(), c.revision)
	return out, nil
}

// change is a role granted or revoked somewhere this edge does not see.
func (c *changingRoles) change() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revision++
}

func (c *changingRoles) seen() (int, []moduleCall) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.issues, append([]moduleCall(nil), c.calls...)
}

func newChangingRoles(t *testing.T) *changingRoles {
	c := &changingRoles{standIn: &standIn{}}
	c.module = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		token := r.Header.Get(WorkContextKey)
		c.calls = append(c.calls, moduleCall{token, r.Header.Get(receipts.EffectIDHeaderName), string(body)})
		current := !c.refuseAll && token == fmt.Sprintf("wc-records-r%d", c.revision)
		c.mu.Unlock()
		if !current {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"the hop refused this Work Context"}`))
			return
		}
		_, _ = w.Write([]byte("answered"))
	}))
	t.Cleanup(c.module.Close)
	return c
}

func (c *changingRoles) edge(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(&Edge{Sessions: c.standIn, Authority: c, Modules: map[string]Module{"records": {Name: "records", REST: mustURL(t, c.module.URL)}}})
	t.Cleanup(srv.Close)
	return srv
}

// call sends one module call as Rémi presenting his bearer.
func call(t *testing.T, srv *httptest.Server, body io.Reader) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/records/items", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer remi-session")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	answer, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(answer)
}

// A Work Context the edge holds is the person's roles as they were when it was
// issued. When their roles change (a grant, or a revoke that leaves them
// another role) the module refuses the held one, and that refusal is not the
// person's answer: the edge drops it, asks the authority again and sends the
// same call once more, under a new effect, so the change applies from the next
// call. The fresh context is then the held one.
func TestACallRefusedWithAHeldWorkContextIsSentAgainWithAFreshOne(t *testing.T) {
	c := newChangingRoles(t)
	srv := c.edge(t)
	if code, body := call(t, srv, strings.NewReader("first")); code != http.StatusOK {
		t.Fatalf("the first call answered %d: %s", code, body)
	}
	c.change()
	if code, body := call(t, srv, strings.NewReader("after the change")); code != http.StatusOK || body != "answered" {
		t.Fatalf("the call after a role change answered %d: %s", code, body)
	}
	issues, calls := c.seen()
	if issues != 2 || len(calls) != 3 {
		t.Fatalf("issued %d, the module received %v", issues, calls)
	}
	if refused, again := calls[1], calls[2]; refused.token != "wc-records-r0" || again.token != "wc-records-r1" || refused.body != "after the change" || again.body != "after the change" ||
		refused.effect == "" || again.effect == "" || refused.effect == again.effect {
		t.Fatalf("the refused call %+v was sent again as %+v", refused, again)
	}
	if code, _ := call(t, srv, nil); code != http.StatusOK {
		t.Fatalf("the next call answered %d", code)
	}
	if issues, calls := c.seen(); issues != 2 || len(calls) != 4 {
		t.Fatalf("the fresh context was not held: issued %d, the module received %v", issues, calls)
	}
}

// A refusal of a context issued for this very call is the module's answer,
// handed on as it is; and a held one is asked again once, never in a loop.
func TestARefusalOfAFreshWorkContextIsTheModulesAnswer(t *testing.T) {
	c := newChangingRoles(t)
	c.refuseAll = true
	srv := c.edge(t)
	for i, want := range []struct{ issues, calls int }{{1, 1}, {2, 3}, {3, 5}} {
		code, body := call(t, srv, strings.NewReader("refused"))
		if code != http.StatusForbidden || !strings.Contains(body, "the hop refused this Work Context") {
			t.Fatalf("call %d answered %d: %s", i, code, body)
		}
		if issues, calls := c.seen(); issues != want.issues || len(calls) != want.calls {
			t.Fatalf("call %d: issued %d, the module received %d calls", i, issues, len(calls))
		}
	}
}

// A call whose body cannot be sent again (its length is not known, or it is
// too large to keep) is not: the refusal is handed on, the held context is
// still dropped, and the next call is asked for afresh.
func TestACallThatCannotBeSentAgainStillDropsTheHeldWorkContext(t *testing.T) {
	for name, body := range map[string]func() io.Reader{
		"a body of unknown length": func() io.Reader { return struct{ io.Reader }{strings.NewReader("streamed")} },
		"a body too large to keep": func() io.Reader { return strings.NewReader(strings.Repeat("x", replayBytes+1)) },
	} {
		c := newChangingRoles(t)
		srv := c.edge(t)
		if code, _ := call(t, srv, nil); code != http.StatusOK {
			t.Fatalf("%s: the first call answered %d", name, code)
		}
		c.change()
		if code, answer := call(t, srv, body()); code != http.StatusForbidden || !strings.Contains(answer, "the hop refused this Work Context") {
			t.Fatalf("%s: answered %d: %s", name, code, answer)
		}
		if issues, calls := c.seen(); issues != 1 || len(calls) != 2 || len(calls[1].body) == 0 {
			t.Fatalf("%s: issued %d, the module received %d calls", name, issues, len(calls))
		}
		if code, _ := call(t, srv, nil); code != http.StatusOK {
			t.Fatalf("%s: the next call answered %d", name, code)
		}
		if issues, calls := c.seen(); issues != 2 || calls[len(calls)-1].token != "wc-records-r1" {
			t.Fatalf("%s: the held context was kept: issued %d, the module received %v", name, issues, calls[len(calls)-1])
		}
	}
}

// A role granted or revoked through this edge, from its setup page or its
// host face, applies from the next call: what the edge held was issued before
// the change, so it holds none of it after, and /auth/session reads the
// person's authority afresh too.
func TestARoleChangedThroughThisEdgeAppliesFromTheNextCall(t *testing.T) {
	c := newChangingRoles(t)
	host := &setupHost{standIn: c.standIn}
	e := &Edge{Sessions: host, Authority: c, Offers: host, Installer: host, Modules: map[string]Module{"records": {Name: "records", REST: mustURL(t, c.module.URL)}}}
	srv := httptest.NewServer(e)
	t.Cleanup(srv.Close)
	f := fixture{edge: srv}
	cookie := &http.Cookie{Name: SessionKey, Value: "remi-session"}
	want := 0
	issued := func(what string) {
		t.Helper()
		for range 2 {
			if code, body := call(t, srv, nil); code != http.StatusOK {
				t.Fatalf("%s: a call answered %d: %s", what, code, body)
			}
		}
		want++
		if issues, _ := c.seen(); issues != want {
			t.Fatalf("%s: issued %d times, want %d", what, issues, want)
		}
	}
	issued("before any change")
	for _, action := range []string{"grant", "revoke"} {
		c.change()
		res, body := f.post(t, cookie, srv.URL, url.Values{"action": {action}, "target": {"proposals"}, "installationId": {"i1"}, "role": {"admin"}, "subject": {"person:remi"}})
		if res.StatusCode != http.StatusSeeOther {
			t.Fatalf("the setup page's %s answered %d: %s", action, res.StatusCode, body)
		}
		issued("after the setup page's " + action)
	}
	c.change()
	if _, err := browser[installationv1.GrantRoleRequest, installationv1.Installation](t, srv, srv.URL, "remi-session", installationv1.InstallationService_GrantRole_FullMethodName,
		&installationv1.GrantRoleRequest{OrganizationId: "acme", InstallationId: "i1", Role: "admin", PersonId: "remi"}); err != nil {
		t.Fatal(err)
	}
	issued("after the host face's GrantRole")
	c.change()
	if _, err := browser[installationv1.RevokeRoleRequest, installationv1.Installation](t, srv, srv.URL, "remi-session", installationv1.InstallationService_RevokeRole_FullMethodName,
		&installationv1.RevokeRoleRequest{OrganizationId: "acme", InstallationId: "i1", Role: "admin", PersonId: "remi"}); err != nil {
		t.Fatal(err)
	}
	issued("after the host face's RevokeRole")
	// No call was refused on the way: the change reached the edge before one.
	if _, calls := c.seen(); len(calls) != 2*want {
		t.Fatalf("the module received %d calls for %d sent", len(calls), 2*want)
	}

	// The session's own read is of the held context too.
	c.change()
	if _, err := browser[installationv1.GrantRoleRequest, installationv1.Installation](t, srv, srv.URL, "remi-session", installationv1.InstallationService_GrantRole_FullMethodName,
		&installationv1.GrantRoleRequest{OrganizationId: "acme", InstallationId: "i1", Role: "user", TeamId: "records-user"}); err != nil {
		t.Fatal(err)
	}
	if res, _ := sessionOf(t, e, cookie); res.Code != http.StatusOK {
		t.Fatalf("session answered %d: %s", res.Code, res.Body)
	}
	if issues, _ := c.seen(); issues != want+1 {
		t.Fatalf("the session read a context held from before the change: issued %d, want %d", issues, want+1)
	}
}

// Calls refused together with the same held context drop it once: the one
// that asked again first holds the fresh context for the others.
func TestCallsRefusedTogetherDoNotDropTheFreshWorkContext(t *testing.T) {
	c := newChangingRoles(t)
	e := &Edge{Authority: c, Now: time.Now}
	stale, err := e.workContext(context.Background(), "remi-session", "records", "")
	if err != nil {
		t.Fatal(err)
	}
	c.change()
	e.forget("remi-session", "records", "", stale.token)
	fresh, err := e.workContext(context.Background(), "remi-session", "records", "")
	if err != nil || fresh.token == stale.token || fresh.cached {
		t.Fatalf("after a refusal the edge holds %+v (%v)", fresh, err)
	}
	e.forget("remi-session", "records", "", stale.token)
	if again, err := e.workContext(context.Background(), "remi-session", "records", ""); err != nil || again.token != fresh.token || !again.cached {
		t.Fatalf("a second refusal of the old context dropped the fresh one: %+v (%v)", again, err)
	}
}
