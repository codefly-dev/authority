package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// signOut posts a sign-out from this origin with the cookies the browser holds.
func (f fixture) signOut(t *testing.T, cookies ...*http.Cookie) (*http.Response, string) {
	t.Helper()
	header := http.Header{"Origin": {f.edge.URL}}
	for _, c := range cookies {
		header.Add("Cookie", c.String())
	}
	return f.do(t, http.MethodPost, "/auth/sign-out", header)
}

// cast acts as records-user and answers the cookies the browser then holds.
func (f fixture) cast(t *testing.T, own *http.Cookie) (cast, parent *http.Cookie) {
	t.Helper()
	res := f.actAs(t, url.Values{"team": {"records-user"}, "return": {"/records"}}, own)
	set := cookiesOf(res)
	if res.StatusCode != http.StatusSeeOther || set[SessionKey] != "remi-as-users" || set[ParentKey] != "remi-session" {
		t.Fatalf("act-as answered %d with cookies %v", res.StatusCode, set)
	}
	return &http.Cookie{Name: SessionKey, Value: set[SessionKey]}, &http.Cookie{Name: ParentKey, Value: set[ParentKey]}
}

// Signing out ends the session at the host (End), so a copy of its bearer is
// unauthenticated from then on; from a cast it ends the session the cast was
// opened from too. A session the host already ended is signed out all the
// same. When the host does not answer, the browser is still signed out here
// and is told the session was not ended.
func TestSignOutEndsTheSessionAtTheHost(t *testing.T) {
	f := newFixture(t)
	own := f.signIn(t)
	res, body := f.signOut(t, own)
	if ended, _ := f.authority.state(); res.StatusCode != http.StatusNoContent || !reflect.DeepEqual(ended, []string{"remi-session"}) {
		t.Fatalf("sign-out answered %d %s, and the host ended %v", res.StatusCode, body, ended)
	}
	if res, _ := f.do(t, http.MethodGet, "/auth/session", http.Header{"Authorization": {"Bearer remi-session"}}); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a copy of the signed-out bearer still answers /auth/session: %d", res.StatusCode)
	}
	if res, _ := f.do(t, http.MethodGet, "/v1/records/types", http.Header{"Authorization": {"Bearer remi-session"}}); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a copy of the signed-out bearer still reaches a module: %d", res.StatusCode)
	}
	if res, _ := f.signOut(t, own); res.StatusCode != http.StatusNoContent || len(res.Cookies()) != 2 {
		t.Fatalf("signing out of a session the host already ended answered %d", res.StatusCode)
	}

	f = newFixture(t)
	cast, parent := f.cast(t, f.signIn(t))
	res, body = f.signOut(t, cast, parent)
	if ended, _ := f.authority.state(); res.StatusCode != http.StatusNoContent || !reflect.DeepEqual(ended, []string{"remi-as-users", "remi-session"}) {
		t.Fatalf("sign-out from a cast answered %d %s, and the host ended %v", res.StatusCode, body, ended)
	}

	f = newFixture(t)
	own = f.signIn(t)
	f.authority.endErr = status.Error(codes.Unavailable, "connection refused")
	res, body = f.signOut(t, own)
	if cleared := cookiesOf(res); res.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "did not end") || !strings.Contains(body, "connection refused") ||
		len(res.Cookies()) != 2 || cleared[SessionKey] != "" || cleared[ParentKey] != "" {
		t.Fatalf("a sign-out the host did not answer was told %d %s with cookies %v", res.StatusCode, body, res.Cookies())
	}
}

// Leaving a cast ends it at the host: "back" is the cast's end, not the
// browser forgetting it. The session it was opened from is untouched and
// becomes the browser's again, for as long as it lasts. A cast the host did
// not end is not left; a way back to a session that has ended is a sign-in.
func TestLeavingACastEndsItAtTheHost(t *testing.T) {
	f := newFixture(t)
	cast, parent := f.cast(t, f.signIn(t))
	res := f.actAs(t, url.Values{"action": {"back"}, "return": {"/records"}}, cast, parent)
	set := cookiesOf(res)
	if ended, _ := f.authority.state(); res.StatusCode != http.StatusSeeOther || set[SessionKey] != "remi-session" || set[ParentKey] != "" || !reflect.DeepEqual(ended, []string{"remi-as-users"}) {
		t.Fatalf("back answered %d with cookies %v, and the host ended %v", res.StatusCode, set, ended)
	}
	for _, c := range res.Cookies() {
		if c.Name == SessionKey && !c.Expires.Equal(sessionExpiry) {
			t.Fatalf("the session restored expires %v, want its own expiry %v", c.Expires, sessionExpiry)
		}
	}
	if res, _ := f.do(t, http.MethodGet, "/auth/session", http.Header{"Authorization": {"Bearer remi-as-users"}}); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a copy of the cast's bearer still answers after back: %d", res.StatusCode)
	}

	f = newFixture(t)
	cast, parent = f.cast(t, f.signIn(t))
	f.authority.endErr = status.Error(codes.Unavailable, "connection refused")
	res = f.actAs(t, url.Values{"action": {"back"}, "return": {"/records"}}, cast, parent)
	if res.StatusCode != http.StatusServiceUnavailable || len(res.Cookies()) != 0 {
		t.Fatalf("a cast the host did not end was left: %d with cookies %v", res.StatusCode, res.Cookies())
	}

	// The session the cast was opened from ended meanwhile (signed out in
	// another tab): there is no way back, and the browser signs in again.
	f = newFixture(t)
	cast, parent = f.cast(t, f.signIn(t))
	f.authority.ended = []string{"remi-session"}
	res = f.actAs(t, url.Values{"action": {"back"}, "return": {"/records"}}, cast, parent)
	if set := cookiesOf(res); res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(res.Header.Get("Location"), "/auth/sign-in") || len(res.Cookies()) != 2 || set[SessionKey] != "" || set[ParentKey] != "" {
		t.Fatalf("back to an ended session answered %d %s with cookies %v", res.StatusCode, res.Header.Get("Location"), res.Cookies())
	}
}

// Every cookie carrying a session lasts no longer than the session: the
// sign-in's until the session's expiry, a cast's and the way back kept beside
// it until the cast's. A host that states no expiry opened no session this
// edge keeps.
func TestACookieLastsNoLongerThanItsSession(t *testing.T) {
	expires := func(res *http.Response) map[string]time.Time {
		out := map[string]time.Time{}
		for _, c := range res.Cookies() {
			out[c.Name] = c.Expires
		}
		return out
	}
	f := newFixture(t)
	res, _ := f.signInAs(t, "fixture-remi", "/records", f.edge.URL)
	if got := expires(res)[SessionKey]; !got.Equal(sessionExpiry) {
		t.Fatalf("the session cookie expires %v, want the session's expiry %v", got, sessionExpiry)
	}
	own := &http.Cookie{Name: SessionKey, Value: "remi-session"}
	res = f.actAs(t, url.Values{"team": {"records-user"}, "return": {"/records"}}, own)
	if got := expires(res); !got[SessionKey].Equal(castExpiry) || !got[ParentKey].Equal(castExpiry) {
		t.Fatalf("the cast's cookies expire %v, want the cast's expiry %v", got, castExpiry)
	}
	over, _, err := castOver(t, f, f.edge.URL, "records-user")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range over.Header().Values("Set-Cookie") {
		if !strings.Contains(line, "Expires="+castExpiry.UTC().Format(http.TimeFormat)) {
			t.Fatalf("a cast opened over the session face set %q, want it to expire with the cast at %v", line, castExpiry)
		}
	}

	f = newFixture(t)
	f.authority.noExpiry = true
	res, body := f.signInAs(t, "fixture-remi", "/records", f.edge.URL)
	if res.StatusCode != http.StatusBadGateway || !strings.Contains(body, "expiry") || len(res.Cookies()) != 0 {
		t.Fatalf("a session with no expiry was kept: %d %s with cookies %v", res.StatusCode, body, res.Cookies())
	}
	f.authority.noExpiry = false
	own = f.signIn(t)
	f.authority.noExpiry = true
	res = f.actAs(t, url.Values{"team": {"records-user"}, "return": {"/records"}}, own)
	if res.StatusCode != http.StatusBadGateway || len(res.Cookies()) != 0 {
		t.Fatalf("a cast with no expiry was kept: %d with cookies %v", res.StatusCode, res.Cookies())
	}
	if _, _, err := castOver(t, f, f.edge.URL, "records-user"); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("a cast with no expiry over the session face: want unavailable, got %v", err)
	}
}

// A Work Context the edge holds is dropped when the session's grant epoch on
// Current differs from the one it was issued at: a role granted or revoked
// anywhere, by another edge or by the host itself, applies from the next call,
// with no call refused on the way. While the epoch is the same the held one
// is used.
func TestAGrantMadeElsewhereAppliesFromTheNextCall(t *testing.T) {
	c := newChangingRoles(t)
	c.standIn.moved("epoch-1")
	e := &Edge{Sessions: c.standIn, Authority: c, Modules: map[string]Module{"records": {Name: "records", REST: mustURL(t, c.module.URL)}}}
	srv := httptest.NewServer(e)
	t.Cleanup(srv.Close)
	want, sent := 0, 0
	issued := func(what string) {
		t.Helper()
		for range 2 {
			sent++
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
	for _, epoch := range []string{"epoch-2", "epoch-3"} {
		c.change()
		c.standIn.moved(epoch)
		issued("after a grant made elsewhere, at " + epoch)
	}
	if _, calls := c.seen(); len(calls) != sent {
		t.Fatalf("the module received %d calls for %d sent: a call was refused before the change applied", len(calls), sent)
	}

	// The session's own read is of the held context too.
	c.change()
	c.standIn.moved("epoch-4")
	if res, _ := sessionOf(t, e, &http.Cookie{Name: SessionKey, Value: "remi-session"}); res.Code != http.StatusOK {
		t.Fatalf("session answered %d: %s", res.Code, res.Body)
	}
	if issues, _ := c.seen(); issues != want+1 {
		t.Fatalf("the session read a context held from before the change: issued %d, want %d", issues, want+1)
	}
}

// A session ended or expired at the host is unauthenticated at the edge from
// the next call, though the edge holds a Work Context issued for it that has
// not lapsed: the module is not reached.
func TestAnEndedSessionReachesNoModuleThoughItsWorkContextIsHeld(t *testing.T) {
	c := newChangingRoles(t)
	srv := c.edge(t)
	if code, body := call(t, srv, nil); code != http.StatusOK {
		t.Fatalf("a call answered %d: %s", code, body)
	}
	c.standIn.mu.Lock()
	c.standIn.ended = []string{"remi-session"}
	c.standIn.mu.Unlock()
	if code, body := call(t, srv, nil); code != http.StatusUnauthorized {
		t.Fatalf("a call for an ended session answered %d: %s", code, body)
	}
	if _, calls := c.seen(); len(calls) != 1 {
		t.Fatalf("the module received %d calls; the ended session's must not reach it", len(calls))
	}
}
