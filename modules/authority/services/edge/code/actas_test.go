package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// cookiesOf is the cookies a response set, by name; a cleared one is "".
func cookiesOf(res *http.Response) map[string]string {
	out := map[string]string{}
	for _, c := range res.Cookies() {
		out[c.Name] = c.Value
		if c.MaxAge < 0 {
			out[c.Name] = ""
		}
	}
	return out
}

func (f fixture) actAs(t *testing.T, form url.Values, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	header := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Origin": {f.edge.URL}}
	for _, c := range cookies {
		header.Add("Cookie", c.String())
	}
	res, _ := f.send(t, http.MethodPost, "/auth/act-as", header, form.Encode())
	return res
}

// Signed in, the page offers the organisation's teams; "act as this team"
// opens a cast the browser then is, with the own session kept as the way
// back; "back" restores it and forgets the cast. Each is a write from this
// origin.
func TestAPersonActsAsATeamAndComesBack(t *testing.T) {
	f := newFixture(t)
	own := f.signIn(t)
	res, body := f.do(t, http.MethodGet, "/auth/sign-in?return=/records", http.Header{"Cookie": {own.String()}})
	data := pageData(t, res, body)
	if data.Session == nil || data.Session.PersonDisplayName != "Rémi" || data.Session.CastTeamID != "" || data.Session.Back || strings.Join(data.Session.Teams, ",") != "records-viewer" {
		t.Fatalf("the page carries %+v", data.Session)
	}
	// Act as records-viewer: the browser becomes the cast, and keeps the way back.
	res = f.actAs(t, url.Values{"team": {"records-viewer"}, "return": {"/records"}}, own)
	set := cookiesOf(res)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/records" || set[SessionKey] != "remi-as-viewers" || set[ParentKey] != "remi-session" {
		t.Fatalf("act-as answered %d %s with cookies %v", res.StatusCode, res.Header.Get("Location"), set)
	}
	cast := &http.Cookie{Name: SessionKey, Value: set[SessionKey]}
	parent := &http.Cookie{Name: ParentKey, Value: set[ParentKey]}
	res, body = f.do(t, http.MethodGet, "/auth/session", http.Header{"Cookie": {cast.String() + "; " + parent.String()}})
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `"castTeamId":"records-viewer"`) {
		t.Fatalf("the session answered %d: %s", res.StatusCode, body)
	}
	res, body = f.do(t, http.MethodGet, "/auth/sign-in", http.Header{"Cookie": {cast.String() + "; " + parent.String()}})
	if data = pageData(t, res, body); data.Session == nil || data.Session.CastTeamID != "records-viewer" || !data.Session.Back {
		t.Fatalf("the page carries %+v", data.Session)
	}
	// Back: the own session again, the cast forgotten.
	res = f.actAs(t, url.Values{"action": {"back"}, "return": {"/records"}}, cast, parent)
	if set = cookiesOf(res); res.StatusCode != http.StatusSeeOther || set[SessionKey] != "remi-session" || set[ParentKey] != "" {
		t.Fatalf("back answered %d with cookies %v", res.StatusCode, set)
	}
	if res = f.actAs(t, url.Values{"action": {"back"}}, own); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("back from an own session answered %d", res.StatusCode)
	}
}

// A sign-in from a cast is a new person's session, and clears the way back
// the cast kept: a later "back" cannot restore the earlier person's session
// with no credential.
func TestASignInClearsTheWayBackACastKept(t *testing.T) {
	f := newFixture(t)
	own := f.signIn(t)
	res := f.actAs(t, url.Values{"team": {"records-viewer"}, "return": {"/records"}}, own)
	set := cookiesOf(res)
	cast := &http.Cookie{Name: SessionKey, Value: set[SessionKey]}
	parent := &http.Cookie{Name: ParentKey, Value: set[ParentKey]}
	header := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Origin": {f.edge.URL}, "Cookie": {cast.String() + "; " + parent.String()}}
	res, _ = f.send(t, http.MethodPost, "/auth/sign-in", header, url.Values{"fixtureToken": {"fixture-remi"}, "return": {"/records"}}.Encode())
	if set = cookiesOf(res); res.StatusCode != http.StatusSeeOther || set[SessionKey] != "remi-session" || len(res.Cookies()) != 2 || set[ParentKey] != "" {
		t.Fatalf("a sign-in from a cast answered %d with cookies %v; the way back must be cleared", res.StatusCode, set)
	}
	if res = f.actAs(t, url.Values{"action": {"back"}}, own); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("back after a sign-in answered %d", res.StatusCode)
	}
}

// A team the authority refuses is refused by name, on the page the ask came
// from; an ask from another origin, or with no session, never reaches it.
func TestAnActAsTheAuthorityRefusesIsShownByName(t *testing.T) {
	f := newFixture(t)
	own := f.signIn(t)
	res := f.actAs(t, url.Values{"team": {"records-editor"}, "return": {"/records"}}, own)
	back, err := url.Parse(res.Header.Get("Location"))
	if err != nil || res.StatusCode != http.StatusSeeOther || back.Path != "/auth/sign-in" || !strings.Contains(back.Query().Get("refused"), "could not grant") || back.Query().Get("return") != "/records" {
		t.Fatalf("a refused act-as answered %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if cookies := cookiesOf(res); len(cookies) != 0 {
		t.Fatalf("a refused act-as set %v", cookies)
	}
	res, body := f.do(t, http.MethodGet, back.String(), http.Header{"Cookie": {own.String()}})
	if data := pageData(t, res, body); !strings.Contains(data.Refused, "could not grant") {
		t.Fatalf("the page carries %+v", data)
	}
	res, _ = f.send(t, http.MethodPost, "/auth/act-as", http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Origin": {"https://elsewhere.test"}, "Cookie": {own.String()}}, "team=records-viewer")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("an act-as from another origin answered %d", res.StatusCode)
	}
	if res = f.actAs(t, url.Values{"team": {"records-viewer"}}); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an act-as with no session answered %d", res.StatusCode)
	}
}
