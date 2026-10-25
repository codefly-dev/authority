package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

var (
	island = regexp.MustCompile(`(?s)<script id="sign-in" type="application/json">(.*?)</script>`)
	asset  = regexp.MustCompile(`/auth/assets/[A-Za-z0-9_.-]+\.(?:js|css)`)
)

// pageData is what the sign-in page's data island carries, which the
// kit-built page renders as one form per person (web/src/sign-in.tsx).
func pageData(t *testing.T, res *http.Response, body string) signInData {
	t.Helper()
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("the sign-in page answered %d %s: %s", res.StatusCode, res.Header.Get("Content-Type"), body)
	}
	m := island.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("the page has no data island:\n%s", body)
	}
	var data signInData
	if err := json.Unmarshal([]byte(m[1]), &data); err != nil {
		t.Fatalf("the island is not JSON: %v\n%s", err, m[1])
	}
	return data
}

// The page names each person's organisation and roles, writes a return to
// another site as the root, and its built script and stylesheet are served
// beside it; the asset directory itself is not listed.
func TestTheSignInPageIsTheKitBuild(t *testing.T) {
	f := newFixture(t)
	res, body := f.do(t, http.MethodGet, "/auth/sign-in?return=//elsewhere.test/", nil)
	data := pageData(t, res, body)
	if data.Return != "/" || len(data.People) != 1 {
		t.Fatalf("the page carries %+v", data)
	}
	if p := data.People[0]; p.OrganizationID != "acme" || len(p.Roles) != 1 || p.Roles[0] != "editor" {
		t.Fatalf("person = %+v", p)
	}
	assets := asset.FindAllString(body, -1)
	if len(assets) < 2 {
		t.Fatalf("the page names no built script and stylesheet: %v", assets)
	}
	for _, a := range assets {
		if res, _ := f.do(t, http.MethodGet, a, nil); res.StatusCode != http.StatusOK {
			t.Fatalf("%s answered %d", a, res.StatusCode)
		}
	}
	if res, _ := f.do(t, http.MethodGet, "/auth/assets/", nil); res.StatusCode != http.StatusNotFound {
		t.Fatalf("the asset directory answered %d", res.StatusCode)
	}
}

// A value the page renders is data, never markup: a fixture email carrying a
// closing script tag stays inside the island.
func TestTheSignInIslandEscapesItsData(t *testing.T) {
	var out strings.Builder
	if err := signInPage.Execute(&out, signInData{People: []fixturePerson{{Email: "</script><script>alert(1)</script>", Roles: []string{}}}, Return: "/"}); err != nil {
		t.Fatal(err)
	}
	m := island.FindStringSubmatch(out.String())
	var data signInData
	if m == nil || json.Unmarshal([]byte(m[1]), &data) != nil || len(data.People) != 1 || data.People[0].Email != "</script><script>alert(1)</script>" {
		t.Fatalf("the island did not round-trip its data:\n%s", out.String())
	}
}
