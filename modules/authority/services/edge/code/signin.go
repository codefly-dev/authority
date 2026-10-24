package main

import (
	"html/template"
	"net/http"

	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"google.golang.org/grpc/status"
)

// The sign-in page is the host's, as it is in a cell: a frontend sends a
// browser with no session here, and it comes back signed in. The people are
// the authority's fixture people, defined once, in its fixture.
var signInPage = template.Must(template.New("sign-in").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>
:root{color-scheme:light dark;--bg:#f6f7f9;--fg:#15202b;--muted:#5d6b7a;--line:#d8dee6;--card:#fff;--accent:#1f4fb3}
@media (prefers-color-scheme:dark){:root{--bg:#0f141b;--fg:#e8edf3;--muted:#9aa6b6;--line:#2a3442;--card:#161d27;--accent:#86a6ff}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;padding:48px 16px}
main{max-width:520px;margin:0 auto;display:grid;gap:16px}
h1{font-size:22px;margin:0}p{margin:0;color:var(--muted)}
ul{list-style:none;margin:0;padding:0;display:grid;gap:8px}
button{all:unset;box-sizing:border-box;width:100%;cursor:pointer;display:grid;gap:2px;padding:12px 14px;border:1px solid var(--line);border-radius:8px;background:var(--card)}
button:hover,button:focus-visible{border-color:var(--accent)}
.who{font-weight:600}.what{color:var(--muted);font-size:13px}
</style></head><body><main>
<h1>Sign in</h1>
<p>This run's authority signs in the people of its fixture. Choose who you are.</p>
{{if .People}}<ul>{{range .People}}<li><form method="post" action="/auth/sign-in">
<input type="hidden" name="fixtureToken" value="{{.FixtureToken}}"><input type="hidden" name="return" value="{{$.Return}}">
<button type="submit"><span class="who">{{.Email}}</span><span class="what">{{.OrganizationId}}{{range .Roles}} · {{.}}{{else}} · no role{{end}}</span></button>
</form></li>{{end}}</ul>{{else}}<p>This authority lists no fixture people: it signs people in through its own identity provider.</p>{{end}}
</main></body></html>`))

func (e *Edge) signInPage(w http.ResponseWriter, r *http.Request) {
	people, err := e.Sessions.ListFixturePeople(r.Context(), &sessionv1.ListFixturePeopleRequest{})
	if err != nil {
		refuse(w, http.StatusBadGateway, "the authority did not list who signs in: "+status.Convert(err).Message())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = signInPage.Execute(w, struct {
		People []*sessionv1.FixturePerson
		Return string
	}{people.GetPeople(), localPath(r.URL.Query().Get("return"))})
}
