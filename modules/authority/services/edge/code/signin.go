package main

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"strings"

	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"google.golang.org/grpc/status"
)

// The sign-in page is the host's, as it is in a cell: a frontend sends a
// browser with no session here, and it comes back signed in. The people are
// the authority's fixture people, defined once, in its fixture.
//
// The page is built from the platform's UI kit (web/, `npm run build`) into
// signin/out, a committed, generated artifact this binary embeds. Its
// index.html is executed as a template: the edge writes who may sign in and
// where to return into the page's JSON data island, so the page fetches
// nothing and each person is still a plain form posted back to /auth/sign-in.
//
//go:embed signin/out
var signInBuild embed.FS

// signInAssets is the page's hashed script and stylesheet, served under
// /auth/assets/ (the build's base is /auth/).
var signInAssets = func() http.Handler {
	out, err := fs.Sub(signInBuild, "signin/out")
	if err != nil {
		panic(err)
	}
	return http.StripPrefix("/auth/", http.FileServer(http.FS(out)))
}()

var signInPage = template.Must(template.ParseFS(signInBuild, "signin/out/index.html"))

// fixturePerson is one person as the page reads them (web/src/sign-in.tsx).
type fixturePerson struct {
	Description      string   `json:"description,omitempty"`
	StartHere        bool     `json:"startHere,omitempty"`
	PersonID         string   `json:"personId"`
	Email            string   `json:"email"`
	OrganizationID   string   `json:"organizationId"`
	OrganizationName string   `json:"organizationName"`
	Roles            []string `json:"roles"`
	FixtureToken     string   `json:"fixtureToken"`
}

// signInData is the page's data island: html/template writes it as JSON,
// escaped for a script element.
type signInData struct {
	People []fixturePerson `json:"people"`
	Return string          `json:"return"`
}

func (e *Edge) signInPage(w http.ResponseWriter, r *http.Request) {
	forbidFraming(w)
	people, err := e.Sessions.ListFixturePeople(r.Context(), &sessionv1.ListFixturePeopleRequest{})
	if err != nil {
		refuse(w, http.StatusBadGateway, "the authority did not list who signs in: "+status.Convert(err).Message())
		return
	}
	data := signInData{People: []fixturePerson{}, Return: localPath(r.URL.Query().Get("return"))}
	for _, p := range people.GetPeople() {
		roles := p.GetRoles()
		if roles == nil {
			roles = []string{}
		}
		data.People = append(data.People, fixturePerson{PersonID: p.GetPersonId(), Email: p.GetEmail(), OrganizationID: p.GetOrganizationId(), OrganizationName: p.GetOrganizationDisplayName(), Roles: roles, FixtureToken: p.GetFixtureToken()})
	}
	data.People, err = selectSignInPeople(data.People, e.SignInChoices)
	if err != nil {
		refuse(w, http.StatusInternalServerError, "the sign-in choices are invalid: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = signInPage.Execute(w, data)
}

// signInAsset serves the page's built script and stylesheet; nothing else is
// under /auth/assets/.
func (e *Edge) signInAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		refuse(w, http.StatusMethodNotAllowed, "the sign-in page's assets are read with GET")
		return
	}
	if strings.HasSuffix(r.URL.Path, "/") {
		refuse(w, http.StatusNotFound, "no sign-in asset at "+r.URL.Path)
		return
	}
	signInAssets.ServeHTTP(w, r)
}
