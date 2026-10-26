package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"google.golang.org/grpc"
)

func TestParseSignInChoices(t *testing.T) {
	for _, value := range []string{"", " \n "} {
		choices, err := parseSignInChoices(value)
		if err != nil || choices != nil {
			t.Fatalf("absent configuration: %v, %v", choices, err)
		}
	}
	for name, tc := range map[string]struct{ value, reason string }{
		"malformed":           {`[`, "expected an array"},
		"unknown field":       {`[{"personId":"one","description":"One","roles":["admin"]}]`, "unknown field"},
		"empty":               {`[]`, "at least one"},
		"null":                {`null`, "at least one"},
		"trailing":            {`[{"personId":"one","description":"One"}] {}`, "single array"},
		"missing id":          {`[{"description":"One"}]`, "nonblank fixture person ID"},
		"padded id":           {`[{"personId":" one ","description":"One"}]`, "without surrounding whitespace"},
		"missing description": {`[{"personId":"one"}]`, "one-line description"},
		"blank description":   {`[{"personId":"one","description":" "}]`, "one-line description"},
		"multiline":           {`[{"personId":"one","description":"One\nTwo"}]`, "one-line description"},
		"duplicate":           {`[{"personId":"one","description":"One"},{"personId":"one","description":"Again"}]`, "more than once"},
		"two starts":          {`[{"personId":"one","description":"One","startHere":true},{"personId":"two","description":"Two","startHere":true}]`, "only one"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseSignInChoices(tc.value)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("got %v, want reason %q", err, tc.reason)
			}
		})
	}
}

type choiceSessions struct {
	*standIn
	people []*sessionv1.FixturePerson
}

func (s choiceSessions) ListFixturePeople(context.Context, *sessionv1.ListFixturePeopleRequest, ...grpc.CallOption) (*sessionv1.ListFixturePeopleResponse, error) {
	return &sessionv1.ListFixturePeopleResponse{People: s.people}, nil
}

func TestCompositionSignInChoices(t *testing.T) {
	var people []*sessionv1.FixturePerson
	for _, id := range []string{"one", "two", "three", "four", "five", "six", "seven"} {
		people = append(people, &sessionv1.FixturePerson{PersonId: id, Email: id + "@fixture.test", OrganizationId: "org", Roles: []string{"viewer"}, FixtureToken: "fixture-" + id})
	}
	edge := &Edge{Sessions: choiceSessions{standIn: &standIn{}, people: people}}
	get := func() (*http.Response, string) {
		rr := httptest.NewRecorder()
		edge.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth/sign-in?return=/tools", nil))
		return rr.Result(), rr.Body.String()
	}
	res, body := get()
	original := pageData(t, res, body)
	if len(original.People) != 7 {
		t.Fatalf("default lost people: %+v", original)
	}
	for i, person := range original.People {
		if person.PersonID != people[i].PersonId || person.Description != "" || person.StartHere {
			t.Fatalf("default changed: %+v", person)
		}
	}
	var err error
	edge.SignInChoices, err = parseSignInChoices(`[{"personId":"seven","description":"Seven — begin here","startHere":true},{"personId":"two","description":"Two — viewer"},{"personId":"four","description":"Four — admin"}]`)
	if err != nil {
		t.Fatal(err)
	}
	res, body = get()
	selected := pageData(t, res, body)
	if res.Header.Get("Cache-Control") != "no-store" || selected.Return != "/tools" || len(selected.People) != 3 {
		t.Fatalf("selection: %+v", selected)
	}
	for i, choice := range edge.SignInChoices {
		person := selected.People[i]
		if person.PersonID != choice.PersonID || person.Description != choice.Description || person.StartHere != choice.StartHere || person.FixtureToken != "fixture-"+choice.PersonID || person.OrganizationID != "org" || !reflect.DeepEqual(person.Roles, []string{"viewer"}) {
			t.Fatalf("selection changed identity or presentation: %+v", person)
		}
	}
	// Presentation does not remove people at the host or alter its sign-in API.
	if len(people) != 7 {
		t.Fatal("host fixture changed")
	}
	session, err := edge.Sessions.SignIn(context.Background(), &sessionv1.SignInRequest{FixtureToken: "fixture-remi"})
	if err != nil || session.PersonId != "remi" {
		t.Fatalf("unlisted person's sign-in changed: %v, %v", session, err)
	}
	edge.SignInChoices = nil
	res, body = get()
	if restored := pageData(t, res, body); !reflect.DeepEqual(original, restored) {
		t.Fatalf("selection mutated fixture: %+v", restored)
	}
	edge.SignInChoices = []signInChoice{{PersonID: "missing", Description: "Missing"}}
	res, body = get()
	if res.StatusCode != http.StatusInternalServerError || !strings.Contains(body, `fixture person \"missing\" is not listed`) {
		t.Fatalf("unknown person was not refused with reason: %d %s", res.StatusCode, body)
	}
}

func TestSignInChoicesRejectAmbiguousHostIDs(t *testing.T) {
	_, err := selectSignInPeople([]fixturePerson{{PersonID: "same"}, {PersonID: "same"}}, []signInChoice{{PersonID: "same"}})
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("got %v", err)
	}
}
