package main

import (
	"context"
	"net/http"
	"net/url"
	"slices"

	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// "Act as this team" is the sign-in page's second card, shown to a browser
// that holds a session: the organisation's teams, each a plain form posted to
// /auth/act-as. The authority decides each ask (the session interface's
// OpenTeamCast: a person may act as a team whose roles they could grant,
// member of it or not), and a refusal is shown by name. The cast is a new
// session that is the team and nothing else; the edge keeps the session it
// was opened from in a second cookie, so "Back to your own session" is a
// form too, and never a second sign-in. Nothing here decides who may act as
// what, and no script holds a credential.

// ParentKey is the cookie the session a cast was opened from travels in.
const ParentKey = "edge_session_parent"

// signedIn is who the browser is, for the sign-in page's act-as card.
type signedIn struct {
	PersonID                string   `json:"personId"`
	PersonDisplayName       string   `json:"personDisplayName"`
	OrganizationID          string   `json:"organizationId"`
	OrganizationDisplayName string   `json:"organizationDisplayName"`
	Roles                   []string `json:"roles"`
	TeamIDs                 []string `json:"teamIds"`
	// CastTeamID is the team this session acts as, when it is a cast.
	CastTeamID string `json:"castTeamId,omitempty"`
	// Back: the session this cast was opened from is held, so the way back
	// is offered.
	Back bool `json:"back,omitempty"`
	// Teams are the organisation's teams the person may ask to act as, as
	// the fixture seats them; the authority decides each ask.
	Teams []string `json:"teams"`
}

// current is the session the browser holds, for the sign-in page: nil with
// no cookie or an ended session. Any other failure to answer is an error.
func (e *Edge) current(r *http.Request) (*signedIn, error) {
	bearer, _ := bearerOf(r)
	if bearer == "" {
		return nil, nil
	}
	ctx := withBearer(r.Context(), bearer)
	sess, err := e.Sessions.Current(ctx, &sessionv1.CurrentRequest{})
	if err != nil {
		if status.Code(err) == codes.Unauthenticated {
			e.evict(bearer)
			return nil, nil
		}
		return nil, err
	}
	who := &signedIn{PersonID: sess.GetPersonId(), PersonDisplayName: sess.GetPersonDisplayName(), OrganizationID: sess.GetOrganizationId(),
		OrganizationDisplayName: sess.GetOrganizationDisplayName(), Roles: nonNil(sess.GetRoles()), TeamIDs: nonNil(sess.GetTeamIds()), CastTeamID: sess.GetCastTeamId(), Teams: []string{}}
	if c, err := r.Cookie(ParentKey); err == nil && c.Value != "" && who.CastTeamID != "" {
		who.Back = true
	}
	people, err := e.Sessions.ListFixturePeople(ctx, &sessionv1.ListFixturePeopleRequest{})
	if err != nil {
		return nil, err
	}
	for _, p := range people.GetPeople() {
		if p.GetOrganizationId() == who.OrganizationID {
			who.Teams = append(who.Teams, p.GetTeamIds()...)
		}
	}
	slices.Sort(who.Teams)
	who.Teams = slices.Compact(who.Teams)
	return who, nil
}

// actAs opens a cast onto the team the form names, or comes back from one.
func (e *Edge) actAs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		refuse(w, http.StatusMethodNotAllowed, "act as a team with POST")
		return
	}
	// A cast changes who the browser is: it must come from this origin.
	if !sameOrigin(r) {
		refuse(w, http.StatusForbidden, "an act-as must come from this origin")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		refuse(w, http.StatusBadRequest, "an act-as names a team")
		return
	}
	bearer, _ := bearerOf(r)
	if bearer == "" {
		refuse(w, http.StatusUnauthorized, "no session: sign in at /auth/sign-in")
		return
	}
	back := localPath(r.PostForm.Get("return"))
	if r.PostForm.Get("action") == "back" {
		parent, err := r.Cookie(ParentKey)
		if err != nil || parent.Value == "" {
			refuse(w, http.StatusBadRequest, "this session was opened from no other: sign in instead")
			return
		}
		// The cast's cached authority goes with it; the own session's is as it was.
		e.evict(bearer)
		http.SetCookie(w, sessionCookie(SessionKey, parent.Value))
		http.SetCookie(w, &http.Cookie{Name: ParentKey, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	team := r.PostForm.Get("team")
	if team == "" {
		refuse(w, http.StatusBadRequest, "an act-as names a team")
		return
	}
	cast, err := e.Sessions.OpenTeamCast(withBearer(r.Context(), bearer), &sessionv1.OpenTeamCastRequest{TeamId: team})
	if err != nil {
		// The authority's refusal, by name, on the page the ask came from.
		http.Redirect(w, r, "/auth/sign-in?"+url.Values{"return": {back}, "refused": {status.Convert(err).Message()}}.Encode(), http.StatusSeeOther)
		return
	}
	http.SetCookie(w, sessionCookie(SessionKey, cast.GetBearer()))
	http.SetCookie(w, sessionCookie(ParentKey, bearer))
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func sessionCookie(name, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

func withBearer(ctx context.Context, bearer string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+bearer)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
