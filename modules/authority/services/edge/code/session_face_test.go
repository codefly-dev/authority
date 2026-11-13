package main

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"connectrpc.com/connect"
	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
)

// castOver asks the session face for a cast with the browser's cookie, from
// origin, and answers the response with the cookies it set.
func castOver(t *testing.T, f fixture, origin, team string) (*connect.Response[sessionv1.Session], map[string]string, error) {
	t.Helper()
	client := connect.NewClient[sessionv1.OpenTeamCastRequest, sessionv1.Session](f.edge.Client(), f.edge.URL+sessionv1.SessionService_OpenTeamCast_FullMethodName, connect.WithProtoJSON())
	req := connect.NewRequest(&sessionv1.OpenTeamCastRequest{TeamId: team})
	req.Header().Set("Origin", origin)
	req.Header().Set("Cookie", (&http.Cookie{Name: SessionKey, Value: "remi-session"}).String())
	res, err := client.CallUnary(context.Background(), req)
	if err != nil {
		return nil, nil, err
	}
	return res, cookiesOf(&http.Response{Header: res.Header()}), nil
}

// A page casts through the host's own session interface on this origin: it
// reads who it is and the teams it may act as, and OpenTeamCast makes the
// browser the cast with its own session as the way back, handing no script a
// bearer; the act-as form's back restores it. The authority decides each.
func TestAPageCastsThroughTheSessionInterface(t *testing.T) {
	f := newFixture(t)
	own, err := browser[sessionv1.CurrentRequest, sessionv1.Session](t, f.edge, f.edge.URL, "remi-session", sessionv1.SessionService_Current_FullMethodName, &sessionv1.CurrentRequest{})
	if err != nil || own.GetPersonId() != "remi" || own.GetCastTeamId() != "" {
		t.Fatalf("Current answered %v, %v", own, err)
	}
	if own.GetBearer() != "" || own.GetSessionId() != "" {
		t.Fatalf("Current answered a page bearer %q, session id %q: a host may key its sessions by the bearer, so a script holds neither", own.GetBearer(), own.GetSessionId())
	}
	teams, err := browser[sessionv1.ListCastableTeamsRequest, sessionv1.ListCastableTeamsResponse](t, f.edge, f.edge.URL, "remi-session", sessionv1.SessionService_ListCastableTeams_FullMethodName, &sessionv1.ListCastableTeamsRequest{})
	if err != nil || len(teams.GetTeams()) != 1 || teams.GetTeams()[0].GetHolds()[0].GetRole() != "viewer" {
		t.Fatalf("ListCastableTeams answered %v, %v", teams, err)
	}

	res, set, err := castOver(t, f, f.edge.URL, "records-viewer")
	if err != nil {
		t.Fatalf("OpenTeamCast: %v", err)
	}
	if res.Msg.GetBearer() != "" || res.Msg.GetSessionId() != "" || res.Msg.GetCastTeamId() != "records-viewer" {
		t.Fatalf("the answer carries bearer %q, session id %q, cast %q: a script holds no credential", res.Msg.GetBearer(), res.Msg.GetSessionId(), res.Msg.GetCastTeamId())
	}
	if set[SessionKey] != "remi-as-viewers" || set[ParentKey] != "remi-session" {
		t.Fatalf("the cast set cookies %v; want the cast as the session and the own session as the way back", set)
	}
	cast, err := browser[sessionv1.CurrentRequest, sessionv1.Session](t, f.edge, f.edge.URL, "remi-as-viewers", sessionv1.SessionService_Current_FullMethodName, &sessionv1.CurrentRequest{})
	if err != nil || cast.GetCastTeamId() != "records-viewer" || cast.GetSessionId() != "" {
		t.Fatalf("Current as the cast answered %v, %v", cast, err)
	}
	back := f.actAs(t, url.Values{"action": {"back"}, "return": {"/"}}, &http.Cookie{Name: SessionKey, Value: set[SessionKey]}, &http.Cookie{Name: ParentKey, Value: set[ParentKey]})
	if got := cookiesOf(back); back.StatusCode != http.StatusSeeOther || got[SessionKey] != "remi-session" || got[ParentKey] != "" {
		t.Fatalf("back answered %d with cookies %v", back.StatusCode, got)
	}
}

// A refused cast changes nothing and says the authority's reason with its
// code; a cast asked from another origin never reaches the authority; the
// session procedures that open or list what a page may not ask are not
// served.
func TestACastTheAuthorityRefusesOrAnotherOriginAsksChangesNothing(t *testing.T) {
	f := newFixture(t)
	_, _, err := castOver(t, f, f.edge.URL, "secrets-admin")
	refusedWith(t, err, connect.CodePermissionDenied, "could not grant")
	_, _, err = castOver(t, f, "http://elsewhere.test", "records-viewer")
	refusedWith(t, err, connect.CodePermissionDenied, "must come from this origin")
	for _, procedure := range []string{sessionv1.SessionService_SignIn_FullMethodName, sessionv1.SessionService_OpenRoleView_FullMethodName, sessionv1.SessionService_ListFixturePeople_FullMethodName} {
		_, err = browser[sessionv1.SignInRequest, sessionv1.Session](t, f.edge, f.edge.URL, "remi-session", procedure, &sessionv1.SignInRequest{})
		refusedWith(t, err, connect.CodeUnimplemented, "to no browser")
	}
}
