package main

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"google.golang.org/grpc/status"
)

// The session face: the three procedures of the host's session interface a
// page's casting controls call (the saas UI kit's team casting), served on
// this origin at the paths the proto names, so a page asks the edge exactly
// what it asks a hosted authority through its gateway. Each is sent on with
// the browser's session and decided by the authority; the edge decides
// nothing. SignIn, OpenRoleView and ListFixturePeople are served to no page:
// a person signs in at /auth/sign-in.
//
// OpenTeamCast is the one that changes who the browser is, so it is the
// act-as form's (actas.go) second spelling, under the same admission (a POST
// from this origin, here also in the Connect protocol): allowed, the browser
// becomes the cast and keeps its own session as the way back, both in
// HttpOnly cookies, and the answer carries no bearer, because no script holds
// a credential. The way back stays the form's (`action=back`): the interface
// has no call for it.

// sessionFromCookie says the admitted session is the browser's cookie.
type sessionFromCookie struct{}

func (e *Edge) sessionProcedures() []faceProcedure {
	return []faceProcedure{
		{sessionv1.SessionService_Current_FullMethodName, forward(sessionv1.SessionService_Current_FullMethodName, e.Sessions.Current)},
		{sessionv1.SessionService_ListCastableTeams_FullMethodName, forward(sessionv1.SessionService_ListCastableTeams_FullMethodName, e.Sessions.ListCastableTeams)},
		{sessionv1.SessionService_OpenTeamCast_FullMethodName, connect.NewUnaryHandler(sessionv1.SessionService_OpenTeamCast_FullMethodName, e.openTeamCast,
			connect.WithRequireConnectProtocolHeader(), connect.WithReadMaxBytes(hostMessageBytes))},
	}
}

// openTeamCast asks the authority for a cast from the browser's session and,
// allowed, makes it the browser's: the cast in the session cookie, the own
// session in the parent cookie, and no bearer in the answer. A caller that
// presented its bearer itself holds no cookie, and is answered as the host
// answers it.
func (e *Edge) openTeamCast(ctx context.Context, req *connect.Request[sessionv1.OpenTeamCastRequest]) (*connect.Response[sessionv1.Session], error) {
	bearer, _ := ctx.Value(sessionBearer{}).(string)
	call, cancel := context.WithTimeout(withBearer(ctx, bearer), hostCallTimeout)
	defer cancel()
	cast, err := e.Sessions.OpenTeamCast(call, req.Msg)
	if err != nil {
		s := status.Convert(err)
		return nil, connect.NewError(connect.Code(s.Code()), errors.New(s.Message()))
	}
	res := connect.NewResponse(cast)
	if cookie, _ := ctx.Value(sessionFromCookie{}).(bool); cookie {
		res.Header().Add("Set-Cookie", sessionCookie(SessionKey, cast.GetBearer()).String())
		res.Header().Add("Set-Cookie", sessionCookie(ParentKey, bearer).String())
		cast.Bearer = ""
	}
	return res, nil
}

// isSessionPath is whether path names a procedure of the session interface:
// the face serves sessionPaths and refuses the others as served to no page.
func isSessionPath(path string) bool { return strings.HasPrefix(path, "/host.session.v1.") }
