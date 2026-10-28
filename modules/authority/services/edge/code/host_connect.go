package main

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	installationv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/installation/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// The Setup tab's face: the host's installation reads and changes, served to
// the signed-in person over Connect on this origin, at the paths the host's
// own proto names (/host.installation.v1.InstallationService/<Method>,
// /host.installation.v1.OfferService/<Method>), so a page calls them with the
// generated client exactly as it calls a hosted authority through its
// gateway. Each call is sent on through the generated host client with the
// person's own session; the authority decides it and its refusal reaches the
// page with its code and reason. The edge decides nothing.
//
// The face also serves a page two of the authority's own procedures,
// AuthorityService Delegate and GetDelegation, so a person's page can delegate
// a run of theirs to a module and read that delegation back (handbook proposal
// 2026-10-28-a-person-delegates-a-run-from-the-page). It refuses a delegation
// with no lifetime, which would stand after the run, and a read naming a
// module's credential, which is the module's read, not the page's; every
// other authority procedure (Issue, RevokeDelegation) is served to no browser.

// hostPackage is the path prefix of the host interface this face serves.
const hostPackage = "/host.installation.v1."

// hostCallTimeout bounds one forwarded call.
const hostCallTimeout = 10 * time.Second

// hostMessageBytes bounds a request: each of these messages is a few names.
const hostMessageBytes = 64 << 10

// Delegations is the authority's delegation procedures the face serves.
type Delegations interface {
	Delegate(ctx context.Context, in *authorityv1.DelegateRequest, opts ...grpc.CallOption) (*authorityv1.Delegation, error)
	GetDelegation(ctx context.Context, in *authorityv1.GetDelegationRequest, opts ...grpc.CallOption) (*authorityv1.Delegation, error)
}

// delegationPaths are the authority procedures the face serves, by full path:
// never the whole package, which carries Issue.
var delegationPaths = []string{authorityv1.AuthorityService_Delegate_FullMethodName, authorityv1.AuthorityService_GetDelegation_FullMethodName}

type faceProcedure struct {
	procedure string
	handler   http.Handler
}

// hostConnectFace is the procedures a browser may call and nothing else:
// Install, Current and the solution's InstallableService are not served here.
func (e *Edge) hostConnectFace() http.Handler {
	e.faceOnce.Do(func() {
		mux := http.NewServeMux()
		var procedures []faceProcedure
		if e.Installer != nil && e.Offers != nil {
			procedures = e.installationProcedures()
		}
		if e.Delegations != nil {
			procedures = append(procedures, e.delegationProcedures()...)
		}
		for _, p := range procedures {
			mux.Handle(p.procedure, p.handler)
		}
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			_ = connectRefusal.Write(w, r, connect.NewError(connect.CodeUnimplemented,
				errors.New("this origin serves "+r.URL.Path+" to no browser: it serves InstallationService List, ListHeld, ListRoleGrants, GrantRole, RevokeRole and Review, OfferService ListOffers and ReviewOffer, and AuthorityService Delegate and GetDelegation")))
		})
		e.face = mux
	})
	return e.face
}

// delegationProcedures serves a page's delegation of a run and its read back.
func (e *Edge) delegationProcedures() []faceProcedure {
	delegate := func(ctx context.Context, in *authorityv1.DelegateRequest, opts ...grpc.CallOption) (*authorityv1.Delegation, error) {
		if in.GetTtlSeconds() <= 0 {
			return nil, status.Error(codes.InvalidArgument, "a page delegates for a lifetime: name ttl_seconds, so the delegation ends after the work it was made for")
		}
		return e.Delegations.Delegate(ctx, in, opts...)
	}
	read := func(ctx context.Context, in *authorityv1.GetDelegationRequest, opts ...grpc.CallOption) (*authorityv1.Delegation, error) {
		if in.GetActor() != nil {
			return nil, status.Error(codes.InvalidArgument, "a page reads a delegation as its grantor: an actor credential is the module's own read")
		}
		return e.Delegations.GetDelegation(ctx, in, opts...)
	}
	return []faceProcedure{
		{authorityv1.AuthorityService_Delegate_FullMethodName, forward(authorityv1.AuthorityService_Delegate_FullMethodName, delegate)},
		{authorityv1.AuthorityService_GetDelegation_FullMethodName, forward(authorityv1.AuthorityService_GetDelegation_FullMethodName, read)},
	}
}

// installationProcedures serves the Setup tab's installation reads and changes.
func (e *Edge) installationProcedures() []faceProcedure {
	return []faceProcedure{
		{installationv1.InstallationService_List_FullMethodName, forward(installationv1.InstallationService_List_FullMethodName, e.Installer.List)},
		{installationv1.InstallationService_ListHeld_FullMethodName, forward(installationv1.InstallationService_ListHeld_FullMethodName, e.Installer.ListHeld)},
		{installationv1.InstallationService_ListRoleGrants_FullMethodName, forward(installationv1.InstallationService_ListRoleGrants_FullMethodName, e.Installer.ListRoleGrants)},
		{installationv1.InstallationService_GrantRole_FullMethodName, forward(installationv1.InstallationService_GrantRole_FullMethodName, e.Installer.GrantRole)},
		{installationv1.InstallationService_RevokeRole_FullMethodName, forward(installationv1.InstallationService_RevokeRole_FullMethodName, e.Installer.RevokeRole)},
		{installationv1.InstallationService_Review_FullMethodName, forward(installationv1.InstallationService_Review_FullMethodName, e.Installer.Review)},
		{installationv1.OfferService_ListOffers_FullMethodName, forward(installationv1.OfferService_ListOffers_FullMethodName, e.Offers.ListOffers)},
		{installationv1.OfferService_ReviewOffer_FullMethodName, forward(installationv1.OfferService_ReviewOffer_FullMethodName, e.Offers.ReviewOffer)},
	}
}

// toHost admits a browser's call to the host face: a session, from this
// origin when the session is the cookie, in the Connect protocol only (a
// unary POST carrying Connect-Protocol-Version, a header no form or simple
// request can set, so another site's page is stopped by its preflight even
// before the origin check). No CORS header is ever set.
func (e *Edge) toHost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if (e.Installer == nil || e.Offers == nil) && e.Delegations == nil {
		refuseCall(w, r, http.StatusNotFound, "this edge composes no host installation or delegation interface")
		return
	}
	bearer, fromCookie := bearerOf(r)
	if bearer == "" {
		refuseCall(w, r, http.StatusUnauthorized, "no session: sign in at /auth/sign-in")
		return
	}
	if fromCookie && !sameOrigin(r) {
		refuseCall(w, r, http.StatusForbidden, "a call made with this origin's session must come from this origin")
		return
	}
	if reason := notConnectUnary(r); reason != "" {
		refuseCall(w, r, http.StatusUnsupportedMediaType, reason)
		return
	}
	r.Header.Del("Cookie")
	r.Header.Del("Authorization")
	e.hostConnectFace().ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionBearer{}, bearer)))
}

// notConnectUnary is why r is not a Connect unary call, or empty when it is.
func notConnectUnary(r *http.Request) string {
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if r.Method != http.MethodPost || r.Header.Get("Connect-Protocol-Version") != "1" || (media != "application/json" && media != "application/proto") {
		return "the host's installation interface is served here over Connect only: a POST with Connect-Protocol-Version: 1 and application/json or application/proto"
	}
	return ""
}

// sessionBearer carries the admitted session to the forwarded call.
type sessionBearer struct{}

// forward serves one procedure by sending its message on to the host through
// the generated client with the person's session, and its answer back. A
// refusal keeps the host's code and reason.
func forward[Req, Res any](procedure string, call func(context.Context, *Req, ...grpc.CallOption) (*Res, error)) http.Handler {
	return connect.NewUnaryHandlerSimple(procedure, func(ctx context.Context, in *Req) (*Res, error) {
		bearer, _ := ctx.Value(sessionBearer{}).(string)
		ctx, cancel := context.WithTimeout(metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+bearer), hostCallTimeout)
		defer cancel()
		out, err := call(ctx, in)
		if err != nil {
			s := status.Convert(err)
			return nil, connect.NewError(connect.Code(s.Code()), errors.New(s.Message()))
		}
		return out, nil
	}, connect.WithRequireConnectProtocolHeader(), connect.WithReadMaxBytes(hostMessageBytes))
}

// isHostPath is whether path names a procedure of the host face.
func isHostPath(path string) bool {
	return strings.HasPrefix(path, hostPackage) || slices.Contains(delegationPaths, path)
}
