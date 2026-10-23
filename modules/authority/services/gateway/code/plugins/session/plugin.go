// Package session serves codefly.dev/session: SignIn, for fixture people.
package session

import (
	"context"
	"strings"

	"gateway/pkg/framework"
	"gateway/pkg/wiring"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"

	"gateway/pkg/business/state"
	sessionv1 "gateway/pkg/gen/host/session/v1"
	authorityplugin "gateway/plugins/authority"
)

// Plugin registers the session service.
type Plugin struct {
	sessionv1.UnimplementedSessionServiceServer
	State *state.State
}

// Name is the plugin's identifier.
func (p *Plugin) Name() string { return "session" }

// RegisterGRPC registers the service.
func (p *Plugin) RegisterGRPC(s *grpc.Server) { sessionv1.RegisterSessionServiceServer(s, p) }

// RegisterREST registers nothing.
// RegisterREST serves the session interface over HTTP too, for the browser
// edge (a page's dev server signs a fixture person in): the same methods,
// transcoded to the gRPC service.
func (p *Plugin) RegisterREST(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error {
	return sessionv1.RegisterSessionServiceHandlerFromEndpoint(ctx, mux, endpoint, opts)
}

// Migrations: none.
func (p *Plugin) Migrations() []string { return nil }

// SignIn opens a session for a fixture person.
func (p *Plugin) SignIn(_ context.Context, req *sessionv1.SignInRequest) (*sessionv1.Session, error) {
	sess, err := p.State.SignIn(req.GetFixtureToken())
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	return &sessionv1.Session{SessionId: sess.ID, PersonId: sess.Person, OrganizationId: sess.Organization, Roles: sess.Roles, TeamIds: sess.Teams, Bearer: sess.ID}, nil
}

// New is the registry's constructor: the plugin over what Configure wired.
// Current answers the session the call's bearer belongs to. The bearer is not
// handed back: the caller already holds it.
func (p *Plugin) Current(ctx context.Context, _ *sessionv1.CurrentRequest) (*sessionv1.Session, error) {
	bearer := bearerOf(ctx)
	if bearer == "" {
		return nil, status.Error(codes.Unauthenticated, "the call carries no session bearer")
	}
	sess, err := p.State.Session(bearer)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "the bearer names no open session")
	}
	return &sessionv1.Session{SessionId: sess.ID, PersonId: sess.Person, OrganizationId: sess.Organization, Roles: sess.Roles, TeamIds: sess.Teams}, nil
}

// bearerOf is the call's `authorization: Bearer <bearer>`, or "".
func bearerOf(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	for _, value := range md.Get("authorization") {
		if token, found := strings.CutPrefix(value, "Bearer "); found && token != "" {
			return token
		}
	}
	return ""
}

func New() framework.Plugin { return &Plugin{State: wiring.State()} }
