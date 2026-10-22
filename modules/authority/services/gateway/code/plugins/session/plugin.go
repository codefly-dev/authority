// Package session serves codefly.dev/session: SignIn, for fixture people.
package session

import (
	"context"

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
func (p *Plugin) RegisterREST(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error {
	return nil
}

// Migrations: none.
func (p *Plugin) Migrations() []string { return nil }

// SignIn opens a session for a fixture person.
func (p *Plugin) SignIn(_ context.Context, req *sessionv1.SignInRequest) (*sessionv1.Session, error) {
	sess, err := p.State.SignIn(req.GetFixtureToken())
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	return &sessionv1.Session{SessionId: sess.ID, PersonId: sess.Person, OrganizationId: sess.Organization, Roles: sess.Roles, TeamIds: sess.Teams}, nil
}
