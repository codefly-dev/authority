// Package session serves codefly.dev/session for fixture people: who they are,
// SignIn, and Current.
package session

import (
	"context"
	"maps"
	"slices"

	"gateway/pkg/framework"
	"gateway/pkg/wiring"

	"google.golang.org/grpc/codes"
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
// It forwards the generated adapter's options unchanged, preserving its
// loopback-only transport credentials.
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
	return wire(sess, sess.ID), nil
}

// wire is a session as the interface answers it.
func wire(sess state.Session, bearer string) *sessionv1.Session {
	out := &sessionv1.Session{PersonDisplayName: sess.PersonDisplayName, OrganizationDisplayName: sess.OrganizationDisplayName, SessionId: sess.ID, PersonId: sess.Person, OrganizationId: sess.Organization, Roles: sess.Roles, TeamIds: sess.Teams, Bearer: bearer, CastTeamId: sess.CastTeam}
	for _, id := range slices.Sorted(maps.Keys(sess.RoleView)) {
		out.RoleView = append(out.RoleView, &sessionv1.RoleViewEntry{InstallationId: id, Roles: sess.RoleView[id]})
	}
	return out
}

// OpenRoleView opens a session that acts as some of the roles the caller's own
// session acts as on one installation.
func (p *Plugin) OpenRoleView(ctx context.Context, req *sessionv1.OpenRoleViewRequest) (*sessionv1.Session, error) {
	bearer := authorityplugin.Bearer(ctx)
	if bearer == "" {
		return nil, status.Error(codes.Unauthenticated, "the call carries no session bearer")
	}
	sess, err := p.State.OpenRoleView(ctx, bearer, req.GetInstallationId(), req.GetRoles())
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	return wire(sess, sess.ID), nil
}

// OpenTeamCast opens a session that acts as one team and nothing else; the
// authority decides whether the caller may.
func (p *Plugin) OpenTeamCast(ctx context.Context, req *sessionv1.OpenTeamCastRequest) (*sessionv1.Session, error) {
	bearer := authorityplugin.Bearer(ctx)
	if bearer == "" {
		return nil, status.Error(codes.Unauthenticated, "the call carries no session bearer")
	}
	sess, err := p.State.OpenTeamCast(ctx, bearer, req.GetTeamId())
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	return wire(sess, sess.ID), nil
}

// ListCastableTeams answers the teams the caller may act as, each with what
// it holds; the core lists them by OpenTeamCast's own rule. A fixture team is
// named by its id.
func (p *Plugin) ListCastableTeams(ctx context.Context, _ *sessionv1.ListCastableTeamsRequest) (*sessionv1.ListCastableTeamsResponse, error) {
	bearer := authorityplugin.Bearer(ctx)
	if bearer == "" {
		return nil, status.Error(codes.Unauthenticated, "the call carries no session bearer")
	}
	teams, err := p.State.CastableTeams(ctx, bearer)
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	out := &sessionv1.ListCastableTeamsResponse{}
	for _, team := range teams {
		listed := &sessionv1.CastableTeam{TeamId: team.Team, DisplayName: team.Team}
		for _, h := range team.Holds {
			listed.Holds = append(listed.Holds, &sessionv1.TeamHolding{InstallationId: h.InstallationID, Target: h.Target, Role: h.Role})
		}
		out.Teams = append(out.Teams, listed)
	}
	return out, nil
}

// Current answers the session the call's bearer belongs to. The bearer is not
// handed back: the caller already holds it.
func (p *Plugin) Current(ctx context.Context, _ *sessionv1.CurrentRequest) (*sessionv1.Session, error) {
	bearer := authorityplugin.Bearer(ctx)
	if bearer == "" {
		return nil, status.Error(codes.Unauthenticated, "the call carries no session bearer")
	}
	sess, err := p.State.Session(bearer)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "the bearer names no open session")
	}
	return wire(sess, ""), nil
}

// ListFixturePeople answers every fixture person, for the edge's sign-in page.
func (p *Plugin) ListFixturePeople(context.Context, *sessionv1.ListFixturePeopleRequest) (*sessionv1.ListFixturePeopleResponse, error) {
	out := &sessionv1.ListFixturePeopleResponse{}
	for _, person := range p.State.FixturePeople() {
		out.People = append(out.People, &sessionv1.FixturePerson{PersonId: person.ID, Email: person.Email, OrganizationId: person.Organization,
			OrganizationDisplayName: p.State.OrganizationDisplayName(person.Organization), Roles: person.Roles, TeamIds: person.Teams, FixtureToken: person.FixtureToken})
	}
	return out, nil
}

// New is the registry's constructor: the plugin over what Configure wired.
func New() framework.Plugin { return &Plugin{State: wiring.State()} }
