// Package session serves codefly.dev/session for fixture people: who they are,
// SignIn, Current and End, role views and casts, and, in a run on its fixture,
// who is in a team.
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
	// Fixture says this run was started on a fixture it selected, in a local
	// run: the fixture's people are listed, with the tokens they sign in by,
	// signed in by them, and put in and taken out of teams by their
	// organisation's administrator. It is false unless said (wiring.FixtureRun; a
	// test says so itself), and then the plugin lists nobody and signs nobody
	// in: the listing is unauthenticated, so nothing else stands between a
	// fixture token and whoever reaches the listener.
	Fixture bool
}

// notAFixtureRun is the refusal of fixture sign-in by a run that was not
// started on a fixture.
func notAFixtureRun() error {
	return status.Error(codes.FailedPrecondition, "this authority was not started on a fixture in a local run, so it lists no fixture person and signs nobody in by a fixture token")
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
func (p *Plugin) SignIn(ctx context.Context, req *sessionv1.SignInRequest) (*sessionv1.Session, error) {
	if !p.Fixture {
		return nil, notAFixtureRun()
	}
	sess, err := p.State.SignIn(req.GetFixtureToken())
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	return p.wire(ctx, sess, sess.ID)
}

// wire is a session as the interface answers it: when it ends on its own, and
// the grant epoch of what it holds now.
func (p *Plugin) wire(ctx context.Context, sess state.Session, bearer string) (*sessionv1.Session, error) {
	epoch, err := p.State.GrantEpoch(ctx, sess.ID)
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	out := &sessionv1.Session{PersonDisplayName: sess.PersonDisplayName, OrganizationDisplayName: sess.OrganizationDisplayName, SessionId: sess.ID, PersonId: sess.Person, OrganizationId: sess.Organization, Roles: sess.Roles, TeamIds: sess.Teams, Bearer: bearer, CastTeamId: sess.CastTeam,
		ExpiresAtUnix: sess.ExpiresAt.Unix(), GrantEpoch: epoch}
	for _, id := range slices.Sorted(maps.Keys(sess.RoleView)) {
		out.RoleView = append(out.RoleView, &sessionv1.RoleViewEntry{InstallationId: id, Roles: sess.RoleView[id]})
	}
	return out, nil
}

// End ends the caller's session and every role view and cast opened from it.
func (p *Plugin) End(ctx context.Context, _ *sessionv1.EndRequest) (*sessionv1.EndResponse, error) {
	bearer := authorityplugin.Bearer(ctx)
	if bearer == "" {
		return nil, status.Error(codes.Unauthenticated, "the call carries no session bearer")
	}
	if err := p.State.EndSession(bearer); err != nil {
		return nil, status.Error(codes.Unauthenticated, "the bearer names no open session")
	}
	return &sessionv1.EndResponse{}, nil
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
	return p.wire(ctx, sess, sess.ID)
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
	return p.wire(ctx, sess, sess.ID)
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
	return p.wire(ctx, sess, "")
}

// ListFixturePeople answers every fixture person, for the edge's sign-in page,
// in a run started on its fixture (Fixture); any other lists nobody.
func (p *Plugin) ListFixturePeople(context.Context, *sessionv1.ListFixturePeopleRequest) (*sessionv1.ListFixturePeopleResponse, error) {
	if !p.Fixture {
		return nil, notAFixtureRun()
	}
	out := &sessionv1.ListFixturePeopleResponse{}
	for _, person := range p.State.FixturePeople() {
		out.People = append(out.People, &sessionv1.FixturePerson{PersonId: person.ID, Email: person.Email, OrganizationId: person.Organization,
			OrganizationDisplayName: p.State.OrganizationDisplayName(person.Organization), Roles: person.Roles, TeamIds: person.Teams, FixtureToken: person.FixtureToken})
	}
	return out, nil
}

// AddFixtureTeamMember puts a fixture person in a team of the organisation
// the caller administers, in a run started on its fixture.
func (p *Plugin) AddFixtureTeamMember(ctx context.Context, req *sessionv1.AddFixtureTeamMemberRequest) (*sessionv1.AddFixtureTeamMemberResponse, error) {
	if err := p.changeFixtureTeam(ctx, req.GetTeamId(), req.GetPersonId(), true); err != nil {
		return nil, err
	}
	return &sessionv1.AddFixtureTeamMemberResponse{}, nil
}

// RemoveFixtureTeamMember takes a fixture person out of a team of the
// organisation the caller administers, in a run started on its fixture.
func (p *Plugin) RemoveFixtureTeamMember(ctx context.Context, req *sessionv1.RemoveFixtureTeamMemberRequest) (*sessionv1.RemoveFixtureTeamMemberResponse, error) {
	if err := p.changeFixtureTeam(ctx, req.GetTeamId(), req.GetPersonId(), false); err != nil {
		return nil, err
	}
	return &sessionv1.RemoveFixtureTeamMemberResponse{}, nil
}

// changeFixtureTeam is both membership calls: a fixture run only, under the
// bearer of the organisation's administrator (state.ChangeFixtureTeam).
func (p *Plugin) changeFixtureTeam(ctx context.Context, team, person string, join bool) error {
	if !p.Fixture {
		return notAFixtureRun()
	}
	bearer := authorityplugin.Bearer(ctx)
	if bearer == "" {
		return status.Error(codes.Unauthenticated, "the call carries no session bearer")
	}
	return authorityplugin.Status(p.State.ChangeFixtureTeam(ctx, bearer, team, person, join))
}

// New is the registry's constructor: the plugin over what Configure wired.
func New() framework.Plugin { return &Plugin{State: wiring.State(), Fixture: wiring.FixtureRun()} }
