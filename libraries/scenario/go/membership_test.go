package scenario

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"

	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// teamHost is a host with one team: it signs dana and carol in, and changes
// the team's members for dana's bearer alone, recording each call.
type teamHost struct {
	sessionv1.UnimplementedSessionServiceServer
	mu      sync.Mutex
	members []string
	calls   []string
}

func (h *teamHost) ListFixturePeople(context.Context, *sessionv1.ListFixturePeopleRequest) (*sessionv1.ListFixturePeopleResponse, error) {
	return &sessionv1.ListFixturePeopleResponse{People: []*sessionv1.FixturePerson{
		{PersonId: "dana", OrganizationId: "acme", Roles: []string{"admin"}, FixtureToken: "dev-dana"},
		{PersonId: "carol", OrganizationId: "acme", FixtureToken: "dev-carol"},
	}}, nil
}

func (h *teamHost) SignIn(_ context.Context, req *sessionv1.SignInRequest) (*sessionv1.Session, error) {
	return &sessionv1.Session{Bearer: "session-of-" + req.GetFixtureToken()}, nil
}

func (h *teamHost) change(ctx context.Context, call, team, person string, join bool) error {
	md, _ := metadata.FromIncomingContext(ctx)
	if !slices.Contains(md.Get("authorization"), "Bearer session-of-dev-dana") {
		return status.Error(codes.PermissionDenied, "the caller does not administer acme")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, fmt.Sprintf("%s %s %s", call, team, person))
	h.members = slices.DeleteFunc(h.members, func(m string) bool { return m == person })
	if join {
		h.members = append(h.members, person)
	}
	return nil
}

func (h *teamHost) AddFixtureTeamMember(ctx context.Context, req *sessionv1.AddFixtureTeamMemberRequest) (*sessionv1.AddFixtureTeamMemberResponse, error) {
	return &sessionv1.AddFixtureTeamMemberResponse{}, h.change(ctx, "add", req.GetTeamId(), req.GetPersonId(), true)
}

func (h *teamHost) RemoveFixtureTeamMember(ctx context.Context, req *sessionv1.RemoveFixtureTeamMemberRequest) (*sessionv1.RemoveFixtureTeamMemberResponse, error) {
	return &sessionv1.RemoveFixtureTeamMemberResponse{}, h.change(ctx, "remove", req.GetTeamId(), req.GetPersonId(), false)
}

// composedOn is a composition whose host is server, reached where it listens.
func composedOn(t *testing.T, server sessionv1.SessionServiceServer) *Composition {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	sessionv1.RegisterSessionServiceServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)
	c := &Composition{delivered: func() map[string]string {
		return map[string]string{
			"CODEFLY__ENDPOINT__AUTHORITY__LOCAL__GRPC__GRPC": listener.Addr().String(),
			"CODEFLY__ENDPOINT__AUTHORITY__EDGE__HTTP__HTTP":  "http://edge.test.invalid",
		}
	}, signed: map[string]*Person{}}
	if err := c.connect(context.Background(), Options{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.conn.Close() })
	return c
}

// Leave takes a person out of a team through the host's own call, under the
// administrator's bearer, and the test's end puts them back; Join is the
// reverse. Nothing is changed for a caller the host refuses.
func TestLeaveAndJoinChangeATeamOnTheHostAndUndoItAtTheTestsEnd(t *testing.T) {
	host := &teamHost{members: []string{"carol"}}
	c := composedOn(t, host)
	t.Run("leave", func(t *testing.T) {
		c.Leave(t, "dana", "wiki-user", "carol")
		if len(host.members) != 0 {
			t.Fatalf("after Leave the team holds %v", host.members)
		}
	})
	if !slices.Equal(host.members, []string{"carol"}) {
		t.Fatalf("after the scenario that left, the team holds %v", host.members)
	}
	t.Run("join", func(t *testing.T) {
		c.Join(t, "dana", "wiki-user", "dana")
		if !slices.Equal(host.members, []string{"carol", "dana"}) {
			t.Fatalf("after Join the team holds %v", host.members)
		}
	})
	if !slices.Equal(host.members, []string{"carol"}) {
		t.Fatalf("after the scenario that joined, the team holds %v", host.members)
	}
	if want := []string{"remove wiki-user carol", "add wiki-user carol", "add wiki-user dana", "remove wiki-user dana"}; !slices.Equal(host.calls, want) {
		t.Fatalf("the host was called %v, want %v", host.calls, want)
	}
	if err := c.member("carol", "wiki-user", "carol", false); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a member's own removal: %v", err)
	}
	if err := c.member("nobody", "wiki-user", "carol", false); err == nil || !strings.Contains(err.Error(), "not a fixture person") {
		t.Fatalf("an administrator the fixture does not have: %v", err)
	}
	if !slices.Equal(host.members, []string{"carol"}) {
		t.Fatalf("a refused change left the team holding %v", host.members)
	}
}

// A host that does not serve the membership calls fails the scenario by
// name: a member who never left proves nothing about leaving.
func TestAHostWithNoMembershipCallFailsTheScenarioByName(t *testing.T) {
	c := composedOn(t, fixtureHostWithSignIn{})
	err := c.member("dana", "wiki-user", "carol", false)
	if err == nil || !strings.Contains(err.Error(), "does not serve the session interface's fixture membership calls") {
		t.Fatalf("want a refusal naming the missing calls, got %v", err)
	}
}

// fixtureHostWithSignIn signs dana in and serves no membership call.
type fixtureHostWithSignIn struct {
	sessionv1.UnimplementedSessionServiceServer
}

func (fixtureHostWithSignIn) ListFixturePeople(context.Context, *sessionv1.ListFixturePeopleRequest) (*sessionv1.ListFixturePeopleResponse, error) {
	return &sessionv1.ListFixturePeopleResponse{People: []*sessionv1.FixturePerson{{PersonId: "dana", OrganizationId: "acme", Roles: []string{"admin"}, FixtureToken: "dev-dana"}}}, nil
}

func (fixtureHostWithSignIn) SignIn(context.Context, *sessionv1.SignInRequest) (*sessionv1.Session, error) {
	return &sessionv1.Session{Bearer: "session-of-dana"}, nil
}
