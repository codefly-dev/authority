package scenario

import (
	"context"
	"io"
	"net"
	"net/http"
	"slices"
	"sync"
	"testing"

	installationv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/installation/v1"
	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// seatingHost answers as the local authority does for what seating touches,
// for the harness's own mechanics: it seats the fixture's teams on every
// installation, and does so again after every install and every delivery,
// whatever an administrator withdrew since (the local authority's
// SeatRoleTeams).
type seatingHost struct {
	installationv1.UnimplementedInstallationServiceServer
	installationv1.UnimplementedOfferServiceServer

	mu      sync.Mutex
	targets []string
	grants  map[string][]*installationv1.RoleGrant
	signIns int
}

// seat grants each target's role teams again, as the host does.
func (h *seatingHost) seat() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, target := range h.targets {
		for _, role := range []string{"admin", "user"} {
			team := target + "-" + role
			if !slices.ContainsFunc(h.grants[target], func(g *installationv1.RoleGrant) bool { return g.GetTeamId() == team }) {
				h.grants[target] = append(h.grants[target], &installationv1.RoleGrant{Role: role, TeamId: team})
			}
		}
	}
}

// held is who holds a role on target, by team or person.
func (h *seatingHost) held(target string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, g := range h.grants[target] {
		out = append(out, g.GetRole()+":"+g.GetTeamId()+g.GetPersonId())
	}
	return out
}

// seatingSessions signs the administrator in at the seating host.
type seatingSessions struct {
	sessionv1.UnimplementedSessionServiceServer
	host *seatingHost
}

func (s seatingSessions) SignIn(context.Context, *sessionv1.SignInRequest) (*sessionv1.Session, error) {
	h := s.host
	h.mu.Lock()
	defer h.mu.Unlock()
	h.signIns++
	return &sessionv1.Session{Bearer: "session-alice"}, nil
}

func (h *seatingHost) List(context.Context, *installationv1.ListRequest) (*installationv1.ListResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := &installationv1.ListResponse{}
	for _, target := range h.targets {
		out.Installations = append(out.Installations, &installationv1.Installation{Id: "i-" + target, OrganizationId: "acme", Target: target, Status: installationv1.Installation_STATUS_ACTIVE})
	}
	return out, nil
}

func (h *seatingHost) ListRoleGrants(_ context.Context, r *installationv1.ListRoleGrantsRequest) (*installationv1.ListRoleGrantsResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return &installationv1.ListRoleGrantsResponse{Grants: slices.Clone(h.grants[r.GetInstallationId()[2:]])}, nil
}

func (h *seatingHost) RevokeRole(_ context.Context, r *installationv1.RevokeRoleRequest) (*installationv1.Installation, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	target := r.GetInstallationId()[2:]
	h.grants[target] = slices.DeleteFunc(h.grants[target], func(g *installationv1.RoleGrant) bool {
		return g.GetRole() == r.GetRole() && g.GetPersonId() == r.GetPersonId() && g.GetTeamId() == r.GetTeamId()
	})
	return &installationv1.Installation{Id: r.GetInstallationId()}, nil
}

func (h *seatingHost) GrantRole(_ context.Context, r *installationv1.GrantRoleRequest) (*installationv1.Installation, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	target := r.GetInstallationId()[2:]
	h.grants[target] = append(h.grants[target], &installationv1.RoleGrant{Role: r.GetRole(), PersonId: r.GetPersonId()})
	return &installationv1.Installation{Id: r.GetInstallationId()}, nil
}

func (h *seatingHost) ReviewOffer(context.Context, *installationv1.ReviewRequest) (*installationv1.ReviewedOffer, error) {
	return &installationv1.ReviewedOffer{Approval: &installationv1.ConsentApproval{}}, nil
}

// Install installs the target and, as the host does after every install,
// seats every installation again.
func (h *seatingHost) Install(_ context.Context, r *installationv1.InstallRequest) (*installationv1.Installation, error) {
	h.mu.Lock()
	h.targets = append(h.targets, r.GetTarget())
	h.mu.Unlock()
	h.seat()
	return &installationv1.Installation{Id: "i-" + r.GetTarget(), Target: r.GetTarget(), Status: installationv1.Installation_STATUS_ACTIVE}, nil
}

// seatedOn is a composition on a seating host with targets installed and
// seated, its people kept on seated alone, and an edge that answers every
// call after serve has looked at the host.
func seatedOn(t *testing.T, seated []string, serve func(), targets ...string) (*Composition, *seatingHost) {
	t.Helper()
	host := &seatingHost{targets: targets, grants: map[string][]*installationv1.RoleGrant{}}
	host.seat()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	installationv1.RegisterInstallationServiceServer(server, host)
	installationv1.RegisterOfferServiceServer(server, host)
	sessionv1.RegisterSessionServiceServer(server, seatingSessions{host: host})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	c := front(t, func(w http.ResponseWriter, _ *http.Request) {
		serve()
		_, _ = io.WriteString(w, `{}`)
	})
	if c.conn, err = grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials())); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.conn.Close() })
	c.people["alice"] = &sessionv1.FixturePerson{PersonId: "alice", OrganizationId: "acme", FixtureToken: "token-alice"}
	if err := c.seat(context.Background(), Options{Seated: seated}, "alice"); err != nil {
		t.Fatal(err)
	}
	return c, host
}

// The seating a test asked for holds: the host seats its people again on
// every installation after each install and each delivery, and a call made
// afterwards still finds them on the named targets alone.
func TestTheSeatingAskedForHoldsAcrossInstallsAndDeliveries(t *testing.T) {
	var atCall []string
	var host *seatingHost
	c, host := seatedOn(t, []string{"wiki"}, func() { atCall = host.held("tracing") }, "wiki", "tracing")
	if got := host.held("tracing"); len(got) != 0 {
		t.Fatalf("at the start, tracing is held by %v", got)
	}
	if got := host.held("wiki"); len(got) != 2 {
		t.Fatalf("at the start, the wiki is held by %v", got)
	}

	// An install: the host seats every installation again.
	c.Install(t, "alice", "annotations")
	for _, target := range []string{"tracing", "annotations"} {
		if got := host.held(target); len(got) != 0 {
			t.Errorf("after an install, %s is held again by %v", target, got)
		}
	}

	// A delivery (a module restarting, a hot reload): the same, with no call
	// of the harness in between. The next call a person makes finds the
	// seating as it was asked.
	host.seat()
	atCall = []string{"no call was served"}
	c.As(t, "carol").Do(t, Call{Page: "wiki", Procedure: "tracing.v1.TraceReadService/ListTraces"})
	if len(atCall) != 0 {
		t.Errorf("after a delivery, a call reached the edge with tracing held by %v", atCall)
	}
	if got := host.held("wiki"); len(got) != 2 {
		t.Errorf("the wiki, which is seated, is held by %v", got)
	}

	// A role a scenario grants itself on a target that is not seated is the
	// scenario's own, and stays.
	c.Grant(t, "alice", "tracing", "user", "erin")
	host.seat()
	c.As(t, "carol").Do(t, Call{Page: "wiki", Procedure: "tracing.v1.TraceReadService/ListTraces"})
	if got := host.held("tracing"); !slices.Equal(got, []string{"user:erin"}) {
		t.Errorf("tracing is held by %v, want the scenario's own grant alone", got)
	}
	// One session of the administrator serves every check.
	if host.signIns > 4 {
		t.Errorf("the administrator signed in %d times", host.signIns)
	}
}

// With no seating asked for, the fixture is left as it is and nothing is
// asked of the host on a call.
func TestNoSeatingAskedForLeavesTheFixture(t *testing.T) {
	c, host := seatedOn(t, nil, func() {}, "wiki", "tracing")
	c.As(t, "carol").Do(t, Call{Page: "wiki", Procedure: "tracing.v1.TraceReadService/ListTraces"})
	if got := host.held("tracing"); len(got) != 2 || host.signIns != 0 {
		t.Errorf("tracing is held by %v after %d sign-ins of the administrator", got, host.signIns)
	}
}

func TestFixtureAdministrator(t *testing.T) {
	people := []*sessionv1.FixturePerson{{PersonId: "ordinary"}, {PersonId: "installer", Roles: []string{"admin"}}}
	setup := Options{Seated: []string{"tracing"}}
	if got, err := fixtureAdministrator(setup, people); err != nil || got != "installer" {
		t.Fatalf("fixture administrator = %q, %v", got, err)
	}
	// Another organisation's administrator (the outsider) is not a second one.
	elsewhere := append(slices.Clone(people), &sessionv1.FixturePerson{PersonId: "outsider", OrganizationId: "elsewhere", Roles: []string{"admin"}})
	if got, err := fixtureAdministrator(setup, elsewhere); err != nil || got != "installer" {
		t.Fatalf("fixture administrator beside another organisation's = %q, %v", got, err)
	}
	for _, ambiguous := range [][]*sessionv1.FixturePerson{nil, {people[1], {PersonId: "another", Roles: []string{"admin"}}}, {{PersonId: "ordinary"}, elsewhere[2]}} {
		if _, err := fixtureAdministrator(setup, ambiguous); err == nil {
			t.Fatal("expected an explicit administrator to be required")
		}
	}
	setup.Administrator = "another"
	if got, err := fixtureAdministrator(setup, nil); got != "another" || err != nil {
		t.Fatalf("explicit administrator = %q, %v", got, err)
	}
	if _, err := fixtureAdministrator(Options{}, nil); err != nil {
		t.Fatal(err)
	}
}
