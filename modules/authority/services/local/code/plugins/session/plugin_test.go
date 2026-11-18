package session_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	sessionv1 "gateway/pkg/gen/host/session/v1"
	"gateway/plugins/session"
)

func as(bearer string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+bearer))
}

func signIn(t *testing.T, p *session.Plugin, token string) *sessionv1.Session {
	t.Helper()
	sess, err := p.SignIn(context.Background(), &sessionv1.SignInRequest{FixtureToken: token})
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

// read is who the bearer is, wherever a session is read: Current, and the
// caller a person's Issue is decided for.
func read(p *session.Plugin, bearer string) error {
	if _, err := p.Current(as(bearer), &sessionv1.CurrentRequest{}); err != nil {
		return err
	}
	_, err := p.State.Caller(bearer)
	return err
}

func open(t *testing.T, p *session.Plugin, name, bearer string) {
	t.Helper()
	if err := read(p, bearer); err != nil {
		t.Fatalf("%s is no longer an open session: %v", name, err)
	}
}

func ended(t *testing.T, p *session.Plugin, name, bearer string) {
	t.Helper()
	if _, err := p.Current(as(bearer), &sessionv1.CurrentRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Current for %s: want unauthenticated, got %v", name, err)
	}
	if _, err := p.State.Caller(bearer); err == nil {
		t.Fatalf("%s still names the caller of a person's Issue", name)
	}
	wiki := state.InstallationID("acme", "wiki")
	for call, err := range map[string]error{
		"OpenRoleView":      second(p.OpenRoleView(as(bearer), &sessionv1.OpenRoleViewRequest{InstallationId: wiki, Roles: []string{"user"}})),
		"OpenTeamCast":      second(p.OpenTeamCast(as(bearer), &sessionv1.OpenTeamCastRequest{TeamId: "wiki-user"})),
		"ListCastableTeams": second(p.ListCastableTeams(as(bearer), &sessionv1.ListCastableTeamsRequest{})),
		"End":               second(p.End(as(bearer), &sessionv1.EndRequest{})),
	} {
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("%s for %s: want unauthenticated, got %v", call, name, err)
		}
	}
}

func second[T any](_ T, err error) error { return err }

// End ends the caller's session and every role view and cast opened from it,
// and theirs; the session a cast was opened from is untouched, and ending is
// never undone.
func TestEndEndsTheSessionAndEverySessionOpenedFromIt(t *testing.T) {
	k := testkit.New(t)
	p := &session.Plugin{State: k.State, Fixture: true}
	wiki := state.InstallationID("acme", "wiki")
	dana := signIn(t, p, "dev-dana")
	other := signIn(t, p, "dev-dana")
	view, err := p.OpenRoleView(as(dana.GetBearer()), &sessionv1.OpenRoleViewRequest{InstallationId: wiki, Roles: []string{"admin"}})
	if err != nil {
		t.Fatal(err)
	}
	cast, err := p.OpenTeamCast(as(dana.GetBearer()), &sessionv1.OpenTeamCastRequest{TeamId: "wiki-user"})
	if err != nil {
		t.Fatal(err)
	}
	castView, err := p.OpenRoleView(as(cast.GetBearer()), &sessionv1.OpenRoleViewRequest{InstallationId: wiki, Roles: []string{"user"}})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := p.End(context.Background(), &sessionv1.EndRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("End with no bearer: want unauthenticated, got %v", err)
	}
	if _, err := p.End(as("not-a-session"), &sessionv1.EndRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("End with a bearer naming no session: want unauthenticated, got %v", err)
	}

	// Leaving the cast ends it and the view opened from it, and nothing else.
	if _, err := p.End(as(cast.GetBearer()), &sessionv1.EndRequest{}); err != nil {
		t.Fatalf("End of the cast: %v", err)
	}
	ended(t, p, "the cast", cast.GetBearer())
	ended(t, p, "the view opened from the cast", castView.GetBearer())
	open(t, p, "the session the cast was opened from", dana.GetBearer())
	open(t, p, "a view of the session the cast was opened from", view.GetBearer())

	// Signing out ends the session and its view; her other sign-in is her own.
	if _, err := p.End(as(dana.GetBearer()), &sessionv1.EndRequest{}); err != nil {
		t.Fatalf("End of the session: %v", err)
	}
	ended(t, p, "the session", dana.GetBearer())
	ended(t, p, "its role view", view.GetBearer())
	open(t, p, "the person's other session", other.GetBearer())
}

// Every session carries an expiry; a view or a cast ends no later than the
// session it was opened from; and an expired bearer is unauthenticated
// wherever a session is read.
func TestEverySessionExpiresAndAViewOrCastNoLaterThanItsParent(t *testing.T) {
	var offset atomic.Int64
	start := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	k := testkit.NewWithClock(t, func() time.Time { return start.Add(time.Duration(offset.Load())) })
	p := &session.Plugin{State: k.State, Fixture: true}
	wiki := state.InstallationID("acme", "wiki")

	dana := signIn(t, p, "dev-dana")
	if want := start.Add(state.SessionLifetime).Unix(); dana.GetExpiresAtUnix() != want {
		t.Fatalf("a session opened at %d expires at %d, want %d", start.Unix(), dana.GetExpiresAtUnix(), want)
	}
	current, err := p.Current(as(dana.GetBearer()), &sessionv1.CurrentRequest{})
	if err != nil || current.GetExpiresAtUnix() != dana.GetExpiresAtUnix() {
		t.Fatalf("Current answers expiry %d (%v), want the session's %d", current.GetExpiresAtUnix(), err, dana.GetExpiresAtUnix())
	}

	// Opened most of a lifetime later, a view and a cast still end with it.
	offset.Store(int64(state.SessionLifetime - time.Minute))
	view, err := p.OpenRoleView(as(dana.GetBearer()), &sessionv1.OpenRoleViewRequest{InstallationId: wiki, Roles: []string{"admin"}})
	if err != nil {
		t.Fatal(err)
	}
	cast, err := p.OpenTeamCast(as(dana.GetBearer()), &sessionv1.OpenTeamCastRequest{TeamId: "wiki-user"})
	if err != nil {
		t.Fatal(err)
	}
	later := signIn(t, p, "dev-dana")
	for name, child := range map[string]*sessionv1.Session{"view": view, "cast": cast} {
		if child.GetExpiresAtUnix() == 0 || child.GetExpiresAtUnix() > dana.GetExpiresAtUnix() {
			t.Fatalf("the %s expires at %d, later than the session it was opened from (%d)", name, child.GetExpiresAtUnix(), dana.GetExpiresAtUnix())
		}
	}
	open(t, p, "the session, a minute before it expires", dana.GetBearer())

	offset.Store(int64(state.SessionLifetime))
	ended(t, p, "the expired session", dana.GetBearer())
	ended(t, p, "the view of the expired session", view.GetBearer())
	ended(t, p, "the cast of the expired session", cast.GetBearer())
	open(t, p, "a session opened later", later.GetBearer())
}

// The grant epoch is the same while what the session holds is the same, and
// differs once it differs: a role granted or revoked to the person, to a team
// of theirs or to the team a cast acts as, leaving a team, and an
// installation made, delivered anew or ended.
func TestTheGrantEpochDiffersWheneverWhatTheSessionHoldsDiffers(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	p := &session.Plugin{State: k.State, Fixture: true}
	wiki := state.InstallationID("acme", "wiki")
	svc := k.State.Service()

	alice := signIn(t, p, "dev-alice")
	admin, err := k.State.Caller(alice.GetBearer())
	if err != nil {
		t.Fatal(err)
	}
	bob := signIn(t, p, "dev-bob")
	carol := signIn(t, p, "dev-carol")
	cast, err := p.OpenTeamCast(as(alice.GetBearer()), &sessionv1.OpenTeamCastRequest{TeamId: "wiki-user"})
	if err != nil {
		t.Fatal(err)
	}
	if signed := bob.GetGrantEpoch(); signed == "" {
		t.Fatal("SignIn states no grant epoch")
	}
	if cast.GetGrantEpoch() == "" {
		t.Fatal("OpenTeamCast states no grant epoch")
	}

	epoch := func(s *sessionv1.Session) string {
		t.Helper()
		current, err := p.Current(as(s.GetBearer()), &sessionv1.CurrentRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if current.GetGrantEpoch() == "" {
			t.Fatal("Current states no grant epoch")
		}
		return current.GetGrantEpoch()
	}
	seen := map[string]string{}
	moved := func(what string, s *sessionv1.Session) {
		t.Helper()
		now := epoch(s)
		if now == seen[s.GetBearer()] {
			t.Fatalf("%s: the grant epoch did not move", what)
		}
		if again := epoch(s); again != now {
			t.Fatalf("%s: the grant epoch moved with nothing changed: %s then %s", what, now, again)
		}
		seen[s.GetBearer()] = now
	}
	same := func(what string, s *sessionv1.Session) {
		t.Helper()
		if now := epoch(s); now != seen[s.GetBearer()] {
			t.Fatalf("%s: the grant epoch moved for a session whose holdings did not", what)
		}
	}
	for _, s := range []*sessionv1.Session{bob, carol, cast} {
		seen[s.GetBearer()] = epoch(s)
		if seen[s.GetBearer()] != s.GetGrantEpoch() && s != cast {
			t.Fatalf("Current's grant epoch %s is not the one SignIn answered, %s", seen[s.GetBearer()], s.GetGrantEpoch())
		}
	}
	if seen[bob.GetBearer()] == seen[carol.GetBearer()] {
		t.Fatal("bob, who holds nothing, and carol, a user of the wiki, state the same grant epoch")
	}

	grant := func(r authority.RoleRequest) {
		t.Helper()
		r.Organization, r.InstallationID = "acme", wiki
		if _, err := svc.GrantRole(ctx, admin, r); err != nil {
			t.Fatal(err)
		}
	}
	revoke := func(r authority.RoleRequest) {
		t.Helper()
		r.Organization, r.InstallationID = "acme", wiki
		if _, err := svc.RevokeRole(ctx, admin, r); err != nil {
			t.Fatal(err)
		}
	}

	grant(authority.RoleRequest{Role: state.UserRole, PersonID: "bob"})
	moved("a role granted to the person", bob)
	same("a role granted to someone else", carol)
	revoke(authority.RoleRequest{Role: state.UserRole, PersonID: "bob"})
	moved("a role revoked from the person", bob)

	grant(authority.RoleRequest{Role: state.AdminRole, TeamID: "wiki-user"})
	moved("a role granted to a team of theirs", carol)
	moved("a role granted to the team the cast acts as", cast)
	same("a role granted to a team they are not in", bob)
	revoke(authority.RoleRequest{Role: state.AdminRole, TeamID: "wiki-user"})
	moved("a role revoked from a team of theirs", carol)
	moved("a role revoked from the team the cast acts as", cast)

	if _, err := k.State.ApplyManifest(testkit.Wiki(9)); err != nil {
		t.Fatal(err)
	}
	moved("the installation's target delivered anew", carol)

	if err := k.State.LeaveTeam(ctx, "carol", "wiki-user"); err != nil {
		t.Fatal(err)
	}
	moved("leaving a team", carol)

	grant(authority.RoleRequest{Role: state.UserRole, PersonID: "bob"})
	moved("a role granted again", bob)
	if err := k.State.UninstallAsHost(wiki); err != nil {
		t.Fatal(err)
	}
	moved("the installation ended", bob)
	if _, err := k.State.InstallAsHost(ctx, "acme", "wiki", state.UserRole, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := k.State.GrantRole(domain.RoleGrant{InstallationID: wiki, Role: state.UserRole, PersonID: "bob"}); err != nil {
		t.Fatal(err)
	}
	moved("the installation made again", bob)
}
