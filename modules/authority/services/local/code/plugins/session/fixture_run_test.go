package session_test

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"gateway/pkg/business/testkit"
	sessionv1 "gateway/pkg/gen/host/session/v1"
	"gateway/plugins/session"
)

// Fixture sign-in is what a run started on its fixture serves, and it has to
// be said: a session plugin nobody told so lists no fixture person, hands out
// no sign-in token and signs nobody in by one. The listing is not
// authenticated (the sign-in page reads it before anyone is signed in), so
// this is the only thing between a fixture token and whoever can reach the
// listener.
func TestFixtureSignInIsServedOnlyByARunStartedOnItsFixture(t *testing.T) {
	k := testkit.New(t)
	closed := &session.Plugin{State: k.State}
	listed, err := closed.ListFixturePeople(context.Background(), &sessionv1.ListFixturePeopleRequest{})
	if status.Code(err) != codes.FailedPrecondition || len(listed.GetPeople()) != 0 {
		t.Fatalf("a plugin not told it serves a fixture listed %d people: %v", len(listed.GetPeople()), err)
	}
	if signed, err := closed.SignIn(context.Background(), &sessionv1.SignInRequest{FixtureToken: "fixture-maya"}); status.Code(err) != codes.FailedPrecondition || signed.GetBearer() != "" {
		t.Fatalf("a plugin not told it serves a fixture signed a fixture person in: %v", err)
	}

	open := &session.Plugin{State: k.State, Fixture: true}
	listed, err = open.ListFixturePeople(context.Background(), &sessionv1.ListFixturePeopleRequest{})
	if err != nil || len(listed.GetPeople()) == 0 || listed.GetPeople()[0].GetFixtureToken() == "" {
		t.Fatalf("a fixture run lists its people with their tokens: %v %v", listed, err)
	}
	if signed, err := open.SignIn(context.Background(), &sessionv1.SignInRequest{FixtureToken: "fixture-maya"}); err != nil || signed.GetBearer() == "" {
		t.Fatalf("a fixture run signs its people in: %v", err)
	}
}
