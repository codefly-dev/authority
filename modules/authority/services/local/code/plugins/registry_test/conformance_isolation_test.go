package registry_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	authorityv1 "gateway/pkg/gen/host/authority/v1"
	sessionv1 "gateway/pkg/gen/host/session/v1"
	conformance "github.com/codefly-dev/authority/libraries/conformance/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestConformanceFixturesIsolateKeysSessionsAndClocks(t *testing.T) {
	now := time.Now().UTC()
	firstClock, secondClock := conformance.NewClock(now), conformance.NewClock(now)
	first, _, f := localConformanceFixture(t, firstClock)
	second, _, other := localConformanceFixture(t, secondClock)
	ctx := context.Background()
	signIn := func(conn grpc.ClientConnInterface, fixture conformance.Fixture) context.Context {
		sess, err := sessionv1.NewSessionServiceClient(conn).SignIn(ctx, &sessionv1.SignInRequest{FixtureToken: fixture.ViewerToken})
		if err != nil {
			t.Fatal(err)
		}
		return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+sess.Bearer)
	}
	firstSession, secondSession := signIn(first, f), signIn(second, other)
	if _, err := sessionv1.NewSessionServiceClient(second).Current(firstSession, &sessionv1.CurrentRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("another fixture accepted the first session: %v", err)
	}
	issue := func(conn grpc.ClientConnInterface, session context.Context, audience string) string {
		out, err := authorityv1.NewAuthorityServiceClient(conn).Issue(session, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: audience, TtlSeconds: 1})
		if err != nil {
			t.Fatal(err)
		}
		return out.Token
	}
	firstToken, secondToken := issue(first, firstSession, f.Audience), issue(second, secondSession, other.Audience)
	check := func(conn grpc.ClientConnInterface, token, audience string) error {
		_, err := authorityv1.NewAuthorityServiceClient(conn).Check(ctx, &authorityv1.CheckRequest{Token: token, Audience: audience})
		return err
	}
	if err := check(second, firstToken, f.Audience); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("another fixture accepted the first signing key: %v", err)
	}
	firstClock.Set(now.Add(time.Minute))
	if err := check(first, firstToken, f.Audience); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("first fixture ignored its clock: %v", err)
	}
	if err := check(second, secondToken, other.Audience); err != nil {
		t.Fatalf("moving the first clock changed the second fixture: %v", err)
	}
	firstEnvelope, err := f.SignAuthority([]byte("isolated release"))
	if err != nil {
		t.Fatal(err)
	}
	secondEnvelope, err := other.SignAuthority([]byte("isolated release"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstEnvelope, secondEnvelope) {
		t.Fatal("fixtures share a release key")
	}
}
