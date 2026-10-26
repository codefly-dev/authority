package hop

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
)

const arrivalMethod = "/test.Service/Read"

// arrive is gRPC tagging a call that reached the server carrying md, as it
// does on every transport before the call's body is read. It returns once the
// reservation started at arrival has been decided, so the test's clock moves
// only after it.
func arrive(v *Verifier, md metadata.MD) context.Context {
	ctx := v.StatsHandler().TagRPC(metadata.NewIncomingContext(context.Background(), md), &stats.RPCTagInfo{FullMethodName: arrivalMethod})
	<-ctx.Value(admissionKey{}).(*admission).reserved
	return ctx
}

func arrivalVerifier(t *testing.T, clock *time.Time) (*Verifier, signer) {
	t.Helper()
	s := newSigner("arrival")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: s.issuer, Keys: []*authorityv1.PublicKey{s.published()}}}
	v, err := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return *clock }
	v.fetched, v.tried = *clock, *clock
	return v, s
}

// Review r164 B3: grpc-go decodes a unary request fully before it runs the
// unary interceptor, so a slow or large upload reached Verify long after the
// hop admitted it and was refused for an expiry that had not happened at call
// start. The window is judged at the instant the stream was accepted, which
// the stats handler records.
func TestTheAdmissionWindowIsJudgedWhenTheCallArrivesNotAfterItsBodyDecodes(t *testing.T) {
	clock := time.Unix(1792818000, 0)
	v, s := arrivalVerifier(t, &clock)
	md := forwarded(t, s.issue(t, clock, "documents"), "proof", "")

	// The stream is accepted now; its body then takes two minutes to arrive,
	// well past stamp.Lifetime.
	ctx := arrive(v, md)
	clock = clock.Add(2 * time.Minute)
	reached := false
	if _, err := v.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: arrivalMethod}, func(context.Context, any) (any, error) {
		reached = true
		return nil, nil
	}); err != nil || !reached {
		t.Fatalf("a call admitted at arrival was refused after its body decoded: %v", err)
	}
}

// Nothing is admitted by the absence of the stats handler: a server that
// installs none judges the window at the instant Verify runs, as it did before.
func TestWithoutTheStatsHandlerTheWindowIsJudgedWhenVerifyRuns(t *testing.T) {
	clock := time.Unix(1792818000, 0)
	v, s := arrivalVerifier(t, &clock)
	md := forwarded(t, s.issue(t, clock, "documents"), "proof", "")
	clock = clock.Add(2 * time.Minute)
	_, err := v.Verify(context.Background(), md, arrivalMethod)
	var reason refusal.Reason
	if !errors.As(err, &reason) || reason != refusal.StampWindow {
		t.Fatalf("want %s without the stats handler: %v", refusal.StampWindow, err)
	}
}

// The window the stats handler opens is the admission's own, not an unbounded one:
// a call accepted further ahead than the clock allowance, or long after the
// admission expired, is still refused, each under its own reason.
func TestTheArrivalInstantDoesNotWidenTheAdmissionWindow(t *testing.T) {
	for _, tc := range []struct {
		name  string
		shift time.Duration
		want  refusal.Reason
	}{
		{"accepted further ahead than the allowance", -stamp.Skew - 5*time.Second, refusal.StampIssued},
		{"accepted long after it expired", stamp.Lifetime + stamp.Skew + time.Second, refusal.StampWindow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := time.Unix(1792818000, 0)
			v, s := arrivalVerifier(t, &clock)
			md := forwarded(t, s.issue(t, clock, "documents"), "proof", "")
			clock = clock.Add(tc.shift)
			ctx := arrive(v, md)
			_, err := v.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: arrivalMethod}, func(context.Context, any) (any, error) {
				return nil, nil
			})
			// The interceptor answers a gRPC status, which carries the reason
			// as its text rather than a wrapped error.
			if err == nil || !strings.Contains(err.Error(), tc.want.Code()) {
				t.Fatalf("want %s: %v", tc.want, err)
			}
		})
	}
}

// A reservation outlives the admission by the same allowance, so a shared store
// evicting on its own clock cannot release a nonce a lagging verifier admits.
func TestAReservationIsRetainedPastExpiryByTheClockAllowance(t *testing.T) {
	clock := time.Unix(1792818000, 0)
	v, s := arrivalVerifier(t, &clock)
	store := &retention{}
	v.replay = store
	md := forwarded(t, s.issue(t, clock, "documents"), "proof", "")
	call, err := stamp.Check(md, testSigner("proof").PublicKey(), arrivalMethod, "documents", clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), md, arrivalMethod); err != nil {
		t.Fatal(err)
	}
	if want := time.Unix(call.Expires+int64(stamp.Skew/time.Second), 0); !store.until.Equal(want) {
		t.Fatalf("retained until %v, want the admission's expiry plus the allowance %v", store.until, want)
	}
}

type retention struct{ until time.Time }

func (r *retention) Consume(_ context.Context, _ string, until time.Time) error {
	r.until = until
	return nil
}

// accepting is a store that has evicted every nonce: each consumption succeeds.
type accepting struct{}

func (accepting) Consume(context.Context, string, time.Time) error { return nil }

// A store with no completion operation keeps a nonce only to its retention. A
// delivery whose consumption completes past that retention found an evicted
// nonce, so it is refused on the window rather than run a second time.
func TestAConsumptionCompletingPastItsRetentionIsRefused(t *testing.T) {
	clock := time.Unix(1792818000, 0)
	v, s := arrivalVerifier(t, &clock)
	v.replay = accepting{}
	md := forwarded(t, s.issue(t, clock, "documents"), "proof", "")
	if _, err := v.reserve(context.Background(), md, arrivalMethod, instant{at: clock, mark: time.Now()}); err != nil {
		t.Fatalf("a delivery consumed inside its retention was refused: %v", err)
	}
	// Arrived inside the window, but its consumption completed a minute later.
	_, err := v.reserve(context.Background(), md, arrivalMethod, instant{at: clock, mark: time.Now().Add(-time.Minute)})
	var reason refusal.Reason
	if !errors.As(err, &reason) || reason != refusal.StampWindow {
		t.Fatalf("want %s for a consumption past its retention: %v", refusal.StampWindow, err)
	}
}
