package decide

import (
	"context"
	"sync"
	"testing"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/hop/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// slow is an authority that answers only once it is released, and otherwise
// for as long as the hop is willing to wait for it.
type slow struct {
	release chan struct{}

	mu      sync.Mutex
	bounded []bool
}

func (s *slow) Check(ctx context.Context, _ *authorityv1.CheckRequest, _ ...grpc.CallOption) (*authorityv1.CheckResponse, error) {
	_, bounded := ctx.Deadline()
	s.mu.Lock()
	s.bounded = append(s.bounded, bounded)
	s.mu.Unlock()
	select {
	case <-s.release:
		return &authorityv1.CheckResponse{Context: &authorityv1.WorkContextV1{OwnerPrincipalId: "maya"}}, nil
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	}
}

// Review item A7: the hop set no deadline of its own on the authority's check,
// so a caller that set none waited on a stalled authority for as long as the
// connection lived. The check is bounded by the hop whatever the caller sent.
func TestTheHopBoundsTheAuthoritysCheckWhenTheCallerSetsNoDeadline(t *testing.T) {
	answered := make(chan struct{})
	close(answered)
	authority := &slow{release: answered}
	d := Decider{Authority: authority, AudienceOf: func(string) (string, error) { return "model", nil },
		Routes: testRoutes("model", "GET /v1/model/profiles"), Modules: map[string]bool{"model": true}}
	if _, err := d.Decide(context.Background(), "GET /v1/model/profiles", metadata.Pairs(hop.WorkContextKey, "x")); err != nil {
		t.Fatal(err)
	}
	if len(authority.bounded) != 1 || !authority.bounded[0] {
		t.Fatalf("the authority was asked with no deadline of the hop's own (bounded: %v)", authority.bounded)
	}
}
