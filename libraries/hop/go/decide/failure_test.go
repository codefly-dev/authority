package decide

import (
	"context"
	"strings"
	"testing"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/hop/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type ended struct{}

func (ended) Check(context.Context, *authorityv1.CheckRequest, ...grpc.CallOption) (*authorityv1.CheckResponse, error) {
	return nil, status.Error(codes.Canceled, "context canceled")
}

// A Check that came back Canceled is the caller ending its request only when
// the caller's request has in fact ended: then Canceled, and the reason says
// so. A mesh or waypoint reset, or the authority shutting down, also surfaces
// as Canceled while the caller is still live; that is the authority not
// answering, Unavailable, and its reason names the authority.
func TestACheckTheCallerEndedIsNotARefusal(t *testing.T) {
	d := Decider{Authority: ended{}, AudienceOf: func(string) (string, error) { return "model", nil },
		Routes: testRoutes("model", "GET /v1/model/profiles"), Modules: map[string]bool{"model": true}}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := d.Decide(cancelled, "GET /v1/model/profiles", metadata.Pairs(hop.WorkContextKey, "x"))
	if status.Code(err) != codes.Canceled {
		t.Fatalf("refused %v, want Canceled", err)
	}
	if message := status.Convert(err).Message(); strings.Contains(message, "refused") || !strings.Contains(message, "the caller's request ended") {
		t.Fatalf("reason %q", message)
	}

	_, err = d.Decide(context.Background(), "GET /v1/model/profiles", metadata.Pairs(hop.WorkContextKey, "x"))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("a live caller's cancelled Check refused %v, want Unavailable", err)
	}
	if message := status.Convert(err).Message(); strings.Contains(message, "the caller's request ended") || !strings.Contains(message, "authority") {
		t.Fatalf("reason %q", message)
	}
}
