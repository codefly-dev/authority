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

// A Check the caller's request ended before is refused under Canceled, and its
// reason says the check ended rather than that the authority refused the call.
func TestACheckTheCallerEndedIsNotARefusal(t *testing.T) {
	d := Decider{Authority: ended{}, AudienceOf: func(string) (string, error) { return "model", nil },
		Routes: testRoutes("model", "GET /v1/model/profiles"), Modules: map[string]bool{"model": true}}
	_, err := d.Decide(context.Background(), "GET /v1/model/profiles", metadata.Pairs(hop.WorkContextKey, "x"))
	if status.Code(err) != codes.Canceled {
		t.Fatalf("refused %v, want Canceled", err)
	}
	if message := status.Convert(err).Message(); strings.Contains(message, "refused") || !strings.Contains(message, "context canceled") {
		t.Fatalf("reason %q", message)
	}
}
