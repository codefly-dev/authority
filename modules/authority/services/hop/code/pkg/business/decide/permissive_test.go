package decide

import (
	"context"
	"errors"
	"testing"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/hop/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type refusing struct{}

func (refusing) Check(context.Context, *authorityv1.CheckRequest, ...grpc.CallOption) (*authorityv1.CheckResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "robin requires robin.intents:read_config for GET /v1/robin/intents/version, which the call does not hold")
}

// Permissive, the hop lets a refused call through: the module is the token's
// audience, the identity what the token claims, the refusal rides as the
// stamp's advisory and is told to Warned. Enforcing, the refusal stands.
func TestAPermissiveHopLetsARefusedCallThroughWithTheRefusalAsAdvisory(t *testing.T) {
	var warned string
	d := Decider{Authority: refusing{}, Modules: map[string]bool{"robin": true}, Permissive: true,
		Warned:     func(method string, err error) { warned = method + ": " + err.Error() },
		AudienceOf: func(string) (string, error) { return "robin", nil }}
	md := metadata.Pairs(hop.WorkContextKey, "not-a-core-token")
	module, id, err := d.Decide(context.Background(), "GET /v1/robin/intents/version", md)
	if err != nil || module != "robin" {
		t.Fatalf("permissive: %v %v", module, err)
	}
	if id.Owner != "developer" || id.Tenant != "local" || id.Advisory == "" {
		t.Fatalf("an undecodable token is stamped as a developer with the advisory: %+v", id)
	}
	if warned == "" {
		t.Fatal("the refusal was not told")
	}
	stamp := metadata.MD{}
	hop.Stamp(stamp, id, "proof")
	read, err := hop.Read(stamp, "proof")
	if err != nil || read.Advisory != id.Advisory {
		t.Fatalf("the advisory rides the stamp: %+v %v", read, err)
	}

	strict := Decider{Authority: refusing{}, Modules: map[string]bool{"robin": true}, AudienceOf: func(string) (string, error) { return "robin", nil }}
	if _, _, err := strict.Decide(context.Background(), "GET /v1/robin/intents/version", md); err == nil || status.Code(err) != codes.PermissionDenied {
		t.Fatalf("enforcing, the refusal stands: %v", err)
	}
	if !errors.Is(err, err) {
		t.Fatal("unreachable")
	}
}
