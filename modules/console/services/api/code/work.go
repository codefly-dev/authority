package main

import (
	"context"
	"fmt"

	"github.com/codefly-dev/authority/libraries/hop/go"
	codefly "github.com/codefly-dev/sdk-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"api/pkg/adapters"
	gen "api/pkg/gen"
)

func init() {
	WithConfigure(answerFromTheStamp)
}

// answerFromTheStamp is all the authority code the console carries: it reads
// who a call is for off the stamp the hop wrote, and refuses a call that did
// not come through the hop. It verifies no token and asks no authority.
func answerFromTheStamp(ctx context.Context, config *adapters.Configuration) (Clean, error) {
	proof, err := codefly.For(ctx).WorkspaceSecret("hop", "PROOF")
	if err != nil || proof == "" {
		return nil, fmt.Errorf("console: no run proof delivered (codefly config generate hop PROOF): %v", err)
	}
	config.GRPCServerOptions = append(config.GRPCServerOptions,
		grpc.ChainUnaryInterceptor(hop.UnaryServerInterceptor(proof)),
		grpc.ChainStreamInterceptor(hop.StreamServerInterceptor(proof)))
	config.Service = &console{}
	return nil, nil
}

type console struct {
	gen.UnimplementedApiServiceServer
}

func (*console) Version(context.Context, *gen.VersionRequest) (*gen.VersionResponse, error) {
	return &gen.VersionResponse{Version: "0.1.0"}, nil
}

// WhoAmI answers who the call is for, from the stamp alone.
func (*console) WhoAmI(ctx context.Context, _ *gen.WhoAmIRequest) (*gen.WhoAmIResponse, error) {
	id, ok := hop.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, hop.ErrNoStamp.Error())
	}
	return &gen.WhoAmIResponse{Owner: id.Owner, OwnerKind: id.OwnerKind, Tenant: id.Tenant, Actors: id.Actors, Scopes: id.Scopes}, nil
}
