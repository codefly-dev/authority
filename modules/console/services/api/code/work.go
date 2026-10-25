package main

import (
	"context"
	"fmt"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/host"
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

// answerFromTheStamp is all the authority code the console carries: the hop's
// Verifier authenticates each forwarded Work Context against the authority's
// published keys and reads who the call is for from it, and refuses, by name,
// a call that did not come through the hop or carries a context the authority
// did not issue for the console. It re-checks no permission the hop decided.
func answerFromTheStamp(ctx context.Context, config *adapters.Configuration) (Clean, error) {
	proof, err := codefly.For(ctx).WorkspaceSecret("hop", "PROOF")
	if err != nil || proof == "" {
		return nil, fmt.Errorf("console: no run proof delivered (codefly config generate hop PROOF): %v", err)
	}
	conn, _, err := host.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("console: %w", err)
	}
	verifier, err := hop.NewVerifier(ctx, authorityv1.NewAuthorityServiceClient(conn), "console", proof)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("console: %w", err)
	}
	config.GRPCServerOptions = append(config.GRPCServerOptions,
		grpc.ChainUnaryInterceptor(verifier.UnaryServerInterceptor()),
		grpc.ChainStreamInterceptor(verifier.StreamServerInterceptor()))
	config.Service = &console{}
	return func() { _ = conn.Close() }, nil
}

type console struct {
	gen.UnimplementedApiServiceServer
}

func (*console) Version(context.Context, *gen.VersionRequest) (*gen.VersionResponse, error) {
	return &gen.VersionResponse{Version: "0.1.0"}, nil
}

// WhoAmI answers who the call is for, from the authenticated Work Context.
func (*console) WhoAmI(ctx context.Context, _ *gen.WhoAmIRequest) (*gen.WhoAmIResponse, error) {
	id, ok := hop.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "the call carries no authenticated Work Context")
	}
	return &gen.WhoAmIResponse{Owner: id.Owner, OwnerKind: id.OwnerKind, Tenant: id.Tenant, Actors: id.Actors, Scopes: id.Scopes}, nil
}
