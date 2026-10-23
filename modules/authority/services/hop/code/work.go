package main

import (
	"context"
	"fmt"

	"github.com/codefly-dev/core/wool"
	codefly "github.com/codefly-dev/sdk-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"

	"hop/pkg/adapters"
	"hop/pkg/business/decide"
	"hop/pkg/infra/policy"
	"hop/pkg/infra/proxy"
)

// The module this hop stands in front of. Its principal is its name, and so the
// audience a Work Context must be addressed to. Composing a hop in front of
// every module, and handing each its module, is the composition's job; until it
// is, this run's hop fronts the console.
const fronted = "console"

func init() {
	WithConfigure(standInFront)
}

func standInFront(ctx context.Context, config *adapters.Configuration) (Clean, error) {
	w := wool.Get(ctx).In("hop")
	proof, err := codefly.For(ctx).WorkspaceSecret("hop", "PROOF")
	if err != nil || proof == "" {
		return nil, fmt.Errorf("hop: no run proof delivered (codefly config generate hop PROOF): %v", err)
	}
	// The authority, through the interface the hop depends on. The SDK resolves an
	// endpoint by its provider, not yet by the interface it implements, so this
	// names the provider the local composition binds; the host is another one.
	authority, err := dial(ctx, "authority", "gateway")
	if err != nil {
		return nil, err
	}
	module, err := dial(ctx, fronted, "api", proxy.DialOptions()...)
	if err != nil {
		return nil, err
	}
	p := &proxy.Proxy{
		Decide: decide.Decider{
			Authority: authorityv1.NewAuthorityServiceClient(authority),
			Audience:  fronted,
			Policies:  &policy.Reader{Module: module},
		}.Decide,
		Upstream: module,
		Proof:    proof,
		Refused: func(method string, err error) {
			w.Warn("refused", wool.Field("module", fronted), wool.Field("method", method), wool.Field("reason", err.Error()))
		},
	}
	config.GRPCServerOptions = append(config.GRPCServerOptions, p.ServerOptions()...)
	w.Info("standing in front of a module", wool.Field("module", fronted))
	return func() { _ = authority.Close(); _ = module.Close() }, nil
}

func dial(ctx context.Context, module, service string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	instance, err := codefly.For(ctx).Module(module).Service(service).API("grpc").ResolveNetworkInstance()
	if err != nil {
		return nil, fmt.Errorf("hop: cannot resolve %s/%s: %w", module, service, err)
	}
	return grpc.NewClient(fmt.Sprintf("%s:%d", instance.Hostname, instance.Port), append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))...)
}
