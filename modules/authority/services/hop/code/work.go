package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/codefly-dev/core/wool"
	codefly "github.com/codefly-dev/sdk-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"

	"hop/pkg/adapters"
	"hop/pkg/business/decide"
	"hop/pkg/infra/proxy"
)

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
	// The module this hop stands in front of is the composition's to name: its
	// principal (the audience a Work Context must be addressed to) and its
	// endpoint, as a ${endpoint:<module>/<service>/<endpoint>} reference the
	// CLI resolves. Codefly composing a hop in front of every module replaces
	// both.
	fronted, err := codefly.For(ctx).WorkspaceConfiguration("hop", "MODULE")
	if err != nil || fronted == "" {
		return nil, fmt.Errorf("hop: the composition names no module to stand in front of (hop/MODULE): %v", err)
	}
	upstream, err := codefly.For(ctx).WorkspaceConfiguration("hop", "UPSTREAM")
	if err != nil || upstream == "" {
		return nil, fmt.Errorf("hop: the composition names no endpoint for %s (hop/UPSTREAM): %v", fronted, err)
	}
	module, err := grpc.NewClient(address(upstream), append(proxy.DialOptions(), grpc.WithTransportCredentials(insecure.NewCredentials()))...)
	if err != nil {
		return nil, err
	}
	p := &proxy.Proxy{
		Decide:   decide.Decider{Authority: authorityv1.NewAuthorityServiceClient(authority), Audience: fronted}.Decide,
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

// address is a resolved endpoint reference as gRPC dials it.
func address(endpoint string) string {
	for _, scheme := range []string{"grpc://", "http://", "tcp://"} {
		endpoint = strings.TrimPrefix(endpoint, scheme)
	}
	return endpoint
}

func dial(ctx context.Context, module, service string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	instance, err := codefly.For(ctx).Module(module).Service(service).API("grpc").ResolveNetworkInstance()
	if err != nil {
		return nil, fmt.Errorf("hop: cannot resolve %s/%s: %w", module, service, err)
	}
	return grpc.NewClient(fmt.Sprintf("%s:%d", instance.Hostname, instance.Port), append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))...)
}
