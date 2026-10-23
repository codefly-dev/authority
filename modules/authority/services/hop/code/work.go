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
	// The modules this hop stands in front of are the composition's to name:
	// MODULES lists their principals, and UPSTREAM_<MODULE> is each one's
	// endpoint, a ${endpoint:<module>/<service>/<endpoint>} reference the CLI
	// resolves. Codefly composing a hop in front of every module replaces both.
	listed, err := codefly.For(ctx).WorkspaceConfiguration("hop", "MODULES")
	if err != nil || listed == "" {
		return nil, fmt.Errorf("hop: the composition names no module to stand in front of (hop/MODULES): %v", err)
	}
	modules, upstreams := map[string]bool{}, map[string]*grpc.ClientConn{}
	for _, name := range strings.Split(listed, ",") {
		name = strings.TrimSpace(name)
		key := "UPSTREAM_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		endpoint, err := codefly.For(ctx).WorkspaceConfiguration("hop", key)
		if err != nil || endpoint == "" {
			return nil, fmt.Errorf("hop: the composition names no endpoint for %s (hop/%s): %v", name, key, err)
		}
		conn, err := grpc.NewClient(address(endpoint), append(proxy.DialOptions(), grpc.WithTransportCredentials(insecure.NewCredentials()))...)
		if err != nil {
			return nil, err
		}
		modules[name], upstreams[name] = true, conn
	}
	p := &proxy.Proxy{
		Decide:    decide.Decider{Authority: authorityv1.NewAuthorityServiceClient(authority), Modules: modules}.Decide,
		Upstreams: upstreams,
		Proof:     proof,
		Refused: func(method string, err error) {
			w.Warn("refused", wool.Field("method", method), wool.Field("reason", err.Error()))
		},
	}
	config.GRPCServerOptions = append(config.GRPCServerOptions, p.ServerOptions()...)
	w.Info("standing in front of modules", wool.Field("modules", listed))
	return func() {
		_ = authority.Close()
		for _, conn := range upstreams {
			_ = conn.Close()
		}
	}, nil
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
