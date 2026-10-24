package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/codefly-dev/core/standards"
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
	// MODULES lists their principals, and each one's endpoint is
	// UPSTREAM_<MODULE> for a module serving gRPC, HTTP_UPSTREAM_<MODULE> for
	// one serving HTTP, CONNECT_UPSTREAM_<MODULE> for one serving Connect on a
	// listener of its own, any of them: a ${endpoint:<module>/<service>/
	// <endpoint>} reference the CLI resolves. Codefly composing a hop in front
	// of every module replaces them.
	listed, err := codefly.For(ctx).WorkspaceConfiguration("hop", "MODULES")
	if err != nil || listed == "" {
		return nil, fmt.Errorf("hop: the composition names no module to stand in front of (hop/MODULES): %v", err)
	}
	modules, upstreams, webs, connects := map[string]bool{}, map[string]*grpc.ClientConn{}, map[string]*url.URL{}, map[string]*url.URL{}
	for _, name := range strings.Split(listed, ",") {
		name = strings.TrimSpace(name)
		suffix := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
		grpcEndpoint, _ := codefly.For(ctx).WorkspaceConfiguration("hop", "UPSTREAM_"+suffix)
		httpEndpoint, _ := codefly.For(ctx).WorkspaceConfiguration("hop", "HTTP_UPSTREAM_"+suffix)
		connectEndpoint, _ := codefly.For(ctx).WorkspaceConfiguration("hop", "CONNECT_UPSTREAM_"+suffix)
		if grpcEndpoint == "" && httpEndpoint == "" && connectEndpoint == "" {
			return nil, fmt.Errorf("hop: the composition names no endpoint for %s (hop/UPSTREAM_%s, hop/HTTP_UPSTREAM_%s or hop/CONNECT_UPSTREAM_%s)", name, suffix, suffix, suffix)
		}
		if grpcEndpoint != "" {
			conn, err := grpc.NewClient(address(grpcEndpoint), append(proxy.DialOptions(), grpc.WithTransportCredentials(insecure.NewCredentials()))...)
			if err != nil {
				return nil, err
			}
			upstreams[name] = conn
		}
		if httpEndpoint != "" {
			target, err := url.Parse(httpEndpoint)
			if err != nil || target.Scheme == "" || target.Host == "" {
				return nil, fmt.Errorf("hop: hop/HTTP_UPSTREAM_%s is not an absolute URL: %q", suffix, httpEndpoint)
			}
			webs[name] = target
		}
		if connectEndpoint != "" {
			target, err := url.Parse(connectEndpoint)
			if err != nil || target.Scheme == "" || target.Host == "" {
				return nil, fmt.Errorf("hop: hop/CONNECT_UPSTREAM_%s is not an absolute URL: %q", suffix, connectEndpoint)
			}
			connects[name] = target
		}
		modules[name] = true
	}
	decision := decide.Decider{Authority: authorityv1.NewAuthorityServiceClient(authority), Modules: modules}.Decide
	refused := func(method string, err error) {
		w.Warn("refused", wool.Field("method", method), wool.Field("reason", err.Error()))
	}
	p := &proxy.Proxy{Decide: decision, Upstreams: upstreams, Proof: proof, Refused: refused}
	config.GRPCServerOptions = append(config.GRPCServerOptions, p.ServerOptions()...)
	// The service declares this endpoint even when every upstream uses gRPC.
	// Keep it listening so the declared readiness contract holds; the proxy
	// still refuses requests for which no authorized HTTP route exists.
	stopWeb, err := serveHTTP(ctx, &proxy.HTTP{Decide: decision, Upstreams: webs, Connect: connects, Proof: proof, Refused: refused})
	if err != nil {
		return nil, err
	}
	w.Info("standing in front of modules", wool.Field("modules", listed))
	return func() {
		stopWeb()
		_ = authority.Close()
		for _, conn := range upstreams {
			_ = conn.Close()
		}
	}, nil
}

// serveHTTP listens on the hop's http endpoint, as the run allocated it, with
// the hop's HTTP face.
func serveHTTP(ctx context.Context, face http.Handler) (func(), error) {
	instance, err := codefly.For(ctx).API(standards.HTTP).ResolveNetworkInstance()
	if err != nil {
		return nil, fmt.Errorf("hop: the hop's http endpoint does not resolve: %w", err)
	}
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", instance.Port))
	if err != nil {
		return nil, fmt.Errorf("hop: listen on the hop's http endpoint: %w", err)
	}
	server := &http.Server{Handler: face, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(listener) }()
	return func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
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
