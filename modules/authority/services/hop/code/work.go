package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/host"
	"github.com/codefly-dev/core/standards"
	"github.com/codefly-dev/core/wool"
	codefly "github.com/codefly-dev/sdk-go"
	"google.golang.org/grpc"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"

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
	// The authority, through the interface the hop depends on: the host the
	// composition names in authority/endpoint (saas accounts, say), else the
	// authority module's local authority (the shared host client).
	authority, at, err := host.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("hop: %w", err)
	}
	w.Info("asking the authority", wool.Field("at", at))
	configured := false
	defer func() {
		if !configured {
			_ = authority.Close()
		}
	}()
	// Codefly joins hop/MODULES to published catalogs and delivers exact
	// listener references through the normal hop-routes configuration group.
	listed, err := codefly.For(ctx).WorkspaceConfiguration("hop", "MODULES")
	if err != nil || listed == "" {
		return nil, fmt.Errorf("hop: the composition names no module to stand in front of (hop/MODULES): %v", err)
	}
	modules, upstreams, webs := map[string]bool{}, map[string]*grpc.ClientConn{}, map[string]*url.URL{}
	defer func() {
		if !configured {
			for _, conn := range upstreams {
				_ = conn.Close()
			}
		}
	}()
	rawRoutes, routesErr := codefly.For(ctx).WorkspaceConfiguration("hop-routes", "ROUTES")
	routes, err := requiredRoutes(rawRoutes, routesErr)
	if err != nil {
		return nil, err
	}
	for _, name := range strings.Split(listed, ",") {
		modules[strings.TrimSpace(name)] = true
	}
	covered := map[string]bool{}
	for _, route := range routes.Endpoints {
		if !modules[route.Audience] {
			return nil, fmt.Errorf("hop routes: undeclared audience %s", route.Audience)
		}
		dialTarget, transport, transportErr := host.Endpoint(ctx, route.Address)
		if transportErr != nil {
			return nil, fmt.Errorf("hop routes: %s/%s: %w", route.Audience, route.Service, transportErr)
		}
		covered[route.Audience] = true
		switch route.Transport {
		case "grpc":
			if strings.Contains(route.Address, "${") {
				return nil, fmt.Errorf("hop routes: unresolved endpoint for %s/%s", route.Audience, route.Service)
			}
			if upstreams[route.Address] != nil {
				continue
			}
			conn, dialErr := grpc.NewClient(dialTarget, append(proxy.DialOptions(), host.DialOptions(transport)...)...)
			if dialErr != nil {
				return nil, dialErr
			}
			upstreams[route.Address] = conn
		default:
			target, urlErr := route.ResolvedURL()
			if urlErr != nil {
				return nil, urlErr
			}
			webs[route.Address] = target
		}
	}
	for module := range modules {
		if !covered[module] {
			return nil, fmt.Errorf("hop routes: no published endpoint for %s", module)
		}
	}

	refused := func(method string, err error) {
		w.Warn("refused", wool.Field("method", method), wool.Field("reason", err.Error()))
	}
	// hop/ENFORCEMENT: enforce (the default) refuses what the authority
	// refuses; warn lets every call through stamped and logs what would have
	// been refused — a composition's choice for a developer's run, never a
	// cell's.
	enforcement, _ := codefly.For(ctx).WorkspaceConfiguration("hop", "ENFORCEMENT")
	permissive, err := enforcementMode(enforcement, codefly.IsLocal())
	if err != nil {
		return nil, err
	}
	decider := decide.Decider{Routes: routes, Authority: authorityv1.NewAuthorityServiceClient(authority), Modules: modules, Permissive: permissive,
		Warned: func(method string, err error) {
			w.Warn("PERMISSIVE: let through a call the authority refused", wool.Field("method", method), wool.Field("reason", err.Error()))
		}}
	decision := decider.Decide
	if permissive {
		w.Warn("hop/ENFORCEMENT=warn: the hop lets every call through and logs what it would have refused")
	}
	p := &proxy.Proxy{Decide: decision, Upstreams: upstreams, Proof: proof, Refused: refused}
	config.GRPCServerOptions = append(config.GRPCServerOptions, p.ServerOptions()...)
	// The service declares this endpoint even when every upstream uses gRPC.
	// Keep it listening so the declared readiness contract holds; the proxy
	// still refuses requests for which no authorized HTTP route exists.
	stopWeb, err := serveHTTP(ctx, &proxy.HTTP{Decide: decision, Upstreams: webs, Proof: proof, Refused: refused})
	if err != nil {
		return nil, err
	}
	w.Info("standing in front of modules", wool.Field("modules", listed))
	configured = true
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

// RouteProducerVersion is the first producer revision; no released version is
// claimed until CLI #1158 ships it. That PR must merge with or before this hop.
const RouteProducerVersion = "Codefly CLI eee37c1117 (hop-routes/v1 producer), shipping via codefly-dev/cli#1158, or a successor containing that producer"

func requiredRoutes(raw string, readErr error) (*routing.Routing, error) {
	if readErr != nil {
		return nil, fmt.Errorf("hop: generated hop-routes/ROUTES requires %s: %w", RouteProducerVersion, readErr)
	}
	routes, err := routing.DecodeRouting(raw)
	if err != nil {
		return nil, fmt.Errorf("hop: generated hop-routes/ROUTES requires %s: %w", RouteProducerVersion, err)
	}
	return routes, nil
}

// enforcementMode refuses configuration mistakes and permits advice only locally.
func enforcementMode(value string, local bool) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "enforce":
		return false, nil
	case "warn":
		if !local {
			return false, fmt.Errorf("hop/ENFORCEMENT=warn requires a local environment; use enforce outside local runs")
		}
		return true, nil
	default:
		return false, fmt.Errorf("hop/ENFORCEMENT must be enforce or warn")
	}
}
