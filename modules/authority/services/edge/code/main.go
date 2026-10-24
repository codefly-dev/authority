// Command edge is the auth gateway's role in a run that composes the
// authority: the one origin a browser talks to (edge.go).
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os/signal"
	"strings"
	"syscall"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if _, err := codefly.Init(ctx); err != nil {
		log.Fatal(err)
	}
	edge, port, closeAuthority, err := compose(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer closeAuthority()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("/", edge)
	srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	log.Printf("edge listening on :%d, routing %d module(s)", port, len(edge.Modules))
	<-ctx.Done()
	_ = srv.Shutdown(context.Background())
}

// compose reads the edge's composition: its own listener, the authority it
// depends on, and the modules it routes to. The edge group names the modules
// (MODULES) and, per module, its REST face (<MODULE>_REST), its Connect face
// (<MODULE>_CONNECT) and the RPC services the Connect face serves
// (<MODULE>_RPC); FRONTEND is what every other path serves. Each address is an
// ${endpoint:…} reference the run resolves and delivers: the edge declares no
// dependency on the modules it routes, so the SDK holds no carrier for them,
// and the delivered value is the composition's answer. The authority module's
// registry of composed modules replaces this list.
func compose(ctx context.Context) (*Edge, int, func(), error) {
	// A query keeps what it is told, so each address gets a query of its own.
	self, err := codefly.For(ctx).Endpoint("http").API("http").ResolveNetworkInstance()
	if err != nil || self == nil || self.Port == 0 {
		return nil, 0, nil, fmt.Errorf("edge: this service's http endpoint is not resolved: %v", err)
	}
	authority, err := codefly.For(ctx).Module("authority").Service("gateway").API("grpc").ResolveNetworkInstance()
	if err != nil || authority == nil {
		return nil, 0, nil, fmt.Errorf("edge: the authority (authority/gateway) is not resolved: %v", err)
	}
	conn, err := grpc.NewClient(authority.Host, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, 0, nil, err
	}
	edge := &Edge{Sessions: sessionv1.NewSessionServiceClient(conn), Authority: authorityv1.NewAuthorityServiceClient(conn), Modules: map[string]Module{}}
	value := func(key string) string {
		v, _ := codefly.For(ctx).WorkspaceConfiguration("edge", key)
		return strings.TrimSpace(v)
	}
	for _, name := range list(value("MODULES")) {
		prefix := strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_"
		m := Module{Name: name, Services: list(value(prefix + "RPC"))}
		if m.REST, err = baseURL(value(prefix + "REST")); err != nil {
			return nil, 0, nil, fmt.Errorf("edge: %sREST: %w", prefix, err)
		}
		if m.Connect, err = baseURL(value(prefix + "CONNECT")); err != nil {
			return nil, 0, nil, fmt.Errorf("edge: %sCONNECT: %w", prefix, err)
		}
		if len(m.Services) > 0 && m.Connect == nil {
			return nil, 0, nil, fmt.Errorf("edge: %s serves %v over Connect but %sCONNECT names no face", name, m.Services, prefix)
		}
		if m.REST == nil && m.Connect == nil {
			return nil, 0, nil, fmt.Errorf("edge: the composition names neither a REST nor a Connect face for %s", name)
		}
		edge.Modules[name] = m
	}
	if edge.Frontend, err = baseURL(value("FRONTEND")); err != nil {
		return nil, 0, nil, fmt.Errorf("edge: FRONTEND: %w", err)
	}
	return edge, int(self.Port), func() { _ = conn.Close() }, nil
}

// baseURL reads a delivered address as an HTTP base URL; empty is none.
func baseURL(address string) (*url.URL, error) {
	if address == "" {
		return nil, nil
	}
	instance, err := resources.ParseAddress(address)
	if err != nil {
		return nil, fmt.Errorf("%q is not an address: %w", address, err)
	}
	return &url.URL{Scheme: "http", Host: instance.Host}, nil
}

// list splits a comma-separated value, dropping blanks.
func list(value string) []string {
	var out []string
	for _, v := range strings.Split(value, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
