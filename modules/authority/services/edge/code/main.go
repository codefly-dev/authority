// Command edge is the auth gateway's role in a run that composes the
// authority: the one origin a browser talks to (edge.go).
package main

import (
	"context"
	"fmt"
	"github.com/codefly-dev/authority/libraries/authority-client/go/host"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/signal"
	"strings"
	"syscall"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	installationv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/installation/v1"
	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if _, err := codefly.Init(ctx); err != nil {
		log.Fatal(err)
	}
	edge, address, closeAuthority, err := compose(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer closeAuthority()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("/", edge)
	srv := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	log.Printf("edge listening on %s, routing %d module(s)", address, len(edge.Modules))
	<-ctx.Done()
	_ = srv.Shutdown(context.Background())
}

// compose reads the edge's composition: its own listener, the host it depends
// on (host.go), and the modules it routes to. The edge group names the modules
// (MODULES) and, per module, its REST face (<MODULE>_REST) and its Connect
// face (<MODULE>_CONNECT); FRONTEND is what every other path serves. Each
// address is an ${endpoint:…} reference the run resolves and delivers: the
// edge declares no dependency on the modules it routes, so the SDK holds no
// carrier for them, and the delivered value is the composition's answer. The
// procedures a Connect face serves are the generated edge-routes group's, read
// from each module's published API catalog (routes.go).
func compose(ctx context.Context) (*Edge, string, func(), error) {
	// A query keeps what it is told, so each address gets a query of its own.
	self, err := codefly.For(ctx).Endpoint("http").API("http").ResolveNetworkInstance()
	if err != nil || self == nil || self.Port == 0 {
		return nil, "", nil, fmt.Errorf("edge: this service's http endpoint is not resolved: %v", err)
	}
	conn, at, err := host.Dial(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("edge: %w", err)
	}
	log.Printf("edge: the host is at %s", at)
	installations := installationv1.NewInstallationServiceClient(conn)
	authority := authorityv1.NewAuthorityServiceClient(conn)
	edge := &Edge{Sessions: sessionv1.NewSessionServiceClient(conn), Authority: authority, Installations: installations,
		Offers: installationv1.NewOfferServiceClient(conn), Installer: installations, Delegations: authority, Modules: map[string]Module{}}
	value := func(key string) string {
		v, _ := codefly.For(ctx).WorkspaceConfiguration("edge", key)
		return strings.TrimSpace(v)
	}
	edge.SignInChoices, err = parseSignInChoices(value("SIGN_IN_CHOICES"))
	if err != nil {
		_ = conn.Close()
		return nil, "", nil, fmt.Errorf("edge: SIGN_IN_CHOICES: %w", err)
	}
	// What each Connect face serves is generated, never typed (routes.go).
	routes, _ := codefly.For(ctx).WorkspaceConfiguration(edgeRoutesGroup, edgeRoutesKey)
	if edge.Modules, err = mount(value, routes); err != nil {
		_ = conn.Close()
		return nil, "", nil, err
	}
	if edge.Frontend, err = baseURL(value("FRONTEND")); err != nil {
		return nil, "", nil, fmt.Errorf("edge: FRONTEND: %w", err)
	}
	address, err := listenAddress(self.Hostname, int(self.Port))
	if err != nil {
		_ = conn.Close()
		return nil, "", nil, err
	}
	return edge, address, func() { _ = conn.Close() }, nil
}

// listenAddress is where the edge listens: the host the run resolved for its
// own endpoint, which on a developer's machine is loopback, so the sign-in
// page and the fixture tokens it lists are not served on every interface of
// that machine. A container keeps the wildcard bind: its ingress is the
// container's own, and the resolved name is not an address it holds. With no
// runtime context named the run is read as native, the bind that exposes
// least.
func listenAddress(hostname string, port int) (string, error) {
	switch resources.RuntimeContextFromEnv().GetKind() {
	case resources.RuntimeContextContainer, resources.RuntimeContextKubernetes:
		return fmt.Sprintf(":%d", port), nil
	}
	host := strings.TrimSpace(hostname)
	if host == "" {
		return "", fmt.Errorf("edge: this service's http endpoint resolved to no host, and the edge binds no wildcard address outside a container")
	}
	return net.JoinHostPort(host, fmt.Sprint(port)), nil
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
