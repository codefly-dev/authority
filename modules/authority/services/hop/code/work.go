package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/host"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"github.com/codefly-dev/core/standards"
	"github.com/codefly-dev/core/wool"
	codefly "github.com/codefly-dev/sdk-go"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/forward"

	"hop/pkg/adapters"
)

func init() {
	WithConfigure(standInFront)
}

// standInFront is the hop's own wiring around the front door the library
// builds (forward.New): the signing seed, the authority and the modules as
// Codefly delivers them to this service, its workload credential, and its
// listeners.
func standInFront(ctx context.Context, config *adapters.Configuration) (Clean, error) {
	w := wool.Get(ctx).In("hop")
	seed, err := codefly.For(ctx).Secret("hop-signing", "SEED")
	if err != nil || seed == "" {
		return nil, fmt.Errorf("hop: no service signing seed delivered (codefly config generate hop-signing SEED --service authority/hop): %v", err)
	}
	signer, err := stamp.NewSigner(seed)
	if err != nil {
		return nil, err
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
	routes, err := codefly.For(ctx).WorkspaceConfiguration("hop-routes", "ROUTES")
	if err != nil {
		return nil, forward.MissingRoutes(err)
	}
	enforcement, _ := codefly.For(ctx).WorkspaceConfiguration("hop", "ENFORCEMENT")
	front, err := forward.New(ctx, forward.Config{
		Signer:    signer,
		Authority: authorityv1.NewAuthorityServiceClient(authority),
		// The hop registers its admission key as the workload the run attests.
		Credential:  hop.RunCredential,
		Modules:     strings.Split(listed, ","),
		Routes:      routes,
		Enforcement: enforcement,
		Log:         w,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if !configured {
			front.Close()
		}
	}()
	config.GRPCServerOptions = append(config.GRPCServerOptions, front.ServerOptions...)
	// The service declares this endpoint even when every upstream uses gRPC.
	// Keep it listening so the declared readiness contract holds; the face
	// still refuses requests for which no authorized HTTP route exists.
	stopWeb, err := serveHTTP(ctx, front.Handler)
	if err != nil {
		return nil, err
	}
	w.Info("standing in front of modules", wool.Field("modules", listed))
	configured = true
	return func() {
		stopWeb()
		front.Close()
		_ = authority.Close()
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
