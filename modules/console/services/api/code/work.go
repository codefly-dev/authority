package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/host"
	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/replaypg"
	"github.com/codefly-dev/core/wool"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/jackc/pgx/v5/pgxpool"
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
// Verifier checks each call's admission by the hop keys the authority
// publishes, authenticates each forwarded Work Context against the authority's
// published keys and reads who the call is for from it, and refuses, by name,
// a call that did not come through the hop or carries a context the authority
// did not issue for the console. It re-checks no permission the hop decided,
// and nothing about the hop is configured here: its key comes with the rest.
func answerFromTheStamp(ctx context.Context, config *adapters.Configuration) (Clean, error) {
	replay, closeReplay, err := reservations(ctx)
	if err != nil {
		return nil, err
	}
	audience, err := hop.Audience()
	if err != nil {
		closeReplay()
		return nil, fmt.Errorf("console: %w", err)
	}
	conn, _, err := host.Dial(ctx)
	if err != nil {
		closeReplay()
		return nil, fmt.Errorf("console: %w", err)
	}
	// It starts whether or not the authority serves its keys yet, and refuses
	// calls with the reason until it does. Outside a local run it also refuses
	// a replay store that is not the one every replica shares.
	verifier, err := hop.NewVerifier(ctx, authorityv1.NewAuthorityServiceClient(conn), audience, replay)
	if err != nil {
		_ = conn.Close()
		closeReplay()
		return nil, fmt.Errorf("console: %w", err)
	}
	install(config, verifier)
	config.Service = &console{}
	return func() { _ = conn.Close(); closeReplay() }, nil
}

// install puts the verifier in front of every call the console serves. Its
// stats handler judges the admission window and reserves the single-use nonce
// when each call reaches the gRPC server, before a request body is read, on
// both listeners: the gRPC one, and the Connect one the hop routes to, which
// hands each call to the same server. The interceptors hold the reservation
// until the handler returns.
func install(config *adapters.Configuration, verifier *hop.Verifier) {
	config.GRPCServerOptions = append(config.GRPCServerOptions,
		grpc.StatsHandler(verifier.StatsHandler()),
		grpc.ChainUnaryInterceptor(verifier.UnaryServerInterceptor()),
		grpc.ChainStreamInterceptor(verifier.StreamServerInterceptor()))
}

// collectEvery is how often aged-out reservations are removed. Collection
// removes only a finished call's reservation past the admission's expiry plus
// the clock allowance, and the store refuses any reservation past that, so
// nothing it removes can be reserved again.
const collectEvery = time.Minute

// reservations opens the console's hop admission reservations in its own store.
// The store is composed (services/store), so a run starts it first and delivers
// its read-write connection here. There is no in-memory fallback: a console
// that forgot an admission would admit a captured one again, so a composed
// store that does not answer is refused rather than fallen back from, and a run
// that composes no store is refused too.
func reservations(ctx context.Context) (*replaypg.Store, func(), error) {
	w := wool.Get(ctx).In("console")
	connection, err := codefly.For(ctx).Service("store").Secret("postgres", "read-write-connection")
	if err != nil || strings.TrimSpace(connection) == "" {
		return nil, nil, fmt.Errorf("console: the hop admission reservations need this module's store: %v", err)
	}
	pool, err := pgxpool.New(ctx, connection)
	if err != nil {
		return nil, nil, fmt.Errorf("console: the store's read-write connection: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("console: the store is composed but does not answer: %w", err)
	}
	store, err := replaypg.New(pool)
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("console: %w", err)
	}
	collecting, stop := context.WithCancel(context.Background())
	go collect(collecting, store, w)
	w.Info("hop admissions are reserved in the console's store")
	return store, func() { stop(); pool.Close() }, nil
}

// collect removes aged-out reservations until the process ends. A failure is
// logged and retried: collection is housekeeping, and a console that cannot
// collect still refuses replays.
func collect(ctx context.Context, store *replaypg.Store, w *wool.Wool) {
	ticker := time.NewTicker(collectEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := store.Collect(ctx); err != nil && ctx.Err() == nil {
				w.Warn("hop admission reservations were not collected", wool.ErrField(err))
			}
		}
	}
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
