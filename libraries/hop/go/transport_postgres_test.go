package hop_test

import (
	"context"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"github.com/codefly-dev/authority/libraries/hop/go/replaypg"
	"github.com/codefly-dev/core/resources"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/tap"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

// postgresStore is the console's reservation store on a real Postgres, named
// by HOP_TEST_POSTGRES (a libpq connection string). CI starts one.
func postgresStore(t *testing.T) (*replaypg.Store, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("HOP_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("HOP_TEST_POSTGRES names no Postgres for the transport regression")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(context.Background(), replaypg.Migration); err != nil {
		t.Fatal(err)
	}
	store, err := replaypg.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	return store, pool
}

// transport is a real grpc-go server, installed the way a module installs the
// verifier, whose one unary method counts how often its handler ran. Calls are
// opened as raw streams so a test decides when each request body is sent.
type transport struct {
	conn     *grpc.ClientConn
	arrived  chan struct{}
	reached  atomic.Int64
	entered  chan struct{}
	hold     chan struct{}
	method   string
	metadata metadata.MD
	expires  time.Time // the admission's expiry plus the clock allowance
	nonce    string
}

func newTransport(t *testing.T, ctx context.Context, store *replaypg.Store) *transport {
	t.Helper()
	tr := &transport{arrived: make(chan struct{}, 8), entered: make(chan struct{}, 8), hold: make(chan struct{}), method: "/regression.Service/Write"}
	close(tr.hold)
	authority := hoptest.New(t)
	token := authority.IssueSingleUse(t, "regression")
	tr.metadata = hoptest.Forward(t, token, "regression", tr.method)
	// A short-lived admission, so its retention passes inside the test.
	issued := time.Now()
	proof, err := hoptest.Signer("regression").Sign(token, tr.method, "regression", issued, issued.Add(time.Second).Unix())
	if err != nil {
		t.Fatal(err)
	}
	tr.metadata.Set(hop.ProofKey, proof)
	call, err := stamp.Check(tr.metadata, hoptest.PublicKey("regression"), tr.method, "regression", issued)
	if err != nil {
		t.Fatal(err)
	}
	tr.nonce = call.ReplayKey(hoptest.PublicKey("regression"))
	tr.expires = time.Unix(call.Expires+int64(stamp.Skew/time.Second), 0)

	v, err := hop.NewVerifier(ctx, authority, "regression", hoptest.PublicKey("regression"), store)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(
		grpc.InTapHandle(func(ctx context.Context, info *tap.Info) (context.Context, error) {
			admitted, err := v.TapHandle()(ctx, info)
			tr.arrived <- struct{}{}
			return admitted, err
		}),
		grpc.ChainUnaryInterceptor(v.UnaryServerInterceptor()))
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "regression.Service",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{{MethodName: "Write", Handler: func(srv any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
			request := new(emptypb.Empty)
			if err := decode(request); err != nil {
				return nil, err
			}
			return interceptor(ctx, request, &grpc.UnaryServerInfo{Server: srv, FullMethod: tr.method}, func(context.Context, any) (any, error) {
				tr.reached.Add(1)
				tr.entered <- struct{}{}
				<-tr.hold
				return &emptypb.Empty{}, nil
			})
		}}},
	}, new(struct{}))
	listener := bufconn.Listen(1 << 20)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	tr.conn, err = grpc.NewClient("passthrough:///regression",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.conn.Close() })
	return tr
}

// deliver opens one delivery of the admission and returns once the server has
// accepted its stream; its body is sent only when send is called.
func (tr *transport) deliver(t *testing.T, ctx context.Context) (send func() error) {
	t.Helper()
	stream, err := tr.conn.NewStream(metadata.NewOutgoingContext(ctx, tr.metadata.Copy()), &grpc.StreamDesc{}, tr.method)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-tr.arrived:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return func() error {
		if err := stream.SendMsg(&emptypb.Empty{}); err != nil {
			return err
		}
		if err := stream.CloseSend(); err != nil {
			return err
		}
		return stream.RecvMsg(&emptypb.Empty{})
	}
}

// pastRetention waits until the admission's retention has passed and runs
// collection, as the console's schedule does.
func (tr *transport) pastRetention(t *testing.T, ctx context.Context, store *replaypg.Store) {
	t.Helper()
	select {
	case <-time.After(time.Until(tr.expires) + 200*time.Millisecond):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := store.Collect(ctx); err != nil {
		t.Fatal(err)
	}
}

// reserved waits, briefly, for the reservation of the delivery just opened, so
// the deliveries that follow it meet it in a known order.
func reserved(t *testing.T, ctx context.Context, pool *pgxpool.Pool, nonce string) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline) && !held(t, ctx, pool, nonce); {
		time.Sleep(10 * time.Millisecond)
	}
}

func held(t *testing.T, ctx context.Context, pool *pgxpool.Pool, nonce string) bool {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM hop_admissions WHERE nonce = $1`, nonce).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count == 1
}

// Review of #28 at 8a3e953b: two deliveries of one single-use admission arrive
// inside its window. The first runs. The second is held before its body is
// read until the admission's retention has passed and collection has run;
// then its body arrives. It must be refused by name, and the handler must have
// run exactly once.
func TestASecondDeliveryHeldPastCollectionIsRefusedOverTheRealTransport(t *testing.T) {
	t.Setenv(resources.EnvironmentPrefix, "production")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, pool := postgresStore(t)
	tr := newTransport(t, ctx, store)

	first := tr.deliver(t, ctx)
	reserved(t, ctx, pool, tr.nonce)
	second := tr.deliver(t, ctx)
	if err := first(); err != nil {
		t.Fatalf("the first delivery was refused: %v", err)
	}
	tr.pastRetention(t, ctx, store)
	err := second()
	if err == nil || !strings.Contains(err.Error(), "stamp_replayed") {
		t.Errorf("the second delivery was not refused as stamp_replayed: %v", err)
	}
	if got := tr.reached.Load(); got != 1 {
		t.Fatalf("SECURITY: one single-use admission ran its handler %d times", got)
	}
}

// The reservation of a call whose handler is still running outlives its
// retention: collection never removes it while the call runs, and removes it
// once the call has returned.
func TestARunningCallKeepsItsReservationPastItsRetention(t *testing.T) {
	t.Setenv(resources.EnvironmentPrefix, "production")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, pool := postgresStore(t)
	tr := newTransport(t, ctx, store)
	tr.hold = make(chan struct{})

	first := tr.deliver(t, ctx)
	result := make(chan error, 1)
	go func() { result <- first() }()
	select {
	case <-tr.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	tr.pastRetention(t, ctx, store)
	if !held(t, ctx, pool, tr.nonce) {
		t.Fatal("collection removed the reservation of a call that is still running")
	}
	if err := tr.deliver(t, ctx)(); err == nil || !strings.Contains(err.Error(), "stamp_") {
		t.Errorf("a delivery after the retention was admitted: %v", err)
	}
	close(tr.hold)
	if err := <-result; err != nil {
		t.Fatalf("the running call was refused: %v", err)
	}
	if _, err := store.Collect(ctx); err != nil {
		t.Fatal(err)
	}
	if held(t, ctx, pool, tr.nonce) {
		t.Fatal("a finished call's reservation outlived its retention")
	}
	if got := tr.reached.Load(); got != 1 {
		t.Fatalf("the handler ran %d times", got)
	}
}

// A delivery cancelled before its body arrived ran no handler, so its hold is
// released and collection removes the reservation once its retention passes;
// a second delivery inside the window is still refused.
func TestACallCancelledBeforeItsBodyReleasesItsHold(t *testing.T) {
	t.Setenv(resources.EnvironmentPrefix, "production")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, pool := postgresStore(t)
	tr := newTransport(t, ctx, store)

	cancelled, stop := context.WithCancel(ctx)
	_ = tr.deliver(t, cancelled)
	reserved(t, ctx, pool, tr.nonce)
	second := tr.deliver(t, ctx)
	stop()
	if err := second(); err == nil || !strings.Contains(err.Error(), "stamp_replayed") {
		t.Errorf("a second delivery inside the window was not refused as stamp_replayed: %v", err)
	}
	for {
		tr.pastRetention(t, ctx, store)
		if !held(t, ctx, pool, tr.nonce) {
			break
		}
	}
	if got := tr.reached.Load(); got != 0 {
		t.Fatalf("the handler ran %d times", got)
	}
}
