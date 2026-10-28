package forward_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/host"
	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/forward"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type publicationAuthority struct {
	*gateway
	allow            atomic.Bool
	expiry           atomic.Int64
	checks           atomic.Int32
	entered, release chan struct{}
	mu               sync.Mutex
}

func (a *publicationAuthority) RegisterAdmissionKey(ctx context.Context, in *authorityv1.RegisterAdmissionKeyRequest, opts ...grpc.CallOption) (*authorityv1.RegisterAdmissionKeyResponse, error) {
	if !a.allow.Load() {
		return nil, status.Error(codes.Unavailable, "registration unavailable")
	}
	out, err := a.gateway.RegisterAdmissionKey(ctx, in, opts...)
	if expiry := a.expiry.Load(); expiry != 0 {
		out.ExpiresAtUnix = expiry
	}
	return out, err
}
func (a *publicationAuthority) Check(ctx context.Context, in *authorityv1.CheckRequest, opts ...grpc.CallOption) (*authorityv1.CheckResponse, error) {
	a.checks.Add(1)
	if a.entered != nil {
		a.entered <- struct{}{}
		<-a.release
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.authority.Check(ctx, in, opts...)
}

type publicationHarness struct {
	front              *forward.Front
	authority          *publicationAuthority
	module             *connectModule
	grpcCall, httpCall func() error
}

func newPublicationHarness(t *testing.T, ctx context.Context, allow bool, expiry int64, blocked bool) *publicationHarness {
	t.Helper()
	a := &publicationAuthority{gateway: &gateway{authority: &authority{Authority: hoptest.New(t), revoked: map[string]bool{}}}}
	a.allow.Store(allow)
	a.expiry.Store(expiry)
	if blocked {
		a.entered = make(chan struct{}, 1)
		a.release = make(chan struct{})
	}
	m := &connectModule{}
	backend := httptest.NewServer(h2c.NewHandler(connectVersion(m.Version), &http2.Server{}))
	t.Cleanup(backend.Close)
	front, err := forward.New(ctx, forward.Config{Signer: hoptest.Signer(proof), Authority: a, Credential: credential, Modules: []string{"module"}, Routes: rawRoutes(t, routeEndpoint("api", "connect", backend.URL, versionProcedure))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(front.Close)
	conn := serve(t, front.ServerOptions, func(*grpc.Server) {})
	web := httptest.NewServer(front.Handler)
	t.Cleanup(web.Close)
	client := connect.NewClient[emptypb.Empty, wrapperspb.StringValue](&http.Client{Transport: host.HTTPTransport()}, web.URL+versionProcedure)
	token := a.Issue(t, "module", identityRead)
	return &publicationHarness{front: front, authority: a, module: m,
		grpcCall: func() error {
			_, err := version(metadata.AppendToOutgoingContext(t.Context(), hop.WorkContextKey, token), conn)
			return err
		},
		httpCall: func() error {
			req := connect.NewRequest(&emptypb.Empty{})
			req.Header().Set(hop.WorkContextKey, token)
			_, err := client.CallUnary(t.Context(), req)
			return err
		},
	}
}
func (h *publicationHarness) refused(t *testing.T) {
	t.Helper()
	before := h.module.calls.Load()
	checked := h.authority.checks.Load()
	if status.Code(h.grpcCall()) != codes.Unavailable {
		t.Fatal("gRPC did not refuse publication")
	}
	if connect.CodeOf(h.httpCall()) != connect.CodeUnavailable {
		t.Fatal("Connect did not refuse publication")
	}
	if h.module.calls.Load() != before || h.authority.checks.Load() != checked {
		t.Fatal("unready front checked policy or forwarded")
	}
}
func (h *publicationHarness) admitted(t *testing.T) {
	t.Helper()
	before := h.module.calls.Load()
	if err := h.grpcCall(); err != nil {
		t.Fatal(err)
	}
	if err := h.httpCall(); err != nil {
		t.Fatal(err)
	}
	if h.module.calls.Load() != before+2 {
		t.Fatal("both faces did not forward authenticated stamps")
	}
}
func waitPublication(t *testing.T, h *publicationHarness, want bool) {
	t.Helper()
	deadline := time.Now().Add(7 * time.Second)
	for h.front.Ready() != want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.front.Ready() != want {
		t.Fatalf("publication ready != %t", want)
	}
}

func TestFrontPublicationFailureRecoveryCancellationAndClose(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h := newPublicationHarness(t, ctx, false, 0, false)
	if h.front.Ready() {
		t.Fatal("initial refusal ready")
	}
	h.refused(t)
	h.authority.allow.Store(true)
	waitPublication(t, h, true)
	h.admitted(t)
	cancel() // constructor context alone, not Close, must invalidate both faces
	if h.front.Ready() {
		t.Fatal("New detached cancellation")
	}
	h.refused(t)
	h.front.Close()
	h.front.Close()
	h.refused(t)
}

func TestFrontPublicationExpiresAndRecovers(t *testing.T) {
	h := newPublicationHarness(t, t.Context(), true, time.Now().Add(2*time.Second).Unix(), false)
	h.admitted(t)
	h.authority.allow.Store(false)
	waitPublication(t, h, false)
	h.refused(t)
	h.authority.expiry.Store(0)
	h.authority.allow.Store(true)
	waitPublication(t, h, true)
	h.admitted(t)
	h.front.Close()
	if h.front.Ready() {
		t.Fatal("Close kept lease ready")
	}
	h.refused(t)
}

func TestFrontRechecksPublicationAfterBlockedPolicy(t *testing.T) {
	for _, face := range []string{"grpc", "connect"} {
		for _, event := range []string{"cancel", "close", "expire"} {
			t.Run(face+"/"+event, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				expiry := int64(0)
				if event == "expire" {
					expiry = time.Now().Add(2 * time.Second).Unix()
				}
				h := newPublicationHarness(t, ctx, true, expiry, true)
				call := h.grpcCall
				if face == "connect" {
					call = h.httpCall
				}
				result := make(chan error, 1)
				go func() { result <- call() }()
				select {
				case <-h.authority.entered:
				case <-time.After(2 * time.Second):
					t.Fatal("policy not entered")
				}
				switch event {
				case "cancel":
					cancel()
				case "close":
					h.front.Close()
				case "expire":
					h.authority.allow.Store(false)
					waitPublication(t, h, false)
				}
				close(h.authority.release)
				err := <-result
				if face == "grpc" && status.Code(err) != codes.Unavailable || face == "connect" && connect.CodeOf(err) != connect.CodeUnavailable {
					t.Fatalf("post-policy gate: %v", err)
				}
				if h.module.calls.Load() != 0 {
					t.Fatal("policy blocked across publication loss, but call was forwarded")
				}
			})
		}
	}
}

func TestLowLevelFacesRequirePublicationGate(t *testing.T) {
	p := &forward.Proxy{}
	conn := serve(t, p.ServerOptions(), func(*grpc.Server) {})
	if _, err := version(t.Context(), conn); status.Code(err) != codes.Unavailable {
		t.Fatalf("nil gRPC gate: %v", err)
	}
	h := &forward.HTTP{}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil HTTP gate: %d", w.Code)
	}
	if (*forward.Front)(nil).Ready() || (&forward.Front{}).Ready() {
		t.Fatal("empty front ready")
	}
}

// Start must not detach the constructor context even while registration blocks.
type blockedRegistration struct {
	entered, release chan struct{}
	*gateway
	renewal bool
	calls   atomic.Int32
}

func (a *blockedRegistration) RegisterAdmissionKey(ctx context.Context, in *authorityv1.RegisterAdmissionKeyRequest, opts ...grpc.CallOption) (*authorityv1.RegisterAdmissionKeyResponse, error) {
	if a.calls.Add(1) == 1 && a.renewal {
		out, err := a.gateway.RegisterAdmissionKey(ctx, in, opts...)
		out.ExpiresAtUnix = time.Now().Add(2 * time.Second).Unix()
		return out, err
	}
	close(a.entered)
	<-a.release
	return a.gateway.RegisterAdmissionKey(ctx, in, opts...) // deliberately return success after cancellation
}
func TestNewCancellationDuringRegistrationCannotReviveFront(t *testing.T) {
	for _, phase := range []string{"initial", "renewal"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			a := &blockedRegistration{entered: make(chan struct{}), release: make(chan struct{}), gateway: &gateway{authority: &authority{Authority: hoptest.New(t)}}, renewal: phase == "renewal"}
			done := make(chan *forward.Front, 1)
			failed := make(chan error, 1)
			routes := rawRoutes(t, routeEndpoint("api", "grpc", "http://127.0.0.1:1", versionProcedure))
			go func() {
				f, err := forward.New(ctx, forward.Config{Signer: hoptest.Signer(proof), Authority: a, Credential: credential, Modules: []string{"module"}, Routes: routes})
				if err != nil {
					failed <- err
					return
				}
				done <- f
			}()
			var f *forward.Front
			if a.renewal {
				select {
				case f = <-done:
				case err := <-failed:
					t.Fatal(err)
				case <-time.After(time.Second):
					t.Fatal("constructor did not finish")
				}
			}
			select {
			case <-a.entered:
			case err := <-failed:
				t.Fatal(err)
			case <-time.After(3 * time.Second):
				t.Fatal("registration not attempted")
			}
			cancel()
			if f != nil && f.Ready() {
				t.Fatal("cancel did not invalidate during blocked renewal")
			}
			close(a.release)
			if f == nil {
				select {
				case f = <-done:
				case err := <-failed:
					t.Fatal(err)
				case <-time.After(time.Second):
					t.Fatal("constructor did not finish")
				}
			}
			defer f.Close()
			if f.Ready() {
				t.Fatal("late registration revived front")
			}
			conn := serve(t, f.ServerOptions, func(*grpc.Server) {})
			if _, err := version(t.Context(), conn); status.Code(err) != codes.Unavailable {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			f.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
			if w.Code != http.StatusServiceUnavailable {
				t.Fatal("HTTP admitted after cancellation")
			}
		})
	}
}
