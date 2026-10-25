package proxy_test

import (
	"context"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
	gen "hop/pkg/gen"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"hop/pkg/business/decide"
	"hop/pkg/infra/proxy"
)

type routeChecker struct {
	calls   []string
	denied  string
	failure error
}

func (c *routeChecker) Check(_ context.Context, req *authorityv1.CheckRequest, _ ...grpc.CallOption) (*authorityv1.CheckResponse, error) {
	c.calls = append(c.calls, req.Method)
	if c.failure != nil {
		return nil, c.failure
	}
	if req.Method == c.denied {
		return nil, status.Error(codes.PermissionDenied, "declared route requires write")
	}
	return &authorityv1.CheckResponse{Context: &authorityv1.WorkContextV1{OwnerPrincipalId: "person", TenantId: "tenant"}}, nil
}

func routeEndpoint(service, transport, address string, methods ...string) routing.RouteEndpoint {
	return routing.RouteEndpoint{Audience: "module", Service: service, Endpoint: transport, Transport: transport, Address: address, Package: "owner/module", Version: "1.0.0", Digest: "sha256:contract", Methods: methods}
}

// A procedure-shaped HTTP path is not evidence of a Connect listener. Its
// matched HTTP policy and destination must be one decision, even in warn mode.
func TestPublishedDestinationAndPolicyAreOneSelection(t *testing.T) {
	var reached atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		if r.URL.Path != "/gauge.v1.Service/Call" {
			t.Errorf("changed path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()
	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	routes := &routing.Routing{Schema: routing.RoutingSchema, Endpoints: []routing.RouteEndpoint{
		routeEndpoint("grpc", "grpc", "unused-grpc", "/gauge.v1.Service/Call"),
		routeEndpoint("web", "http", backend.URL, "POST /{service}/{operation}"),
	}}
	if err := routes.Validate(); err != nil {
		t.Fatal(err)
	}
	checker := &routeChecker{denied: "POST /gauge.v1.Service/Call"}
	decision := decide.Decider{Routes: routes, Authority: checker, Modules: map[string]bool{"module": true}, AudienceOf: func(string) (string, error) { return "module", nil }}
	for _, warn := range []bool{false, true} {
		decision.Permissive = warn
		refused := 0
		face := proxy.HTTP{Decide: decision.Decide, Upstreams: map[string]*url.URL{backend.URL: u}, Proof: proof, Refused: func(string, error) { refused++ }}
		req := httptest.NewRequest(http.MethodPost, "/gauge.v1.Service/Call?original=yes", nil)
		req.Header.Set(hop.WorkContextKey, "context")
		rec := httptest.NewRecorder()
		face.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || reached.Load() != 0 || refused != 1 {
			t.Fatalf("warn %v: status=%d reached=%d refused=%d", warn, rec.Code, reached.Load(), refused)
		}
	}
	if len(checker.calls) != 2 || checker.calls[0] != checker.denied || checker.calls[1] != checker.denied {
		t.Fatalf("checked wrong policy: %v", checker.calls)
	}
	// Inverting the grants admits the HTTP route despite the gRPC refusal.
	checker.denied = "/gauge.v1.Service/Call"
	face := proxy.HTTP{Decide: decision.Decide, Upstreams: map[string]*url.URL{backend.URL: u}, Proof: proof}
	req := httptest.NewRequest(http.MethodPost, "/gauge.v1.Service/Call", nil)
	req.Header.Set(hop.WorkContextKey, "context")
	rec := httptest.NewRecorder()
	face.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || reached.Load() != 1 {
		t.Fatalf("HTTP route borrowed gRPC policy: %d %d", rec.Code, reached.Load())
	}
	// A genuinely published Connect endpoint uses the protobuf policy instead.
	routes.Endpoints[1] = routeEndpoint("connect", "connect", backend.URL, "/gauge.v1.Service/Call")
	rec = httptest.NewRecorder()
	face.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || reached.Load() != 1 {
		t.Fatalf("Connect policy not checked: %d %d", rec.Code, reached.Load())
	}
	// No wildcard or old module-wide destination can receive an unknown route.
	face.Upstreams["module"] = u
	unknown := httptest.NewRequest(http.MethodPost, "/other.Service/Call", nil)
	unknown.Header.Set(hop.WorkContextKey, "context")
	calls := len(checker.calls)
	rec = httptest.NewRecorder()
	face.ServeHTTP(rec, unknown)
	if rec.Code != http.StatusNotFound || reached.Load() != 1 || len(checker.calls) != calls {
		t.Fatal("unknown route fell back or consumed authority")
	}
	checker.failure = status.Error(codes.Unauthenticated, "invalid signature")
	rec = httptest.NewRecorder()
	face.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || reached.Load() != 1 {
		t.Fatal("invalid identity reached a route in warn mode")
	}
}

func TestGeneratedGRPCRoutesKeepSiblingAndAudienceSeparate(t *testing.T) {
	a, b := &module{}, &module{}
	first := routedBackend(t, func(s *grpc.Server) { gen.RegisterHopServiceServer(s, a) })
	second := routedBackend(t, func(s *grpc.Server) { gen.RegisterHopServiceServer(s, b) })
	// The same generated unary protocol can be exported by two independently
	// scoped audiences. An absent method cannot fall back to either listener.
	routes := &routing.Routing{Schema: routing.RoutingSchema, Endpoints: []routing.RouteEndpoint{routeEndpoint("first", "grpc", "first", "/api.HopService/Version")}}
	other := routeEndpoint("second", "grpc", "second", "/api.HopService/Version")
	other.Audience = "other"
	routes.Endpoints = append(routes.Endpoints, other)
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	third := routedBackend(t, func(s *grpc.Server) { healthv1.RegisterHealthServer(s, healthServer) })
	routes.Endpoints = append(routes.Endpoints, routeEndpoint("health", "grpc", "third", "/grpc.health.v1.Health/Check", "/grpc.health.v1.Health/Watch"))
	checker := &routeChecker{}
	decision := decide.Decider{Routes: routes, Authority: checker, Modules: map[string]bool{"module": true, "other": true}, AudienceOf: func(token string) (string, error) { return token, nil }}
	p := &proxy.Proxy{Decide: decision.Decide, Proof: proof, Upstreams: map[string]*grpc.ClientConn{"first": first, "second": second, "third": third, "module": second}}
	conn := serve(t, p.ServerOptions(), func(*grpc.Server) {})
	for _, audience := range []string{"module", "other"} {
		ctx := metadata.AppendToOutgoingContext(t.Context(), hop.WorkContextKey, audience)
		if _, err := gen.NewHopServiceClient(conn).Version(ctx, &gen.VersionRequest{}); err != nil {
			t.Fatal(err)
		}
	}
	if a.reached != 1 || b.reached != 1 {
		t.Fatalf("wrong audience: %d %d", a.reached, b.reached)
	}
	ctx := metadata.AppendToOutgoingContext(t.Context(), hop.WorkContextKey, "module")
	got, err := healthv1.NewHealthClient(conn).Check(ctx, &healthv1.HealthCheckRequest{})
	if err != nil || got.GetStatus() != healthv1.HealthCheckResponse_SERVING {
		t.Fatalf("second service: %v %v", got, err)
	}
	streamCtx, cancel := context.WithCancel(ctx)
	stream, err := healthv1.NewHealthClient(conn).Watch(streamCtx, &healthv1.HealthCheckRequest{})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if _, err = stream.Recv(); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	if _, err = stream.Recv(); status.Code(err) != codes.Canceled {
		t.Fatalf("stream cancellation: %v", err)
	}
	if err := conn.Invoke(ctx, "/unknown.Service/Call", &proxy.Frame{}, &proxy.Frame{}, grpc.ForceCodec(proxy.Codec{})); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown method: %v", err)
	}
	if a.reached != 1 || b.reached != 1 {
		t.Fatal("unknown method used module fallback")
	}
}

func routedBackend(t *testing.T, register func(*grpc.Server)) *grpc.ClientConn {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.UnaryInterceptor(hop.UnaryServerInterceptor(proof)))
	register(server)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return dial(t, listener, proxy.DialOptions()...)
}
