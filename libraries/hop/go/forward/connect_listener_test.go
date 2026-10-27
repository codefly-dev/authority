package forward_test

import (
	"connectrpc.com/connect"
	"context"
	"github.com/codefly-dev/authority/libraries/authority-client/go/host"
	callstamp "github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/decide"
	"github.com/codefly-dev/authority/libraries/hop/go/forward"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type connectModule struct{ calls atomic.Int32 }

func (m *connectModule) Version(_ context.Context, req *connect.Request[emptypb.Empty]) (*connect.Response[wrapperspb.StringValue], error) {
	md := metadata.MD{}
	for key, values := range req.Header() {
		md[strings.ToLower(key)] = values
	}
	if _, err := callstamp.Check(md, hoptest.PublicKey(proof), versionProcedure, "module", time.Now()); err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}
	m.calls.Add(1)
	return connect.NewResponse(wrapperspb.String("one-listener")), nil
}

func TestGRPCAndConnectReachOnePublishedConnectListener(t *testing.T) {
	t.Setenv("CODEFLY__ENVIRONMENT", "local")
	m := &connectModule{}
	handler := connectVersion(m.Version)
	backend := httptest.NewServer(h2c.NewHandler(handler, &http2.Server{}))
	defer backend.Close()
	target, options, err := host.Endpoint(t.Context(), backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := grpc.NewClient(target, append(host.DialOptions(options), grpc.WithDefaultCallOptions(forward.CallOptions()...))...)
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	routes := &routing.Routing{Schema: routing.RoutingSchema, Endpoints: []routing.RouteEndpoint{routeEndpoint("module", "connect", backend.URL, versionProcedure)}}
	if err := routes.Validate(); err != nil {
		t.Fatal(err)
	}
	checker := &routeChecker{}
	decider := decide.Decider{Routes: routes, Authority: checker, Modules: map[string]bool{"module": true}, AudienceOf: func(string) (string, error) { return "module", nil }}
	p := &forward.Proxy{Decide: decider.Decide, Signer: hoptest.Signer(proof), Upstreams: map[string]*grpc.ClientConn{backend.URL: upstream}}
	conn := serve(t, p.ServerOptions(), func(*grpc.Server) {})
	ctx := metadata.AppendToOutgoingContext(t.Context(), hop.WorkContextKey, "context")
	got, err := version(ctx, conn)
	if err != nil || got != "one-listener" {
		t.Fatalf("grpc: %v %v", got, err)
	}
	u, _ := url.Parse(backend.URL)
	face := httptest.NewServer(&forward.HTTP{Decide: decider.Decide, Signer: hoptest.Signer(proof), Upstreams: map[string]*url.URL{backend.URL: u}})
	defer face.Close()
	client := connect.NewClient[emptypb.Empty, wrapperspb.StringValue](&http.Client{Transport: host.HTTPTransport()}, face.URL+versionProcedure)
	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set(hop.WorkContextKey, "context")
	answer, err := client.CallUnary(t.Context(), req)
	if err != nil || answer.Msg.GetValue() != "one-listener" {
		t.Fatalf("connect: %v %v", answer, err)
	}
	checker.denied = versionProcedure
	if _, err := version(ctx, conn); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("grpc refusal: %v", err)
	}
	if _, err := client.CallUnary(t.Context(), req); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("connect refusal: %v", err)
	}
	if m.calls.Load() != 2 {
		t.Fatalf("refusal reached backend: %d", m.calls.Load())
	}
}

// A module that still publishes its service on a gRPC endpoint beside its
// Connect endpoint is one destination: the hop starts and sends gRPC to Connect.
func TestDualPublishedServiceSendsGRPCToItsConnectListener(t *testing.T) {
	t.Setenv("CODEFLY__ENVIRONMENT", "local")
	dial := func(m *connectModule) (string, *grpc.ClientConn) {
		handler := connectVersion(m.Version)
		backend := httptest.NewServer(h2c.NewHandler(handler, &http2.Server{}))
		t.Cleanup(backend.Close)
		target, options, err := host.Endpoint(t.Context(), backend.URL)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := grpc.NewClient(target, append(host.DialOptions(options), grpc.WithDefaultCallOptions(forward.CallOptions()...))...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return backend.URL, conn
	}
	connectFace, grpcFace := &connectModule{}, &connectModule{}
	connectURL, connectConn := dial(connectFace)
	grpcURL, grpcConn := dial(grpcFace)
	routes := &routing.Routing{Schema: routing.RoutingSchema, Endpoints: []routing.RouteEndpoint{
		routeEndpoint("module", "grpc", grpcURL, versionProcedure),
		routeEndpoint("module", "connect", connectURL, versionProcedure),
	}}
	if err := routes.Validate(); err != nil {
		t.Fatal(err)
	}
	decider := decide.Decider{Routes: routes, Authority: &routeChecker{}, Modules: map[string]bool{"module": true}, AudienceOf: func(string) (string, error) { return "module", nil }}
	p := &forward.Proxy{Decide: decider.Decide, Signer: hoptest.Signer(proof), Upstreams: map[string]*grpc.ClientConn{connectURL: connectConn, grpcURL: grpcConn}}
	conn := serve(t, p.ServerOptions(), func(*grpc.Server) {})
	ctx := metadata.AppendToOutgoingContext(t.Context(), hop.WorkContextKey, "context")
	if _, err := version(ctx, conn); err != nil {
		t.Fatal(err)
	}
	if connectFace.calls.Load() != 1 || grpcFace.calls.Load() != 0 {
		t.Fatalf("connect=%d grpc=%d", connectFace.calls.Load(), grpcFace.calls.Load())
	}
}
