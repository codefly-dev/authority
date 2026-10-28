package forward_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/forward"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// gateway is the authority a second host hands New: the test authority's Check,
// and a RegisterAdmissionKey that publishes whatever key it is shown.
type gateway struct {
	*authority
	registered atomic.Int32
}

func (h *gateway) RegisterAdmissionKey(_ context.Context, in *authorityv1.RegisterAdmissionKeyRequest, _ ...grpc.CallOption) (*authorityv1.RegisterAdmissionKeyResponse, error) {
	h.registered.Add(1)
	return &authorityv1.RegisterAdmissionKeyResponse{Key: &authorityv1.PublicKey{KeyId: stamp.KeyID(in.GetPublicKey()), PublicKey: in.GetPublicKey(), Algorithm: core.Algorithm, Purpose: stamp.Purpose}, ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}, nil
}

// credential is a workload credential naming the authority it is for; the
// test authority attests nothing, so it carries no signature.
func credential() (string, error) {
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"authority"}`))
	return "header." + claims + ".signature", nil
}

func rawRoutes(t *testing.T, endpoints ...routing.RouteEndpoint) string {
	t.Helper()
	raw, err := json.Marshal(routing.Routing{Schema: routing.RoutingSchema, Endpoints: endpoints})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// A host whose configuration cannot stand in front of its modules is refused
// by name, before its admission key is registered or a module is dialled.
func TestNewRefusesBeforeRegistering(t *testing.T) {
	grpcRoute := routeEndpoint("api", "grpc", "http://127.0.0.1:1", versionProcedure)
	for _, tc := range []struct {
		name    string
		modules []string
		routes  string
		mode    string
		want    string
	}{
		{"no module", nil, rawRoutes(t, grpcRoute), "", "names no module"},
		{"malformed routes", []string{"module"}, "{", "", forward.RouteProducerVersion},
		{"empty routes", []string{"module"}, "", "", forward.RouteProducerVersion},
		{"undeclared audience", []string{"other"}, rawRoutes(t, grpcRoute), "", "undeclared audience module"},
		{"uncovered module", []string{"module", "records"}, rawRoutes(t, grpcRoute), "", "no published endpoint for records"},
		{"unprotected upstream", []string{"module"}, rawRoutes(t, routeEndpoint("api", "grpc", "http://unprotected.example:8080", versionProcedure)), "", "requires HTTPS"},
		{"warn mode", []string{"module"}, rawRoutes(t, grpcRoute), "warn", "must be enforce"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &gateway{authority: &authority{Authority: hoptest.New(t)}}
			front, err := forward.New(t.Context(), forward.Config{Signer: hoptest.Signer(proof), Authority: h, Credential: credential, Modules: tc.modules, Routes: tc.routes, Enforcement: tc.mode})
			if front != nil {
				front.Close()
				t.Fatal("a refused configuration built a front door")
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if h.registered.Load() != 0 {
				t.Fatal("a refused front door registered its admission key")
			}
		})
	}
}

// A second host builds the whole front door from its configuration: the key
// is registered before New returns, and a call through its gRPC face reaches
// the module, which authenticates the host's stamp with its own Verifier.
func TestASecondHostStandsInFrontWithNew(t *testing.T) {
	h := &gateway{authority: &authority{Authority: hoptest.New(t), revoked: map[string]bool{}}}
	verifier, err := hop.NewVerifier(t.Context(), h.PublishHop(proof), "module", hoptest.Replay())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := &module{}
	moduleServer := grpc.NewServer(grpc.UnaryInterceptor(verifier.UnaryServerInterceptor()))
	registerModule(moduleServer, m)
	go func() { _ = moduleServer.Serve(listener) }()
	t.Cleanup(moduleServer.Stop)

	front, err := forward.New(t.Context(), forward.Config{
		Signer:     hoptest.Signer(proof),
		Authority:  h,
		Credential: credential,
		Modules:    []string{"module"},
		Routes:     rawRoutes(t, routeEndpoint("api", "grpc", "http://"+listener.Addr().String(), versionProcedure)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	if h.registered.Load() == 0 || !front.Ready() {
		t.Fatal("New returned before registering the host's admission key")
	}
	if front.Handler == nil {
		t.Fatal("no HTTP face")
	}
	conn := serve(t, front.ServerOptions, func(*grpc.Server) {})
	token := h.Issue(t, "module", identityRead)
	got, err := version(metadata.AppendToOutgoingContext(t.Context(), hop.WorkContextKey, token), conn)
	if err != nil {
		t.Fatal(err)
	}
	if want := "principal-owner@tenant-conformance console.identity:read token=" + token; got != want || m.reached != 1 {
		t.Fatalf("the module read %q (reached %d), want %q", got, m.reached, want)
	}
}
