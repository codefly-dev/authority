package proxy_test

import (
	"context"
	"net"
	"strings"
	"testing"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/hop/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	hopv1 "github.com/codefly-dev/authority/libraries/hop/go/gen/authority/hop/v1"

	"hop/pkg/business/decide"
	gen "hop/pkg/gen"
	"hop/pkg/infra/proxy"
)

const proof = "run-proof"

var human = "human"

// declared answers each method's policy as a module would declare it.
type declared map[string]*hopv1.Policy

func (d declared) Policy(_ context.Context, method string) (*hopv1.Policy, error) {
	policy, ok := d[method]
	if !ok {
		return nil, decide.ErrNoMethod
	}
	return policy, nil
}

var requires = func(kind string, actions ...string) *hopv1.Policy {
	return &hopv1.Policy{Requires: []*hopv1.Requirement{{ResourceKind: kind, Actions: actions}}}
}

// authority answers Check the way the interface does: maya's token is
// addressed to the module, anything else is refused.
type authority struct{ asked []string }

func (a *authority) Check(_ context.Context, in *authorityv1.CheckRequest, _ ...grpc.CallOption) (*authorityv1.CheckResponse, error) {
	a.asked = append(a.asked, in.GetAudience())
	if in.GetToken() != "maya-at-module" {
		return nil, status.Error(codes.PermissionDenied, "work context: revoked: maya no longer holds the role")
	}
	return &authorityv1.CheckResponse{Context: &authorityv1.WorkContextV1{
		OwnerPrincipalId: "maya", OwnerPrincipalKind: &human, TenantId: "acme",
		AuthorityScopes: []*authorityv1.WorkScopeV1{{ResourceKind: "console.identity", Actions: []string{"read"}}},
	}}, nil
}

// module answers Version with who the hop said the call is for, read through
// the same interceptor a module runs.
type module struct {
	gen.UnimplementedHopServiceServer
	reached int
}

func (m *module) Version(ctx context.Context, _ *gen.VersionRequest) (*gen.VersionResponse, error) {
	m.reached++
	id, _ := hop.FromContext(ctx)
	md, _ := metadata.FromIncomingContext(ctx)
	return &gen.VersionResponse{Version: id.Owner + "@" + id.Tenant + " " + strings.Join(id.Scopes, ",") + " token=" + strings.Join(md.Get(hop.WorkContextKey), "")}, nil
}

func serve(t *testing.T, opts []grpc.ServerOption, register func(*grpc.Server)) *grpc.ClientConn {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(opts...)
	register(server)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return dial(t, listener)
}

func dial(t *testing.T, listener *bufconn.Listener, opts ...grpc.DialOption) *grpc.ClientConn {
	conn, err := grpc.NewClient("passthrough:///bufnet", append(opts,
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func setup(t *testing.T, policies declared) (through gen.HopServiceClient, direct gen.HopServiceClient, m *module, a *authority, refused *[]string) {
	m, a, refused = &module{}, &authority{}, &[]string{}
	moduleListener := bufconn.Listen(1 << 20)
	moduleServer := grpc.NewServer(grpc.UnaryInterceptor(hop.UnaryServerInterceptor(proof)))
	gen.RegisterHopServiceServer(moduleServer, m)
	go func() { _ = moduleServer.Serve(moduleListener) }()
	t.Cleanup(moduleServer.Stop)
	p := &proxy.Proxy{
		Decide:   decide.Decider{Authority: a, Audience: "console", Policies: policies}.Decide,
		Upstream: dial(t, moduleListener, proxy.DialOptions()...),
		Proof:    proof,
		Refused:  func(method string, err error) { *refused = append(*refused, method+": "+err.Error()) },
	}
	hopConn := serve(t, p.ServerOptions(), func(*grpc.Server) {})
	return gen.NewHopServiceClient(hopConn), gen.NewHopServiceClient(dial(t, moduleListener)), m, a, refused
}

func TestTheHopLetsThroughOnlyACallTheAuthorityChecked(t *testing.T) {
	through, _, m, a, refused := setup(t, declared{"/api.HopService/Version": requires("console.identity", "read")})
	ctx := metadata.AppendToOutgoingContext(context.Background(), hop.WorkContextKey, "maya-at-module",
		hop.OwnerKey, "mallory", hop.ScopesKey, "console.identity:admin") // a forged stamp, stripped
	got, err := through.Version(ctx, &gen.VersionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if want := "maya@acme console.identity:read token=maya-at-module"; got.GetVersion() != want {
		t.Fatalf("the module read %q, want %q", got.GetVersion(), want)
	}
	if len(a.asked) != 1 || a.asked[0] != "console" || m.reached != 1 || len(*refused) != 0 {
		t.Fatalf("asked %v reached %d refused %v", a.asked, m.reached, *refused)
	}
}

func TestTheHopRefusesByNameAndTheModuleIsNeverReached(t *testing.T) {
	through, _, m, _, refused := setup(t, declared{"/api.HopService/Version": requires("console.identity", "read")})
	_, err := through.Version(context.Background(), &gen.VersionRequest{})
	if status.Code(err) != codes.Unauthenticated || !strings.Contains(err.Error(), "carries no Work Context") {
		t.Fatalf("no token: %v", err)
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), hop.WorkContextKey, "revoked")
	_, err = through.Version(ctx, &gen.VersionRequest{})
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "the authority refused the call to console: work context: revoked") {
		t.Fatalf("refused token: %v", err)
	}
	if m.reached != 0 || len(*refused) != 2 || !strings.HasPrefix((*refused)[0], "/api.HopService/Version: ") {
		t.Fatalf("reached %d refused %v", m.reached, *refused)
	}
}

func TestACallAroundTheHopIsRefusedByTheModule(t *testing.T) {
	_, direct, m, _, _ := setup(t, declared{"/api.HopService/Version": requires("console.identity", "read")})
	ctx := metadata.AppendToOutgoingContext(context.Background(), hop.WorkContextKey, "maya-at-module",
		hop.OwnerKey, "maya", hop.TenantKey, "acme", hop.ProofKey, "a-guess")
	_, err := direct.Version(ctx, &gen.VersionRequest{})
	if status.Code(err) != codes.Unauthenticated || !strings.Contains(err.Error(), "did not come through the hop") || m.reached != 0 {
		t.Fatalf("around the hop: %v reached %d", err, m.reached)
	}
}

func TestEffectiveScopesAreTheOwnersNarrowedByEveryActor(t *testing.T) {
	id := decide.IdentityOf(&authorityv1.WorkContextV1{
		OwnerPrincipalId: "maya", TenantId: "acme",
		AuthorityScopes: []*authorityv1.WorkScopeV1{
			{ResourceKind: "documents", Actions: []string{"read", "write"}},
			{ResourceKind: "records", Actions: []string{"read"}, ResourceIds: []string{"r1"}},
		},
		ActorChain: []*authorityv1.WorkActorV1{
			{PrincipalId: "org-directory"},
			{PrincipalId: "documents-reader", GrantedScopes: []*authorityv1.WorkScopeV1{{ResourceKind: "documents", Actions: []string{"read"}}}},
		},
	})
	if strings.Join(id.Scopes, ",") != "documents:read" || strings.Join(id.Actors, ",") != "org-directory,documents-reader" {
		t.Fatalf("identity: %+v", id)
	}
}

func TestTheHopAppliesEachMethodsDeclaredPolicy(t *testing.T) {
	ctx := metadata.AppendToOutgoingContext(context.Background(), hop.WorkContextKey, "maya-at-module")
	for _, c := range []struct {
		name     string
		policy   *hopv1.Policy
		code     codes.Code
		contains string
	}{
		{"held", requires("console.identity", "read"), codes.OK, ""},
		{"any checked caller", &hopv1.Policy{AnyCheckedCaller: true}, codes.OK, ""},
		{"not held", requires("console.identity", "read", "admin"), codes.PermissionDenied,
			"console refuses /api.HopService/Version for maya: it requires console.identity:admin, which the call does not hold (it holds console.identity:read)"},
		{"declares nothing", nil, codes.PermissionDenied, "the method declares no policy"},
		{"not served", &hopv1.Policy{AnyCheckedCaller: true}, codes.Unimplemented, "console serves no method /api.HopService/Version"},
		{"says nothing is required without saying so", &hopv1.Policy{}, codes.PermissionDenied, "requires nothing and does not say so"},
		{"both", &hopv1.Policy{AnyCheckedCaller: true, Requires: requires("console.identity", "read").GetRequires()}, codes.PermissionDenied, "both requires scopes and requires none"},
	} {
		t.Run(c.name, func(t *testing.T) {
			policies := declared{"/api.HopService/Version": c.policy}
			if c.name == "not served" {
				policies = declared{}
			}
			through, _, m, _, _ := setup(t, policies)
			_, err := through.Version(ctx, &gen.VersionRequest{})
			if status.Code(err) != c.code || !strings.Contains(status.Convert(err).Message(), c.contains) {
				t.Fatalf("got %v, want %v containing %q", err, c.code, c.contains)
			}
			if reached := m.reached == 1; reached != (c.code == codes.OK) {
				t.Fatalf("module reached %d times", m.reached)
			}
		})
	}
}
