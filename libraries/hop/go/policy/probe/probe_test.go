package probe_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/hop/go"
	hopv1 "github.com/codefly-dev/authority/libraries/hop/go/gen/authority/hop/v1"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"github.com/codefly-dev/authority/libraries/hop/go/policy/probe"
	"github.com/codefly-dev/core/composition"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

// The module under probe is a real gRPC server over a real connection: the
// health service, published with a policy on each of its procedures, behind an
// interceptor that plays the handler's own rule on the Work Context the call
// carries. Nothing here is a closure standing in for a handler.
const (
	check = "/grpc.health.v1.Health/Check"
	watch = "/grpc.health.v1.Health/Watch"
	list  = "/grpc.health.v1.Health/List"
)

func requires(permissions ...string) *hopv1.Policy {
	p := &hopv1.Policy{}
	for _, permission := range permissions {
		kind, action, _ := strings.Cut(permission, ":")
		p.Requires = append(p.Requires, &hopv1.Requirement{ResourceKind: kind, Actions: []string{action}})
	}
	return p
}

var open = &hopv1.Policy{AnyCheckedCaller: true}

// published is the health contract with declared on each procedure named.
func published(t *testing.T, declared map[string]*hopv1.Policy) []byte {
	t.Helper()
	file := protodesc.ToFileDescriptorProto(healthv1.File_grpc_health_v1_health_proto)
	for _, method := range file.GetService()[0].GetMethod() {
		if p, ok := declared["/grpc.health.v1.Health/"+method.GetName()]; ok {
			method.Options = &descriptorpb.MethodOptions{}
			proto.SetExtension(method.Options, hopv1.E_Policy, p)
		}
	}
	raw, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{file}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var all = map[string]*hopv1.Policy{check: requires("doc:read"), watch: open, list: open}

// rule is what a handler decides on what the call holds, by procedure.
type rule func(method string, holds func(permission string) bool) error

func agrees(string, func(string) bool) error { return nil }

// module serves health behind rule and is probed with cases for all three
// procedures; carry mints the Work Context each call carries.
func module(t *testing.T, contract []byte, decide rule, carry func(scopes []*basev0.WorkScopeV1) []*basev0.WorkScopeV1) probe.Module {
	t.Helper()
	// admitted is the module's verifier: a call that carries no Work Context
	// never reaches a handler. reads is false for a server that skips it.
	reads := decide != nil
	admitted := func(ctx context.Context) error {
		md, _ := metadata.FromIncomingContext(ctx)
		if reads && len(md.Get(hop.WorkContextKey)) != 1 {
			return status.Error(codes.Unauthenticated, "no Work Context")
		}
		return nil
	}
	if decide == nil {
		decide = agrees
	}
	held := func(ctx context.Context) func(string) bool {
		md, _ := metadata.FromIncomingContext(ctx)
		var scopes []*basev0.WorkScopeV1
		if tokens := md.Get(hop.WorkContextKey); len(tokens) == 1 {
			if decoded, err := workcontext.Decode(tokens[0]); err == nil {
				scopes = decoded.Context().GetAuthorityScopes()
			}
		}
		return func(permission string) bool {
			kind, action, _ := strings.Cut(permission, ":")
			return slices.ContainsFunc(scopes, func(s *basev0.WorkScopeV1) bool {
				return s.GetResourceKind() == kind && s.GetResourceOwnerId() == "installation" && slices.Contains(s.GetActions(), action)
			})
		}
	}
	server := grpc.NewServer(
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
			if err := admitted(ctx); err != nil {
				return nil, err
			}
			if err := decide(info.FullMethod, held(ctx)); err != nil {
				if err == errAbsent {
					return &healthv1.HealthListResponse{}, nil // a refusal rendered as an empty answer
				}
				return nil, err
			}
			return next(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, next grpc.StreamHandler) error {
			if err := admitted(stream.Context()); err != nil {
				return err
			}
			if err := decide(info.FullMethod, held(stream.Context())); err != nil {
				return err
			}
			return next(srv, stream)
		}))
	healthv1.RegisterHealthServer(server, health.NewServer())
	// As a shipped server does, it registers reflection beside its surface.
	// The hop routes none of it, so none of it is probed.
	reflection.Register(server)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	authority := hoptest.New(t)
	serving := func(answer protoreflect.Message) error {
		if field := answer.Descriptor().Fields().ByName("status"); field == nil || answer.Get(field).Enum() != protoreflect.EnumNumber(healthv1.HealthCheckResponse_SERVING) {
			return status.Error(codes.Unknown, "the answer does not say SERVING")
		}
		return nil
	}
	sum := sha256.Sum256(contract)
	return probe.Module{
		Endpoint: composition.APIContractEndpoint{Digest: "sha256:" + hex.EncodeToString(sum[:]),
			Services: []composition.APIContractService{{FullName: "grpc.health.v1.Health", Procedures: []string{check, watch, list}}}},
		Contract: contract, Server: server, Conn: conn, Owner: "installation",
		Carry: func(ctx context.Context, _ string, scopes []*basev0.WorkScopeV1) (context.Context, error) {
			return metadata.AppendToOutgoingContext(ctx, hop.WorkContextKey, authority.Issue(t, "module", carry(scopes)...)), nil
		},
		Cases: map[string]probe.Case{
			check: {Request: &healthv1.HealthCheckRequest{}, Shows: serving},
			watch: {Request: &healthv1.HealthCheckRequest{}, Shows: serving},
			list: {Request: &healthv1.HealthListRequest{}, Shows: func(answer protoreflect.Message) error {
				if answer.Get(answer.Descriptor().Fields().ByName("statuses")).Map().Len() == 0 {
					return status.Error(codes.Unknown, "the list is empty")
				}
				return nil
			}},
		},
	}
}

// errAbsent is a handler's decision to answer OK with nothing rather than refuse.
var errAbsent = status.Error(codes.Unknown, "answer as though nothing were there")

func asGiven(scopes []*basev0.WorkScopeV1) []*basev0.WorkScopeV1 { return scopes }

func refusing(method string, code codes.Code, unless ...string) rule {
	return func(called string, holds func(string) bool) error {
		if called != method || slices.ContainsFunc(unless, holds) {
			return nil
		}
		if code == codes.OK {
			return errAbsent
		}
		return status.Error(code, "refused")
	}
}

func TestADeclarationItsHandlersAgreeWithPasses(t *testing.T) {
	contract := published(t, all)
	probe.Run(t, module(t, contract, refusing(check, codes.PermissionDenied, "doc:read"), asGiven))
}

// Each way a declaration and its handler have disagreed is one finding naming
// the procedure, found by calls the probe itself made on the module's server.
func TestEachDisagreementIsAFinding(t *testing.T) {
	for name, c := range map[string]struct {
		declared map[string]*hopv1.Policy
		decide   rule
		carry    func([]*basev0.WorkScopeV1) []*basev0.WorkScopeV1
		drop     string
		want     string
	}{
		"a handler rule under an open declaration (module-record-store#223)": {decide: refusing(list, codes.PermissionDenied, "records.types:read", "records.records:read"), want: list + ": holding exactly what it declares (nothing), the call is answered PermissionDenied"},
		"the same refusal concealed as NotFound":                             {decide: refusing(list, codes.NotFound, "records.types:read"), want: list + ": holding exactly what it declares (nothing), the call is answered NotFound"},
		"the same refusal rendered as an empty answer":                       {decide: refusing(list, codes.OK, "records.types:read"), want: list + ": holding exactly what it declares (nothing), the call is answered OK without what was asked for"},
		"a handler that wants more than its declaration":                     {decide: refusing(check, codes.PermissionDenied, "doc:admin"), want: check + ": holding exactly what it declares (doc:read@installation), the call is answered PermissionDenied"},
		"a streaming handler with a rule of its own":                         {decide: refusing(watch, codes.PermissionDenied, "doc:read"), want: watch + ": holding exactly what it declares (nothing)"},
		"a fixture that grants every action": {decide: refusing(check, codes.PermissionDenied, "doc:admin"), carry: func(scopes []*basev0.WorkScopeV1) []*basev0.WorkScopeV1 {
			if len(scopes) == 0 {
				return nil
			}
			return []*basev0.WorkScopeV1{{ResourceKind: "doc", Actions: []string{"*"}, ResourceOwnerId: "installation"}}
		}, want: check + ": the call carries doc:*@installation, and the declaration is exactly doc:read@installation"},
		"a fixture that holds a second permission": {decide: agrees, carry: func(scopes []*basev0.WorkScopeV1) []*basev0.WorkScopeV1 {
			if len(scopes) == 0 {
				return nil
			}
			return append(scopes, &basev0.WorkScopeV1{ResourceKind: "doc", Actions: []string{"admin"}, ResourceOwnerId: "installation"})
		}, want: check + ": the call carries doc:admin@installation, doc:read@installation"},
		"a served procedure with no case":                 {decide: agrees, drop: watch, want: watch + ": has no case"},
		"a server that does not read what a call carries": {decide: nil, want: "three"},
		"a served procedure that declares nothing":        {declared: map[string]*hopv1.Policy{check: requires("doc:read"), watch: open, list: {}}, decide: agrees, want: list + ": declares no readable policy"},
		"a declaration that says two things":              {declared: map[string]*hopv1.Policy{check: {AnyCheckedCaller: true, Requires: requires("doc:read").Requires}, watch: open, list: open}, decide: agrees, want: check + ": declares no readable policy"},
		"a permission declared twice is asked once":       {declared: map[string]*hopv1.Policy{check: requires("doc:read", "doc:read"), watch: open, list: open}, decide: refusing(check, codes.PermissionDenied, "doc:read"), want: ""},
	} {
		declared, carry := c.declared, c.carry
		if declared == nil {
			declared = all
		}
		if carry == nil {
			carry = asGiven
		}
		m := module(t, published(t, declared), c.decide, carry)
		delete(m.Cases, c.drop)
		findings, err := probe.Check(t.Context(), m)
		switch {
		case err != nil:
			t.Errorf("%s: %v", name, err)
		case c.want == "three":
			// The control: every procedure answers a call that carries no
			// Work Context, so nothing it "decided" on the exact one counts.
			if len(findings) != 3 || !strings.Contains(findings[0], "a call carrying no Work Context is answered OK") {
				t.Errorf("%s: findings %q, want one per procedure naming the unread call", name, findings)
			}
		case c.want == "" && len(findings) != 0:
			t.Errorf("%s: findings %q, want none", name, findings)
		case c.want != "" && (len(findings) != 1 || !strings.HasPrefix(findings[0], c.want)):
			t.Errorf("%s: findings %q, want one starting %q", name, findings, c.want)
		}
	}
}

// What is probed is what the hop routes to the endpoint: reflection, which the
// server registers and the hop does not route, is not probed and is no
// finding; a routed procedure the server does not register, or the contract
// does not declare, is; and a contract that is not the one the catalog names
// is an error, not a pass.
func TestWhatIsProbedIsWhatTheHopRoutes(t *testing.T) {
	m := module(t, published(t, all), agrees, asGiven)
	if findings, err := probe.Check(t.Context(), m); err != nil || len(findings) != 0 {
		t.Fatalf("a server that also registers reflection: findings %q (%v), want none", findings, err)
	}
	m.Endpoint.Services[0].Procedures = append(m.Endpoint.Services[0].Procedures, "/grpc.health.v1.Health/Gone", "/grpc.reflection.v1.ServerReflection/Absent")
	findings, err := probe.Check(t.Context(), m)
	if err != nil || len(findings) != 2 || !strings.Contains(strings.Join(findings, "\n"), "does not declare it") {
		t.Fatalf("routed and not published: findings %q (%v)", findings, err)
	}
	unregistered := module(t, published(t, all), agrees, asGiven)
	unregistered.Server = grpc.NewServer()
	findings, err = probe.Check(t.Context(), unregistered)
	if err != nil || len(findings) != 3 || !strings.Contains(findings[0], "the server registers no handler for it") {
		t.Fatalf("routed and not registered: findings %q (%v)", findings, err)
	}
	m.Endpoint.Services = nil
	if _, err := probe.Check(t.Context(), m); err == nil {
		t.Fatal("an endpoint the hop routes nothing to was probed as though it compared something")
	}
	stale := module(t, published(t, all), agrees, asGiven)
	stale.Contract = published(t, nil)
	if _, err := probe.Check(t.Context(), stale); err == nil || !strings.Contains(err.Error(), "the catalog names") {
		t.Fatalf("a contract that is not the catalog's: %v, want it refused by digest", err)
	}
}

// A case whose Shows accepts the empty answer cannot tell an answer from a
// refusal rendered as one, and is a finding before any call is made.
func TestAShowsThatAcceptsNothingIsAFinding(t *testing.T) {
	m := module(t, published(t, all), refusing(list, codes.OK, "records.types:read"), asGiven)
	lazy := m.Cases[list]
	lazy.Shows = func(protoreflect.Message) error { return nil }
	m.Cases[list] = lazy
	findings, err := probe.Check(t.Context(), m)
	if err != nil || len(findings) != 1 || !strings.HasPrefix(findings[0], list+": its case's Shows accepts an empty answer") {
		t.Fatalf("findings %q (%v)", findings, err)
	}
}
