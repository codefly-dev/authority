package probe_test

import (
	"slices"
	"strings"
	"testing"

	hopv1 "github.com/codefly-dev/authority/libraries/hop/go/gen/authority/hop/v1"
	"github.com/codefly-dev/authority/libraries/hop/go/policy"
	"github.com/codefly-dev/authority/libraries/hop/go/policy/probe"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
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

func published(t *testing.T, methods map[string]*hopv1.Policy) []byte {
	t.Helper()
	service := &descriptorpb.ServiceDescriptorProto{Name: proto.String("S")}
	for name, declared := range methods {
		method := &descriptorpb.MethodDescriptorProto{Name: proto.String(name), InputType: proto.String(".p.M"), OutputType: proto.String(".p.M"), Options: &descriptorpb.MethodOptions{}}
		proto.SetExtension(method.Options, hopv1.E_Policy, declared)
		service.Method = append(service.Method, method)
	}
	raw, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{
		Name: proto.String("p.proto"), Package: proto.String("p"), Service: []*descriptorpb.ServiceDescriptorProto{service},
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("M")}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// module is a module behind its test hop: the hop decides the published
// contract with policy.Admit, then the handler answers on what the call holds.
func module(t *testing.T, contract []byte, handlers map[string]func(holds func(string) bool) error) probe.Call {
	t.Helper()
	declared, err := policy.Contract(contract)
	if err != nil {
		t.Fatal(err)
	}
	return func(method string, holding []policy.Permission) error {
		var scopes []*basev0.WorkScopeV1
		for _, p := range holding {
			scopes = append(scopes, &basev0.WorkScopeV1{ResourceKind: p.Kind(), Actions: []string{p.Action()}, ResourceOwnerId: "owner"})
		}
		if err := policy.Admit(declared, method, scopes); err != nil {
			return err
		}
		handler, served := handlers[method]
		if !served {
			return status.Error(codes.Unimplemented, "no handler")
		}
		return handler(func(p string) bool { return slices.Contains(holding, policy.Permission(p)) })
	}
}

func agrees(func(string) bool) error { return nil }

// typeRead is the record store's type read as its handler decided it from 9
// November: the catalogue is read by a caller holding records.types:read or
// records.records:read, refused as refusal names it.
func typeRead(refusal codes.Code) func(func(string) bool) error {
	return func(holds func(string) bool) error {
		if holds("records.types:read") || holds("records.records:read") {
			return nil
		}
		return status.Error(refusal, "record type")
	}
}

func TestADeclarationItsHandlerAgreesWithPasses(t *testing.T) {
	contract := published(t, map[string]*hopv1.Policy{"Version": open, "Put": requires("records.records:read", "records.records:write"), "GetType": requires("records.types:read")})
	probe.Run(t, contract, module(t, contract, map[string]func(func(string) bool) error{
		"/p.S/Version": agrees, "/p.S/Put": agrees,
		"/p.S/GetType": func(holds func(string) bool) error {
			if !holds("records.types:read") {
				return status.Error(codes.PermissionDenied, "records.types:read")
			}
			return nil
		},
	}))
}

// Each way a declaration and its handler have disagreed is a finding that
// names the method: the drift of module-record-store#223 (a handler rule under
// a declaration left open), the same refusal concealed as NotFound, a policy
// declared for a handler that does not exist (Freeze, TransferOwnership), a
// method that declares nothing, and a suite whose hop is not in the path.
func TestEachDisagreementIsAFinding(t *testing.T) {
	for name, c := range map[string]struct {
		declared *hopv1.Policy
		handler  func(func(string) bool) error
		want     string
	}{
		"a handler rule under an open declaration": {open, typeRead(codes.PermissionDenied), "holding exactly what it declares ([]), the call is answered PermissionDenied"},
		"the same refusal concealed as NotFound":   {open, typeRead(codes.NotFound), "the call is answered NotFound"},
		"a handler stricter than its declaration": {requires("records.records:read"), func(holds func(string) bool) error {
			return typeRead(codes.PermissionDenied)(func(p string) bool { return p == "records.types:read" && holds(p) })
		}, "the declaration and the handler disagree"},
		"a policy declared for no handler":   {open, nil, "the call is answered Unimplemented"},
		"a method that declares nothing":     {&hopv1.Policy{}, agrees, "declares no readable policy"},
		"a declaration that says two things": {&hopv1.Policy{AnyCheckedCaller: true, Requires: requires("a:b").Requires}, agrees, "declares no readable policy"},
	} {
		contract := published(t, map[string]*hopv1.Policy{"M": c.declared})
		handlers := map[string]func(func(string) bool) error{}
		if c.handler != nil {
			handlers["/p.S/M"] = c.handler
		}
		findings, err := probe.Check(contract, module(t, contract, handlers))
		if err != nil || len(findings) != 1 || !strings.Contains(findings[0], c.want) || !strings.HasPrefix(findings[0], "/p.S/M") {
			t.Errorf("%s: findings %q (%v), want one naming /p.S/M and %q", name, findings, err, c.want)
		}
	}
	// A suite that reaches the handler around the hop proves nothing about
	// the declaration, and says so.
	contract := published(t, map[string]*hopv1.Policy{"M": requires("records.types:read")})
	findings, err := probe.Check(contract, func(string, []policy.Permission) error { return nil })
	if err != nil || len(findings) != 1 || !strings.Contains(findings[0], "without records.types:read the call is answered OK") {
		t.Errorf("around the hop: findings %q (%v)", findings, err)
	}
	if _, err := probe.Check(published(t, nil), nil); err == nil {
		t.Error("a contract declaring no procedure was probed as though it compared something")
	}
}
