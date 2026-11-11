package policy_test

import (
	"slices"
	"testing"

	hopv1 "github.com/codefly-dev/authority/libraries/hop/go/gen/authority/hop/v1"
	"github.com/codefly-dev/authority/libraries/hop/go/policy"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func scope(kind, owner string, actions ...string) *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: kind, ResourceOwnerId: owner, Actions: actions}
}

func requires(kind string, actions ...string) *hopv1.Policy {
	return &hopv1.Policy{Requires: []*hopv1.Requirement{{ResourceKind: kind, Actions: actions}}}
}

// selectedTo is a module's answer to "is this permission held on a resource
// owner holds": by a scope that names that owner, never an ownerless one. It
// is where owner selection lives: in the question the module hands the
// evaluator, not in a rule of its own.
func selectedTo(held []*basev0.WorkScopeV1, owner string) func(kind, action string) bool {
	return func(kind, action string) bool {
		return slices.ContainsFunc(held, func(h *basev0.WorkScopeV1) bool {
			return owner != "" && h.GetResourceOwnerId() == owner && h.GetResourceKind() == kind && slices.Contains(h.GetActions(), action)
		})
	}
}

// One declaration is decided at the hop on any resource and by the module on
// the resource the call names, by one evaluator. Whatever a caller holds, the
// module admits on some owner only what the hop admitted, so nothing the
// module admits was refused before it, and the module adds no permission.
func TestTheHopAndTheModuleDecideOneDeclaration(t *testing.T) {
	m := policy.FromProto(requires("records.types", "read"))
	atoms := []*basev0.WorkScopeV1{
		scope("records.types", "a", "read"), scope("records.types", "b", "read"), scope("records.types", "", "read"),
		scope("records.types", "a", "define"), scope("records.records", "a", "read"), scope("records.types", "", policy.AnyAction),
	}
	admitted := 0
	for mask := range 1 << len(atoms) {
		var held []*basev0.WorkScopeV1
		for i, atom := range atoms {
			if mask&(1<<i) != 0 {
				held = append(held, atom)
			}
		}
		hop := len(m.Unmet(policy.OnAnyResource(held))) == 0
		onA := len(m.Unmet(selectedTo(held, "a"))) == 0
		if onA && !hop {
			t.Fatalf("the module admits %v on owner a and the hop refuses the call", held)
		}
		if want := slices.ContainsFunc(held, func(h *basev0.WorkScopeV1) bool { return h == atoms[0] }); onA != want {
			t.Fatalf("holding %v, the read of owner a's type is %t, want %t: only records.types:read selected to a holds it", held, onA, want)
		}
		if onA {
			admitted++
		}
	}
	if admitted == 0 {
		t.Fatal("no caller was admitted, so the comparison proved nothing")
	}
	if unmet := m.Unmet(policy.OnAnyResource([]*basev0.WorkScopeV1{scope("records.records", "a", "read")})); !slices.Equal(unmet, []string{"records.types:read"}) {
		t.Fatalf("a rows-only reader is refused by name; got %q", unmet)
	}
}

// A ceiling derived from the calls a consumer names is exact when each call
// states one conjunction. The consumer that defines a type and reads it back
// derived records.types:define alone while the read declared
// any_checked_caller; with the read declaring what it requires, the ceiling
// carries read, and the module issued it is admitted at both points.
func TestADerivedCeilingIsWhatTheCallsDeclare(t *testing.T) {
	define := policy.FromProto(requires("records.types", "define"))
	open := policy.FromProto(&hopv1.Policy{AnyCheckedCaller: true})
	read := policy.FromProto(requires("records.types", "read"))
	if got := slices.Concat(define.Ceiling(), open.Ceiling()); !slices.Equal(got, []policy.Permission{policy.Of("records.types", "define")}) {
		t.Fatalf("with the read declared open the ceiling is %q", got)
	}
	ceiling := slices.Concat(define.Ceiling(), read.Ceiling())
	if !slices.Equal(ceiling, []policy.Permission{policy.Of("records.types", "define"), policy.Of("records.types", "read")}) {
		t.Fatalf("derived ceiling %q", ceiling)
	}
	held := []*basev0.WorkScopeV1{scope("records.types", "a", "define", "read")}
	if len(read.Unmet(policy.OnAnyResource(held)))+len(read.Unmet(selectedTo(held, "a"))) != 0 {
		t.Fatal("the derived ceiling does not admit the read")
	}
}

func TestADeclarationThatSaysTwoThingsIsRefused(t *testing.T) {
	both := requires("doc", "read")
	both.AnyCheckedCaller = true
	if policy.FromProto(both).Validate() == nil {
		t.Error("requires beside any_checked_caller was read as a declaration")
	}
	if policy.FromProto(&hopv1.Policy{AnyCheckedCaller: true, Carries: both.Requires}).Validate() == nil {
		t.Error("carries beside any_checked_caller was read as a declaration")
	}
	if policy.FromProto(nil).Declares() {
		t.Error("an absent option declares something")
	}
}

// contract is a published descriptor set of one service: each method with the
// policy given, or with none where the policy is nil.
func contract(t *testing.T, methods map[string]*hopv1.Policy) []byte {
	t.Helper()
	service := &descriptorpb.ServiceDescriptorProto{Name: proto.String("S")}
	for name, declared := range methods {
		method := &descriptorpb.MethodDescriptorProto{Name: proto.String(name), InputType: proto.String(".p.M"), OutputType: proto.String(".p.M")}
		if declared != nil {
			method.Options = &descriptorpb.MethodOptions{}
			proto.SetExtension(method.Options, hopv1.E_Policy, declared)
		}
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

// The published contract is read as the delivery reads it, and decided with
// the evaluator the authority decides with.
func TestAContractIsReadAndDecided(t *testing.T) {
	declared, err := policy.Contract(contract(t, map[string]*hopv1.Policy{
		"Write": requires("doc", "read", "write"), "Open": {AnyCheckedCaller: true}, "Unmarked": nil,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := declared["/p.S/Write"].Requires; !slices.Equal(got, []policy.Permission{policy.Of("doc", "read"), policy.Of("doc", "write")}) {
		t.Fatalf("/p.S/Write requires %q", got)
	}
	reader := []*basev0.WorkScopeV1{scope("doc", "a", "read")}
	for method, want := range map[string]codes.Code{"/p.S/Write": codes.PermissionDenied, "/p.S/Open": codes.OK, "/p.S/Unmarked": codes.PermissionDenied, "/p.S/Unserved": codes.PermissionDenied} {
		if got := status.Code(policy.Admit(declared, method, reader)); got != want {
			t.Errorf("%s: a reader is answered %v, want %v", method, got, want)
		}
	}
	if err := policy.Admit(declared, "/p.S/Write", []*basev0.WorkScopeV1{scope("doc", "a", policy.AnyAction)}); err != nil {
		t.Errorf("a fixture grant of every action is refused: %v", err)
	}
}
