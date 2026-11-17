package policy_test

import (
	"slices"
	"strings"
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

// A method that requires two permissions is one act on one resource: a read
// held on one owner's resources and a write held on another's hold it on
// nothing. The hop refuses such a call itself, naming where each is held,
// where it used to pass the call on for the module to find it reaches nothing.
// A grant that selects no owner holds its permission on every owner, so it is
// held together with anything, and a call is refused only when no owner at
// all is common to what it requires: which resource of a shared owner is the
// module's question still.
func TestACallHoldingWhatAMethodRequiresOnNoOwnerInCommonIsRefused(t *testing.T) {
	named := func(kind, owner string, ids []string, actions ...string) *basev0.WorkScopeV1 {
		return &basev0.WorkScopeV1{ResourceKind: kind, ResourceOwnerId: owner, ResourceIds: ids, Actions: actions}
	}
	edits := policy.FromProto(requires("doc", "read", "write"))
	typed := policy.Method{Requires: []policy.Permission{policy.Of("doc", "read"), policy.Of("doc", "write"), policy.Of("types", "read")}}
	for _, tc := range []struct {
		name   string
		method policy.Method
		held   []*basev0.WorkScopeV1
		apart  []string
	}{
		{"a read on one owner and a write on another", edits,
			[]*basev0.WorkScopeV1{scope("doc", "a", "read"), scope("doc", "b", "write")},
			[]string{"doc:read on a", "doc:write on b"}},
		{"neither owner of the read holds the write", edits,
			[]*basev0.WorkScopeV1{scope("doc", "a", "read"), scope("doc", "b", "read"), scope("doc", "c", "write")},
			[]string{"doc:read on a, b", "doc:write on c"}},
		{"two of three share an owner the third is not held on", typed,
			[]*basev0.WorkScopeV1{scope("doc", "a", "read", "write"), scope("types", "b", "read")},
			[]string{"doc:read on a", "doc:write on a", "types:read on b"}},
		{"the whole kind beside two owners that share nothing", typed,
			[]*basev0.WorkScopeV1{scope("doc", "", "read"), scope("doc", "a", "write"), scope("types", "b", "read")},
			[]string{"doc:read on every owner", "doc:write on a", "types:read on b"}},
		{"resources named on different owners", edits,
			[]*basev0.WorkScopeV1{named("doc", "a", []string{"d-1"}, "read"), named("doc", "b", []string{"d-1"}, "write")},
			[]string{"doc:read on a", "doc:write on b"}},

		{"both on one owner", edits, []*basev0.WorkScopeV1{scope("doc", "a", "read"), scope("doc", "a", "write")}, nil},
		{"one owner among several is common", edits,
			[]*basev0.WorkScopeV1{scope("doc", "a", "read"), scope("doc", "b", "read"), scope("doc", "b", "write"), scope("doc", "c", "write")}, nil},
		{"the write on the whole kind", edits, []*basev0.WorkScopeV1{scope("doc", "a", "read"), scope("doc", "", "write")}, nil},
		{"both on the whole kind", edits, []*basev0.WorkScopeV1{scope("doc", "", "read", "write")}, nil},
		{"every action on the whole kind", edits, []*basev0.WorkScopeV1{scope("doc", "", policy.AnyAction)}, nil},
		{"every action on the owner of the read", edits, []*basev0.WorkScopeV1{scope("doc", "a", "read"), scope("doc", "a", policy.AnyAction)}, nil},
		{"resources named with no owner hold on any owner", edits,
			[]*basev0.WorkScopeV1{scope("doc", "a", "read"), named("doc", "", []string{"d-1"}, "write")}, nil},
		{"one owner, resources named apart: the module's question", edits,
			[]*basev0.WorkScopeV1{named("doc", "a", []string{"d-1"}, "read"), named("doc", "a", []string{"d-2"}, "write")}, nil},
		{"a whole kind and a kind on one owner", typed,
			[]*basev0.WorkScopeV1{scope("doc", "a", "read", "write"), scope("types", "", "read")}, nil},
		{"one permission required", policy.FromProto(requires("doc", "read")),
			[]*basev0.WorkScopeV1{scope("doc", "a", "read"), scope("doc", "b", "write")}, nil},
		{"a permission held nowhere is unmet, not apart", edits, []*basev0.WorkScopeV1{scope("doc", "a", "read"), scope("types", "b", "write")}, nil},
		{"a permission required twice", policy.Method{Requires: []policy.Permission{policy.Of("doc", "read"), policy.Of("doc", "read")}},
			[]*basev0.WorkScopeV1{scope("doc", "a", "read"), scope("doc", "b", "read")}, nil},
		{"what a method carries is not required together", policy.Method{Requires: []policy.Permission{policy.Of("doc", "read")}, Carries: []policy.Permission{policy.Of("doc", "write")}},
			[]*basev0.WorkScopeV1{scope("doc", "a", "read"), scope("doc", "b", "write")}, nil},
		{"any checked caller", policy.Method{AnyCheckedCaller: true}, []*basev0.WorkScopeV1{scope("doc", "a", "read"), scope("doc", "b", "write")}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.method.Apart(tc.held); !slices.Equal(got, tc.apart) {
				t.Fatalf("apart %q, want %q", got, tc.apart)
			}
			unmet := len(tc.method.Unmet(policy.OnAnyResource(tc.held))) > 0
			err := policy.Admit(map[string]policy.Method{"/p.S/M": tc.method}, "/p.S/M", tc.held)
			switch {
			case tc.apart != nil:
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("the hop admits a call holding what the method requires on no owner in common: %v", err)
				}
				for _, where := range tc.apart {
					if !strings.Contains(err.Error(), where) {
						t.Errorf("the refusal %q does not say %q", err, where)
					}
				}
				if !strings.Contains(err.Error(), "no owner in common") {
					t.Errorf("the refusal does not say why: %v", err)
				}
			case !unmet && err != nil:
				t.Fatalf("a call holding what the method requires on a common owner is refused: %v", err)
			case unmet && (err == nil || strings.Contains(err.Error(), "no owner in common")):
				t.Fatalf("an unmet requirement is refused as such: %v", err)
			}
		})
	}
}

// What the module admits on an owner, the hop admitted: with two permissions
// required, a call that holds both selected to one owner is never apart.
func TestTheHopRefusesAsApartNothingTheModuleAdmitsOnAnOwner(t *testing.T) {
	m := policy.FromProto(requires("doc", "read", "write"))
	atoms := []*basev0.WorkScopeV1{
		scope("doc", "a", "read"), scope("doc", "b", "read"), scope("doc", "", "read"),
		scope("doc", "a", "write"), scope("doc", "b", "write"), scope("doc", "", "write"), scope("doc", "c", policy.AnyAction),
	}
	refused, admitted := 0, 0
	for mask := range 1 << len(atoms) {
		var held []*basev0.WorkScopeV1
		for i, atom := range atoms {
			if mask&(1<<i) != 0 {
				held = append(held, atom)
			}
		}
		hop := policy.Admit(map[string]policy.Method{"/p.S/M": m}, "/p.S/M", held) == nil
		for _, owner := range []string{"a", "b", "c"} {
			if len(m.Unmet(selectedTo(held, owner))) == 0 || len(m.Unmet(func(kind, action string) bool {
				return selectedTo(held, owner)(kind, action) || selectedTo(held, owner)(kind, policy.AnyAction)
			})) == 0 {
				admitted++
				if !hop {
					t.Fatalf("the module admits %v on owner %s and the hop refuses the call", held, owner)
				}
			}
		}
		if !hop && len(m.Unmet(policy.OnAnyResource(held))) == 0 {
			refused++
		}
	}
	if refused == 0 || admitted == 0 {
		t.Fatalf("%d calls refused as apart and %d admitted on an owner: the comparison proved nothing", refused, admitted)
	}
}
