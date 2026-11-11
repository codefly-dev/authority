// Package policy is one method's declaration (authority.hop.v1.Policy) and the
// one evaluator of it. A declaration is stated once and decided at two points:
// the hop asks whether a call holds it on any resource, the module behind the
// hop asks whether the call holds it on the resource the call names. Both call
// Method.Unmet, each with its own answer to "is this permission held", so no
// module names a permission of its own or keeps a copy of the decision.
package policy

import (
	"fmt"
	"slices"
	"strings"

	hopv1 "github.com/codefly-dev/authority/libraries/hop/go/gen/authority/hop/v1"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// AnyAction is the action a fixture grant holds every action with.
const AnyAction = "*"

// Permission is one action on one resource kind, "kind:action".
type Permission string

// Of is the permission for action on kind.
func Of(kind, action string) Permission { return Permission(kind + ":" + action) }

// Kind is the permission's resource kind; kinds never contain a colon.
func (p Permission) Kind() string { k, _, _ := strings.Cut(string(p), ":"); return k }

// Action is the permission's action.
func (p Permission) Action() string { _, a, _ := strings.Cut(string(p), ":"); return a }

// Method is one method's declaration: every permission of Requires, or
// AnyCheckedCaller and nothing. It states conjunctions only, on purpose: a
// binding ceiling is derived from the calls a consumer names, and a call with
// alternatives has no ceiling that is both sufficient and least.
type Method struct {
	AnyCheckedCaller bool
	Requires         []Permission
	// Carries is what a call may exercise beyond what it requires. No
	// decision reads it; a derived ceiling includes it.
	Carries []Permission
}

// FromProto reads a declaration; nil is a method that declares nothing.
func FromProto(p *hopv1.Policy) Method {
	return Method{AnyCheckedCaller: p.GetAnyCheckedCaller(), Requires: each(p.GetRequires()), Carries: each(p.GetCarries())}
}

func each(requirements []*hopv1.Requirement) []Permission {
	var out []Permission
	for _, r := range requirements {
		for _, action := range r.GetActions() {
			out = append(out, Of(r.GetResourceKind(), action))
		}
	}
	return out
}

// Declares reports whether the method declares anything at all.
func (m Method) Declares() bool { return m.AnyCheckedCaller || len(m.Requires) > 0 }

// Validate refuses a declaration that says two things: any_checked_caller
// beside something a call must or may hold.
func (m Method) Validate() error {
	if m.AnyCheckedCaller && len(m.Requires)+len(m.Carries) > 0 {
		return fmt.Errorf("declares both requirements and any_checked_caller")
	}
	return nil
}

// Unmet is each required permission the call does not hold, empty when it
// holds the declaration. holds answers whether the call holds action on kind:
// on any resource (OnAnyResource, the hop's question) or on the resource the
// call names (the module's, through its claims and that resource's owner).
func (m Method) Unmet(holds func(kind, action string) bool) []string {
	var unmet []string
	for _, p := range m.Requires {
		if !holds(p.Kind(), p.Action()) {
			unmet = append(unmet, string(p))
		}
	}
	return unmet
}

// Ceiling is every permission the method names, sorted: what a binding that
// names the call may carry at most.
func (m Method) Ceiling() []Permission {
	all := slices.Concat(m.Requires, m.Carries)
	slices.Sort(all)
	return slices.Compact(all)
}

// OnAnyResource answers holds for the hop: the call carries action on some
// resource of kind, whatever its ids or owner. Which resource is the module's.
func OnAnyResource(held []*basev0.WorkScopeV1) func(kind, action string) bool {
	return func(kind, action string) bool {
		return slices.ContainsFunc(held, func(h *basev0.WorkScopeV1) bool {
			return h.GetResourceKind() == kind && (slices.Contains(h.GetActions(), action) || slices.Contains(h.GetActions(), AnyAction))
		})
	}
}

// Contract reads what each procedure of a published protobuf contract
// declares, keyed "/package.Service/Method": the descriptor set a module
// package carries (contract.binpb), which is what a delivery to the authority
// is read from and so what a deployed hop enforces. A procedure that declares
// nothing is listed, declaring nothing. A table generated from the contract is
// a second statement of it and is not read here.
func Contract(descriptorSet []byte) (map[string]Method, error) {
	var set descriptorpb.FileDescriptorSet
	// Decoded against the registered types, so the policy option reads as a
	// message rather than unknown bytes.
	if err := (proto.UnmarshalOptions{Resolver: protoregistry.GlobalTypes}).Unmarshal(descriptorSet, &set); err != nil {
		return nil, fmt.Errorf("contract does not decode: %w", err)
	}
	out := map[string]Method{}
	for _, file := range set.GetFile() {
		for _, service := range file.GetService() {
			for _, method := range service.GetMethod() {
				name := "/" + strings.TrimPrefix(file.GetPackage()+"."+service.GetName(), ".") + "/" + method.GetName()
				declared, _ := proto.GetExtension(method.GetOptions(), hopv1.E_Policy).(*hopv1.Policy)
				out[name] = FromProto(declared)
			}
		}
	}
	return out, nil
}

// Admit is the hop's decision for a module's own tests, on the contract the
// module publishes: the evaluator the authority decides with, so a test hop
// keeps no copy of it. A refusal is PermissionDenied and names what is unmet.
func Admit(contract map[string]Method, method string, held []*basev0.WorkScopeV1) error {
	m, served := contract[method]
	switch {
	case !served || !m.Declares():
		return status.Errorf(codes.PermissionDenied, "hop: %s declares no policy", method)
	case m.Validate() != nil:
		return status.Errorf(codes.PermissionDenied, "hop: %s %v", method, m.Validate())
	}
	if unmet := m.Unmet(OnAnyResource(held)); len(unmet) > 0 {
		return status.Errorf(codes.PermissionDenied, "hop: %s requires %s, which the call does not hold", method, strings.Join(unmet, ", "))
	}
	return nil
}
