// Package probe makes the call: for every procedure a module's server
// registers, it holds exactly what the published contract declares and invokes
// the handler itself, over the module's own connection. Every other check of a
// method policy compares one statement of it with another; this one compares
// the statement with what the module does. It takes no exception: a registered
// procedure with no case, no handler, no declaration, or a handler that
// refuses what its declaration says is enough, fails by name.
//
// What it proves is that the declaration is SUFFICIENT, for the principal,
// owner and request the case chooses. It does not prove:
//
//   - that the handler requires as much as it declares. A handler laxer than
//     its declaration passes; the hop refuses those calls before it.
//   - that an answer is complete. A handler that answers OK with less (a
//     filtered list, an empty page) instead of refusing is caught only by the
//     case's Shows, which must say what the answer has to carry. A Shows that
//     accepts an empty answer does not catch a refusal rendered as absence.
//   - rules that are not about scopes (who the principal is, stored state, a
//     request field). The case picks a principal and a resource that satisfy
//     them; they stay the handler's, named in its refusals.
package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/policy"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Module is a module as its suite runs it: its real handlers registered on
// Server, reached over Conn.
type Module struct {
	// Contract is the published descriptor set (contract.binpb), the artifact
	// a deployed hop's policy is read from.
	Contract []byte
	// Server is the server the handlers are registered on (*grpc.Server). The
	// procedures probed are the contract's that it registers, so a service
	// the contract merely imports is not probed, and one it serves outside
	// the contract is a finding.
	Server interface {
		GetServiceInfo() map[string]grpc.ServiceInfo
	}
	// Conn reaches Server. The probe invokes each procedure on it.
	Conn grpc.ClientConnInterface
	// Owner is the fixture installation every scope the probe builds is
	// selected to; empty for a module whose kinds have no owner.
	Owner string
	// Carry returns ctx carrying, as outgoing metadata, a Work Context that
	// holds exactly scopes and the stamp of a hop that admitted the call to
	// method. The probe has already decided the call as the hop does
	// (policy.Admit); it reads the Work Context back and refuses one that
	// holds anything else.
	Carry func(ctx context.Context, method string, scopes []*basev0.WorkScopeV1) (context.Context, error)
	// Cases is one call per registered procedure, by "/package.Service/Method".
	Cases map[string]Case
}

// Case is a call that succeeds for a caller holding what the method declares.
type Case struct {
	// Request addresses a resource the fixture's Owner holds.
	Request proto.Message
	// Shows returns an error unless the answer carries what the request
	// asked for: the row, the type, the page's entries. It is required, and
	// it is the only thing that tells an answer from a refusal rendered as
	// an empty one.
	Shows func(answer protoreflect.Message) error
}

// Run fails t for each finding of Check.
func Run(t *testing.T, m Module) {
	t.Helper()
	findings, err := Check(t.Context(), m)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		t.Error(finding)
	}
}

// Check probes every procedure of the contract that the server registers and
// returns one finding per disagreement, each naming its procedure.
func Check(ctx context.Context, m Module) ([]string, error) {
	declared, err := policy.Contract(m.Contract)
	if err != nil {
		return nil, err
	}
	var set descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(m.Contract, &set); err != nil {
		return nil, err
	}
	files, err := protodesc.NewFiles(&set)
	if err != nil {
		return nil, fmt.Errorf("contract: %w", err)
	}
	var findings []string
	finding := func(format string, args ...any) { findings = append(findings, fmt.Sprintf(format, args...)) }
	probed := 0
	for service, info := range m.Server.GetServiceInfo() {
		for _, registered := range info.Methods {
			method := "/" + service + "/" + registered.Name
			d, _ := files.FindDescriptorByName(protoreflect.FullName(service + "." + registered.Name))
			descriptor, published := d.(protoreflect.MethodDescriptor)
			if !published {
				finding("%s is served and the published contract does not declare it", method)
				continue
			}
			probed++
			if reason := m.probe(ctx, method, descriptor, declared[method]); reason != "" {
				finding("%s: %s", method, reason)
			}
		}
	}
	if probed == 0 {
		return nil, errors.New("the server registers no procedure of the contract, so the probe would compare nothing")
	}
	slices.Sort(findings)
	return findings, nil
}

// probe is the one call, or why it disagrees with the declaration.
func (m Module) probe(ctx context.Context, method string, descriptor protoreflect.MethodDescriptor, declared policy.Method) string {
	if !declared.Declares() || declared.Validate() != nil {
		return "declares no readable policy; the hop refuses every call to it"
	}
	c, ok := m.Cases[method]
	if !ok || c.Request == nil || c.Shows == nil {
		return "has no case with a request and what its answer shows; every served procedure is probed"
	}
	scopes := exactly(declared.Requires, m.Owner)
	if err := policy.Admit(map[string]policy.Method{method: declared}, method, scopes); err != nil {
		return err.Error()
	}
	carried, err := m.Carry(ctx, method, scopes)
	if err != nil {
		return fmt.Sprintf("no Work Context for %s: %v", describe(scopes), err)
	}
	if reason := holdsExactly(carried, scopes); reason != "" {
		return reason
	}
	answer := dynamicpb.NewMessage(descriptor.Output())
	if err := m.invoke(carried, method, descriptor, c.Request, answer); err != nil {
		return fmt.Sprintf("holding exactly what it declares (%s), the call is answered %v (%v); the declaration and the handler disagree",
			describe(scopes), status.Code(err), err)
	}
	if err := c.Shows(answer); err != nil {
		return fmt.Sprintf("holding exactly what it declares (%s), the call is answered OK without what was asked for (%v); a refusal rendered as absence is a disagreement",
			describe(scopes), err)
	}
	return ""
}

// invoke makes the call on the module's connection and reads its first answer.
func (m Module) invoke(ctx context.Context, method string, descriptor protoreflect.MethodDescriptor, request proto.Message, answer proto.Message) error {
	if !descriptor.IsStreamingClient() && !descriptor.IsStreamingServer() {
		return m.Conn.Invoke(ctx, method, request, answer)
	}
	stream, err := m.Conn.NewStream(ctx, &grpc.StreamDesc{ClientStreams: descriptor.IsStreamingClient(), ServerStreams: descriptor.IsStreamingServer()}, method)
	if err != nil {
		return err
	}
	if err := stream.SendMsg(request); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if err := stream.CloseSend(); err != nil {
		return err
	}
	return stream.RecvMsg(answer)
}

// exactly is one scope per declared permission, selected to owner, and nothing
// else: no wildcard action, no second kind, no unselected scope.
func exactly(requires []policy.Permission, owner string) []*basev0.WorkScopeV1 {
	var scopes []*basev0.WorkScopeV1
	for _, p := range requires {
		if !slices.ContainsFunc(scopes, func(s *basev0.WorkScopeV1) bool {
			return s.GetResourceKind() == p.Kind && s.GetActions()[0] == p.Action
		}) {
			scopes = append(scopes, &basev0.WorkScopeV1{ResourceKind: p.Kind, Actions: []string{p.Action}, ResourceOwnerId: owner})
		}
	}
	return scopes
}

// holdsExactly reads the Work Context the call carries and answers why it is
// not exactly scopes: a fixture that grants more would hide a handler that
// wants more than the method declares.
func holdsExactly(ctx context.Context, scopes []*basev0.WorkScopeV1) string {
	md, _ := metadata.FromOutgoingContext(ctx)
	tokens := md.Get(hop.WorkContextKey)
	if len(tokens) != 1 {
		return "the call carries no single Work Context, so what it holds cannot be read"
	}
	decoded, err := workcontext.Decode(tokens[0])
	if err != nil {
		return fmt.Sprintf("the call's Work Context does not decode: %v", err)
	}
	held := decoded.Context().GetAuthorityScopes()
	if chain := decoded.Context().GetActorChain(); len(chain) > 0 {
		held = chain[len(chain)-1].GetGrantedScopes()
	}
	if got, want := describe(held), describe(scopes); got != want {
		return fmt.Sprintf("the call carries %s, and the declaration is exactly %s; a fixture holding more proves nothing", got, want)
	}
	return ""
}

// describe spells scopes canonically, one "kind:action@owner[ids]" per action.
func describe(scopes []*basev0.WorkScopeV1) string {
	points := map[string]bool{}
	for _, s := range scopes {
		for _, action := range s.GetActions() {
			point := s.GetResourceKind() + ":" + action + "@" + s.GetResourceOwnerId()
			if ids := s.GetResourceIds(); len(ids) > 0 {
				point += fmt.Sprint(ids)
			}
			points[point] = true
		}
	}
	if len(points) == 0 {
		return "nothing"
	}
	return strings.Join(slices.Sorted(maps.Keys(points)), ", ")
}
