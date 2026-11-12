// Package probe makes the call: for every procedure the hop routes to a
// module's endpoint, it holds exactly what the published contract declares and
// invokes the handler itself, over the module's own connection. Every other check of a
// method policy compares one statement of it with another; this one compares
// the statement with what the module does. It takes no exception: a routed
// procedure with no case, no handler, no declaration, a handler that refuses
// what its declaration says is enough, or one that answers a call carrying no
// Work Context at all, fails by name.
//
// What it proves is that the declaration is SUFFICIENT, for the principal,
// owner and request the case chooses. It does not prove:
//
//   - that the handler requires as much as it declares. A handler laxer than
//     its declaration passes; the hop refuses those calls before it.
//   - that an answer is complete. A handler that answers OK with less (a
//     filtered list, an empty page) instead of refusing is caught only by the
//     case's Shows, which must say what the answer has to carry. The probe
//     refuses a Shows that accepts the empty answer; beyond that, what Shows
//     asserts is the case's.
//   - that the handler's decision reads the scopes a call carries. The
//     control call shows the server refuses a call with no Work Context; a
//     server that demands one and then treats every permission as held is
//     found only where its handler refuses the exact holding.
//   - deliberate forgery: a Conn that does not reach Server, or a Shows that
//     refuses the empty answer once and accepts everything after.
//
// A procedure whose correct answer is the zero value of a type that has
// fields has no honest Shows; its case must ask for something that answers
// with more.
//   - rules that are not about scopes (who the principal is, stored state, a
//     request field). The case picks a principal and a resource that satisfy
//     them; they stay the handler's, named in its refusals.
package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/policy"
	"github.com/codefly-dev/core/composition"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
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
	// Dir is the module's directory, which holds its contract catalog
	// (contracts/api/catalog.codefly.json) as the generator wrote it. Service
	// and Endpoint name the catalog's entry for the endpoint Server serves.
	// The probe reads the catalog and the contract it names itself: the
	// procedures the hop routes to the endpoint, each of them, are what is
	// probed, and the module hands in no list of its own. A service the
	// contract merely imports is not routed, and neither is what a server
	// registers beside its own surface (health, reflection), which the
	// contract does not declare and no caller reaches through the hop.
	Dir, Service, Endpoint string
	// Server is the server the handlers are registered on (*grpc.Server): the
	// one the module ships. A routed procedure it does not register is a
	// finding.
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

// Check probes every procedure the hop routes to the endpoint and returns one
// finding per disagreement, each naming its procedure.
func Check(ctx context.Context, m Module) ([]string, error) {
	entry, contract, err := m.published()
	if err != nil {
		return nil, err
	}
	declared, err := policy.Contract(contract)
	if err != nil {
		return nil, err
	}
	var set descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(contract, &set); err != nil {
		return nil, err
	}
	files, err := protodesc.NewFiles(&set)
	if err != nil {
		return nil, fmt.Errorf("contract: %w", err)
	}
	var findings []string
	finding := func(format string, args ...any) { findings = append(findings, fmt.Sprintf(format, args...)) }
	registered := map[string]bool{}
	for service, info := range m.Server.GetServiceInfo() {
		for _, method := range info.Methods {
			registered["/"+service+"/"+method.Name] = true
		}
	}
	var routed []string
	for _, service := range entry.Services {
		routed = append(routed, service.Procedures...)
	}
	if len(routed) == 0 {
		return nil, errors.New("the catalog routes no procedure to the endpoint, so the probe would compare nothing")
	}
	slices.Sort(routed)
	for _, method := range slices.Compact(routed) {
		service, name, _ := strings.Cut(strings.TrimPrefix(method, "/"), "/")
		d, _ := files.FindDescriptorByName(protoreflect.FullName(service + "." + name))
		descriptor, published := d.(protoreflect.MethodDescriptor)
		switch {
		case !published:
			finding("%s: the hop routes it and the published contract does not declare it", method)
		case !registered[method]:
			finding("%s: the hop routes it and the server registers no handler for it", method)
		default:
			if reason := m.probe(ctx, method, descriptor, declared[method]); reason != "" {
				finding("%s: %s", method, reason)
			}
		}
	}
	// The entry is not a way to leave a procedure out: one the contract
	// declares and the server registers is served, routed or not.
	for method := range registered {
		if _, declares := declared[method]; declares && !slices.Contains(routed, method) {
			finding("%s: the contract declares it and the server registers it, and the catalog does not route it; every served procedure is probed", method)
		}
	}
	slices.Sort(findings)
	return findings, nil
}

// published reads the endpoint's entry from the module's catalog and the
// contract it names, held to the digest the entry records: the bytes a
// delivery is read from.
func (m Module) published() (composition.APIContractEndpoint, []byte, error) {
	catalog, err := composition.LoadAPIContractCatalog(m.Dir)
	if err != nil {
		return composition.APIContractEndpoint{}, nil, err
	}
	for _, entry := range catalog.Endpoints {
		if entry.Service != m.Service || entry.Endpoint != m.Endpoint {
			continue
		}
		contract, err := os.ReadFile(filepath.Join(m.Dir, filepath.FromSlash(entry.Path)))
		if err != nil {
			return entry, nil, err
		}
		sum := sha256.Sum256(contract)
		if got := "sha256:" + hex.EncodeToString(sum[:]); got != entry.Digest {
			return entry, nil, fmt.Errorf("contract %s is %s and the catalog names %s; run codefly generate contracts", entry.Path, got, entry.Digest)
		}
		return entry, contract, nil
	}
	return composition.APIContractEndpoint{}, nil, fmt.Errorf("the catalog records no endpoint %s/%s", m.Service, m.Endpoint)
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
	// The answer has to be able to tell something from nothing: a Shows that
	// accepts the empty answer accepts a refusal rendered as absence. An
	// answer type with no field can show nothing, and is held to success.
	if descriptor.Output().Fields().Len() > 0 && c.Shows(dynamicpb.NewMessage(descriptor.Output())) == nil {
		return "its case's Shows accepts an empty answer, so it could not tell an answer from a refusal rendered as one"
	}
	// The control: the server reads what a call carries. A call with no Work
	// Context is refused; a server that answers it decides nothing on what
	// the next call holds, whatever that call carries.
	bare := dynamicpb.NewMessage(descriptor.Output())
	if err := m.invoke(ctx, method, descriptor, c.Request, bare); status.Code(err) != codes.Unauthenticated && status.Code(err) != codes.PermissionDenied {
		return fmt.Sprintf("a call carrying no Work Context is answered %v, want it refused; the server does not read what a call holds", status.Code(err))
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
