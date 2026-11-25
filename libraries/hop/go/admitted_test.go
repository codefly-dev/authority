package hop_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	hop "github.com/codefly-dev/authority/libraries/hop/go"
	hopv1 "github.com/codefly-dev/authority/libraries/hop/go/gen/authority/hop/v1"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"github.com/codefly-dev/authority/libraries/hop/go/policy"
	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// What the records module of these tests declares, as its contract would: a
// list requires reading records, a content read requires reading and carries
// reading content, a version requires nothing.
const (
	listRecords = "/records.v1.Records/List"
	readContent = "/records.v1.Records/Content"
	versionOf   = "/records.v1.Records/Version"
	getOverHTTP = "GET /v1/records/{id}"
)

var declared = map[string]policy.Method{
	listRecords: {Requires: []policy.Permission{policy.Of("records.records", "read")}},
	readContent: {Requires: []policy.Permission{policy.Of("records.records", "read")}, Carries: []policy.Permission{policy.Of("records.records", "read_content")}},
	versionOf:   {AnyCheckedCaller: true},
	getOverHTTP: {Requires: []policy.Permission{policy.Of("records.records", "read")}},
}

func declaring(t *testing.T, a *hoptest.Authority, audience string) *hop.Verifier {
	t.Helper()
	v, err := hop.NewVerifier(context.Background(), a.PublishHop(proof), audience, hoptest.Replay(), hop.Declarations(declared))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func scope(kind, owner string, ids []string, actions ...string) *basev1.WorkScopeV1 {
	return &basev1.WorkScopeV1{ResourceKind: kind, Actions: actions, ResourceOwnerId: owner, ResourceIds: ids}
}

// Decision 2: the hop hands the module what admitted the call. A handler reads
// which owners the scopes that hold its method's declaration select, and names
// no permission to do it.
func TestAHandlerReadsTheOwnersThatAdmittedTheCallAndNamesNoPermission(t *testing.T) {
	a := hoptest.New(t)
	token := a.Issue(t, "records",
		scope("records.records", "installation-a", nil, "read"),
		scope("records.records", "installation-b", nil, "read", "write"),
		scope("records.records", "installation-c", nil, "write"), // not what a list declares
		scope("records.types", "", nil, "read"))                  // another kind
	md := hoptest.Forward(t, token, proof, listRecords)
	if len(md.Get(hop.AdmittedKey)) != 1 || md.Get(hop.AdmittedKey)[0] == "" {
		t.Fatalf("the hop stamped no admission: %v", md)
	}
	id, err := declaring(t, a, "records").Verify(context.Background(), md, listRecords)
	if err != nil {
		t.Fatal(err)
	}
	if id.Admitted == nil {
		t.Fatal("the verifier handed the module no admission")
	}
	required := id.Admitted.Required()
	if got := required.Owners(); !slices.Equal(got, []string{"installation-a", "installation-b"}) || required.Whole() {
		t.Fatalf("a list is admitted for owners %v (whole %v), want installation-a and installation-b only", got, required.Whole())
	}
	if !required.Allows("installation-a", "r-1") || required.Allows("installation-c", "r-1") || required.Allows("", "r-1") {
		t.Fatal("the selection must reach an admitted owner's resource and no other's")
	}
}

// The narrower of two scopes: the owner holds the kind, the actor acting for
// them was granted one installation's resources. The hop stamps what the call
// holds after every actor narrowed it, so the module reads the narrower.
func TestACallAdmittedByANarrowerScopeStampsTheNarrowerSelection(t *testing.T) {
	wc := &basev1.WorkContextV1{
		OwnerPrincipalId: "maya", TenantId: "acme", ExpiresAtUnix: time.Now().Add(time.Minute).Unix(),
		AuthorityScopes: []*basev1.WorkScopeV1{scope("records.records", "", nil, "read", "write")},
		ActorChain: []*basev1.WorkActorV1{
			{PrincipalId: "wiki", GrantedScopes: []*basev1.WorkScopeV1{scope("records.records", "installation-a", nil, "read", "write")}},
			{PrincipalId: "reader", GrantedScopes: []*basev1.WorkScopeV1{scope("records.records", "installation-a", []string{"r-2", "r-1"}, "read")}},
		},
	}
	md := metadata.Pairs(hop.WorkContextKey, "the-token")
	if err := hop.Stamp(md, hop.IdentityOf(wc), hoptest.Signer(proof), listRecords, "records", time.Now()); err != nil {
		t.Fatal(err)
	}
	grants, err := hop.GrantsOf(md.Get(hop.AdmittedKey)[0])
	if err != nil {
		t.Fatal(err)
	}
	want := []hop.Grant{{Kind: "records.records", Action: "read", Owner: "installation-a", Resources: []string{"r-1", "r-2"}}}
	if len(grants) != 1 || grants[0].Kind != want[0].Kind || grants[0].Action != want[0].Action || grants[0].Owner != want[0].Owner || !slices.Equal(grants[0].Resources, want[0].Resources) {
		t.Fatalf("the hop stamped %+v, want the last actor's narrower grant %+v", grants, want)
	}
	selection := hop.AdmissionOf(policy.Method{Requires: []policy.Permission{policy.Of("records.records", "read")}}, listRecords, grants).Required()
	if selection.Whole() || len(selection.Owners()) != 0 || !selection.Allows("installation-a", "r-1") || selection.Allows("installation-a", "r-3") || selection.Allows("installation-b", "r-1") {
		t.Fatalf("the narrower selection reads as %+v", selection.Named())
	}
}

// Metadata against content: a method requires the one and carries the other,
// and the handler reads how far the carried one reaches without naming it.
func TestWhatAMethodCarriesIsReadAsItsOwnNarrowerSelection(t *testing.T) {
	a := hoptest.New(t)
	v := declaring(t, a, "records")
	var stamped []hop.Grant
	read := func(scopes ...*basev1.WorkScopeV1) *hop.Admission {
		t.Helper()
		md := hoptest.Forward(t, a.Issue(t, "records", scopes...), proof, readContent)
		var err error
		if stamped, err = hop.GrantsOf(md.Get(hop.AdmittedKey)[0]); err != nil {
			t.Fatal(err)
		}
		id, err := v.Verify(context.Background(), md, readContent)
		if err != nil {
			t.Fatal(err)
		}
		return id.Admitted
	}
	carriedStamped := func() bool {
		return slices.ContainsFunc(stamped, func(g hop.Grant) bool { return g.Action == "read_content" })
	}
	both := read(scope("records.records", "installation-a", nil, "read", "read_content"), scope("records.records", "installation-b", nil, "read"))
	if got := both.Required().Owners(); !slices.Equal(got, []string{"installation-a", "installation-b"}) {
		t.Fatalf("metadata is admitted for %v", got)
	}
	if !carriedStamped() {
		t.Fatalf("a caller holding what the method carries had it left off the stamp: %+v", stamped)
	}
	if got := both.Carried().Owners(); !slices.Equal(got, []string{"installation-a"}) {
		t.Fatalf("content is carried for %v, want installation-a alone", got)
	}
	metadataOnly := read(scope("records.records", "installation-a", nil, "read"))
	if carriedStamped() || !metadataOnly.Carried().Empty() || metadataOnly.Required().Empty() {
		t.Fatal("a call that holds only what the method requires carries nothing")
	}
}

// A caller cannot write the admission: the hop strips what it sent, and a
// value that disagrees with the authenticated Work Context is refused.
func TestAForgedAdmissionIsStrippedByTheHopAndRefusedByTheModule(t *testing.T) {
	a := hoptest.New(t)
	token := a.Issue(t, "records", scope("records.records", "installation-a", nil, "read"))
	forged, err := hop.EncodeGrants([]hop.Grant{{Kind: "records.records", Action: "read"}}) // the whole kind
	if err != nil {
		t.Fatal(err)
	}
	// What a caller sent is replaced by what the hop established.
	genuine := hoptest.Forward(t, token, proof, listRecords)
	md := metadata.Pairs(hop.WorkContextKey, token, hop.AdmittedKey, forged)
	if err := hop.Stamp(md, hop.Identity{Owner: "maya", Expires: time.Now().Add(time.Minute).Unix(), Grants: []hop.Grant{{Kind: "records.records", Action: "read", Owner: "installation-a"}}}, hoptest.Signer(proof), listRecords, "records", time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := md.Get(hop.AdmittedKey); len(got) != 1 || got[0] == forged || got[0] != genuine.Get(hop.AdmittedKey)[0] {
		t.Fatalf("the caller's admission survived the hop: %v", got)
	}
	// Written past the hop, it disagrees with the token and the call is refused.
	v := declaring(t, a, "records")
	tampered := hoptest.Forward(t, token, proof, listRecords)
	tampered.Set(hop.AdmittedKey, forged)
	if _, err := v.Verify(context.Background(), tampered, listRecords); err == nil || !strings.Contains(err.Error(), "stamp_identity") {
		t.Fatalf("a forged admission: %v", err)
	}
	twice := hoptest.Forward(t, token, proof, listRecords)
	twice.Append(hop.AdmittedKey, forged)
	if _, err := v.Verify(context.Background(), twice, listRecords); err == nil || !strings.Contains(err.Error(), "stamp_identity") {
		t.Fatalf("a second admission beside the hop's: %v", err)
	}
	// A hop that stamped none (one older than this contract) admits the call
	// and hands the module no admission: a handler that narrows reaches nothing.
	unstamped := hoptest.Forward(t, token, proof, listRecords)
	delete(unstamped, hop.AdmittedKey)
	id, err := v.Verify(context.Background(), unstamped, listRecords)
	if err != nil {
		t.Fatal(err)
	}
	if id.Admitted != nil {
		t.Fatal("an admission was invented for a call the hop stamped none on")
	}
	if got, ok := hop.Admitted(context.Background()); ok || !got.Required().Empty() {
		t.Fatal("a context no call was admitted on reads as an admission")
	}
}

// A method that declares nothing a call must hold, or that the module does not
// declare at all, selects nothing: reading it never widens.
func TestAMethodThatRequiresNothingOrIsUndeclaredSelectsNothing(t *testing.T) {
	a := hoptest.New(t)
	v := declaring(t, a, "records")
	token := func() string { return a.Issue(t, "records", scope("records.records", "", nil, "read")) }
	id, err := v.Verify(context.Background(), hoptest.Forward(t, token(), proof, versionOf), versionOf)
	if err != nil {
		t.Fatal(err)
	}
	if !id.Admitted.AnyCheckedCaller || !id.Admitted.Required().Empty() {
		t.Fatalf("any_checked_caller reads as %+v", id.Admitted)
	}
	const unknown = "/records.v1.Records/Unknown"
	id, err = v.Verify(context.Background(), hoptest.Forward(t, token(), proof, unknown), unknown)
	if err != nil {
		t.Fatal(err)
	}
	if id.Admitted.Declared || !id.Admitted.Required().Empty() {
		t.Fatalf("an undeclared method reads as %+v", id.Admitted)
	}
	// A whole-kind grant reads as the whole kind where the method requires it,
	// and an HTTP request is read on the route template it is an instance of.
	const request = "GET /v1/records/r-9"
	id, err = v.Verify(context.Background(), hoptest.Forward(t, token(), proof, request), request)
	if err != nil {
		t.Fatal(err)
	}
	if !id.Admitted.Required().Whole() || !id.Admitted.Required().Allows("anyone", "r-9") {
		t.Fatalf("a whole-kind grant on a route reads as %+v", id.Admitted)
	}
}

type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s serverStream) Context() context.Context { return s.ctx }
func (s serverStream) SendMsg(any) error        { return nil }
func (s serverStream) RecvMsg(any) error        { return nil }

// A stream is covered: its handler reads the same admission a unary one does.
func TestAStreamHandlerReadsWhatAdmittedItsStream(t *testing.T) {
	a := hoptest.New(t)
	v := declaring(t, a, "records")
	md := hoptest.Forward(t, a.Issue(t, "records", scope("records.records", "installation-a", nil, "read")), proof, listRecords)
	var owners []string
	err := v.StreamServerInterceptor()(nil, serverStream{ctx: metadata.NewIncomingContext(context.Background(), md)}, &grpc.StreamServerInfo{FullMethod: listRecords},
		func(_ any, stream grpc.ServerStream) error {
			admitted, ok := hop.Admitted(stream.Context())
			if !ok {
				t.Error("the stream's handler was handed no admission")
			}
			owners = admitted.Required().Owners()
			return nil
		})
	if err != nil || !slices.Equal(owners, []string{"installation-a"}) {
		t.Fatalf("a stream read owners %v: %v", owners, err)
	}
	unary := v.UnaryServerInterceptor()
	md = hoptest.Forward(t, a.Issue(t, "records", scope("records.records", "installation-b", nil, "read")), proof, listRecords)
	got, err := unary(metadata.NewIncomingContext(context.Background(), md), nil, &grpc.UnaryServerInfo{FullMethod: listRecords}, func(ctx context.Context, _ any) (any, error) {
		admitted, _ := hop.Admitted(ctx)
		return admitted.Required().Owners(), nil
	})
	if err != nil || !slices.Equal(got.([]string), []string{"installation-b"}) {
		t.Fatalf("a unary call read owners %v: %v", got, err)
	}
}

// With no declarations handed to it, the verifier reads a procedure's
// declaration from the contract the module's binary serves: the descriptors
// its generated code registers, with authority.hop.v1.policy on each rpc.
func TestTheDeclarationIsReadFromTheContractTheBinaryServes(t *testing.T) {
	options := &descriptorpb.MethodOptions{}
	proto.SetExtension(options, hopv1.E_Policy, &hopv1.Policy{
		Requires: []*hopv1.Requirement{{ResourceKind: "notes.notes", Actions: []string{"read"}}},
		Carries:  []*hopv1.Requirement{{ResourceKind: "notes.notes", Actions: []string{"read_content"}}},
	})
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("hoptest/notes/v1/notes.proto"), Package: proto.String("hoptest.notes.v1"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Empty")}},
		Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Notes"), Method: []*descriptorpb.MethodDescriptorProto{
			{Name: proto.String("List"), InputType: proto.String(".hoptest.notes.v1.Empty"), OutputType: proto.String(".hoptest.notes.v1.Empty"), Options: options},
		}}},
	}, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	if err := protoregistry.GlobalFiles.RegisterFile(file); err != nil {
		t.Fatal(err)
	}
	const method = "/hoptest.notes.v1.Notes/List"
	a := hoptest.New(t)
	v, err := hop.NewVerifier(context.Background(), a.PublishHop(proof), "notes", hoptest.Replay())
	if err != nil {
		t.Fatal(err)
	}
	token := a.Issue(t, "notes", scope("notes.notes", "installation-a", nil, "read"), scope("notes.notes", "installation-a", []string{"n-1"}, "read_content"))
	id, err := v.Verify(context.Background(), hoptest.Forward(t, token, proof, method), method)
	if err != nil {
		t.Fatal(err)
	}
	if !id.Admitted.Declared || !slices.Equal(id.Admitted.Required().Owners(), []string{"installation-a"}) {
		t.Fatalf("read from the served contract: %+v", id.Admitted)
	}
	if carried := id.Admitted.Carried(); !carried.Allows("installation-a", "n-1") || carried.Allows("installation-a", "n-2") || len(carried.Owners()) != 0 {
		t.Fatalf("carried, from the served contract: %+v", carried.Named())
	}
}

// Issue 3 of the RBAC review: a stream outlives its Work Context. The module's
// interceptor ends an admitted stream when the context that admitted it
// expires, whatever its handler is doing.
func TestAnAdmittedStreamEndsWhenItsWorkContextExpires(t *testing.T) {
	a := hoptest.New(t)
	v := declaring(t, a, "records")
	token := a.IssueFor(t, "records", 2*time.Second, scope("records.records", "installation-a", nil, "read"))
	md := hoptest.Forward(t, token, proof, listRecords)
	released := make(chan struct{})
	started := time.Now()
	err := v.StreamServerInterceptor()(nil, serverStream{ctx: metadata.NewIncomingContext(context.Background(), md)}, &grpc.StreamServerInfo{FullMethod: listRecords},
		func(_ any, stream grpc.ServerStream) error {
			defer close(released)
			<-stream.Context().Done() // a handler that streams for as long as it is let
			if err := stream.SendMsg(nil); status.Code(err) != codes.Unauthenticated {
				t.Errorf("a send past the expiry: %v", err)
			}
			return stream.Context().Err()
		})
	if status.Code(err) != codes.Unauthenticated || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("the stream ended with %v, want Unauthenticated naming the expiry", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("the stream outlived its two-second Work Context by %v", elapsed)
	}
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler was never told its stream ended")
	}
}
