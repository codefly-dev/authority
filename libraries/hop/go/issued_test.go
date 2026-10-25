package hop

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// answering is an authority that answers every issue with one response.
type answering struct {
	asked  *authorityv1.IssueRequest
	answer *authorityv1.IssueResponse
	err    error
}

func (a *answering) Issue(_ context.Context, in *authorityv1.IssueRequest, _ ...grpc.CallOption) (*authorityv1.IssueResponse, error) {
	a.asked = proto.Clone(in).(*authorityv1.IssueRequest)
	return a.answer, a.err
}

// An issue a caller holds across calls comes back as the authority gave it:
// the token, when it expires, and whom it is for; the asked scopes reach the
// authority as asked; and carrying it is what the For* methods do.
func TestAnIssueReturnedIsTheAuthoritysAnswer(t *testing.T) {
	expires := time.Now().Add(5 * time.Minute).Truncate(time.Second)
	a := &answering{answer: &authorityv1.IssueResponse{Token: "child", ExpiresAtUnix: expires.Unix(),
		Context: &authorityv1.WorkContextV1{TenantId: "acme", OwnerPrincipalId: "maya"}}}
	o := Outbound{Authority: a, Credential: func() (string, error) { return "workload-credential", nil }}
	read := &authorityv1.WorkScopeV1{ResourceKind: "documents", Actions: []string{"read"}, ResourceIds: []string{"doc-1"}}

	issued, err := o.IssueForParent(context.Background(), "parent-token", "documents", Scopes(read))
	if err != nil {
		t.Fatal(err)
	}
	if issued.Token != "child" || !issued.ExpiresAt.Equal(expires) || issued.Context.GetOwnerPrincipalId() != "maya" || issued.Context.GetTenantId() != "acme" {
		t.Fatalf("issued %+v", issued)
	}
	if a.asked.GetParentToken() != "parent-token" || a.asked.GetActor().GetCredential() != "workload-credential" || a.asked.GetOperationBindingId() != "documents" ||
		len(a.asked.GetScopes()) != 1 || !proto.Equal(a.asked.GetScopes()[0], read) {
		t.Fatalf("asked %v", a.asked)
	}

	if _, err := o.IssueForModule(context.Background(), "acme", "tracing"); err != nil || a.asked.GetWorkload().GetCredential() != "workload-credential" ||
		a.asked.GetOrganizationId() != "acme" || a.asked.GetOperationBindingId() != "tracing" || len(a.asked.GetScopes()) != 0 {
		t.Fatalf("for the module: %v %v", a.asked, err)
	}

	out := issued.Carry(metadata.NewOutgoingContext(context.Background(), metadata.Pairs("request-id", "kept")))
	md, _ := metadata.FromOutgoingContext(out)
	if got := md.Get(WorkContextKey); len(got) != 1 || got[0] != "child" || md.Get("request-id")[0] != "kept" {
		t.Fatalf("carried %v", md)
	}

	if _, err := o.IssueForParent(context.Background(), "", "documents"); !errors.Is(err, ErrNoCaller) {
		t.Fatalf("no parent: %v", err)
	}
}

// The authority's refusal keeps its status and reason for the caller to answer
// with, and names the binding.
func TestARefusedIssueKeepsTheAuthoritysStatus(t *testing.T) {
	a := &answering{err: status.Error(codes.PermissionDenied, "maya holds nothing through that binding")}
	o := Outbound{Authority: a, Credential: func() (string, error) { return "workload-credential", nil }}
	_, err := o.IssueForParent(context.Background(), "parent-token", "documents")
	var carrier interface{ GRPCStatus() *status.Status }
	if !errors.As(err, &carrier) || carrier.GRPCStatus().Code() != codes.PermissionDenied || carrier.GRPCStatus().Message() != "maya holds nothing through that binding" {
		t.Fatalf("the refusal lost its status: %v", err)
	}
	if want := `binding "documents"`; !strings.Contains(err.Error(), want) {
		t.Fatalf("the refusal does not name the binding: %v", err)
	}
}

// A credential read from a path is read again on every call, so a rotated
// projection takes effect, and an absent or empty one is refused by name.
func TestAFileCredentialIsReadOnEveryCall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	credential := FileCredential(path)
	if _, err := credential(); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("an absent credential: %v", err)
	}
	for _, value := range []string{"first\n", "rotated"} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := credential(); err != nil || got != strings.TrimSpace(value) {
			t.Fatalf("read %q, %v; want %q", got, err, strings.TrimSpace(value))
		}
	}
	if err := os.WriteFile(path, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := credential(); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("an empty credential: %v", err)
	}
}
