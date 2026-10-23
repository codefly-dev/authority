package hop

import (
	"context"
	"errors"
	"testing"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type authority struct{ asked *authorityv1.IssueRequest }

func (a *authority) Issue(_ context.Context, in *authorityv1.IssueRequest, _ ...grpc.CallOption) (*authorityv1.IssueResponse, error) {
	a.asked = in
	return &authorityv1.IssueResponse{Token: "issued"}, nil
}

func TestACallOutActsForTheCallerOrTheModuleThroughABinding(t *testing.T) {
	a := &authority{}
	o := Outbound{Authority: a, Credential: func() (string, error) { return "workload-credential", nil }}
	md := metadata.Pairs(WorkContextKey, "caller-token")
	Stamp(md, Identity{Owner: "maya", Tenant: "acme"}, "proof")
	in, err := admit(metadata.NewIncomingContext(context.Background(), md), "/m.S/Do", "proof")
	if err != nil {
		t.Fatal(err)
	}
	out, err := o.ForCaller(in, "runtime-admission")
	if err != nil {
		t.Fatal(err)
	}
	if a.asked.GetParentToken() != "caller-token" || a.asked.GetActor().GetCredential() != "workload-credential" || a.asked.GetOperationBindingId() != "runtime-admission" {
		t.Fatalf("for the caller: %v", a.asked)
	}
	if got, _ := metadata.FromOutgoingContext(out); got.Get(WorkContextKey)[0] != "issued" {
		t.Fatalf("the call carries what was issued: %v", got)
	}
	if _, err := o.ForModule(context.Background(), "tracing"); err != nil || a.asked.GetWorkload().GetCredential() != "workload-credential" || a.asked.GetOperationBindingId() != "tracing" {
		t.Fatalf("for the module: %v %v", a.asked, err)
	}
	if _, err := o.ForParent(context.Background(), "parent-token", "model"); err != nil || a.asked.GetParentToken() != "parent-token" || a.asked.GetOperationBindingId() != "model" {
		t.Fatalf("for a parent the module read itself: %v %v", a.asked, err)
	}
	if _, err := o.ForParent(context.Background(), "parent-token", "model", Lookup()); err != nil || a.asked.GetOperation() != "lookup" {
		t.Fatalf("a lookup: %v %v", a.asked, err)
	}
	if _, err := o.ForDelegation(context.Background(), "dlg_1", "documents"); err != nil || a.asked.GetDelegation().GetDelegationId() != "dlg_1" || a.asked.GetActor().GetCredential() != "workload-credential" {
		t.Fatalf("from a delegation: %v %v", a.asked, err)
	}
	if _, err := o.ForParent(context.Background(), "", "model"); !errors.Is(err, ErrNoCaller) {
		t.Fatalf("no parent: %v", err)
	}
	if _, err := o.ForCaller(context.Background(), "runtime-admission"); !errors.Is(err, ErrNoCaller) {
		t.Fatalf("no caller: %v", err)
	}
}
