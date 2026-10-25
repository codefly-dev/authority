package hop

import (
	"context"
	"errors"
	"strings"
	"testing"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type authority struct {
	asked *authorityv1.IssueRequest
	err   error
}

func (a *authority) Issue(_ context.Context, in *authorityv1.IssueRequest, _ ...grpc.CallOption) (*authorityv1.IssueResponse, error) {
	a.asked = in
	if a.err != nil {
		return nil, a.err
	}
	return &authorityv1.IssueResponse{Token: "issued"}, nil
}

func TestACallOutActsForTheCallerOrTheModuleThroughABinding(t *testing.T) {
	a := &authority{}
	o := Outbound{Authority: a, Credential: func() (string, error) { return "workload-credential", nil }}
	// The identity the module's Verifier authenticated (hop_test.go proves that path).
	in := context.WithValue(context.Background(), identityKey{}, Identity{Owner: "maya", Tenant: "acme", Context: "caller-token"})
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
	if _, err := o.ForModule(context.Background(), "acme", "tracing"); err != nil || a.asked.GetWorkload().GetCredential() != "workload-credential" || a.asked.GetOperationBindingId() != "tracing" || a.asked.GetOrganizationId() != "acme" {
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

func TestForModuleLeavesAnEmptyOrganizationToTheAuthority(t *testing.T) {
	for _, reason := range []string{"", "ambiguous active installations; a workload must name one organization", "no active installation; a workload must name one organization"} {
		name := reason
		if name == "" {
			name = "installed tenant resolved"
		}
		t.Run(name, func(t *testing.T) {
			a := &authority{}
			if reason != "" {
				a.err = errors.New(reason)
			}
			o := Outbound{Authority: a, Credential: func() (string, error) { return "workload-credential", nil }}
			ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("request-id", "preserved"))
			out, err := o.ForModule(ctx, "", "tracing", Lookup())
			if a.asked == nil {
				t.Fatalf("empty organization did not reach the authority: %v", err)
			}
			if a.asked.GetOrganizationId() != "" || a.asked.GetWorkload().GetCredential() != "workload-credential" || a.asked.GetOperationBindingId() != "tracing" || a.asked.GetOperation() != "lookup" {
				t.Fatal("workload request lost its empty organization, credential, binding or option")
			}
			if a.err != nil {
				if out != nil || !errors.Is(err, a.err) || !strings.Contains(err.Error(), "tracing") {
					t.Fatalf("authority refusal lost its reason or binding: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			md, _ := metadata.FromOutgoingContext(out)
			if got := md.Get(WorkContextKey); len(got) != 1 || got[0] != "issued" {
				t.Fatal("outbound context does not carry the authority's issued token")
			}
			if got := md.Get("request-id"); len(got) != 1 || got[0] != "preserved" {
				t.Fatal("outbound metadata was lost")
			}
		})
	}
}
