package issuer_test

import (
	"context"
	"errors"
	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	"google.golang.org/protobuf/proto"
	"testing"
)

// Rows 5 and 15: the binding contributes the person's solution-role scope;
// the module remains the actor and never becomes the owner.
func TestModuleToolBindingUsesThePersonsSolutionEntitlement(t *testing.T) {
	for _, bindRoot := range []bool{false, true} {
		for _, who := range []string{"maya", "remi"} {
			t.Run(who+map[bool]string{false: "/child", true: "/binding-root"}[bindRoot], func(t *testing.T) {
				k := testkit.New(t)
				testkit.SolutionTools(t, k)
				request := &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "robin"}
				if bindRoot {
					request.OperationBindingId = "tools"
				}
				root, err := k.Issuer.Issue(person(t, k, "fixture-"+who), request)
				if bindRoot && who == "remi" {
					if !errors.Is(err, issuer.ErrRefused) {
						t.Fatalf("person without target entitlement obtained binding scopes: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				read := scopes(testkit.Scope("proposals.item", "read"))
				if bindRoot {
					found := false
					for _, sc := range root.Context.AuthorityScopes {
						if proto.Equal(sc, read[0]) {
							found = true
						}
					}
					if !found {
						t.Fatalf("person binding omitted its scopes: %v", root.Context.AuthorityScopes)
					}
				}
				child, err := k.Issuer.Issue(context.Background(), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: root.Token}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "robin")}, OperationBindingId: "tools", Audience: "proposals", Scopes: read})
				if who == "remi" {
					if !errors.Is(err, issuer.ErrRefused) {
						t.Fatalf("unentitled child: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				wc := child.Context
				if wc.OwnerPrincipalId != who || wc.GetOwnerPrincipalKind() != "human" || len(wc.ActorChain) != 1 || wc.ActorChain[0].PrincipalId != "robin" {
					t.Fatalf("owner/actor changed: %v", wc)
				}
				if _, err := k.Issuer.Check(context.Background(), child.Token, "proposals", "/tools.Solution/Read"); err != nil {
					t.Fatalf("real method check: %v", err)
				}
			})
		}
	}
}

// Row 12: knowing an installation ID, or holding a person's session, is not
// proof of being the installed solution's workload.
func TestInstallationIssueRequiresTheSolutionsWorkload(t *testing.T) {
	k := testkit.New(t)
	testkit.SolutionTools(t, k)
	for _, tc := range []struct {
		name, credential string
		session, allowed bool
	}{
		{name: "missing"}, {name: "forged", credential: "not-a-credential"},
		{name: "other module", credential: k.Credential(t, "robin")},
		{name: "other solution", credential: k.Credential(t, "proposals")},
		{name: "signed-in installer", session: true},
		{name: "own solution", credential: k.Credential(t, "wiki"), allowed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.session {
				ctx = person(t, k, "fixture-alex")
			}
			out, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Installation{Installation: &authorityv1.InstallationRef{InstallationId: state.InstallationID("acme", "wiki")}}, Actor: &authorityv1.WorkloadCredential{Credential: tc.credential}, Audience: "wiki"})
			if !tc.allowed {
				if err == nil {
					t.Fatal("installation issuance accepted an unauthenticated or unrelated caller")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if out.Context.OwnerPrincipalId != state.InstallationID("acme", "wiki")+"/agent" {
				t.Fatalf("wrong installation owner: %v", out.Context)
			}
			if _, err := k.Issuer.Check(ctx, out.Token, "wiki", ""); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUnentitledPersonCannotHopToSolutionWithAnEmptyAsk(t *testing.T) {
	k := testkit.New(t)
	testkit.SolutionTools(t, k)
	root, err := k.Issuer.Issue(person(t, k, "fixture-remi"), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "robin"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = k.Issuer.Issue(context.Background(), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: root.Token}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "robin")}, OperationBindingId: "tools", Audience: "proposals"})
	if !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("unentitled empty-ask child issued: %v", err)
	}
}

func TestInstallationWorkloadDeliveryCannotChangeDuringIssuance(t *testing.T) {
	for _, stage := range []string{"before_mint", "during_mint"} {
		t.Run(stage, func(t *testing.T) {
			k := testkit.New(t)
			m := installationManifest("conformance-solution", "viewer", 1, "read")
			if _, err := k.State.ApplyManifest(m); err != nil {
				t.Fatal(err)
			}
			inst, err := k.State.Install(context.Background(), "acme", m.Module, "viewer", "alex")
			if err != nil {
				t.Fatal(err)
			}
			req := &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Installation{Installation: &authorityv1.InstallationRef{InstallationId: inst.ID}}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, m.Module)}, Audience: m.Principal}
			_, err = interleaveIssuance(t, stage, func() {
				m.Generation++
				if _, err := k.State.ApplyManifest(m); err != nil {
					t.Fatal(err)
				}
			}, func() (*authorityv1.IssueResponse, error) { return k.Issuer.Issue(context.Background(), req) })
			if !errors.Is(err, issuer.ErrRefused) {
				t.Fatalf("installation minted across its authenticated workload generation: %v", err)
			}
		})
	}
}
