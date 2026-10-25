package issuer_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"gateway/pkg/business/issuer"
	"testing"
	"time"

	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	"github.com/codefly-dev/core/workcontext"
)

func TestDelegationRevocationInvalidatesExistingUsesAndPreservesOtherTenants(t *testing.T) {
	k := testkit.New(t)
	declareDelegationChain(t, k)
	ctx := context.Background()
	grantor := person(t, k, "fixture-remi")
	d, err := k.Issuer.Delegate(grantor, "org-directory",
		append(testkit.OrgDirectory(1).Bindings["documents"].InvokeScopes, testkit.Documents(1).Bindings["model"].InvokeScopes...), "bounded work")
	if err != nil {
		t.Fatal(err)
	}
	delegated, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As:       &authorityv1.IssueRequest_Delegation{Delegation: &authorityv1.DelegationRef{DelegationId: d.ID}},
		Actor:    &authorityv1.WorkloadCredential{Credential: k.Credential(t, "org-directory")},
		Audience: "documents", OperationBindingId: "documents",
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := k.Issuer.Issue(person(t, k, "fixture-zoe"), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents",
	})
	if err != nil {
		t.Fatal(err)
	}
	descendant, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As:       &authorityv1.IssueRequest_ParentToken{ParentToken: delegated.GetToken()},
		Actor:    &authorityv1.WorkloadCredential{Credential: k.Credential(t, "documents")},
		Audience: "model", OperationBindingId: "model",
	})
	if err != nil {
		t.Fatal(err)
	}
	uses := map[string]func() error{
		"existing descendant": func() error { _, err := k.Issuer.Check(ctx, descendant.GetToken(), "model", ""); return err },
		"check":               func() error { _, err := k.Issuer.Check(ctx, delegated.GetToken(), "documents", ""); return err },
		"resources": func() error {
			_, err := k.Issuer.ListResources(ctx, delegated.GetToken(), "documents", "documents", "read")
			return err
		},
		"child": func() error {
			_, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
				As:       &authorityv1.IssueRequest_ParentToken{ParentToken: delegated.GetToken()},
				Actor:    &authorityv1.WorkloadCredential{Credential: k.Credential(t, "documents")},
				Audience: "model", OperationBindingId: "model",
			})
			return err
		},
	}
	for name, use := range uses {
		if err := use(); err != nil {
			t.Fatalf("%s before revocation: %v", name, err)
		}
	}
	if _, err := k.Issuer.RevokeDelegation(grantor, d.ID); err != nil {
		t.Fatal(err)
	}
	for name, use := range uses {
		if err := use(); !errors.Is(err, workcontext.ErrRevoked) {
			t.Errorf("%s after revocation: %v", name, err)
		}
	}
	if _, err := k.Issuer.Check(ctx, other.GetToken(), "documents", ""); err != nil {
		t.Fatalf("another tenant lost authority: %v", err)
	}
	fresh, err := k.Issuer.Issue(grantor, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Issuer.RevokeDelegation(grantor, d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Issuer.Check(ctx, fresh.GetToken(), "documents", ""); err != nil {
		t.Fatalf("repeating an already-complete revocation invalidated fresh authority: %v", err)
	}
}

// Exercise revocation at every clock boundary of issuance. The clock remains
// fixed; only the interleaving changes. A refusal or a token rejected by the
// ordinary verifier is safe, but refreshed authority after revocation is not.
func TestRevocationDuringIssuanceCannotRefreshAuthority(t *testing.T) {
	for _, child := range []bool{false, true} {
		name := "delegation"
		if child {
			name = "parent"
		}
		t.Run(name, func(t *testing.T) {
			run := func(t *testing.T, revokeAt int) int {
				k := testkit.New(t)
				declareDelegationChain(t, k)
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				ticks, armed := 0, false
				var delegationID string
				grantor := person(t, k, "fixture-remi")
				k.Issuer = issuer.New(k.State, testkit.Audience, "race-test", key, func() time.Time {
					if armed {
						ticks++
						if ticks == revokeAt {
							if _, err := k.State.RevokeDelegation("remi", delegationID); err != nil {
								t.Fatal(err)
							}
						}
					}
					return k.Now
				})
				d, err := k.Issuer.Delegate(grantor, "org-directory", append(testkit.OrgDirectory(1).Bindings["documents"].InvokeScopes, testkit.Documents(1).Bindings["model"].InvokeScopes...), "race test")
				if err != nil {
					t.Fatal(err)
				}
				delegationID = d.ID
				req := &authorityv1.IssueRequest{
					As:       &authorityv1.IssueRequest_Delegation{Delegation: &authorityv1.DelegationRef{DelegationId: d.ID}},
					Actor:    &authorityv1.WorkloadCredential{Credential: k.Credential(t, "org-directory")},
					Audience: "documents", OperationBindingId: "documents",
				}
				if child {
					parent, err := k.Issuer.Issue(context.Background(), req)
					if err != nil {
						t.Fatal(err)
					}
					req = &authorityv1.IssueRequest{
						As:       &authorityv1.IssueRequest_ParentToken{ParentToken: parent.GetToken()},
						Actor:    &authorityv1.WorkloadCredential{Credential: k.Credential(t, "documents")},
						Audience: "model", OperationBindingId: "model",
					}
				}
				armed = true
				out, issueErr := k.Issuer.Issue(context.Background(), req)
				armed = false
				if revokeAt == 0 {
					if issueErr != nil {
						t.Fatal(issueErr)
					}
				} else {
					if ticks < revokeAt {
						t.Fatalf("revocation point %d not reached (%d)", revokeAt, ticks)
					}
					if issueErr == nil {
						if _, err := k.Issuer.Check(context.Background(), out.GetToken(), req.Audience, ""); !errors.Is(err, workcontext.ErrRevoked) {
							t.Fatalf("issuance refreshed revoked authority at clock boundary %d: %v", revokeAt, err)
						}
					}
				}
				return ticks
			}
			count := run(t, 0)
			for tick := 1; tick <= count; tick++ {
				t.Run(fmt.Sprintf("clock-%d", tick), func(t *testing.T) { run(t, tick) })
			}
		})
	}
}

func TestFailedRevocationDoesNotInvalidateExistingAuthority(t *testing.T) {
	k := testkit.New(t)
	grantor := person(t, k, "fixture-remi")
	d, err := k.Issuer.Delegate(grantor, "org-directory", testkit.OrgDirectory(1).Bindings["documents"].InvokeScopes, "failure isolation")
	if err != nil {
		t.Fatal(err)
	}
	before, err := k.State.AuthorizationRevision(context.Background(), d.Organization)
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []struct{ person, id string }{{"maya", d.ID}, {"remi", "unknown-delegation"}} {
		if _, err := k.State.RevokeDelegation(attempt.person, attempt.id); err == nil {
			t.Fatal("invalid revocation succeeded")
		}
		after, err := k.State.AuthorizationRevision(context.Background(), d.Organization)
		if err != nil || after != before {
			t.Fatalf("failed revocation changed revision: %d -> %d (%v)", before, after, err)
		}
	}
}
