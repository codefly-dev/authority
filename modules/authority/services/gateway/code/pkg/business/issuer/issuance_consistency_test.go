package issuer_test

import (
	"context"
	"crypto/rand"
	"testing"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/google/uuid"
)

// UUID creation is an existing injection point around Core's live version reads.
// These tests are deliberately serial: uuid's reader is process-wide.
type issuanceChangeReader struct {
	remaining int
	apply     func()
}

func (r *issuanceChangeReader) Read(p []byte) (int, error) {
	r.remaining--
	if r.remaining == 0 {
		r.apply()
	}
	return rand.Read(p)
}

func interleaveIssuance(t *testing.T, stage string, apply func(), issue func() (*authorityv1.IssueResponse, error)) (*authorityv1.IssueResponse, error) {
	t.Helper()
	applied := false
	change := func() { apply(); applied = true }
	switch stage {
	case "before_resolution":
		change()
	case "before_mint", "during_mint":
		n := 1
		if stage == "during_mint" {
			n = 2
		}
		uuid.SetRand(&issuanceChangeReader{remaining: n, apply: change})
		defer uuid.SetRand(nil)
	}
	out, err := issue()
	uuid.SetRand(nil)
	if stage == "after_issue" {
		if err != nil {
			t.Fatalf("ordinary issuance: %v", err)
		}
		change()
	}
	if !applied {
		t.Fatal("interleaving not reached")
	}
	return out, err
}

func TestRoleNarrowingBetweenResolutionAndMint(t *testing.T) {
	for _, owner := range []string{"installation", "installation_removed", "person", "delegation", "child"} {
		for _, stage := range []string{"before_resolution", "before_mint", "during_mint", "after_issue"} {
			t.Run(owner+"/"+stage, func(t *testing.T) {
				k := testkit.New(t)
				ctx := context.Background()
				old := installationManifest("conformance-solution", "task_operator", 1, "read", "write")
				if _, err := k.State.ApplyManifest(old); err != nil {
					t.Fatal(err)
				}
				inst, err := k.State.Install(ctx, "acme", old.Module, "task_operator", "alex")
				if err != nil {
					t.Fatal(err)
				}
				req := &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Installation{Installation: &authorityv1.InstallationRef{InstallationId: inst.ID}}, Audience: old.Principal, Scopes: scopes(testkit.Scope(old.Module+".item", "write"))}
				next := installationManifest(old.Module, "task_operator", 2, "read")
				if owner == "person" {
					ctx = person(t, k, "fixture-alex")
					req.As = &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}
				}
				if owner == "person" || owner == "delegation" {
					next.Roles[state.InstallerRole] = []*basev0.WorkScopeV1{testkit.Scope(old.Module+".item", "read")}
				}
				if owner == "installation_removed" {
					delete(next.Roles, "task_operator")
				}
				if owner == "delegation" {
					ctx = person(t, k, "fixture-alex")
					d, err := k.Issuer.Delegate(ctx, old.Module, []*basev0.WorkScopeV1{testkit.Scope(old.Module+".item", "write")}, "consistency regression")
					if err != nil {
						t.Fatal(err)
					}
					req.As = &authorityv1.IssueRequest_Delegation{Delegation: &authorityv1.DelegationRef{DelegationId: d.ID}}
					req.Actor = &authorityv1.WorkloadCredential{Credential: k.Credential(t, old.Module)}
					req.OperationBindingId = "self"
				}
				if owner == "child" {
					parent, err := k.Issuer.Issue(ctx, req)
					if err != nil {
						t.Fatal(err)
					}
					req.As = &authorityv1.IssueRequest_ParentToken{ParentToken: parent.Token}
					req.Actor = &authorityv1.WorkloadCredential{Credential: k.Credential(t, old.Module)}
					req.OperationBindingId = "self"
				}
				// Prove this owner can issue the exact requested scope before scheduling a change.
				before, err := k.Issuer.Issue(ctx, req)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := k.Issuer.Check(ctx, before.Token, old.Principal, ""); err != nil {
					t.Fatal(err)
				}
				out, err := interleaveIssuance(t, stage, func() {
					if _, err := k.State.ApplyManifest(next); err != nil {
						t.Fatal(err)
					}
				}, func() (*authorityv1.IssueResponse, error) { return k.Issuer.Issue(ctx, req) })
				if err != nil {
					t.Logf("safely refused: %v", err)
					return
				}
				if _, err := k.Issuer.Check(ctx, out.Token, old.Principal, ""); err != nil {
					t.Logf("safely rejected: %v", err)
					return
				}
				t.Fatalf("stale write accepted: signed revision=%d installation revision=%d", out.Context.GetAuthorizationRevision(), out.Context.GetSeal().GetInstallationRevision())
			})
		}
	}
}

func TestBindingNarrowingBetweenResolutionAndMint(t *testing.T) {
	for _, owner := range []string{"workload", "delegation", "child", "person"} {
		for _, changeName := range []string{"narrow", "remove", "retarget", "resource"} {
			for _, stage := range []string{"before_resolution", "before_mint", "during_mint", "after_issue"} {
				t.Run(owner+"/"+changeName+"/"+stage, func(t *testing.T) {
					k := testkit.New(t)
					ctx := context.Background()
					credential := k.Credential(t, "documents")
					req := &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Workload{Workload: &authorityv1.WorkloadCredential{Credential: credential}}, OrganizationId: "acme", Audience: "model", OperationBindingId: "model", Scopes: scopes(testkit.Scope("modelservice.profiles", "invoke"))}
					if owner == "person" {
						ctx = person(t, k, "fixture-dev")
						req.As = &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}
						req.Audience = "documents"
					}
					if owner == "delegation" {
						ctx = person(t, k, "fixture-dev")
						d, err := k.Issuer.Delegate(ctx, "documents", []*basev0.WorkScopeV1{testkit.Scope("modelservice.profiles", "invoke")}, "binding consistency regression")
						if err != nil {
							t.Fatal(err)
						}
						req.As = &authorityv1.IssueRequest_Delegation{Delegation: &authorityv1.DelegationRef{DelegationId: d.ID}}
						req.Actor = &authorityv1.WorkloadCredential{Credential: credential}
					}
					if owner == "child" {
						ctx = person(t, k, "fixture-dev")
						parent, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents", Scopes: scopes(testkit.Scope("documents", "read"))})
						if err != nil {
							t.Fatal(err)
						}
						req.As = &authorityv1.IssueRequest_ParentToken{ParentToken: parent.Token}
						req.Actor = &authorityv1.WorkloadCredential{Credential: credential}
					}
					before, err := k.Issuer.Issue(ctx, req)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := k.Issuer.Check(ctx, before.Token, req.Audience, ""); err != nil {
						t.Fatal(err)
					}
					next := testkit.Documents(2)
					binding := next.Bindings["model"]
					switch changeName {
					case "narrow":
						binding.HeadlessScopes = []*basev0.WorkScopeV1{testkit.Scope("modelservice.profiles", "read")}
						binding.InvokeScopes = binding.HeadlessScopes
					case "retarget":
						binding.Audience = "runtime"
					case "resource":
						scoped := testkit.Scope("modelservice.profiles", "invoke", "read")
						scoped.ResourceIds = []string{"profile-one"}
						binding.HeadlessScopes = []*basev0.WorkScopeV1{scoped}
						binding.InvokeScopes = binding.HeadlessScopes
					}
					next.Bindings["model"] = binding
					if changeName == "remove" {
						delete(next.Bindings, "model")
					}
					out, err := interleaveIssuance(t, stage, func() {
						if _, err := k.State.ApplyManifest(next); err != nil {
							t.Fatal(err)
						}
					}, func() (*authorityv1.IssueResponse, error) { return k.Issuer.Issue(ctx, req) })
					if err != nil {
						t.Logf("safely refused: %v", err)
						return
					}
					if _, err := k.Issuer.Check(ctx, out.Token, req.Audience, ""); err != nil {
						t.Logf("safely rejected: %v", err)
						return
					}
					t.Fatal("old invoke accepted after binding narrowing/removal")
				})
			}
		}
	}
}

func TestPersonBindingReadRemainsUsableAfterNarrowingAndExpansion(t *testing.T) {
	k := testkit.New(t)
	ctx := person(t, k, "fixture-dev")
	req := &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents", OperationBindingId: "model", Scopes: scopes(testkit.Scope("modelservice.profiles", "read"))}
	next := testkit.Documents(2)
	binding := next.Bindings["model"]
	binding.InvokeScopes = []*basev0.WorkScopeV1{testkit.Scope("modelservice.profiles", "read")}
	binding.HeadlessScopes = binding.InvokeScopes
	next.Bindings["model"] = binding
	if _, err := k.State.ApplyManifest(next); err != nil {
		t.Fatal(err)
	}
	read, err := k.Issuer.Issue(ctx, req)
	if err != nil {
		t.Fatalf("fresh read after narrowing: %v", err)
	}
	if _, err := k.Issuer.Check(ctx, read.Token, req.Audience, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := k.State.ApplyManifest(testkit.Documents(3)); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Issuer.Check(ctx, read.Token, req.Audience, ""); err != nil {
		t.Fatalf("unchanged person read revoked by expansion: %v", err)
	}
	req.Scopes = scopes(testkit.Scope("modelservice.profiles", "invoke"))
	invoke, err := k.Issuer.Issue(ctx, req)
	if err != nil {
		t.Fatalf("fresh invoke after expansion: %v", err)
	}
	if _, err := k.Issuer.Check(ctx, invoke.Token, req.Audience, ""); err != nil {
		t.Fatal(err)
	}
}

// Issue reads its audience before sessionOf calls Value; capture a delivery
// there to exercise the early audience snapshot independently of mint UUIDs.
type deliveryOnSession struct {
	context.Context
	apply func()
}

func (c *deliveryOnSession) Value(key any) any {
	value := c.Context.Value(key)
	if value != nil && c.apply != nil {
		apply := c.apply
		c.apply = nil
		apply()
	}
	return value
}
func TestBindingChangeBeforePersonRevisionSnapshot(t *testing.T) {
	k := testkit.New(t)
	ctx := person(t, k, "fixture-dev")
	req := &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents", OperationBindingId: "model", Scopes: scopes(testkit.Scope("modelservice.profiles", "invoke"))}
	original, err := k.Issuer.Issue(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Issuer.Check(ctx, original.Token, "documents", ""); err != nil {
		t.Fatal(err)
	}
	next := testkit.Documents(2)
	b := next.Bindings["model"]
	b.InvokeScopes = []*basev0.WorkScopeV1{testkit.Scope("modelservice.profiles", "read")}
	b.HeadlessScopes = b.InvokeScopes
	next.Bindings["model"] = b
	interleaved := &deliveryOnSession{Context: ctx, apply: func() {
		if _, err := k.State.ApplyManifest(next); err != nil {
			t.Fatal(err)
		}
	}}
	out, err := k.Issuer.Issue(interleaved, req)
	if interleaved.apply != nil {
		t.Fatal("early interleaving not reached")
	}
	if err != nil {
		t.Logf("refused stale audience: %v", err)
		return
	}
	if _, err := k.Issuer.Check(ctx, out.Token, "documents", ""); err != nil {
		t.Logf("rejected stale audience: %v", err)
		return
	}
	t.Fatalf("stale early audience accepted with authorization revision %d", out.Context.GetAuthorizationRevision())
}
