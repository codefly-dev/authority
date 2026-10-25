package issuer_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

func installationChainParent(t *testing.T, k *testkit.Kit) *authorityv1.IssueResponse {
	t.Helper()
	ctx := context.Background()
	credential := &authorityv1.WorkloadCredential{Credential: k.Credential(t, "wiki")}
	root, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As:    &authorityv1.IssueRequest_Installation{Installation: &authorityv1.InstallationRef{InstallationId: state.InstallationID("acme", "wiki")}},
		Actor: credential, Audience: "wiki",
	})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_ParentToken{ParentToken: root.Token}, Actor: credential,
		Audience: "org-directory", OperationBindingId: "directory",
	})
	if err != nil {
		t.Fatal(err)
	}
	return parent
}

func installationChainRequest(t *testing.T, k *testkit.Kit, parent *authorityv1.IssueResponse) *authorityv1.IssueRequest {
	t.Helper()
	return &authorityv1.IssueRequest{
		As:       &authorityv1.IssueRequest_ParentToken{ParentToken: parent.Token},
		Actor:    &authorityv1.WorkloadCredential{Credential: k.Credential(t, "org-directory")},
		Audience: "documents", OperationBindingId: "documents",
	}
}

func TestInstallationChainRetainsOwnerRoleResourcesAndProvenance(t *testing.T) {
	held := testkit.Scope("documents", "read")
	held.ResourceIds = []string{"one"}
	k, _ := solutionRoleKit(t, held)
	parent := installationChainParent(t, k)
	req := installationChainRequest(t, k, parent)
	ctx := context.Background()
	out, err := k.Issuer.Issue(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	wc, before := out.Context, parent.Context
	if wc.OwnerPrincipalId != state.InstallationID("acme", "wiki")+"/agent" ||
		wc.GetOwnerPrincipalKind() != "agent" || wc.GetOwnerAgentId() != "wiki" ||
		wc.TenantId != before.TenantId || wc.TaskId != before.TaskId ||
		wc.GetParentSessionId() != before.SessionId || wc.ExpiresAtUnix > before.ExpiresAtUnix ||
		len(wc.ActorChain) != 2 || wc.ActorChain[0].PrincipalId != "wiki" || wc.ActorChain[1].PrincipalId != "org-directory" ||
		wc.Seal.InstallationId != state.InstallationID("acme", "org-directory") ||
		wc.OperationBinding.BindingId != "acme/org-directory/documents" {
		t.Fatalf("installation provenance changed: %v", wc)
	}
	if len(wc.AuthorityScopes) != 1 || actions(wc, "documents") != "read" ||
		len(wc.AuthorityScopes[0].ResourceIds) != 1 || wc.AuthorityScopes[0].ResourceIds[0] != "one" {
		t.Fatalf("role projection changed: %v", wc.AuthorityScopes)
	}
	if _, err := k.Issuer.Check(ctx, out.Token, "documents", ""); err != nil {
		t.Fatal(err)
	}
	grants, err := k.Issuer.ListResources(ctx, out.Token, "documents", "documents", "read")
	if err != nil || !covered(t, grants).Matches("one") || covered(t, grants).Matches("two") || covered(t, grants).All() {
		t.Fatalf("resource ceiling lost: %v %v", grants, err)
	}
	for _, ask := range []*authorityv1.WorkScopeV1{
		{ResourceKind: "documents", Actions: []string{"write"}, ResourceIds: []string{"one"}},
		{ResourceKind: "documents", Actions: []string{"read"}},
		{ResourceKind: "documents", Actions: []string{"read"}, ResourceIds: []string{"two"}},
	} {
		req.Scopes = []*authorityv1.WorkScopeV1{ask}
		if _, err := k.Issuer.Issue(ctx, req); err == nil {
			t.Fatalf("role restriction widened: %v", ask)
		}
	}
	req.Scopes = nil
	req.Actor.Credential = k.Credential(t, "documents")
	if _, err := k.Issuer.Issue(ctx, req); err == nil {
		t.Fatal("wrong actor accepted")
	}
}

func TestInstallationChainRevocation(t *testing.T) {
	for _, change := range []string{"source uninstall", "actor uninstall", "role narrowing", "binding narrowing"} {
		t.Run(change, func(t *testing.T) {
			k, solution := solutionRoleKit(t, testkit.Scope("documents", "read"))
			parent := installationChainParent(t, k)
			req := installationChainRequest(t, k, parent)
			ctx := context.Background()
			out, err := k.Issuer.Issue(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "source uninstall":
				err = k.State.Revoke(state.InstallationID("acme", "wiki"))
			case "actor uninstall":
				err = k.State.Revoke(state.InstallationID("acme", "org-directory"))
			case "role narrowing":
				solution.Generation++
				solution.Roles["viewer"] = append(testkit.Wiki(1).Roles["viewer"], testkit.Scope("directory.entry", "read"))
				_, err = k.State.ApplyManifest(solution)
			case "binding narrowing":
				module := testkit.OrgDirectory(2)
				delete(module.Bindings, "documents")
				_, err = k.State.ApplyManifest(module)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := k.Issuer.Check(ctx, out.Token, "documents", ""); err == nil {
				t.Fatal("old child survived revocation")
			}
			if _, err := k.Issuer.Issue(ctx, req); err == nil {
				t.Fatal("parent refreshed revoked authority")
			}
			if change == "role narrowing" || change == "binding narrowing" {
				fresh := installationChainRequest(t, k, installationChainParent(t, k))
				if _, err := k.Issuer.Issue(ctx, fresh); err == nil {
					t.Fatal("fresh chain recovered removed authority")
				}
			}
		})
	}
}

func TestInstallationUninstallDuringSecondHopCannotRefreshAuthority(t *testing.T) {
	run := func(t *testing.T, revokeAt int) int {
		k, _ := solutionRoleKit(t, testkit.Scope("documents", "read"))
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ticks, armed := 0, false
		k.Issuer = issuer.New(k.State, testkit.Audience, "installation-race", key, func() time.Time {
			if armed {
				ticks++
				if ticks == revokeAt {
					if err := k.State.Revoke(state.InstallationID("acme", "wiki")); err != nil {
						t.Fatal(err)
					}
				}
			}
			return k.Now
		})
		req := installationChainRequest(t, k, installationChainParent(t, k))
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
				if _, err := k.Issuer.Check(context.Background(), out.Token, "documents", ""); err == nil {
					t.Fatalf("issuance refreshed revoked installation at clock %d", revokeAt)
				}
			}
		}
		return ticks
	}
	count := run(t, 0)
	for tick := 1; tick <= count; tick++ {
		t.Run(fmt.Sprintf("clock-%d", tick), func(t *testing.T) { run(t, tick) })
	}
}
