package issuer_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	base "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
	"github.com/google/uuid"
)

func TestInvalidChildBindingDoesNotSpendSingleUseParent(t *testing.T) {
	for _, binding := range []string{"", "undeclared", "records"} {
		t.Run(binding, func(t *testing.T) {
			k := testkit.New(t)
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now // the replay store expires entries against wall-clock time
			k.Issuer = issuer.New(k.State, testkit.Audience, "one-use", key, now)
			authority := &workcontext.Authority{Issuer: testkit.Audience, KeyID: "one-use", Key: key, Revisions: k.State, Seals: k.State, MaxTTL: time.Minute, Now: now}
			parent, _, err := authority.Start(t.Context(), workcontext.StartInput{
				TenantID: "acme", OrganizationID: "acme", OwnerPrincipalID: "remi", OwnerPrincipalKind: "human",
				TaskID: uuid.NewString(), Audience: "org-directory", AuthorityScopes: []*base.WorkScopeV1{testkit.Scope("directory.entry", "read")},
				InstallationID: state.InstallationID("acme", "org-directory"), ReplayPolicy: workcontext.ReplaySingleUse, TTL: time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = k.Issuer.Issue(t.Context(), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: parent},
				Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "org-directory")}, Audience: "documents", OperationBindingId: binding})
			if err == nil {
				t.Fatal("invalid binding was accepted")
			}
			if _, err := k.Issuer.Check(t.Context(), parent, "org-directory", ""); err != nil {
				t.Fatalf("refused hop spent its parent: %v", err)
			}
			if _, err := k.Issuer.Check(t.Context(), parent, "org-directory", ""); err == nil {
				t.Fatal("fixture is not single use")
			}
		})
	}
}
