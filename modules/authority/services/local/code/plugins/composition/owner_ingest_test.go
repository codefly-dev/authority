package composition

import (
	"context"
	"strings"
	"testing"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authorityv1 "gateway/pkg/gen/host/authority/v1"
	compositionv1 "gateway/pkg/gen/host/composition/v1"
)

// A delivery naming a resource owner in a scope ceiling, a binding, a role or
// a method requirement is refused by name, never stored as the whole kind
// (r132 m3).
func TestADeliveryNamingAnOwnerIsRefused(t *testing.T) {
	owned := func(kind string, actions ...string) *authorityv1.WorkScopeV1 {
		return &authorityv1.WorkScopeV1{ResourceKind: kind, Actions: actions, ResourceOwnerId: "principal-u"}
	}
	for name, doc := range map[string]*compositionv1.AuthorityManifestV1{
		"a scope ceiling":      {ScopeCeilings: []*authorityv1.WorkScopeV1{owned("conformance.page", "read")}},
		"a method requirement": {Methods: []*compositionv1.MethodPolicyV1{{Method: "/probe.Service/Read", Requires: []*authorityv1.WorkScopeV1{owned("conformance.page", "read")}}}},
	} {
		t.Run(name, func(t *testing.T) {
			p, k := verifying(t)
			_, err := p.ApplyManifest(context.Background(), carrier(t, k, "conformance-probe", solutionhost.KindModule, 2, []string{"conformance.page"}, doc))
			if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "owner") {
				t.Fatalf("an owner-selected declaration was accepted: %v", err)
			}
		})
	}
	t.Run("a binding", func(t *testing.T) {
		_, k := verifying(t)
		m := state.Manifest{Name: "owned-binding", Principal: "owned-binding", Kind: "module", Generation: 1,
			Bindings: map[string]state.Binding{"store": {ID: "store", Audience: "documents", InvokeScopes: issuer.FromWire([]*authorityv1.WorkScopeV1{owned("documents", "read")})}}}
		if _, err := k.State.ApplyManifest(m); err == nil || !strings.Contains(err.Error(), "owner") {
			t.Fatalf("an owner-selected binding was accepted: %v", err)
		}
	})
}
