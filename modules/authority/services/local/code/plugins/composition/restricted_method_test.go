package composition

import (
	"context"
	"strings"
	"testing"

	authorityv1 "gateway/pkg/gen/host/authority/v1"
	compositionv1 "gateway/pkg/gen/host/composition/v1"
	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSignedMethodRequirementRejectsResourceIDsBeforeAdmission(t *testing.T) {
	p, k := verifying(t)
	required := scope("conformance.page", "read")
	required.ResourceIds = []string{"one"}
	doc := &compositionv1.AuthorityManifestV1{Methods: []*compositionv1.MethodPolicyV1{{Method: "/probe.Service/Read", Requires: []*authorityv1.WorkScopeV1{required}}}}
	ctx := context.Background()
	_, err := p.ApplyManifest(ctx, carrier(t, k, "conformance-probe", solutionhost.KindModule, 2, []string{"conformance.page"}, doc))
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "resource ids") {
		t.Fatalf("a method policy's unsupported restriction was silently accepted: %v", err)
	}
	if m, ok := k.State.Module("conformance-probe"); ok && m.Generation == 2 {
		t.Fatal("refused generation became current")
	}
	// Failed validation consumes no generation. A corrected signed delivery
	// applies at the same generation without removing the method requirement.
	required.ResourceIds = nil
	response, err := p.ApplyManifest(ctx, carrier(t, k, "conformance-probe", solutionhost.KindModule, 2, []string{"conformance.page"}, doc))
	if err != nil || response.GetGeneration() != 2 {
		t.Fatalf("corrected policy: %v %v", response, err)
	}
}
