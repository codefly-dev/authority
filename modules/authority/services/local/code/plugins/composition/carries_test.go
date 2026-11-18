package composition

import (
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/delivered"
	"github.com/codefly-dev/authority/libraries/solutionhost/go"

	authorityv1 "gateway/pkg/gen/host/authority/v1"
	compositionv1 "gateway/pkg/gen/host/composition/v1"
)

// This host reads what a delivered method carries off the wire, so the core
// holds it to the module's ceilings: a host that dropped the field would
// accept a method carrying what no capability at the module can hold.
func TestWhatADeliveredMethodCarriesReachesTheCore(t *testing.T) {
	wire := func(carried string) *compositionv1.AuthorityManifestV1 {
		return &compositionv1.AuthorityManifestV1{Module: "answers", Generation: 1,
			ScopeCeilings: []*authorityv1.WorkScopeV1{{ResourceKind: "answers.answer", Actions: []string{"read", "review"}}},
			Methods: []*compositionv1.MethodPolicyV1{{Method: "/answers.v1.Answers/Reach",
				Requires: []*authorityv1.WorkScopeV1{{ResourceKind: "answers.answer", Actions: []string{"read"}}},
				Carries:  []*authorityv1.WorkScopeV1{{ResourceKind: "answers.answer", Actions: []string{carried}}}}}}
	}
	manifest := &solutionhost.ModuleManifest{Alias: "answers", Kind: solutionhost.KindModule, Generation: 1,
		Authority: &solutionhost.Authority{Principal: "answers", ResourceKinds: []string{"answers.answer"}}}
	doc := DocumentOf(wire("review"))
	if len(doc.Methods) != 1 || len(doc.Methods[0].Carries) != 1 || doc.Methods[0].Carries[0].GetResourceKind() != "answers.answer" {
		t.Fatalf("what the method carries was dropped from the document: %+v", doc.Methods)
	}
	if _, err := delivered.Module(manifest, doc); err != nil {
		t.Fatalf("a method carrying what the module serves is refused: %v", err)
	}
	_, err := delivered.Module(manifest, DocumentOf(wire("purge")))
	if err == nil || !strings.Contains(err.Error(), "/answers.v1.Answers/Reach carries answers.answer:purge, which answers does not serve") {
		t.Fatalf("a method carrying what the module does not serve was accepted: %v", err)
	}
}
