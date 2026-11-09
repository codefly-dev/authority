package composition

import (
	"slices"
	"testing"

	compositionv1 "gateway/pkg/gen/host/composition/v1"
)

// The authority's document carries the kinds a module declares shared, and
// the host reads them as the core's: a scope of one is issued unselected.
func TestTheDocumentCarriesTheModulesSharedKinds(t *testing.T) {
	doc := DocumentOf(&compositionv1.AuthorityManifestV1{Module: "model", SharedKinds: []string{"modelservice.profiles"}})
	if !slices.Equal(doc.SharedKinds, []string{"modelservice.profiles"}) {
		t.Fatalf("shared kinds %v", doc.SharedKinds)
	}
	if doc := DocumentOf(&compositionv1.AuthorityManifestV1{Module: "documents"}); len(doc.SharedKinds) != 0 {
		t.Fatalf("a module declaring none has %v", doc.SharedKinds)
	}
}
