package composition

import (
	"slices"
	"testing"

	authorityv1 "gateway/pkg/gen/host/authority/v1"
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

// The authority's document carries what a role names through each binding,
// and the host reads it as the core's: part of the role's grant, kept by
// binding.
func TestTheDocumentCarriesWhatARoleNamesThroughABinding(t *testing.T) {
	read := &authorityv1.WorkScopeV1{ResourceKind: "documents", Actions: []string{"read"}}
	doc := DocumentOf(&compositionv1.AuthorityManifestV1{Module: "wiki", Roles: []*compositionv1.RoleV1{{Name: "viewer",
		Through: []*compositionv1.RoleThroughV1{{Binding: "robin", Scopes: []*authorityv1.WorkScopeV1{read}}}}}})
	if len(doc.Roles) != 1 || len(doc.Roles[0].Through["robin"]) != 1 || doc.Roles[0].Through["robin"][0].GetResourceKind() != "documents" {
		t.Fatalf("roles %+v", doc.Roles)
	}
}
