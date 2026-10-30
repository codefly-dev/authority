package delivered_test

import (
	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/delivered"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/offers"
	modulecontract "github.com/codefly-dev/core/contracts/module"
	"slices"
	"testing"
)

func TestInstallationDeclarationCarriageIsOpaqueAndIsolated(t *testing.T) {
	// Whitespace is intentionally not Core-valid: this adapter must not become
	// another parser or silently repair bytes already covered by a signature.
	for _, selector := range []string{"", "none", "editor", " editor "} {
		doc := &delivered.Document{InstallationRole: selector, EdgeDependencies: []domain.EdgeDependency{{Module: " module-id ", Presence: "required"}, {Module: "second", Presence: "optional"}}}
		manifest := solutionManifest()
		manifest.Authority.InstallationRole = selector
		for _, edge := range doc.EdgeDependencies {
			manifest.Authority.EdgeDependencies = append(manifest.Authority.EdgeDependencies, modulecontract.EdgeDependency{Module: edge.Module, Presence: edge.Presence})
		}
		m, err := delivered.Module(manifest, doc)
		if err != nil {
			t.Fatal(err)
		}
		review, err := offers.Project(authority.ReviewedOffer{Module: m}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if m.InstallationRole != selector || review.InstallationRole != selector || !slices.Equal(doc.EdgeDependencies, review.EdgeDependencies) {
			t.Fatal("declaration transformed")
		}
		if len(review.Ceiling) != 0 || len(review.Roles) != 0 {
			t.Fatal("edges created authority")
		}
		doc.EdgeDependencies[0].Module = "changed"
		review.EdgeDependencies[1].Module = "changed"
		if m.EdgeDependencies[0].Module != " module-id " || m.EdgeDependencies[1].Module != "second" {
			t.Fatal("carrier aliases declaration")
		}
	}
}
