package installation

import (
	installationv1 "gateway/pkg/gen/host/installation/v1"
	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestReviewedOfferWireCarriesExactInstallationDeclaration(t *testing.T) {
	for _, selector := range []string{"", "none", "editor"} {
		m := domain.Module{Name: "solution", InstallationRole: selector, EdgeDependencies: []domain.EdgeDependency{{Module: "z-principal", Presence: "required"}, {Module: "a-principal", Presence: "optional"}}}
		wire, err := (&Plugin{}).review(authority.ReviewedOffer{Module: m}, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := proto.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		var got installationv1.ReviewedOffer
		if err := proto.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if got.GetInstallationRole() != selector || len(got.GetEdgeDependencies()) != 2 || got.EdgeDependencies[0].GetModule() != "z-principal" || got.EdgeDependencies[1].GetModule() != "a-principal" || got.EdgeDependencies[0].GetPresence() != "required" || got.EdgeDependencies[1].GetPresence() != "optional" {
			t.Fatalf("wire changed declaration: %v", &got)
		}
		if len(got.GetCeiling()) != 0 || len(got.GetRoles()) != 0 {
			t.Fatal("presence created authority")
		}
	}
}
