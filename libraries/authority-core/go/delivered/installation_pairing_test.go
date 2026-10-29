package delivered_test

import (
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/delivered"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	delivery "github.com/codefly-dev/authority/libraries/delivery/go"
	modulecontract "github.com/codefly-dev/core/contracts/module"
	"github.com/codefly-dev/core/solutionhost"
)

// These are shared-reader tests, not the CLI-generated signed protobuf path.
// Existing signature tests cover authentication; here all identity/digest
// pairing fields agree so each negative isolates the duplicated declaration.
func TestInstallationDeclarationPairingRefusesEitherCarrierMismatch(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		change      func(*solutionhost.ModuleManifest, **delivered.Document)
	}{
		{"selector", "installation_role", func(m *solutionhost.ModuleManifest, d **delivered.Document) { (*d).InstallationRole = "editor" }},
		{"sidecar selector absent", "installation_role", func(m *solutionhost.ModuleManifest, d **delivered.Document) { (*d).InstallationRole = "" }},
		{"core selector absent", "installation_role", func(m *solutionhost.ModuleManifest, d **delivered.Document) { m.Authority.InstallationRole = "" }},
		{"sidecar absent", "installation_role", func(m *solutionhost.ModuleManifest, d **delivered.Document) { *d = nil }},
		{"core authority absent", "installation_role", func(m *solutionhost.ModuleManifest, d **delivered.Document) { m.Authority = nil }},
		{"edge identity", "edge_dependencies", func(m *solutionhost.ModuleManifest, d **delivered.Document) {
			(*d).EdgeDependencies[0].Module = "different"
		}},
		{"edge presence", "edge_dependencies", func(m *solutionhost.ModuleManifest, d **delivered.Document) {
			(*d).EdgeDependencies[0].Presence = "optional"
		}},
		{"edge order", "edge_dependencies", func(m *solutionhost.ModuleManifest, d **delivered.Document) {
			(*d).EdgeDependencies[0], (*d).EdgeDependencies[1] = (*d).EdgeDependencies[1], (*d).EdgeDependencies[0]
		}},
		{"sidecar edges absent", "edge_dependencies", func(m *solutionhost.ModuleManifest, d **delivered.Document) { (*d).EdgeDependencies = nil }},
		{"core edges absent", "edge_dependencies", func(m *solutionhost.ModuleManifest, d **delivered.Document) { m.Authority.EdgeDependencies = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := solutionManifest()
			m.Authority.InstallationRole = "none"
			m.Authority.EdgeDependencies = []modulecontract.EdgeDependency{{Module: "z", Presence: "required"}, {Module: "a", Presence: "optional"}}
			carrier := []byte("verified carrier bytes")
			doc := &delivered.Document{Module: m.Alias, Generation: m.Generation, CoreManifestDigest: delivery.Digest(carrier), InstallationRole: "none", EdgeDependencies: []domain.EdgeDependency{{Module: "z", Presence: "required"}, {Module: "a", Presence: "optional"}}}
			if err := delivered.Pair(*doc, carrier, m); err != nil {
				t.Fatal("positive control", err)
			}
			if _, err := delivered.Module(m, doc); err != nil {
				t.Fatal("positive control", err)
			}
			tc.change(m, &doc)
			if doc != nil {
				err := delivered.Pair(*doc, carrier, m)
				code(t, err, domain.Denied)
				if !strings.Contains(err.Error(), tc.field) {
					t.Fatal(err)
				}
			}
			_, err := delivered.Module(m, doc)
			code(t, err, domain.Denied)
			if !strings.Contains(err.Error(), tc.field) {
				t.Fatal(err)
			}
		})
	}
}

func TestInstallationDeclarationPairingKeepsLegacyAbsence(t *testing.T) {
	for _, authority := range []*solutionhost.Authority{nil, {}, {EdgeDependencies: []modulecontract.EdgeDependency{}}} {
		for _, doc := range []*delivered.Document{nil, {}, {EdgeDependencies: []domain.EdgeDependency{}}} {
			m := solutionManifest()
			m.Authority = authority
			got, err := delivered.Module(m, doc)
			if err != nil || got.InstallationRole != "" || len(got.EdgeDependencies) != 0 {
				t.Fatalf("legacy: %+v %v", got, err)
			}
		}
	}
}

func TestInstallationDeclarationFromCorePreservesBytesWithoutAliasing(t *testing.T) {
	m := solutionManifest()
	m.Authority.InstallationRole = "none"
	m.Authority.EdgeDependencies = []modulecontract.EdgeDependency{{Module: "z", Presence: "required"}, {Module: "a", Presence: "optional"}}
	got := delivered.FromCore(m)
	if got.InstallationRole != "none" || got.EdgeDependencies[0].Module != "z" || got.EdgeDependencies[1].Module != "a" {
		t.Fatalf("projection: %+v", got)
	}
	m.Authority.EdgeDependencies[0].Module = "changed"
	if got.EdgeDependencies[0].Module != "z" {
		t.Fatal("projection aliases signed manifest")
	}
}
