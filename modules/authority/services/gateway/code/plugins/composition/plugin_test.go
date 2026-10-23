package composition

import (
	"testing"

	"github.com/codefly-dev/core/solutionhost"
)

// Core's manifest writes a binding's operations as operation → "<kind>:<action>"
// entries; the state reads invoke and headless scopes from them.
func TestCoreBindingOperationsAreReadAsScopesPerOperation(t *testing.T) {
	m := FromCore(&solutionhost.ModuleManifest{Alias: "robin", Kind: solutionhost.KindModule, Generation: 1,
		Authority: &solutionhost.Authority{Principal: "robin", Bindings: []solutionhost.AuthorityBinding{{
			ID: "model", Audience: "model",
			Operations: map[string][]string{
				"invoke":   {"modelservice.profiles:invoke", "modelservice.profiles:read"},
				"lookup":   {"modelservice.profiles:read"},
				"headless": {"modelservice.profiles:read"},
			},
		}}}})
	b, ok := m.Bindings["model"]
	if !ok || b.Audience != "model" {
		t.Fatalf("binding: %+v", m.Bindings)
	}
	if len(b.InvokeScopes) != 1 || b.InvokeScopes[0].GetResourceKind() != "modelservice.profiles" || len(b.InvokeScopes[0].GetActions()) != 2 {
		t.Fatalf("invoke scopes: %v", b.InvokeScopes)
	}
	if len(b.HeadlessScopes) != 1 || b.HeadlessScopes[0].GetActions()[0] != "read" {
		t.Fatalf("headless scopes: %v", b.HeadlessScopes)
	}
}
