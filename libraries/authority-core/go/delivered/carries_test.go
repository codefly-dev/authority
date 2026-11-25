package delivered_test

import (
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/delivered"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/solutionhost/go"
	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"
)

// A capability at a module holds nothing beyond the module's own ceilings:
// issuance cuts what its owner holds to them. So what a method carries that
// the ceilings do not list reaches no handler, whatever a role grants, and
// nothing refuses the call: the handler reads "nothing carried" for good. The
// delivery is refused instead, naming the method and the permission.
func TestAMethodCarryingWhatTheModuleDoesNotServeIsRefusedByName(t *testing.T) {
	manifest := func() *solutionhost.ModuleManifest {
		return &solutionhost.ModuleManifest{Alias: "answers", Kind: solutionhost.KindModule, Generation: 1,
			Authority: &solutionhost.Authority{Principal: "answers", ResourceKinds: []string{"answers.answer", "answers.note"}}}
	}
	read := []*basev1.WorkScopeV1{ws("answers.answer", "read")}
	deliver := func(ceilings []*basev1.WorkScopeV1, carries ...*basev1.WorkScopeV1) error {
		_, err := delivered.Module(manifest(), &delivered.Document{Module: "answers", Generation: 1, ScopeCeilings: ceilings,
			Methods: []delivered.Method{{Method: "/answers.v1.Answers/Reach", Requires: read, Carries: carries}}})
		return err
	}
	ceilings := []*basev1.WorkScopeV1{ws("answers.answer", "read", "review")}

	for name, carries := range map[string][]*basev1.WorkScopeV1{
		"nothing":                              nil,
		"an action its ceiling lists":          {ws("answers.answer", "review")},
		"what it also requires":                {ws("answers.answer", "read", "review")},
		"any action of a kind it never ceiled": {ws("answers.note", "redact")},
	} {
		if err := deliver(ceilings, carries...); err != nil {
			t.Errorf("a method carrying %s is refused: %v", name, err)
		}
	}
	for _, tc := range []struct {
		name    string
		carries []*basev1.WorkScopeV1
		reason  string
	}{
		{"an action its ceiling does not list", []*basev1.WorkScopeV1{ws("answers.answer", "review", "purge")},
			"/answers.v1.Answers/Reach carries answers.answer:purge, which answers does not serve"},
		{"a kind it does not serve", []*basev1.WorkScopeV1{ws("documents.collection", "create")},
			"/answers.v1.Answers/Reach carries documents.collection:create, which answers does not serve"},
		{"every unserved permission, named", []*basev1.WorkScopeV1{ws("answers.answer", "purge"), ws("documents.collection", "create")},
			"carries answers.answer:purge, documents.collection:create, which answers does not serve"},
		{"resource ids", []*basev1.WorkScopeV1{{ResourceKind: "answers.answer", Actions: []string{"review"}, ResourceIds: []string{"a-1"}}},
			"names whole resource kinds"},
		{"a resource owner", []*basev1.WorkScopeV1{{ResourceKind: "answers.answer", Actions: []string{"review"}, ResourceOwnerId: "u"}},
			"names whole resource kinds"},
		{"a kind with no action", []*basev1.WorkScopeV1{ws("answers.answer")}, "carries answers.answer with no action"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := deliver(ceilings, tc.carries...)
			code(t, err, domain.Denied)
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("want a refusal naming %q, got %v", tc.reason, err)
			}
		})
	}

	t.Run("beside any_checked_caller", func(t *testing.T) {
		_, err := delivered.Module(manifest(), &delivered.Document{Module: "answers", Generation: 1, ScopeCeilings: ceilings,
			Methods: []delivered.Method{{Method: "/answers.v1.Answers/Ping", AnyCheckedCaller: true, Carries: []*basev1.WorkScopeV1{ws("answers.answer", "review")}}}})
		code(t, err, domain.Denied)
		if !strings.Contains(err.Error(), "/answers.v1.Answers/Ping carries answers.answer:review beside any_checked_caller") {
			t.Fatal(err)
		}
	})
}
