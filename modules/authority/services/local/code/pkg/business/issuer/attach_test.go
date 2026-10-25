package issuer_test

import (
	"errors"
	"strings"
	"testing"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// A kind two composed modules declare has no one module trusted to say what
// was created, so neither attaches anything of it.
func TestAttachmentNeedsTheKindsOneServingModule(t *testing.T) {
	k := testkit.New(t)
	decoy := state.Manifest{Module: "robin", Principal: "robin", Kind: "module", Generation: 1,
		ResourceKinds: []*basev0.WorkScopeV1{testkit.Scope("documents.collection", "read")}}
	if _, err := k.State.ApplyManifest(decoy); err != nil {
		t.Fatal(err)
	}
	for _, module := range []string{"documents", "robin"} {
		_, err := k.Issuer.AttachResource(t.Context(), "not-read", k.Credential(t, module), "documents.collection", "c1")
		if !errors.Is(err, issuer.ErrRefused) || !strings.Contains(err.Error(), "one serving module") {
			t.Fatalf("%s: %v", module, err)
		}
	}
}
