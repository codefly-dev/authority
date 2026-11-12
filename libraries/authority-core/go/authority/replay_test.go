package authority_test

import (
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// A host composes one delivery on more than one path at once (its delivery
// endpoint's pass and its reconcile loop's), so the core may already hold the
// generation a path brings. The same declaration at the held generation is a
// replay: it changes nothing, and nothing issued under it ends. A different
// declaration at that generation is refused, naming both; an older generation
// is refused as before.
func TestARedeliveryOfTheHeldGenerationIsAReplay(t *testing.T) {
	h := newHarness(t)
	before := h.seal("maya", "a")

	// The same declaration as a store reads it back: its scopes in another
	// order, an empty set spelled as absent.
	again := solution("a", true)
	viewer := again.Roles["viewer"]
	again.Roles["viewer"] = []*basev0.WorkScopeV1{viewer[2], viewer[0], viewer[1]}
	again.OwnedRoles = map[string][]*basev0.WorkScopeV1{}
	ids, err := h.svc.ApplyModule(h.ctx, again)
	if err != nil {
		t.Fatalf("the held generation, delivered again, was refused: %v", err)
	}
	if ids != nil {
		t.Fatalf("a replay answered installations %v", ids)
	}
	if after := h.seal("maya", "a"); after != before {
		t.Fatalf("a replay moved the installation from %d to %d", before, after)
	}

	// A module installed at every organization answers no installation on a
	// replay either: nothing was installed.
	store, err := h.svc.Composed(h.ctx, "store")
	if err != nil {
		t.Fatal(err)
	}
	if ids, err := h.svc.ApplyModule(h.ctx, store); err != nil || ids != nil {
		t.Fatalf("the held store, delivered again: %v %v", ids, err)
	}

	other := solution("a", true)
	other.Roles["viewer"] = append(slices.Clone(other.Roles["viewer"]), sc("a.note", "write"))
	_, err = h.svc.ApplyModule(h.ctx, other)
	code(t, err, domain.Precondition)
	refused(t, err, "a generation 1 is held as sha256:")
	refused(t, err, "and delivered as sha256:")
	if after := h.seal("maya", "a"); after != before {
		t.Fatalf("a refused redelivery moved the installation from %d to %d", before, after)
	}

	newer := solution("a", true)
	newer.Generation = 2
	if _, err := h.svc.ApplyModule(h.ctx, newer); err != nil {
		t.Fatal(err)
	}
	_, err = h.svc.ApplyModule(h.ctx, solution("a", true))
	code(t, err, domain.Precondition)
	refused(t, err, "a is at 2, got 1")
}
