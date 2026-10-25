// Package approvalstest is the contract every state.Approvals passes: the
// in-memory one and the store's. One suite, so the two never drift on what
// "standing", "again" and "revoked" mean.
package approvalstest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"gateway/pkg/business/state"
)

// Digest is a well-formed artifact digest for a name: what the local authority computes
// over an identity, shaped so the store's check accepts it.
func Digest(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Contract runs the suite over the implementation open gives. Every subtest
// names its own installation, so the suite holds over a shared database too.
func Contract(t *testing.T, open func(t *testing.T) state.Approvals) {
	ctx := context.Background()
	inst := func(t *testing.T) string { return "inst-" + strings.ReplaceAll(t.Name(), "/", "-") }

	t.Run("approving records consent and approving again answers the same one", func(t *testing.T) {
		a, in := open(t), inst(t)
		first, err := a.Approve(ctx, in, "robin.intents", Digest("field-naturalist"), 3)
		if err != nil {
			t.Fatalf("approve: %v", err)
		}
		if first.ID == "" || first.Installation != in || first.Policy != "robin.intents" || first.Digest != Digest("field-naturalist") || first.Revision != 3 || first.Revoked {
			t.Fatalf("approval = %+v", first)
		}
		if !strings.HasPrefix(first.QualifiedName(), "host/approved-artifacts/") {
			t.Fatalf("qualified name = %q", first.QualifiedName())
		}
		again, err := a.Approve(ctx, in, "robin.intents", Digest("field-naturalist"), 9)
		if err != nil || again != first {
			t.Fatalf("approving again: %+v %v (first %+v)", again, err, first)
		}
	})

	t.Run("standing answers the approval or refuses", func(t *testing.T) {
		a, in := open(t), inst(t)
		if _, err := a.Standing(ctx, in, "robin.intents", Digest("field-naturalist")); !errors.Is(err, state.ErrForbidden) {
			t.Fatalf("nothing approved yet: %v", err)
		}
		approved, err := a.Approve(ctx, in, "robin.intents", Digest("field-naturalist"), 1)
		if err != nil {
			t.Fatal(err)
		}
		standing, err := a.Standing(ctx, in, "robin.intents", Digest("field-naturalist"))
		if err != nil || standing != approved {
			t.Fatalf("standing: %+v %v", standing, err)
		}
	})

	t.Run("another artifact, policy or installation stands apart", func(t *testing.T) {
		a, in := open(t), inst(t)
		if _, err := a.Approve(ctx, in, "robin.intents", Digest("field-naturalist"), 1); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct{ inst, policy, digest string }{
			{in, "robin.intents", Digest("tool-assistant")},
			{in, "robin.tasks", Digest("field-naturalist")},
			{in + "-other", "robin.intents", Digest("field-naturalist")},
		} {
			if _, err := a.Standing(ctx, c.inst, c.policy, c.digest); !errors.Is(err, state.ErrForbidden) {
				t.Fatalf("%+v stands: %v", c, err)
			}
		}
		other, err := a.Approve(ctx, in, "robin.intents", Digest("tool-assistant"), 1)
		if err != nil || other.Digest != Digest("tool-assistant") {
			t.Fatalf("a second artifact: %+v %v", other, err)
		}
	})

	t.Run("revoke marks for good", func(t *testing.T) {
		a, in := open(t), inst(t)
		approved, err := a.Approve(ctx, in, "robin.intents", Digest("field-naturalist"), 1)
		if err != nil {
			t.Fatal(err)
		}
		revoked, err := a.Revoke(ctx, in, "robin.intents", approved.ID)
		if err != nil || !revoked.Revoked || revoked.ID != approved.ID {
			t.Fatalf("revoke: %+v %v", revoked, err)
		}
		if _, err := a.Standing(ctx, in, "robin.intents", Digest("field-naturalist")); !errors.Is(err, state.ErrForbidden) {
			t.Fatalf("a revoked artifact stands: %v", err)
		}
		if _, err := a.Approve(ctx, in, "robin.intents", Digest("field-naturalist"), 1); !errors.Is(err, state.ErrForbidden) || !strings.Contains(err.Error(), "revoked") {
			t.Fatalf("approving a revoked artifact again: %v", err)
		}
		// Revoking twice is the same withdrawal.
		if again, err := a.Revoke(ctx, in, "robin.intents", approved.ID); err != nil || !again.Revoked {
			t.Fatalf("revoking again: %+v %v", again, err)
		}
	})

	t.Run("revoking an approval that is not the installation's under the policy is unknown", func(t *testing.T) {
		a, in := open(t), inst(t)
		approved, err := a.Approve(ctx, in, "robin.intents", Digest("field-naturalist"), 1)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct{ inst, policy, id string }{
			{in, "robin.intents", "no-such-approval"},
			{in + "-other", "robin.intents", approved.ID},
			{in, "robin.tasks", approved.ID},
		} {
			if _, err := a.Revoke(ctx, c.inst, c.policy, c.id); !errors.Is(err, state.ErrUnknown) {
				t.Fatalf("%+v revoked: %v", c, err)
			}
		}
		if standing, err := a.Standing(ctx, in, "robin.intents", Digest("field-naturalist")); err != nil || standing.Revoked {
			t.Fatalf("still standing: %+v %v", standing, err)
		}
	})
}
