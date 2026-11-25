package authority

import (
	"testing"

	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"
)

// The session a role view is keyed by is recovered from the capability at any
// depth: the root's own, else the first hop's delegation. The last hop's
// delegation is its parent's session, which carries no view.
func TestTheRootSessionIsRecoveredAtEveryDepth(t *testing.T) {
	t.Parallel()
	hop := func(delegation string) *basev1.WorkActorV1 { return &basev1.WorkActorV1{DelegationId: delegation} }
	for name, tc := range map[string]struct {
		wc   *basev1.WorkContextV1
		want string
	}{
		"a root":     {&basev1.WorkContextV1{SessionId: "root"}, "root"},
		"one hop":    {&basev1.WorkContextV1{SessionId: "s1", ActorChain: []*basev1.WorkActorV1{hop("root")}}, "root"},
		"three hops": {&basev1.WorkContextV1{SessionId: "s3", ActorChain: []*basev1.WorkActorV1{hop("root"), hop("s1"), hop("s2")}}, "root"},
	} {
		if got := rootSession(tc.wc); got != tc.want {
			t.Errorf("%s: root session %q, want %q", name, got, tc.want)
		}
	}
}
