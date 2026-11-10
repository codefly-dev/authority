package authority

import (
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The session a role view is keyed by is recovered from the capability at any
// depth: the root's own, else the first hop's delegation. The last hop's
// delegation is its parent's session, which carries no view.
func TestTheRootSessionIsRecoveredAtEveryDepth(t *testing.T) {
	hop := func(delegation string) *basev0.WorkActorV1 { return &basev0.WorkActorV1{DelegationId: delegation} }
	for name, tc := range map[string]struct {
		wc   *basev0.WorkContextV1
		want string
	}{
		"a root":     {&basev0.WorkContextV1{SessionId: "root"}, "root"},
		"one hop":    {&basev0.WorkContextV1{SessionId: "s1", ActorChain: []*basev0.WorkActorV1{hop("root")}}, "root"},
		"three hops": {&basev0.WorkContextV1{SessionId: "s3", ActorChain: []*basev0.WorkActorV1{hop("root"), hop("s1"), hop("s2")}}, "root"},
	} {
		if got := rootSession(tc.wc); got != tc.want {
			t.Errorf("%s: root session %q, want %q", name, got, tc.want)
		}
	}
}
