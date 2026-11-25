package authority

import (
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

func owned(kind, id string) *basev0.WorkContextV1 {
	return &basev0.WorkContextV1{OwnerPrincipalKind: &kind, OwnerPrincipalId: id}
}

// The approved-reach gate knows three owners: a person, an installation's
// agent, and a module's own work, which no installation's consent bounds. A
// capability owned by any other kind is refused, never passed unbounded.
func TestTheApprovedReachGateRefusesAnOwnerKindItDoesNotKnow(t *testing.T) {
	t.Parallel()
	s, m := &Service{}, domain.Module{Name: "store", Principal: "store"}
	refusal, err := s.withinApprovedReach(nil, owned("service", "store"), nil, m, "/store.v1.Store/Read")
	if refusal != nil || err != nil {
		t.Fatalf("a module's own work: refusal %v, error %v", refusal, err)
	}
	for _, kind := range []string{"", "robot", "Human", "client"} {
		refusal, err := s.withinApprovedReach(nil, owned(kind, "x"), nil, m, "/store.v1.Store/Read")
		if err != nil {
			t.Fatalf("owner kind %q: %v", kind, err)
		}
		if code, ok := domain.CodeOf(refusal); refusal == nil || !ok || code != domain.Denied || !strings.Contains(refusal.Error(), "owner") {
			t.Errorf("a capability owned by kind %q passed the approved-reach gate: %v", kind, refusal)
		}
	}
}
