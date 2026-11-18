package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

func (t lookupOutageTx) RoleView(session string) (domain.RoleView, error) {
	if t.down("RoleView", session) {
		return domain.RoleView{}, errStoreDown
	}
	return t.Tx.RoleView(session)
}

// A capability issued in a cast is checked against the cast every time: the
// person is read again under it. A read that fails, or a person the host no
// longer has, cannot say the cast still holds, so the check refuses or fails;
// only a denial used to stop it, and any other error passed the capability.
func TestACastCapabilityIsNotAdmittedWhenTheCastCannotBeReadAgain(t *testing.T) {
	t.Run("the person is gone from the host", func(t *testing.T) {
		r := newRemoval(t)
		if err := r.h.check(r.asCast); err != nil {
			t.Fatalf("the cast's call before: %v", err)
		}
		r.h.store.DeletePerson("tam")
		if err := r.h.check(r.asCast); err == nil {
			t.Fatal("a call made as the team is admitted for a person the host no longer has")
		}
	})
	for _, call := range []string{"Member", "RoleView"} {
		t.Run("the store stops answering "+call, func(t *testing.T) {
			r := newRemoval(t)
			for from := 1; ; from++ {
				seen := 0
				svc, err := authority.New(lookupOutage{r.h.store, func(c string) bool { return c == call }, from, &seen}, r.h.cfg)
				if err != nil {
					t.Fatal(err)
				}
				seen = 0
				_, _, err = svc.Check(r.h.ctx, r.asCast.Token, r.asCast.Context.GetAudience())
				if seen < from {
					if err != nil {
						t.Fatalf("the cast's call with the store answering: %v", err)
					}
					if from == 1 {
						t.Fatalf("the check makes no %s lookup: the case proves nothing", call)
					}
					return
				}
				if err == nil {
					t.Fatalf("a call made as the team was admitted when lookup %d of %s failed (%d made)", from, call, seen)
				}
			}
		})
	}
}
