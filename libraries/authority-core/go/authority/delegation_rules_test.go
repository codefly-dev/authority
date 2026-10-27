package authority_test

import (
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// A delegation is to a module installed at the grantor's organization, with a
// bounded purpose; its grantor or an administrator of its organization ends
// it, and anyone else learns nothing of it.
func TestDelegationRules(t *testing.T) {
	h := newHarness(t)
	read := []*basev0.WorkScopeV1{sc(kind, "read")}
	rob := h.person("rob")

	t.Run("a purpose past its bound is malformed", func(t *testing.T) {
		_, err := h.svc.Delegate(h.ctx, rob, "store", read, strings.Repeat("p", authority.MaxDelegationPurpose+1))
		code(t, err, domain.Invalid)
	})
	t.Run("a module not installed at the grantor's organization is refused", func(t *testing.T) {
		if err := h.svc.UninstallAsHost(h.ctx, acme, authority.StableInstallationID(acme, "store")); err != nil {
			t.Fatal(err)
		}
		_, err := h.svc.Delegate(h.ctx, rob, "store", read, "a job")
		code(t, err, domain.Precondition)
		refused(t, err, "is not installed")
	})
}

func TestADelegationIsEndedByItsGrantorOrAnAdministratorAlone(t *testing.T) {
	h := newHarness(t)
	read := []*basev0.WorkScopeV1{sc(kind, "read")}
	rob, maya, alex, zoe := h.person("rob"), h.person("maya"), h.person("alex"), h.person("zoe")
	for _, tc := range []struct {
		name   string
		who    authority.Person
		ok     bool
		reason domain.Code
	}{
		{"another member", maya, false, domain.NotFound},
		{"another organization's administrator", zoe, false, domain.NotFound},
		{"an administrator of its organization", alex, true, 0},
		{"its grantor", rob, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := h.svc.Delegate(h.ctx, rob, "store", read, "a job")
			if err != nil {
				t.Fatal(err)
			}
			ended, err := h.svc.RevokeDelegation(h.ctx, tc.who, d.ID)
			if !tc.ok {
				code(t, err, tc.reason)
				return
			}
			if err != nil || !ended.Revoked {
				t.Fatalf("revoked %+v %v", ended, err)
			}
			if again, err := h.svc.RevokeDelegation(h.ctx, tc.who, d.ID); err != nil || !again.Revoked {
				t.Fatalf("revoking twice answers the delegation as it stands: %+v %v", again, err)
			}
		})
	}
}
