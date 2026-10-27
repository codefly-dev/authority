package storetest_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/memstore"
	"github.com/codefly-dev/authority/libraries/authority-core/go/storetest"
)

// The in-memory store meets the contract every host's store meets.
func TestTheMemoryStoreMeetsTheStoreContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T, id storetest.Identity) authority.Store {
		s := memstore.New()
		for _, o := range id.Organizations {
			s.PutOrganization(o)
		}
		for _, m := range id.Members {
			p := domain.Person{ID: m.Person, Organization: m.Organization, Teams: m.Teams}
			if m.Administrator {
				p.Roles = append(p.Roles, "admin")
			}
			if len(m.Scopes) > 0 {
				role := "storetest-" + m.Person
				s.PutOrgRole(domain.OrgRole{Organization: m.Organization, Name: role, Scopes: m.Scopes})
				p.Roles = append(p.Roles, role)
			}
			s.PutPerson(p)
		}
		return s
	})
}
