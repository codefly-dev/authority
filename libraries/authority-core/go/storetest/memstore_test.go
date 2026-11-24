package storetest_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/access"
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
		for _, team := range id.Teams {
			s.PutTeam(team.Organization, team.ID)
		}
		for _, m := range id.Members {
			p := domain.Person{ID: m.Person, Organization: m.Organization, Teams: m.Teams}
			if m.Administrator {
				p.Roles = append(p.Roles, "admin")
			}
			s.PutPerson(p)
		}
		return s
	})
}

// The in-memory store meets the contract every host's access store meets.
func TestTheMemoryStoreMeetsTheAccessStoreContract(t *testing.T) {
	storetest.RunAccess(t, func(*testing.T) access.Store { return memstore.New() })
	storetest.RunAccessSequence(t, func(*testing.T) access.Store { return memstore.New() })
}
