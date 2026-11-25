package authority_test

import (
	"context"
	"errors"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

var errStoreDown = errors.New("store unavailable")

// lookupOutage is a store whose named lookups fail from the from-th one on,
// as a store that stops answering part-way through a check does: with an
// error that is no refusal and no "not found".
type lookupOutage struct {
	authority.Store
	fails func(call string) bool
	from  int
	seen  *int
}

type lookupOutageTx struct {
	authority.Tx
	o lookupOutage
}

func (o lookupOutage) Read(ctx context.Context, fn func(authority.Tx) error) error {
	return o.Store.Read(ctx, func(tx authority.Tx) error { return fn(lookupOutageTx{tx, o}) })
}

func (t lookupOutageTx) down(call, _ string) bool {
	if !t.o.fails(call) {
		return false
	}
	*t.o.seen++
	return *t.o.seen >= t.o.from
}

func (t lookupOutageTx) Module(principal string) (domain.Module, error) {
	if t.down("Module", principal) {
		return domain.Module{}, errStoreDown
	}
	return t.Tx.Module(principal)
}

func (t lookupOutageTx) Installations(organization string) ([]domain.Installation, error) {
	if t.down("Installations", organization) {
		return nil, errStoreDown
	}
	return t.Tx.Installations(organization)
}

func (t lookupOutageTx) InstallationByPrincipal(principal string) (domain.Installation, error) {
	if t.down("InstallationByPrincipal", principal) {
		return domain.Installation{}, errStoreDown
	}
	return t.Tx.InstallationByPrincipal(principal)
}

func (t lookupOutageTx) Member(organization, id string) (domain.Person, error) {
	if t.down("Member", id) {
		return domain.Person{}, errStoreDown
	}
	return t.Tx.Member(organization, id)
}

// The approved-reach gate bounds a call by the consent of the installation it
// came through. A lookup the gate needs that fails (the module a principal on
// the path is, its installation, the agent's installation, the person) is an
// outage and ends the check as one, wherever in the check the store stops
// answering: it is never read as "nothing bounds this call", which admitted a
// method the installation's consent does not reach.
func TestTheApprovedReachGateFailsClosedOnALookupItCannotMake(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		agent bool
		call  string
	}{
		"the module a principal on a person's path is":   {false, "Module"},
		"the installations of the person's organization": {false, "Installations"},
		"the person":                    {false, "Member"},
		"the installation of the agent": {true, "InstallationByPrincipal"},
		"the module, for the agent":     {true, "Module"},
	} {
		t.Run(name, func(t *testing.T) {
			h := reachHarness(t)
			// The store relaxes Purge to what a's admin holds: beyond the reach
			// a's installation approved until the upgrade is approved.
			if _, err := h.svc.ApplyModule(h.ctx, storeAt(3, "write", true)); err != nil {
				t.Fatal(err)
			}
			issue := func() (authority.Issued, error) { return h.through("maya", "a", "store") }
			if tc.agent {
				issue = func() (authority.Issued, error) { return h.agent("a", "store") }
			}
			at := h.must(issue())
			refused(t, h.callStore(at, storePurge), "beyond the reach its installation approved")

			// The store stops answering at its first such lookup, then its
			// second, and so on through the whole check.
			for from := 1; ; from++ {
				seen := 0
				svc, err := authority.New(lookupOutage{h.store, func(call string) bool { return call == tc.call }, from, &seen}, h.cfg)
				if err != nil {
					t.Fatal(err)
				}
				seen = 0
				_, _, refusal, err := svc.CheckMethod(h.ctx, at.Token, "store", storePurge, false)
				if err == nil && refusal == nil {
					t.Fatalf("a method beyond the approved reach was admitted when lookup %d of %s failed (%d made)", from, tc.call, seen)
				}
				if seen < from {
					// No lookup failed: the check ran whole.
					refused(t, err, "beyond the reach its installation approved")
					if from == 1 {
						t.Fatalf("the check makes no %s lookup: the case proves nothing", tc.call)
					}
					return
				}
			}
		})
	}
}
