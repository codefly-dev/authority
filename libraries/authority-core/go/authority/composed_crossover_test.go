package authority_test

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The tests in this file pin the one-release STOPGAP of domain.LegacyInstallerRole
// on a module page held by the receipt composition took (domain.ComposedConsent):
// nobody reviewed that receipt, so the page-role rename moves its grants with
// the delivery, or, on a host holding the renamed generation already, at its
// next replay of it. Delete them with the stopgap.

// movedBy is, for each subject a role grant or revocation by actor in
// events marks as the crossover, its "kind old>new basis" lines, sorted.
func movedBy(events []domain.Event, actor string) map[string][]string {
	out := map[string][]string{}
	for _, e := range events {
		if e.Actor != actor || e.Detail[domain.CrossoverFrom] == "" {
			continue
		}
		subject := e.Detail["person"] + e.Detail["team"]
		out[subject] = append(out[subject], string(e.Kind)+" "+e.Detail[domain.CrossoverFrom]+">"+e.Detail["role"]+" "+e.Detail[domain.CrossoverBasis])
	}
	for _, lines := range out {
		slices.Sort(lines)
	}
	return out
}

// wantMoves is movedBy's answer for the four old roles moving.
func wantMoves() map[string][]string {
	move := func(old, role, basis string) []string {
		return []string{string(domain.RoleGranted) + " " + old + ">" + role + " " + basis, string(domain.RoleRevoked) + " " + old + ">" + old + " " + basis}
	}
	return map[string][]string{
		"remi": move(domain.LegacyInstallerRole, domain.AdminRole, domain.BasisInstaller),
		"ines": move("editor", domain.UserRole, domain.BasisLegacyToUser),
		"maya": move("viewer", domain.UserRole, domain.BasisLegacyToUser),
		"tam":  move("steward", domain.UserRole, domain.BasisLegacyToUser),
	}
}

// A module page composition installed, held by composition's receipt, is
// delivered renamed: installer to admin, editor, viewer and steward to user,
// asking nothing beyond what those roles held. Its grants move with the
// delivery, journaled by it with the crossover's Detail, and its receipt
// advances: no administrator owes an approval of a receipt nobody reviewed.
func TestARenameDeliveryMovesAComposedPagesGrants(t *testing.T) {
	h := newHarness(t)
	svc, events := journaled(h)
	rw, r := []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}, []*basev0.WorkScopeV1{sc("pages.note", "read")}
	m := legacyPage(1, rw, rw, r)
	m.Roles["steward"] = rw
	if _, err := svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", domain.LegacyInstallerRole, "remi")
	h.grant("pages", "editor", "ines")
	h.grant("pages", "viewer", "maya")
	h.grant("pages", "steward", "tam")
	if c := h.pagesAt(acme).Consent; c.OperationID != domain.ComposedConsent {
		t.Fatalf("setup: the page is not held by composition's receipt: %+v", c)
	}

	if _, err := svc.ApplyModule(h.ctx, twoRolePage(2, "read")); err != nil {
		t.Fatal(err)
	}
	if got := grantsOf(h); !slices.Equal(got, []string{"admin remi", "user ines", "user maya", "user tam"}) {
		t.Fatalf("the delivery left grants %v", got)
	}
	if got := movedBy(*events, "delivery:pages"); !maps.EqualFunc(got, wantMoves(), slices.Equal) {
		t.Fatalf("the delivery journaled the moves %v, want %v", got, wantMoves())
	}
	inst := h.pagesAt(acme)
	if c := inst.Consent; c.OperationID != domain.ComposedConsent || c.Generation != 2 {
		t.Fatalf("composition's receipt did not advance with the rename: %+v", c)
	}
	if _, ok := lastEventOn(*events, domain.InstallationReconverged, inst.ID); !ok {
		t.Fatal("the rename is not journaled as installation.reconverged")
	}
	if _, ok := lastEventOn(*events, domain.InstallationUpgradeAvailable, inst.ID); ok {
		t.Fatal("the rename alone offers an upgrade")
	}
	if up, err := svc.UpgradeAvailable(h.ctx, inst); err != nil || up {
		t.Fatalf("the rename alone leaves an upgrade: %v %v", up, err)
	}
	if m := h.must(h.root("ines", "pages")); !holds(m, "pages.note", "read") || holds(m, "pages.note", "write") {
		t.Fatalf("ines, the former editor, holds %v, want the user's read alone", effective(m))
	}
	if err := h.grantAs("remi", domain.UserRole, "dev"); err != nil {
		t.Fatalf("remi, now admin, administers the page's grants: %v", err)
	}
	code(t, h.grantAs("tam", domain.UserRole, "dev"), domain.Denied)
}

// A rename that asks more than the old roles held (here the user writes,
// which only the viewer crossing to it never did) stays held at
// composition's receipt: the update names the moves, the grants stand, and
// the approval moves them.
func TestARenameAskingMoreHoldsAComposedPage(t *testing.T) {
	h := newHarness(t)
	svc, events := journaled(h)
	rw, r := []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}, []*basev0.WorkScopeV1{sc("pages.note", "read")}
	if _, err := svc.ApplyModule(h.ctx, legacyPage(1, rw, nil, r)); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", domain.LegacyInstallerRole, "remi")
	h.grant("pages", "viewer", "maya")
	if _, err := svc.ApplyModule(h.ctx, twoRolePage(2, "read", "write")); err != nil {
		t.Fatal(err)
	}
	e, ok := lastEventOn(*events, domain.InstallationUpgradeAvailable, h.pagesAt(acme).ID)
	if !ok || !strings.Contains(e.Detail["widened"], "holders of role viewer move to user") {
		t.Fatalf("the held update does not name the move: %+v %v", e, ok)
	}
	if got := grantsOf(h); !slices.Equal(got, []string{"installer remi", "viewer maya"}) {
		t.Fatalf("a rename asking more moved grants before the approval: %v", got)
	}
	if m := h.must(h.root("maya", "pages")); holds(m, "pages.note", "write") {
		t.Fatal("maya, the viewer, writes before the approval")
	}
	if _, err := h.approvePage(svc, "remi"); err != nil {
		t.Fatal(err)
	}
	if got := grantsOf(h); !slices.Equal(got, []string{"admin remi", "user maya"}) {
		t.Fatalf("the approval left grants %v", got)
	}
}

// A host that installs modules itself (Config.HostInstallsModules) holds the
// renamed generation already, delivered before the core crossed grants over:
// its module page's record still has grants on the old names. Its next
// replay of the held generation (the boot's re-read of the delivery it
// keeps) moves them, journaled with the crossover's Detail, whether
// composition's receipt stands behind the rename, at it, or was never taken;
// a later replay changes nothing.
func TestAHostHoldingTheRenamedGenerationMovesStrandedGrantsAtItsNextReplay(t *testing.T) {
	const source = "sha256:the-signed-documents-of-pages-at-2"
	for _, receipt := range []string{"behind", "at the rename", "none"} {
		t.Run(receipt, func(t *testing.T) {
			hi := newHostInstalled(t)
			var events []domain.Event
			cfg := hi.cfg
			cfg.HostInstallsModules = true
			cfg.Journal = func(_ context.Context, _ authority.Tx, e domain.Event) error { events = append(events, e); return nil }
			svc, err := authority.New(hi.store, cfg)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{"remi", "ines", "maya", "tam"} {
				hi.store.PutPerson(domain.Person{ID: p, Organization: acme})
			}
			rw, r := []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}, []*basev0.WorkScopeV1{sc("pages.note", "read")}
			old := legacyPage(1, rw, rw, r)
			old.Roles["steward"] = rw
			if _, err := svc.ApplyModule(hi.ctx, old); err != nil {
				t.Fatal(err)
			}
			renamed := twoRolePage(2, "read")
			renamed.Source = source
			// The host's own record of the page at acme, its grants on the old
			// names, and the renamed generation held as a core before the
			// crossover composed it: the update held, the grants left.
			if err := hi.store.Write(hi.ctx, func(tx authority.Tx) error {
				if err := tx.PutInstallation(domain.Installation{ID: "record-pages", Organization: acme, Target: "pages", Status: domain.Active, Revision: 1}); err != nil {
					return err
				}
				for role, person := range map[string]string{domain.LegacyInstallerRole: "remi", "editor": "ines", "viewer": "maya", "steward": "tam"} {
					if err := tx.PutRoleGrant(domain.RoleGrant{InstallationID: "record-pages", Role: role, PersonID: person}); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			hold := func() {
				if err := svc.AdoptLegacyReach(hi.ctx); err != nil {
					t.Fatal(err)
				}
			}
			compose := func() {
				if err := hi.store.Write(hi.ctx, func(tx authority.Tx) error { return tx.PutModule(renamed) }); err != nil {
					t.Fatal(err)
				}
			}
			switch receipt {
			case "behind":
				hold()
				compose()
			case "at the rename":
				compose()
				hold()
			case "none":
				compose()
			}
			record := func() domain.Installation {
				var inst domain.Installation
				if err := hi.store.Read(hi.ctx, func(tx authority.Tx) (err error) { inst, err = tx.Installation("record-pages"); return err }); err != nil {
					t.Fatal(err)
				}
				return inst
			}
			if c := record().Consent; (receipt == "none") != (c.OperationID == "") {
				t.Fatalf("setup: receipt %s, consent %+v", receipt, c)
			}

			events = nil
			if reread, err := svc.RereadModule(hi.ctx, renamed); err != nil || reread {
				t.Fatalf("the held generation read again: reread %t, %v", reread, err)
			}
			var got []string
			if err := hi.store.Read(hi.ctx, func(tx authority.Tx) error {
				grants, err := tx.RoleGrants("record-pages")
				for _, g := range grants {
					got = append(got, g.Role+" "+g.PersonID)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			slices.Sort(got)
			if !slices.Equal(got, []string{"admin remi", "user ines", "user maya", "user tam"}) {
				t.Fatalf("the replay left grants %v", got)
			}
			if moved := movedBy(events, "delivery:pages"); !maps.EqualFunc(moved, wantMoves(), slices.Equal) {
				t.Fatalf("the replay journaled the moves %v, want %v", moved, wantMoves())
			}
			inst := record()
			if receipt != "none" && (inst.Consent.OperationID != domain.ComposedConsent || inst.Consent.Generation != 2) {
				t.Fatalf("composition's receipt is not at the renamed generation: %+v", inst.Consent)
			}
			if inst.Revision < 2 {
				t.Fatalf("the move did not raise the record's revision: %d", inst.Revision)
			}
			held, err := svc.HeldInstallations(hi.ctx, hi.person("remi"), acme)
			if err != nil || len(held) != 1 || !slices.Equal(held[0].Roles, []string{domain.AdminRole}) {
				t.Fatalf("remi holds %+v, %v; want admin on the page", held, err)
			}

			events = nil
			if _, err := svc.ApplyModule(hi.ctx, renamed); err != nil {
				t.Fatal(err)
			}
			if len(events) != 0 || record().Revision != inst.Revision {
				t.Fatalf("a later replay changed something: %+v", events)
			}
		})
	}
}
