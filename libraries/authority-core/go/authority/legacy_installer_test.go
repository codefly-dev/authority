package authority_test

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/google/uuid"
)

// The tests in this file pin the one-release STOPGAP of domain.LegacyInstallerRole
// (the alias and the grant crossover). Delete them with it.

// legacyPage is the module page as a delivery before the rename declared it:
// roles named installer, editor and viewer (each one present only when
// given scopes).
func legacyPage(generation uint64, installer, editor, viewer []*basev0.WorkScopeV1) domain.Module {
	m := pageModule(generation, false)
	m.Roles = map[string][]*basev0.WorkScopeV1{}
	for name, scopes := range map[string][]*basev0.WorkScopeV1{domain.LegacyInstallerRole: installer, "editor": editor, "viewer": viewer} {
		if scopes != nil {
			m.Roles[name] = scopes
		}
	}
	return m
}

// twoRolePage is the module page re-rendered with the two roles.
func twoRolePage(generation uint64, user ...string) domain.Module {
	m := pageModule(generation, false)
	m.Roles = map[string][]*basev0.WorkScopeV1{domain.AdminRole: {sc("pages.note", "read", "write")}, domain.UserRole: {sc("pages.note", user...)}}
	return m
}

// grantsOf is the page's grants as "role person|team", sorted.
func grantsOf(h *harness) []string {
	h.t.Helper()
	var out []string
	for _, g := range h.roleGrants("pages") {
		out = append(out, g.Role+" "+g.PersonID+g.TeamID)
	}
	slices.Sort(out)
	return out
}

func (h *harness) grantAs(caller, role, person string) error {
	_, err := h.svc.GrantRole(h.ctx, h.person(caller), authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, "pages").ID, Role: role, PersonID: person})
	return err
}

// A module page delivered before the rename still declares "installer" for
// its admin role. It is installed, and the holder of "installer" administers
// its grants and approves its pending update as an admin holder does.
func TestALegacyInstallerHolderAdministersAndApprovesAPage(t *testing.T) {
	h := newHarness(t)
	note := []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}
	if _, err := h.svc.ApplyModule(h.ctx, legacyPage(1, note, nil, []*basev0.WorkScopeV1{sc("pages.note", "read")})); err != nil {
		t.Fatalf("a page declaring installer is refused: %v", err)
	}
	h.grant("pages", domain.LegacyInstallerRole, "remi")
	h.grant("pages", "viewer", "maya")

	// A viewer approves and grants nothing; the installer holder does both.
	widened := legacyPage(2, note, note, []*basev0.WorkScopeV1{sc("pages.note", "read")})
	if _, err := h.svc.ApplyModule(h.ctx, widened); err != nil {
		t.Fatal(err)
	}
	if _, err := h.approvePage(h.svc, "maya"); err == nil {
		t.Fatal("a viewer approved the page's update")
	}
	if up, err := h.approvePage(h.svc, "remi"); err != nil || up.Consent.Generation != 2 {
		t.Fatalf("the installer holder's approval: %+v %v", up.Consent, err)
	}
	if err := h.grantAs("remi", "editor", "dev"); err != nil {
		t.Fatalf("the installer holder grants: %v", err)
	}
	code(t, h.grantAs("maya", "editor", "dev"), domain.Denied)
}

// The reviewer's probe, on the consented path: a page held at {installer,
// viewer} is redelivered as {admin, user}. Until an administrator approves,
// the approved declaration answers and the old grants stand; the approval
// moves Rémi's installer grant to admin and Maya's viewer grant to user,
// journaled as a grant and a revocation by the approver. Rémi then
// administers as admin; Maya holds user and administers nothing.
func TestApprovingTheTwoRoleDeliveryMovesTheOldGrants(t *testing.T) {
	h := newHarness(t)
	svc, events := journaled(h)
	if _, err := svc.ApplyModule(h.ctx, legacyPage(1, []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}, nil, []*basev0.WorkScopeV1{sc("pages.note", "read")})); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", domain.LegacyInstallerRole, "remi")
	h.grant("pages", "viewer", "maya")

	if _, err := svc.ApplyModule(h.ctx, twoRolePage(2, "read")); err != nil {
		t.Fatal(err)
	}
	if up, err := svc.UpgradeAvailable(h.ctx, h.pagesAt(acme)); err != nil || !up {
		t.Fatalf("the two-role delivery offers no upgrade: %v %v", up, err)
	}
	// What the pending update asks names the move, for the approver.
	if e, ok := lastEventOn(*events, domain.InstallationUpgradeAvailable, h.pagesAt(acme).ID); !ok ||
		!strings.Contains(e.Detail["widened"], "holders of role installer move to admin") || !strings.Contains(e.Detail["widened"], "holders of role viewer move to user") {
		t.Fatalf("installation.upgrade_available does not name the crossover: %+v %v", e, ok)
	}
	if got := grantsOf(h); !slices.Equal(got, []string{"installer remi", "viewer maya"}) {
		t.Fatalf("a held installation's grants moved before the approval: %v", got)
	}
	if m := h.must(h.root("maya", "pages")); !holds(m, "pages.note", "read") || holds(m, "pages.note", "write") {
		t.Fatalf("maya, the viewer before the approval, holds %v", effective(m))
	}

	if _, err := h.approvePage(svc, "remi"); err != nil {
		t.Fatalf("the installer holder's approval: %v", err)
	}
	if got := grantsOf(h); !slices.Equal(got, []string{"admin remi", "user maya"}) {
		t.Fatalf("the approval left grants %v, want admin remi and user maya", got)
	}
	granted, revoked := 0, 0
	for _, e := range *events {
		if e.Actor != "remi" {
			continue
		}
		switch {
		case e.Kind == domain.RoleGranted && (e.Detail["role"] == "admin" && e.Detail["person"] == "remi" && e.Detail[domain.CrossoverFrom] == "installer" ||
			e.Detail["role"] == "user" && e.Detail["person"] == "maya" && e.Detail[domain.CrossoverFrom] == "viewer"):
			granted++
		case e.Kind == domain.RoleRevoked && e.Detail[domain.CrossoverFrom] == e.Detail["role"] &&
			(e.Detail["role"] == "installer" && e.Detail["person"] == "remi" || e.Detail["role"] == "viewer" && e.Detail["person"] == "maya"):
			revoked++
		}
	}
	if granted != 2 || revoked != 2 {
		t.Fatalf("the move was journaled as %d grants and %d revocations by the approver marked as the crossover, want 2 and 2: %+v", granted, revoked, *events)
	}
	if err := h.grantAs("remi", domain.UserRole, "dev"); err != nil {
		t.Fatalf("remi, now admin, administers the page's grants: %v", err)
	}
	if m := h.must(h.root("maya", "pages")); !holds(m, "pages.note", "read") || holds(m, "pages.note", "write") {
		t.Fatalf("maya, now user, holds %v", effective(m))
	}
	code(t, h.grantAs("maya", domain.AdminRole, "maya"), domain.Denied)
}

// The unconsented path: an installation no consent holds (a solution its
// host installed without one) follows each delivery, so its grants move on
// the delivery itself, journaled by the delivery. This is the Wiki's shape:
// the new user only reads. The installer's holder holds admin; the editor
// and the steward wrote what user does not cover, so they hold admin and
// keep writing; the viewer, whose read user covers, holds user.
func TestADeliveryMovesTheOldGrantsOfAnUnconsentedInstallation(t *testing.T) {
	h := newHarness(t)
	svc, events := journaled(h)
	rw, r := []*basev0.WorkScopeV1{sc("legacy.note", "read", "write")}, []*basev0.WorkScopeV1{sc("legacy.note", "read")}
	m := solution("legacy", true)
	m.InstallationRole = domain.NoInstallationRole
	m.Roles = map[string][]*basev0.WorkScopeV1{domain.LegacyInstallerRole: rw, "editor": rw, "viewer": r, "steward": rw}
	if _, err := svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	inst, err := svc.InstallAsHost(h.ctx, acme, "legacy", "", "alex", nil)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Consent.OperationID != "" {
		t.Fatalf("setup: a host's install recorded a consent: %+v", inst.Consent)
	}
	grant := func(caller, role, person string) error {
		_, err := svc.GrantRole(h.ctx, h.person(caller), authority.RoleRequest{Organization: acme, InstallationID: inst.ID, Role: role, PersonID: person})
		return err
	}
	for role, person := range map[string]string{domain.LegacyInstallerRole: "remi", "editor": "ines", "viewer": "maya", "steward": "tam"} {
		if err := grant("alex", role, person); err != nil {
			t.Fatal(err)
		}
	}

	next := m
	next.Generation = 2
	next.Roles = map[string][]*basev0.WorkScopeV1{domain.AdminRole: rw, domain.UserRole: r}
	if _, err := svc.ApplyModule(h.ctx, next); err != nil {
		t.Fatal(err)
	}
	grants, err := svc.ListRoleGrants(h.ctx, h.admin(acme), acme, inst.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, g := range grants {
		got = append(got, g.Role+" "+g.PersonID)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"admin ines", "admin remi", "admin tam", "user maya"}) {
		t.Fatalf("the delivery left grants %v, want admin for remi, ines and tam, user for maya", got)
	}
	moved := map[string]string{}
	for _, e := range *events {
		if e.Kind == domain.RoleGranted && e.Actor == "delivery:legacy" {
			moved[e.Detail["person"]] = e.Detail[domain.CrossoverFrom] + ">" + e.Detail["role"]
		}
	}
	if want := map[string]string{"remi": "installer>admin", "ines": "editor>admin", "maya": "viewer>user", "tam": "steward>admin"}; !maps.Equal(moved, want) {
		t.Fatalf("the moves journaled by the delivery are %v, want %v", moved, want)
	}
	if err := grant("remi", domain.UserRole, "dev"); err != nil {
		t.Fatalf("remi, now admin, administers the grants: %v", err)
	}
	code(t, grant("maya", domain.UserRole, "dev"), domain.Denied)
}

// A page whose roles were derived: the names derived before the rename
// (installer, editor, viewer) become the two derived now
// (decide.StandardRoles) through the same move, at the approval of the
// update the new derivation offers. The derived user reads and writes, so it
// covers the old editor's write and the viewer's read: both hold user.
func TestApprovingADerivedPagesNewRolesMovesTheOldGrants(t *testing.T) {
	h := newHarness(t)
	rw, r := []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}, []*basev0.WorkScopeV1{sc("pages.note", "read")}
	if _, err := h.svc.ApplyModule(h.ctx, legacyPage(1, rw, rw, r)); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", domain.LegacyInstallerRole, "remi")
	h.grant("pages", "editor", "ines")
	h.grant("pages", "viewer", "maya")
	derived := pageModule(2, false)
	derived.Roles = decide.StandardRoles(derived)
	if _, err := h.svc.ApplyModule(h.ctx, derived); err != nil {
		t.Fatal(err)
	}
	if _, err := h.approvePage(h.svc, "remi"); err != nil {
		t.Fatalf("the installer holder's approval: %v", err)
	}
	if got := grantsOf(h); !slices.Equal(got, []string{"admin remi", "user ines", "user maya"}) {
		t.Fatalf("the approval left grants %v, want admin remi, user ines and user maya", got)
	}
	if !holds(h.must(h.root("maya", "pages")), "pages.note", "write") {
		t.Fatal("maya, now user, does not hold the derived user's write")
	}
}

// A user approves no page update and administers no grant; the admin does.
func TestAUserNeitherApprovesNorAdministersAPage(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.ApplyModule(h.ctx, twoRolePage(1, "read")); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", domain.AdminRole, "remi")
	h.grant("pages", domain.UserRole, "maya")
	if _, err := h.svc.ApplyModule(h.ctx, twoRolePage(2, "read", "write")); err != nil {
		t.Fatal(err)
	}
	_, err := h.approvePage(h.svc, "maya")
	refused(t, err, "requires an administrator or owner")
	code(t, h.grantAs("maya", domain.UserRole, "dev"), domain.Denied)
	if up, err := h.approvePage(h.svc, "remi"); err != nil || up.Consent.Generation != 2 {
		t.Fatalf("the admin's approval: %+v %v", up.Consent, err)
	}
}

// A subject holding two old roles that move to the same one, or holding the
// successor already, is granted it once: one grant event, or none.
func TestTheCrossoverGrantsEachSubjectOnce(t *testing.T) {
	h := newHarness(t)
	svc, events := journaled(h)
	rw, r := []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}, []*basev0.WorkScopeV1{sc("pages.note", "read")}
	before := legacyPage(1, rw, rw, r)
	before.Roles[domain.UserRole] = r
	if _, err := svc.ApplyModule(h.ctx, before); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", "editor", "ines")
	h.grant("pages", "viewer", "ines")
	h.grant("pages", "viewer", "maya")
	h.grant("pages", domain.UserRole, "maya")
	h.grant("pages", domain.LegacyInstallerRole, "remi")
	// The new user reads and writes, so it covers the editor and the viewer.
	if _, err := svc.ApplyModule(h.ctx, twoRolePage(2, "read", "write")); err != nil {
		t.Fatal(err)
	}
	*events = nil
	if _, err := h.approvePage(svc, "remi"); err != nil {
		t.Fatal(err)
	}
	if got := grantsOf(h); !slices.Equal(got, []string{"admin remi", "user ines", "user maya"}) {
		t.Fatalf("the approval left grants %v", got)
	}
	granted := map[string]int{}
	for _, e := range *events {
		if e.Kind == domain.RoleGranted {
			granted[e.Detail["person"]+" "+e.Detail["role"]]++
		}
	}
	if granted["ines user"] != 1 || granted["maya user"] != 0 || granted["remi admin"] != 1 || len(granted) != 2 {
		t.Fatalf("grant events %v, want one each for ines and remi and none for maya, who held user", granted)
	}
}

// Outside the page-role rename the crossover does not run: a target keeping a
// custom role beside admin and user, which drops a role it named editor, ends
// that role's grants as it ends any dropped role's.
func TestACustomEditorDroppedBesideAThirdRoleEndsItsGrants(t *testing.T) {
	h := newHarness(t)
	rw := []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}
	m := twoRolePage(1, "read")
	m.Roles["editor"] = rw
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", "editor", "ines")
	h.grant("pages", domain.AdminRole, "remi")
	next := twoRolePage(2, "read")
	next.Roles["auditor"] = []*basev0.WorkScopeV1{sc("pages.note", "read")}
	if _, err := h.svc.ApplyModule(h.ctx, next); err != nil {
		t.Fatal(err)
	}
	if _, err := h.approvePage(h.svc, "remi"); err != nil {
		t.Fatal(err)
	}
	if got := grantsOf(h); !slices.Equal(got, []string{"admin remi"}) {
		t.Fatalf("grants %v, want the editor's ended and not moved", got)
	}
}

// When the declaration a grant was held under is unknown (a legacy consent
// recording no generation, whose approved declaration the store does not
// keep), what an editor, viewer or steward held cannot be compared: each
// moves to user, keeping day-to-day access and handing nobody grant
// management, and the move is journaled as unknown coverage. The installer
// still moves to admin.
func TestAnUnknownDeclarationMovesEditorsViewersAndStewardsToUser(t *testing.T) {
	h := newHarness(t)
	svc, events := journaled(h)
	rw, r := []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}, []*basev0.WorkScopeV1{sc("pages.note", "read")}
	m := legacyPage(1, rw, rw, r)
	m.Roles["steward"] = rw
	if _, err := svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	for role, person := range map[string]string{domain.LegacyInstallerRole: "remi", "editor": "ines", "viewer": "maya", "steward": "tam"} {
		h.grant("pages", role, person)
	}
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error {
		i, err := tx.Installation(h.inst(acme, "pages").ID)
		if err != nil {
			return err
		}
		i.Consent.Generation, i.Consent.Digest = 0, ""
		return tx.PutInstallation(i)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApplyModule(h.ctx, twoRolePage(2, "read")); err != nil {
		t.Fatal(err)
	}
	*events = nil
	if _, err := h.approvePage(svc, "remi"); err != nil {
		t.Fatalf("the installer holder's approval: %v", err)
	}
	if got := grantsOf(h); !slices.Equal(got, []string{"admin remi", "user ines", "user maya", "user tam"}) {
		t.Fatalf("the approval left grants %v, want admin remi and user for ines, maya and tam", got)
	}
	basis := map[string]string{}
	for _, e := range *events {
		if e.Kind == domain.RoleGranted {
			basis[e.Detail["person"]] = e.Detail[domain.CrossoverFrom] + ">" + e.Detail["role"] + " " + e.Detail[domain.CrossoverBasis]
		}
	}
	want := map[string]string{
		"remi": "installer>admin " + domain.BasisInstaller,
		"ines": "editor>user " + domain.BasisUnknownDeclaration,
		"maya": "viewer>user " + domain.BasisUnknownDeclaration,
		"tam":  "steward>user " + domain.BasisUnknownDeclaration,
	}
	if !maps.Equal(basis, want) {
		t.Fatalf("the moves journaled %v, want %v", basis, want)
	}
	code(t, h.grantAs("ines", domain.UserRole, "dev"), domain.Denied)
}

// crossovers is, for each person granted a role in events, its
// "old>new basis".
func crossovers(events []domain.Event) map[string]string {
	out := map[string]string{}
	for _, e := range events {
		if e.Kind == domain.RoleGranted && e.Detail[domain.CrossoverFrom] != "" {
			out[e.Detail["person"]] = e.Detail[domain.CrossoverFrom] + ">" + e.Detail["role"] + " " + e.Detail[domain.CrossoverBasis]
		}
	}
	return out
}

// The Wiki's shape, on the approval path: the old editor wrote, the new user
// only reads. The pending update names that the editor's holders move to
// admin, and the approval moves them there on the declaration they were held
// under (declared_coverage), so they keep writing.
func TestApprovingTheWikiShapeMovesTheEditorToAdminOnItsDeclaration(t *testing.T) {
	h := newHarness(t)
	svc, events := journaled(h)
	rw, r := []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}, []*basev0.WorkScopeV1{sc("pages.note", "read")}
	if _, err := svc.ApplyModule(h.ctx, legacyPage(1, rw, rw, r)); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", domain.LegacyInstallerRole, "remi")
	h.grant("pages", "editor", "ines")
	h.grant("pages", "viewer", "maya")
	if _, err := svc.ApplyModule(h.ctx, twoRolePage(2, "read")); err != nil {
		t.Fatal(err)
	}
	if e, ok := lastEventOn(*events, domain.InstallationUpgradeAvailable, h.pagesAt(acme).ID); !ok || !strings.Contains(e.Detail["widened"], "holders of role editor move to admin") {
		t.Fatalf("the pending update does not name the editor's move to admin: %+v %v", e, ok)
	}
	*events = nil
	if _, err := h.approvePage(svc, "remi"); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"remi": "installer>admin " + domain.BasisInstaller,
		"ines": "editor>admin " + domain.BasisCoverage,
		"maya": "viewer>user " + domain.BasisCoverage,
	}
	if got := crossovers(*events); !maps.Equal(got, want) {
		t.Fatalf("the approval moved %v, want %v", got, want)
	}
	if !holds(h.must(h.root("ines", "pages")), "pages.note", "write") {
		t.Fatal("ines, the editor, lost write")
	}
}

// A consent behind the delivered generation: generation 1 is approved, a
// generation 2 widening the viewer to write is left pending, and generation 3
// is the two roles with a user that reads. The pending update names each move
// the approval makes, and the approval reads coverage from the generation the
// grants were held under (1, where the viewer read), not from the pending 2:
// the viewer moves to user.
func TestApprovingBehindTheDeliveredGenerationReadsTheHeldGeneration(t *testing.T) {
	h := newHarness(t)
	svc, events := journaled(h)
	rw, r := []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}, []*basev0.WorkScopeV1{sc("pages.note", "read")}
	if _, err := svc.ApplyModule(h.ctx, legacyPage(1, rw, nil, r)); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", domain.LegacyInstallerRole, "remi")
	h.grant("pages", "viewer", "maya")
	if _, err := svc.ApplyModule(h.ctx, legacyPage(2, rw, nil, rw)); err != nil {
		t.Fatal(err)
	}
	if held := h.pagesAt(acme); held.Consent.Generation != 1 {
		t.Fatalf("setup: the widening to generation 2 was taken: %+v", held.Consent)
	}
	if _, err := svc.ApplyModule(h.ctx, twoRolePage(3, "read")); err != nil {
		t.Fatal(err)
	}
	e, ok := lastEventOn(*events, domain.InstallationUpgradeAvailable, h.pagesAt(acme).ID)
	if !ok || !strings.Contains(e.Detail["widened"], "behind") || !strings.Contains(e.Detail["widened"], "holders of role viewer move to user") ||
		!strings.Contains(e.Detail["widened"], "holders of role installer move to admin") {
		t.Fatalf("the pending update behind the delivered generation does not name the moves: %+v %v", e, ok)
	}
	*events = nil
	if _, err := h.approvePage(svc, "remi"); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"remi": "installer>admin " + domain.BasisInstaller, "maya": "viewer>user " + domain.BasisCoverage}
	if got := crossovers(*events); !maps.Equal(got, want) {
		t.Fatalf("the approval moved %v, want %v", got, want)
	}
}

// unansweringStore fails every read of a kept approved declaration while fail is
// set, as a store that cannot answer would.
type unansweringStore struct {
	authority.Store
	fail *bool
}

type unansweringTx struct {
	authority.Tx
	fail *bool
}

func (f unansweringTx) ApprovedModule(name string, generation uint64, digest string) (domain.Module, error) {
	if *f.fail {
		return domain.Module{}, errors.New("the store cannot answer")
	}
	return f.Tx.ApprovedModule(name, generation, digest)
}

func (f unansweringStore) Read(ctx context.Context, fn func(authority.Tx) error) error {
	return f.Store.Read(ctx, func(tx authority.Tx) error { return fn(unansweringTx{tx, f.fail}) })
}

func (f unansweringStore) Write(ctx context.Context, fn func(authority.Tx) error) error {
	return f.Store.Write(ctx, func(tx authority.Tx) error { return fn(unansweringTx{tx, f.fail}) })
}

// A store that cannot answer what the grants were held under fails the
// approval: no grant moves on a guess, and the old grants stand.
func TestAStoreErrorReadingTheHeldDeclarationFailsTheApproval(t *testing.T) {
	h := newHarness(t)
	fail := false
	svc, err := authority.New(unansweringStore{h.store, &fail}, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	rw, r := []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}, []*basev0.WorkScopeV1{sc("pages.note", "read")}
	if _, err := svc.ApplyModule(h.ctx, legacyPage(1, rw, rw, r)); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", domain.LegacyInstallerRole, "remi")
	h.grant("pages", "editor", "ines")
	if _, err := svc.ApplyModule(h.ctx, twoRolePage(2, "read")); err != nil {
		t.Fatal(err)
	}
	a, err := svc.Review(h.ctx, h.person("remi"), acme, "pages")
	if err != nil {
		t.Fatal(err)
	}
	a.OperationID = uuid.NewString()
	fail = true
	if _, err := svc.Install(h.ctx, h.person("remi"), acme, "pages", "", "", &a, nil); err == nil || !strings.Contains(err.Error(), "cannot answer") {
		t.Fatalf("the approval with a store that cannot answer: want its error, got %v", err)
	}
	fail = false
	if got := grantsOf(h); !slices.Equal(got, []string{"editor ines", "installer remi"}) {
		t.Fatalf("a failed approval moved grants: %v", got)
	}
}
