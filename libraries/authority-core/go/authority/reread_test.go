package authority_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/memstore"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// A host that learns to read a declaration field reads the delivery it holds
// for a generation as a different declaration than the one it composed from
// it before. That is the same delivery read again, not a new generation: the
// core takes it as a redelivery that keeps its generation (RereadModule),
// proven by the delivery's source, holding every consent at what it approved.

const deliveryOfA = "sha256:the-signed-documents-of-a-at-1"

// readWithThrough is solution a at generation 1 as a host reading roles'
// through declarations reads it: the editor also writes the store's kind
// through the store binding, which a host that did not read through never saw.
func readWithThrough(source string) domain.Module {
	m := solution("a", true)
	m.Roles["editor"] = append(m.Roles["editor"], sc(kind, "write"))
	m.Through = map[string]map[string][]*basev0.WorkScopeV1{"editor": {"store": {sc(kind, "write")}}}
	m.Source = source
	return m
}

func TestARereadOfTheHeldGenerationWidensNothingUntilTheUpgradeIsApproved(t *testing.T) {
	h := newHarness(t)
	svc, events := journalingService(h)
	h.grant("a", "editor", "maya")
	// writes is whether the editor's hop through the store binding writes the
	// store's kind, owned by a's principal at acme.
	writes := func() error {
		_, err := h.through("maya", "a", "store", owned(kind, h.principal(acme, "a"), []string{"write"}))
		return err
	}
	if writes() == nil {
		t.Fatal("the editor writes the store before any re-read")
	}
	approvedBefore := h.stored(acme, "a").Consent

	// Delivered on the delivery path, the same generation read differently
	// from no recorded source is still refused: only the host's re-read of
	// the delivery it keeps vouches for it.
	if _, err := svc.ApplyModule(h.ctx, readWithThrough(deliveryOfA)); err == nil {
		t.Fatal("a changed declaration at the held generation was applied without a re-read")
	}
	reread, err := svc.RereadModule(h.ctx, readWithThrough(deliveryOfA))
	if err != nil || !reread {
		t.Fatalf("the held generation read again with through: reread %t, %v", reread, err)
	}

	inst := h.stored(acme, "a")
	if inst.Status != domain.Active || inst.Consent.Generation != 1 || inst.Consent.Digest != approvedBefore.Digest || inst.Consent.ReachDigest != approvedBefore.ReachDigest {
		t.Fatalf("the re-read moved the consent: %+v, was %+v", inst.Consent, approvedBefore)
	}
	if writes() == nil {
		t.Fatal("the re-read widened the editor without an approval")
	}
	if _, err := h.through("maya", "a", "store", owned(kind, h.principal(acme, "a"), []string{"read"})); err != nil {
		t.Fatalf("the editor lost what was approved: %v", err)
	}
	if up, err := svc.UpgradeAvailable(h.ctx, inst); err != nil || !up {
		t.Fatalf("the re-read offers no upgrade: %t, %v", up, err)
	}
	approved, err := svc.ApprovedDeclaration(h.ctx, inst)
	if err != nil || slices.ContainsFunc(approved.Roles["editor"], func(s *basev0.WorkScopeV1) bool {
		return slices.Contains(s.GetActions(), "write") && s.GetResourceKind() == kind
	}) {
		t.Fatalf("the approved declaration is the re-read, not what was approved: %v, %v", approved.Roles["editor"], err)
	}
	if !slices.Contains(kinds(*events), domain.InstallationUpgradeAvailable) || slices.Contains(kinds(*events), domain.RoleRevoked) {
		t.Fatalf("the re-read is not offered as an upgrade, or revoked a grant: %v", kinds(*events))
	}

	// The administrator approves the re-read at the same generation: both
	// readings stay kept, each for the consent that approved it.
	if _, err := svc.Install(h.ctx, h.admin(acme), acme, "a", "author", "remi", h.approval(acme, "a"), nil); err != nil {
		t.Fatalf("the re-read's upgrade is not approved: %v", err)
	}
	if err := writes(); err != nil {
		t.Fatalf("the approved upgrade does not reach: %v", err)
	}
	next := readWithThrough("sha256:the-signed-documents-of-a-at-2")
	next.Generation = 2
	if _, err := svc.ApplyModule(h.ctx, next); err != nil {
		t.Fatal(err)
	}
	if err := writes(); err != nil {
		t.Fatalf("behind generation 2, the consent to the re-read no longer holds it: %v", err)
	}
	for _, org := range []string{acme, globex} {
		if _, err := svc.ApprovedDeclaration(h.ctx, h.stored(org, "a")); err != nil {
			t.Fatalf("the reading %s approved is not kept: %v", org, err)
		}
	}
}

func TestARereadFromAnotherDeliveryOrOfAGenerationNotHeldIsRefused(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.RereadModule(h.ctx, readWithThrough("")); err == nil {
		t.Fatal("a re-read naming no source was taken")
	}
	ahead := readWithThrough(deliveryOfA)
	ahead.Generation = 2
	if _, err := h.svc.RereadModule(h.ctx, ahead); err == nil {
		t.Fatal("a re-read of a generation the core does not hold was taken")
	}
	if _, err := h.svc.RereadModule(h.ctx, readWithThrough(deliveryOfA)); err != nil {
		t.Fatal(err)
	}
	// From then on, the generation is held from that delivery: another one,
	// read as another declaration, is a new generation on either path.
	other := readWithThrough("sha256:another-delivery-at-1")
	other.Roles["viewer"] = other.Roles["viewer"][:1]
	for name, apply := range map[string]func(domain.Module) error{
		"re-read":  func(m domain.Module) error { _, err := h.svc.RereadModule(h.ctx, m); return err },
		"delivery": func(m domain.Module) error { _, err := h.svc.ApplyModule(h.ctx, m); return err },
	} {
		err := apply(other)
		code(t, err, domain.Precondition)
		refused(t, err, "another delivery is a new generation")
		_ = name
	}
	held, err := h.svc.Composed(h.ctx, "a")
	if err != nil || held.Source != deliveryOfA || len(held.Through) == 0 {
		t.Fatalf("the refused delivery changed what is held: %+v, %v", held, err)
	}
}

func TestARereadReadingTheSameRecordsItsSourceAndANarrowingAppliesAtOnce(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	same := solution("a", true)
	same.Source = deliveryOfA
	if reread, err := h.svc.RereadModule(h.ctx, same); err != nil || reread {
		t.Fatalf("the same declaration read again: reread %t, %v; want a replay", reread, err)
	}
	if held, err := h.svc.Composed(h.ctx, "a"); err != nil || held.Source != deliveryOfA {
		t.Fatalf("the replay did not record the source it was read from: %q, %v", held.Source, err)
	}
	before := h.must(h.root("maya", "a"))
	revision := h.stored(acme, "a").Revision

	narrower := solution("a", true)
	narrower.Roles["viewer"] = narrower.Roles["viewer"][:2] // the legacy kind was never the viewer's
	narrower.Source = deliveryOfA
	if reread, err := h.svc.RereadModule(h.ctx, narrower); err != nil || !reread {
		t.Fatalf("a narrowing re-read: reread %t, %v", reread, err)
	}
	inst := h.stored(acme, "a")
	if inst.Status != domain.Active || inst.Revision <= revision || inst.Consent.Generation != 1 {
		t.Fatalf("a narrowing re-read did not re-converge the installation: %+v", inst)
	}
	if up, err := h.svc.UpgradeAvailable(h.ctx, inst); err != nil || up {
		t.Fatalf("a narrowing re-read offers an upgrade: %t, %v", up, err)
	}
	if err := h.check(before); err == nil {
		t.Fatal("what was issued under the wider reading still checks")
	}
	if _, err := h.root("maya", "a", sc(legacyKind, "read")); err == nil {
		t.Fatal("the viewer still holds what the narrowing re-read dropped")
	}
	if _, err := h.root("maya", "a"); err != nil {
		t.Fatalf("the viewer's grant ended with the narrowing: %v", err)
	}
	_ = errors.New
	_ = authority.OfferDigest
}

// A module page held by composition's receipt is held the same way: a re-read
// widening one of its roles keeps the grant at what the receipt holds and
// offers the upgrade; composition did not grow, so the receipt is not
// re-taken.
func TestAModulePageReadAgainWiderHoldsItsHoldersAtItsReceipt(t *testing.T) {
	h := newHarness(t)
	svc, events := journalingService(h)
	if _, err := svc.ApplyModule(h.ctx, pageModule(1, true)); err != nil {
		t.Fatal(err)
	}
	inst := h.pagesAt(acme)
	if _, err := svc.GrantRole(h.ctx, h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: inst.ID, Role: "viewer", PersonID: "maya"}); err != nil {
		t.Fatal(err)
	}
	wider := pageModule(1, true)
	wider.Roles["viewer"] = []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}
	wider.Source = "sha256:the-signed-documents-of-pages-at-1"
	if reread, err := svc.RereadModule(h.ctx, wider); err != nil || !reread {
		t.Fatalf("the page read again: reread %t, %v", reread, err)
	}
	write := authority.IssueRequest{Audience: "pages", Scopes: []*basev0.WorkScopeV1{sc("pages.note", "write")}}
	if _, err := svc.IssueForPerson(h.ctx, h.person("maya"), write); err == nil {
		t.Fatal("a viewer granted read holds write after the page was read again wider")
	}
	if _, err := svc.IssueForPerson(h.ctx, h.person("maya"), authority.IssueRequest{Audience: "pages", Scopes: []*basev0.WorkScopeV1{sc("pages.note", "read")}}); err != nil {
		t.Fatalf("the viewer's grant no longer answers at its receipt: %v", err)
	}
	if up, err := svc.UpgradeAvailable(h.ctx, h.pagesAt(acme)); err != nil || !up {
		t.Fatalf("the page offers no upgrade: %t, %v", up, err)
	}
	if !slices.Contains(kinds(*events), domain.InstallationUpgradeAvailable) || slices.Contains(kinds(*events), domain.RoleRevoked) {
		t.Fatalf("the widening is not offered as an upgrade, or revoked a grant: %v", kinds(*events))
	}
}

// unkeptApproved is a host store that keeps no approved declaration of
// module until written after the store is wrapped: a consent recorded before
// the host kept them, whose declaration it rebuilds later from the documents
// it received (a host may hold such a consent; it must not hold its holders
// to whatever the core composes now once that changes).
type unkeptApproved struct {
	*memstore.Store
	module string
	kept   map[string]bool
}

type unkeptApprovedTx struct {
	authority.Tx
	s *unkeptApproved
}

func (t unkeptApprovedTx) ApprovedModule(name string, generation uint64, digest string) (domain.Module, error) {
	if name == t.s.module && !t.s.kept[digest] {
		return domain.Module{}, fmt.Errorf("%s@%d %s: %w", name, generation, digest, domain.ErrNotFound)
	}
	return t.Tx.ApprovedModule(name, generation, digest)
}

func (t unkeptApprovedTx) PutApprovedModule(m domain.Module) error {
	if m.Name == t.s.module {
		digest, err := authority.OfferDigest(m)
		if err != nil {
			return err
		}
		t.s.kept[digest] = true
	}
	return t.Tx.PutApprovedModule(m)
}

func (s *unkeptApproved) Read(ctx context.Context, fn func(authority.Tx) error) error {
	return s.Store.Read(ctx, func(tx authority.Tx) error { return fn(unkeptApprovedTx{tx, s}) })
}

func (s *unkeptApproved) Write(ctx context.Context, fn func(authority.Tx) error) error {
	return s.Store.Write(ctx, func(tx authority.Tx) error { return fn(unkeptApprovedTx{tx, s}) })
}

// A consent at the held generation whose approved declaration the host does
// not keep yet reads the module as composed, which until a re-read is what it
// approved. A re-read that widens a role must not reach its holders through
// that: the core keeps the reading the consent approved when it holds the
// consent there.
func TestARereadWidensNothingForAConsentWhoseApprovedReadingIsNotKeptYet(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "editor", "maya")
	store := &unkeptApproved{Store: h.store, module: "a", kept: map[string]bool{}}
	svc, err := authority.New(store, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	writes := func() error {
		_, err := svc.IssueForPerson(h.ctx, h.person("maya"), authority.IssueRequest{Audience: "a", Scopes: []*basev0.WorkScopeV1{owned("a.note", h.principal(acme, "a"), []string{"write"})}})
		return err
	}
	if writes() == nil {
		t.Fatal("the editor writes a.note before any re-read")
	}
	wider := solution("a", true)
	wider.Roles["editor"] = []*basev0.WorkScopeV1{sc("a.note", "read", "write"), sc(kind, "read")}
	wider.Source = deliveryOfA
	if reread, err := svc.RereadModule(h.ctx, wider); err != nil || !reread {
		t.Fatalf("the held generation read again wider: reread %t, %v", reread, err)
	}
	if writes() == nil {
		t.Fatal("the re-read widened the editor without an approval: the reading its consent approved was not kept")
	}
	if _, err := svc.IssueForPerson(h.ctx, h.person("maya"), authority.IssueRequest{Audience: "a", Scopes: []*basev0.WorkScopeV1{owned("a.note", h.principal(acme, "a"), []string{"read"})}}); err != nil {
		t.Fatalf("the editor lost what was approved: %v", err)
	}
	if up, err := svc.UpgradeAvailable(h.ctx, h.stored(acme, "a")); err != nil || !up {
		t.Fatalf("the re-read offers no upgrade: %t, %v", up, err)
	}
}
