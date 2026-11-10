package authority_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// widenTo delivers a generation of a asking more than generation 1, so acme's
// installation stays on its consent and its holders hold the approved roles.
func widenTo(h *harness, generation uint64) domain.Module {
	h.t.Helper()
	wider := solution("a", true)
	wider.Generation = generation
	wider.Roles["viewer"] = []*basev0.WorkScopeV1{sc("a.note", "read", "write"), sc(kind, "read"), sc(legacyKind, "read")}
	if _, err := h.svc.ApplyModule(h.ctx, wider); err != nil {
		h.t.Fatal(err)
	}
	return wider
}

// The declaration that governs what holders hold is one rule, exported:
// a host reading authority.ApprovedDeclaration sees what issuance applies.
// It is the composed module while the consent stands at its generation, the
// approved one once a redelivery asked more, and the composed one again after
// the upgrade.
func TestTheExportedApprovedDeclarationIsIssuancesChoice(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	declared := func() domain.Module {
		t.Helper()
		m, err := h.svc.ApprovedDeclaration(h.ctx, h.stored(acme, "a"))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := declared(); m.Generation != 1 {
		t.Fatalf("at its own generation the rule answers generation %d", m.Generation)
	}
	widenTo(h, 2)
	m := declared()
	if m.Generation != 1 || !slices.Equal(m.Roles["viewer"][0].GetActions(), []string{"read"}) {
		t.Fatalf("behind the delivered generation the rule answers %d with viewer %v, want the approved generation 1", m.Generation, m.Roles["viewer"])
	}
	// Issuance holds the viewer to exactly what the rule answers.
	exactly(t, h.must(h.root("maya", "a")), "a.note", h.principal(acme, "a"), []string{"read"})

	if _, err := h.svc.Install(h.ctx, h.admin(acme), acme, "a", "author", "remi", h.approval(acme, "a"), nil); err != nil {
		t.Fatal(err)
	}
	if m := declared(); m.Generation != 2 || !slices.Equal(m.Roles["viewer"][0].GetActions(), []string{"read", "write"}) {
		t.Fatalf("after the upgrade the rule answers generation %d with viewer %v", m.Generation, m.Roles["viewer"])
	}
	exactly(t, h.must(h.root("maya", "a")), "a.note", h.principal(acme, "a"), []string{"read", "write"})
}

// A kept declaration that is not the offer the consent approved (its digest
// is not the consent's) governs nothing: issuance through the installation is
// refused by name, and the exported rule answers the same refusal, so no host
// lists roles from it either.
func TestAnApprovedDeclarationThatIsNotTheConsentedOfferRefusesIssuance(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	widenTo(h, 2)
	h.must(h.root("maya", "a"))

	inst := h.stored(acme, "a")
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error {
		inst.Consent.Digest = "sha256:another-offer"
		return tx.PutInstallation(inst)
	}); err != nil {
		t.Fatal(err)
	}
	_, err := h.root("maya", "a")
	code(t, err, domain.Precondition)
	refused(t, err, "installation "+inst.ID+" is not the offer it approved")
	refused(t, err, "generation 1 of a")
	_, ruleErr := h.svc.ApprovedDeclaration(h.ctx, inst)
	if ruleErr == nil || ruleErr.Error() != err.Error() {
		t.Fatalf("the exported rule answers %v, issuance %v", ruleErr, err)
	}
	// A target no longer composed is not found, not a declaration.
	if _, err := h.svc.ApprovedDeclaration(h.ctx, domain.Installation{Target: "never"}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("an uncomposed target answers %v, want ErrNotFound", err)
	}
}

// A redelivery that names a scope governing the installation's sources asks
// something new of the organization: until an administrator approves it, the
// approved declaration governs no source, and a host reading it admits nobody
// by the new scope. Approved, it governs.
func TestAGoverningScopeAddedByARedeliveryWaitsForApproval(t *testing.T) {
	h := newHarness(t)
	governed := solution("a", true)
	governed.Generation = 2
	governed.SourceGovernance = []*basev0.WorkScopeV1{sc("a.note", "write")}
	if _, err := h.svc.ApplyModule(h.ctx, governed); err != nil {
		t.Fatal(err)
	}
	inst := h.stored(acme, "a")
	upgrade, err := h.svc.UpgradeAvailable(h.ctx, inst)
	if err != nil || !upgrade {
		t.Fatalf("a governing scope added asks no approval: upgrade %v, %v", upgrade, err)
	}
	m, err := h.svc.ApprovedDeclaration(h.ctx, inst)
	if err != nil {
		t.Fatal(err)
	}
	if m.Generation != 1 || len(m.SourceGovernance) != 0 {
		t.Fatalf("before approval the declaration at generation %d governs by %v", m.Generation, m.SourceGovernance)
	}
	if _, err := h.svc.Install(h.ctx, h.admin(acme), acme, "a", "author", "remi", h.approval(acme, "a"), nil); err != nil {
		t.Fatal(err)
	}
	if m, err = h.svc.ApprovedDeclaration(h.ctx, h.stored(acme, "a")); err != nil || m.Generation != 2 || len(m.SourceGovernance) != 1 {
		t.Fatalf("after approval the declaration at generation %d governs by %v (%v)", m.Generation, m.SourceGovernance, err)
	}
}
