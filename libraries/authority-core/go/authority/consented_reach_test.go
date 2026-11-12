package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

const (
	vaultKind  = "vault.item"
	vaultRead  = "/vault.v1.Vault/Read"
	vaultWrite = "/vault.v1.Vault/Write"
	vaultPurge = "/vault.v1.Vault/Purge"
)

// vaultAt is a module reached through the relay, at generation, serving
// served of its kind and declaring methods.
func vaultAt(generation uint64, served []string, methods map[string]domain.MethodPolicy) domain.Module {
	return domain.Module{Name: "vault", Principal: "vault", Kind: domain.KindModule, Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{sc(vaultKind, served...)}, Methods: methods}
}

func requires(actions ...string) domain.MethodPolicy {
	return domain.MethodPolicy{Requires: []*basev0.WorkScopeV1{sc(vaultKind, actions...)}}
}

// vaultMethods is the vault's first generation: Read requires read, Purge
// requires admin.
func vaultMethods() map[string]domain.MethodPolicy {
	return map[string]domain.MethodPolicy{vaultRead: requires("read"), vaultPurge: requires("admin")}
}

// relayAt is a module a consumer binds to, carrying read and write onward to
// the vault when it does.
func relayAt(generation uint64, toVault bool) domain.Module {
	m := domain.Module{Name: "relay", Principal: "relay", Kind: domain.KindModule, Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{sc("relay.turn", "run")}, Bindings: map[string]domain.Binding{}}
	if toVault {
		m.Bindings["vault"] = domain.Binding{ID: "vault", Audience: "vault", InvokeScopes: []*basev0.WorkScopeV1{sc(vaultKind, "read", "write")}}
	}
	return m
}

// relayConsumer is a solution, or a module page, whose viewer runs turns on
// the relay and names, through its binding to it, the vault's read and write:
// a declaration consented to before the vault serves write.
func relayConsumer(page bool) domain.Module {
	m := domain.Module{Name: "app", Principal: "app", Kind: domain.KindSolution, Generation: 1, OwnerAware: true, Page: true,
		InstallationRole: domain.NoInstallationRole, ResourceKinds: []*basev0.WorkScopeV1{sc("app.note", "read")}}
	if page {
		m = pageModule(1, true)
	}
	m.Bindings = map[string]domain.Binding{"relay": {ID: "relay", Audience: "relay", InvokeScopes: []*basev0.WorkScopeV1{sc("relay.turn", "run")}}}
	own := m.ResourceKinds[0].GetResourceKind()
	m.Roles = map[string][]*basev0.WorkScopeV1{domain.InstallerRole: {sc(own, "read")}, "viewer": {sc(own, "read"), sc("relay.turn", "run")}}
	through(&m, "viewer", "relay", sc(vaultKind, "read", "write"))
	return m
}

// consentedConsumer composes the vault, the relay and the consumer, and
// answers the consumer's installation at acme with its consent taken.
func consentedConsumer(t *testing.T, h *harness, svc *authority.Service, page bool) func() domain.Installation {
	t.Helper()
	consumer := relayConsumer(page)
	for _, m := range []domain.Module{vaultAt(1, []string{"read"}, vaultMethods()), relayAt(1, true), consumer} {
		if _, err := svc.ApplyModule(h.ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	if !page {
		h.installAs(acme, consumer.Name, "")
	} else if err := svc.AdoptLegacyReach(h.ctx); err != nil {
		t.Fatal(err)
	}
	inst := func() domain.Installation { return h.stored(acme, consumer.Name) }
	if c := inst().Consent; c.OperationID == "" || c.ReachDigest == "" {
		t.Fatalf("the consumer's consent recorded no reach: %+v", c)
	}
	return inst
}

// A consent covers what a role reaches through a binding as the scopes its
// declaration names there, never the operations those scopes open: a
// redelivery widening a row within what the role names through the binding
// is admitted silently only if every operation the row reaches, and the
// policy each one requires, is the receipt's or narrower. A wider one holds
// the installation at its approved reach and offers the upgrade, for a
// solution and a module page alike.
func TestAConsentedReachThroughABindingIsHeldWhenARedeliveryOpensAnOperation(t *testing.T) {
	cases := []struct {
		name    string
		served  []string
		methods map[string]domain.MethodPolicy
		widens  bool
	}{
		{"the vault serving write gains an operation", []string{"read", "write"},
			map[string]domain.MethodPolicy{vaultRead: requires("read"), vaultWrite: requires("write"), vaultPurge: requires("admin")}, true},
		{"an operation is opened to any checked caller", []string{"read", "write"},
			map[string]domain.MethodPolicy{vaultRead: requires("read"), vaultPurge: {AnyCheckedCaller: true}}, true},
		{"an operation narrows", []string{"read", "write"},
			map[string]domain.MethodPolicy{vaultRead: requires("read", "write")}, false},
		{"the operations and their policies are equal", []string{"read", "write"}, vaultMethods(), false},
	}
	for _, consumer := range []struct {
		name string
		page bool
	}{{"a solution", false}, {"a module page", true}} {
		for _, c := range cases {
			t.Run(consumer.name+": "+c.name, func(t *testing.T) {
				h := newHarness(t)
				svc, events := journaled(h)
				inst := consentedConsumer(t, h, svc, consumer.page)
				before := inst()
				if _, err := svc.ApplyModule(h.ctx, vaultAt(2, c.served, c.methods)); err != nil {
					t.Fatal(err)
				}
				after := inst()
				up, err := svc.UpgradeAvailable(h.ctx, after)
				if err != nil {
					t.Fatal(err)
				}
				_, offered := lastEventOn(*events, domain.InstallationUpgradeAvailable, after.ID)
				if c.widens {
					if !up || !offered || after.Consent.ReachDigest != before.Consent.ReachDigest {
						t.Fatalf("a widening advanced the receipt with no upgrade offered: upgrade %v, offered %v, receipt moved %v",
							up, offered, after.Consent.ReachDigest != before.Consent.ReachDigest)
					}
					return
				}
				if up || offered || after.Consent.ReachDigest == before.Consent.ReachDigest {
					t.Fatalf("a narrowing did not re-converge: upgrade %v, offered %v, receipt moved %v",
						up, offered, after.Consent.ReachDigest != before.Consent.ReachDigest)
				}
			})
		}
	}
}

// A row the receipt does not hold has no approved operation: a declared
// reach a redelivery left unreached, reached again by a later one, admits
// its operations only through an approved upgrade, for a solution and a
// module page alike.
func TestAReachReachedAgainWithOperationsTheReceiptDoesNotHoldOffersTheUpgrade(t *testing.T) {
	for _, consumer := range []struct {
		name string
		page bool
	}{{"a solution", false}, {"a module page", true}} {
		t.Run(consumer.name, func(t *testing.T) {
			h := newHarness(t)
			svc, _ := journaled(h)
			inst := consentedConsumer(t, h, svc, consumer.page)
			if _, err := svc.ApplyModule(h.ctx, relayAt(2, false)); err != nil {
				t.Fatal(err)
			}
			if up, err := svc.UpgradeAvailable(h.ctx, inst()); err != nil || up {
				t.Fatalf("leaving the reach unreached is a narrowing: %v %v", up, err)
			}
			narrowed := inst()
			if _, err := svc.ApplyModule(h.ctx, relayAt(3, true)); err != nil {
				t.Fatal(err)
			}
			if up, err := svc.UpgradeAvailable(h.ctx, inst()); err != nil || !up || inst().Consent.ReachDigest != narrowed.Consent.ReachDigest {
				t.Fatalf("the vault's Read, which the receipt no longer holds, is reached again with no upgrade offered: %v %v", up, err)
			}
		})
	}
}

// A person naming a page's binding is issued at the page no more of what the
// binding reaches than the page's approved reach holds there: a delivery
// widening the reach, held at the approved one, widens no root either.
func TestAPersonNamingAPagesBindingIsHeldToTheApprovedReach(t *testing.T) {
	h := newHarness(t)
	page := pageModule(1, true)
	page.Bindings = map[string]domain.Binding{"vault": {ID: "vault", Audience: "vault", InvokeScopes: []*basev0.WorkScopeV1{sc(vaultKind, "read", "write")}}}
	page.Roles["viewer"] = append(page.Roles["viewer"], sc(vaultKind, "read", "write"))
	for _, m := range []domain.Module{vaultAt(1, []string{"read"}, vaultMethods()), page} {
		if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	h.grant("pages", "viewer", "maya")
	if err := h.svc.AdoptLegacyReach(h.ctx); err != nil {
		t.Fatal(err)
	}
	ask := func(actions ...string) (authority.Issued, error) {
		return h.svc.IssueForPerson(h.ctx, h.person("maya"), authority.IssueRequest{Audience: "pages", Binding: "vault", Scopes: []*basev0.WorkScopeV1{sc(vaultKind, actions...)}})
	}
	h.must(ask("read"))
	if _, err := h.svc.ApplyModule(h.ctx, vaultAt(2, []string{"read", "write"}, map[string]domain.MethodPolicy{vaultRead: requires("read"), vaultWrite: requires("write")})); err != nil {
		t.Fatal(err)
	}
	if up, err := h.svc.UpgradeAvailable(h.ctx, h.pagesAt(acme)); err != nil || !up {
		t.Fatalf("the vault serving write offers the page no upgrade: %v %v", up, err)
	}
	_, err := h.through("maya", "pages", "vault", sc(vaultKind, "write"))
	if err == nil {
		t.Fatal("the hop carries write beyond the approved reach")
	}
	if got, err := ask("write"); err == nil {
		t.Fatalf("a root naming the page's binding carries write beyond the approved reach: %v", got.Context.GetAuthorityScopes())
	}
	h.must(ask("read"))
}
