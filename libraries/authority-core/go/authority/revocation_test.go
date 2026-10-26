package authority_test

import (
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

func TestAGrantLeavesCapabilitiesValidAndARevokeEndsOnlyItsOwn(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	h.grant("b", "viewer", "maya")
	h.grant("a", "author", "remi")
	before := h.must(h.through("maya", "a", "store"))
	throughB := h.must(h.through("maya", "b", "store"))
	unrelated := h.must(h.through("remi", "a", "store"))
	h.grant("a", "author", "maya")
	h.grant("a", "viewer", "dev")
	for _, c := range []authority.Issued{before, throughB, unrelated} {
		if err := h.check(c); err != nil {
			t.Fatalf("a new grant invalidated a capability: %v", err)
		}
	}
	h.revoke("a", "author", "maya", "")
	h.revoke("a", "viewer", "maya", "")
	if err := h.check(before); err == nil {
		t.Fatal("a capability through A survived its holder's revoke on A")
	}
	_, err := h.hop(before, "self")
	if err == nil {
		t.Fatal("a child of a revoked capability was issued")
	}
	_, err = h.root("maya", "a")
	refused(t, err, "holds no role")
	for name, c := range map[string]authority.Issued{"the same person through B": throughB, "another person through A": unrelated} {
		if err := h.check(c); err != nil {
			t.Fatalf("revoking a role on A invalidated %s: %v", name, err)
		}
	}
	h.grant("a", "viewer", "maya")
	h.must(h.through("maya", "a", "store"))
	if err := h.check(before); err == nil {
		t.Fatal("a re-grant revived an old capability")
	}
}

func TestATeamGrantIsItsMembersAccess(t *testing.T) {
	h := newHarness(t)
	h.grantTeam("a", "viewer", "team")
	before := h.must(h.through("tam", "a", "store"))
	h.revoke("a", "viewer", "", "team")
	if err := h.check(before); err == nil {
		t.Fatal("a team revoke left a member's capability valid")
	}
	h.grant("a", "viewer", "tam")
	h.grantTeam("a", "viewer", "team")
	h.revoke("a", "viewer", "", "team")
	h.must(h.through("tam", "a", "store"))
	leaving := h.must(h.through("tam", "a", "store"))
	if err := h.svc.PersonChanged(h.ctx, "tam"); err != nil {
		t.Fatal(err)
	}
	if err := h.check(leaving); err == nil {
		t.Fatal("a person leaving kept a capability")
	}
}

func TestUninstallDisablesThePrincipalAndClearsGrants(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	h.grant("a", "author", "ada")
	before := h.must(h.through("maya", "a", "store"))
	parent := h.must(h.root("maya", "a"))
	agent := h.must(h.agent("a", "store"))
	inst := h.inst(acme, "a").ID
	if err := h.svc.Uninstall(h.ctx, nil, acme, inst); err != nil {
		t.Fatal(err)
	}
	for _, c := range []authority.Issued{before, agent} {
		if err := h.check(c); err == nil {
			t.Fatal("a capability survived the uninstall")
		}
	}
	_, err := h.svc.IssueChild(h.ctx, parent.Token, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store"})
	if err == nil {
		t.Fatal("a pre-uninstall parent derived a child")
	}
	_, err = h.agent("a", "store")
	code(t, err, domain.Precondition)
	_, err = h.root("maya", "a")
	code(t, err, domain.Precondition)
	_, err = h.svc.GrantRole(h.ctx, h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: inst, Role: "viewer", PersonID: "maya"})
	refused(t, err, "not installed")
	if again := h.install(acme, "a"); again.PrincipalID != h.principal(acme, "a") {
		t.Fatal("the reinstalled principal changed")
	}
	_, err = h.root("maya", "a")
	refused(t, err, "holds no role")
	h.grant("a", "viewer", "maya")
	exactly(t, h.must(h.through("maya", "a", "store")), kind, h.principal(acme, "a"), read)
	if err := h.check(before); err == nil {
		t.Fatal("reinstalling revived an old capability")
	}
}

func TestATransferIsAPersonsActOnWhatTheyAdminister(t *testing.T) {
	h := newHarness(t)
	u, v := h.principal(acme, "a"), h.principal(acme, "b")
	h.grant("a", "editor", "ada")
	asEditor := h.must(h.through("ada", "a", "store"))
	transfer := func(capability authority.Issued, storeModule, id, from, to string) (authority.TransferDecision, error) {
		return h.svc.AuthorizeTransfer(h.ctx, authority.TransferRequest{Token: capability.Token, Store: authority.Workload{Module: storeModule}, Kind: kind, ResourceID: id, From: from, To: to})
	}
	_, err := transfer(asEditor, "store", "store-x", acme, u)
	refused(t, err, "write on")
	h.grant("a", "author", "ada")
	for _, from := range []string{acme, "ada"} {
		d, err := transfer(asEditor, "store", "store-x", from, u)
		if err != nil || d.PrincipalID != u || d.AuthorizedBy != "ada" {
			t.Fatalf("from %s: %+v %v", from, d, err)
		}
	}
	h.grant("a", "author", "rob")
	h.grant("a", domain.InstallerRole, "ines")
	reads, installs := h.must(h.through("rob", "a", "store")), h.must(h.through("ines", "a", "store"))
	agent := h.must(h.agent("a", "store"))
	atRoot := h.must(h.root("ada", "a"))
	for name, c := range map[string]struct {
		capability                  authority.Issued
		store, id, from, to, reason string
	}{
		"from another solution principal":       {asEditor, "store", "store-x", v, u, "solution principal"},
		"from another organization":             {asEditor, "store", "store-x", globex, u, "not a person or the organization"},
		"from another organization's person":    {asEditor, "store", "store-x", "omar", u, "not a person or the organization"},
		"from an unknown owner":                 {asEditor, "store", "store-x", "nobody", u, "not a person or the organization"},
		"from no owner":                         {asEditor, "store", "store-x", "", u, "not a person or the organization"},
		"a resource the person does not admin":  {asEditor, "store", "store-y", acme, u, "own organization grants"},
		"to a principal it is not through":      {asEditor, "store", "store-x", acme, v, "not issued through"},
		"by a reader":                           {reads, "store", "store-x", acme, u, "own organization grants"},
		"by the installer role alone":           {installs, "store", "store-x", acme, u, "own organization grants"},
		"by the agent":                          {agent, "store", "store-x", acme, u, "a person's act"},
		"asked by a module that does not serve": {asEditor, "a", "store-x", acme, u, "does not serve"},
		"with a capability addressed elsewhere": {atRoot, "store", "store-x", acme, u, "audience"},
		"of the wildcard id":                    {asEditor, "store", "*", acme, u, "not a usable id"},
		"of an oversize id":                     {asEditor, "store", strings.Repeat("x", 129), acme, u, "not a usable id"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := transfer(c.capability, c.store, c.id, c.from, c.to)
			refused(t, err, c.reason)
		})
	}
}
