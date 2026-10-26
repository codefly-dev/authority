package authority_test

import (
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

var read, write, create, admin = []string{"read"}, []string{"write"}, []string{"create"}, []string{"admin"}

func TestThePrincipalIsStableDistinctAndPerOrganization(t *testing.T) {
	h := newHarness(t)
	u := h.principal(acme, "a")
	if u == h.inst(acme, "a").ID || u == h.principal(acme, "b") || u == h.principal(globex, "a") {
		t.Fatal("a principal is shared with an installation id, another solution or another organization")
	}
	if err := h.svc.Uninstall(h.ctx, nil, acme, h.inst(acme, "a").ID); err != nil {
		t.Fatal(err)
	}
	if again := h.install(acme, "a"); again.PrincipalID != u {
		t.Fatalf("a reinstall made principal %s, want %s", again.PrincipalID, u)
	}
}

func TestWhoMayGrantAndEveryMalformedGrant(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	h.grant("a", "installer", "ines")
	h.grant("a", "viewer", "maya")
	grants, err := h.svc.ListRoleGrants(h.ctx, h.person("alex"), acme, h.inst(acme, "a").ID)
	if err != nil || slices.IndexFunc(grants, func(g domain.RoleGrant) bool { return g.PersonID == "maya" }) < 0 || len(grants) != 2 {
		t.Fatalf("grants %v %v: a repeated grant is one row", grants, err)
	}
	ines := h.person("ines")
	if _, err := h.svc.GrantRole(h.ctx, ines, authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, "a").ID, Role: "viewer", PersonID: "dev"}); err != nil {
		t.Fatalf("the installer grants: %v", err)
	}
	instA, instB, elsewhere := h.inst(acme, "a").ID, h.inst(acme, "b").ID, h.inst(globex, "a").ID
	for name, c := range map[string]struct {
		caller authority.Person
		req    authority.RoleRequest
		code   domain.Code
		reason string
	}{
		"a viewer granting itself":             {h.person("maya"), authority.RoleRequest{Organization: acme, InstallationID: instA, Role: domain.InstallerRole, PersonID: "maya"}, domain.Denied, "may not grant"},
		"another organization's administrator": {h.person("zoe"), authority.RoleRequest{Organization: acme, InstallationID: instA, Role: "viewer", PersonID: "dev"}, domain.Denied, "may not grant"},
		"A's installer on B":                   {ines, authority.RoleRequest{Organization: acme, InstallationID: instB, Role: "author", PersonID: "ines"}, domain.Denied, "may not grant"},
		"another organization named":           {h.person("alex"), authority.RoleRequest{Organization: globex, InstallationID: instA, Role: "viewer", PersonID: "dev"}, domain.Denied, "organization"},
		"another organization's installation":  {h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: elsewhere, Role: "viewer", PersonID: "dev"}, domain.Denied, "organization"},
		"an undeclared role":                   {h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: instA, Role: "owner", PersonID: "dev"}, domain.NotFound, "declares no role"},
		"both subjects":                        {h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: instA, Role: "viewer", PersonID: "dev", TeamID: "team"}, domain.Invalid, "exactly one"},
		"no subject":                           {h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: instA, Role: "viewer"}, domain.Invalid, "exactly one"},
		"a person of another organization":     {h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: instA, Role: "viewer", PersonID: "omar"}, domain.Denied, "not a member"},
		"a team of another organization":       {h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: instA, Role: "viewer", TeamID: "ops"}, domain.Denied, "not a team of"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.svc.GrantRole(h.ctx, c.caller, c.req)
			refused(t, err, c.reason)
			code(t, err, c.code)
		})
	}
	_, err = h.svc.ListRoleGrants(h.ctx, h.person("maya"), acme, instA)
	refused(t, err, "may not")
}
