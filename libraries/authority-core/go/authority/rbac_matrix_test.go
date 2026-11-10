package authority_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The issuance matrix (RBAC audit, layer 1): who is issued what, at which
// target, over whose data. Each row is one cell: a principal kind (a person
// as administrator, member, viewer or holding nothing; a page hop; a
// solution installation acting for itself; a module's binding; headless; a
// delegated or child hop; another tenant), a target (a solution, a module
// page, a module) and a resource (the installation's own data, another
// installation's, another tenant's, a shared kind). allow names the one
// effective row it must hold (kind, owner, actions); refuse names the
// refusal. The decision of every row is the shared core's, which both hosts
// (the local authority and accounts) issue through; the host-level parity of
// the same rules is the conformance suite's (libraries/conformance).
//
// The fixture is the harness's (solutions a and b owner-aware, c not; the
// owner-aware store, and the legacy store and the ledger checking no owner;
// acme and globex) plus a module page "pages" reaching the store, the legacy
// store and a shared kind (pageReachingTheStore).
type cell struct {
	id, principal, target, resource string
	issue                           func(h *harness) (authority.Issued, error)
	allow                           *row
	refuse                          string
	skip                            string // a finding id: the cell states the decided model and the code does not meet it yet
}

type row struct {
	kind    string
	owner   func(h *harness) string
	actions []string
	ids     []string
}

func ownerOf(org, target string) func(h *harness) string {
	return func(h *harness) string { return h.principal(org, target) }
}

func noOwner(*harness) string { return "" }

func TestRBACIssuanceMatrix(t *testing.T) {
	note := func(s string) string { return s + ".note" }
	cells := []cell{
		// --- a person at a solution ---------------------------------------
		{id: "M01", principal: "person: admin, no grant", target: "solution", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) { return h.root("alex", "a") }, refuse: "alex holds no role on a"},
		{id: "M02", principal: "person: viewer", target: "solution", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) {
				return h.root("maya", "a", owned(note("a"), h.principal(acme, "a"), []string{"read"}))
			}, allow: &row{note("a"), ownerOf(acme, "a"), []string{"read"}, nil}},
		{id: "M02b", principal: "person: viewer, unselected ask", target: "solution", resource: "every owner",
			issue: func(h *harness) (authority.Issued, error) { return h.root("maya", "a", sc(note("a"), "read")) }, refuse: "widens what the owner holds"},
		{id: "M03", principal: "person: viewer, wider than role", target: "solution", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) { return h.root("maya", "a", sc(note("a"), "write")) }, refuse: "asked beyond what the owner holds"},
		{id: "M04", principal: "person: viewer", target: "solution", resource: "another installation's data",
			issue: func(h *harness) (authority.Issued, error) {
				return h.root("maya", "a", owned(note("a"), h.principal(acme, "b"), []string{"read"}))
			}, refuse: "widens what the owner holds"},
		{id: "M05", principal: "person: member, no grant", target: "solution", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) { return h.root("dev", "a") }, refuse: "dev holds no role on a"},
		{id: "M06", principal: "person: member via team grant", target: "solution", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) {
				return h.root("tam", "a", owned(note("a"), h.principal(acme, "a"), []string{"read"}))
			},
			allow: &row{note("a"), ownerOf(acme, "a"), []string{"read"}, nil}},
		{id: "M07", principal: "person: another tenant presenting this tenant", target: "solution", resource: "another tenant's data",
			issue: func(h *harness) (authority.Issued, error) {
				return h.svc.IssueForPerson(h.ctx, authority.Person{ID: "zoe", Organization: acme, SessionID: "s"}, authority.IssueRequest{Audience: "a"})
			}, refuse: "no longer a member of acme"},
		{id: "M08", principal: "person: viewer at an uninstalled solution", target: "solution", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) { return h.root("maya", "b") }, refuse: "maya holds no role on b"},
		{id: "M09", principal: "person: viewer", target: "solution not owner-aware", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) { return h.root("maya", "c") }, refuse: "does not declare owner-aware checking"},

		// --- a person through a solution to a module ----------------------
		{id: "M10", principal: "person through solution binding", target: "module", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) { return h.through("maya", "a", "store") },
			allow: &row{kind, ownerOf(acme, "a"), []string{"read"}, nil}},
		{id: "M11", principal: "person through solution binding", target: "module", resource: "another installation's data",
			issue: func(h *harness) (authority.Issued, error) {
				return h.through("maya", "a", "store", owned(kind, h.principal(acme, "b"), []string{"read"}))
			}, refuse: "confined to its principal's data"},
		{id: "M12", principal: "person through solution binding, wider than role", target: "module", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) {
				return h.through("maya", "a", "store", owned(kind, h.principal(acme, "a"), []string{"write"}))
			}, refuse: "widens what its owner holds"},
		{id: "M13", principal: "person through solution", target: "module not owner-aware", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) { return h.through("maya", "a", "legacy") }, refuse: "does not declare owner-aware checking"},
		{id: "M14", principal: "person through a binding the target does not declare", target: "module", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) { return h.through("maya", "a", "undeclared") }, refuse: `operation binding "undeclared" is not one a declares`},
		{id: "M15", principal: "person through a binding: whole kind ask", target: "module", resource: "every owner",
			issue:  func(h *harness) (authority.Issued, error) { return h.through("maya", "a", "store", sc(kind, "read")) },
			refuse: "confined to its principal's data"},
		{id: "M16", principal: "person on own session", target: "module not owner-aware (organization roles)", resource: "resource-scoped grant",
			issue: func(h *harness) (authority.Issued, error) {
				return h.root("rob", "ledger", &basev0.WorkScopeV1{ResourceKind: ledgerKind, Actions: []string{"read"}, ResourceIds: []string{"entry-x"}})
			}, allow: &row{ledgerKind, noOwner, []string{"read"}, []string{"entry-x"}}},
		{id: "M16b", principal: "person on own session, resource-scoped organization role", target: "module (owner-aware)", resource: "the granted id",
			issue: func(h *harness) (authority.Issued, error) {
				return h.root("rob", "store", &basev0.WorkScopeV1{ResourceKind: kind, Actions: []string{"read"}, ResourceIds: []string{"store-x"}})
			}, refuse: "store checks owners, so an organization role reaches none of its owned data"},
		{id: "M17", principal: "person on own session, other ids", target: "module not owner-aware (organization roles)", resource: "outside the grant",
			issue: func(h *harness) (authority.Issued, error) {
				return h.root("rob", "ledger", &basev0.WorkScopeV1{ResourceKind: ledgerKind, Actions: []string{"read"}, ResourceIds: []string{"entry-y"}})
			}, refuse: "widens what the owner holds"},
		{id: "M18", principal: "person: no organization role", target: "module (organization roles)", resource: "any",
			issue: func(h *harness) (authority.Issued, error) { return h.root("maya", "ledger") }, refuse: "the owner holds nothing at this audience"},

		{id: "M19", principal: "person: organization administrator (every kind, every action) on own session", target: "module (owner-aware)", resource: "a solution installation's data",
			issue: func(h *harness) (authority.Issued, error) {
				return h.root("boss", "store", owned(kind, h.principal(acme, "a"), []string{"read"}))
			}, refuse: "store checks owners, so an organization role reaches none of its owned data"},
		{id: "M19b", principal: "person: organization administrator (every kind, every action) on own session", target: "module (owner-aware)", resource: "the whole kind, unowned",
			issue:  func(h *harness) (authority.Issued, error) { return h.root("boss", "store", sc(kind, "read")) },
			refuse: "store checks owners, so an organization role reaches none of its owned data"},
		{id: "M19c", principal: "person: organization administrator (every kind, every action) on own session", target: "module (owner-aware)", resource: "anything",
			issue:  func(h *harness) (authority.Issued, error) { return h.root("boss", "store") },
			refuse: "store checks owners, so an organization role reaches none of its owned data"},
		{id: "M19d", principal: "person: organization administrator (every kind, every action) on own session", target: "module not owner-aware", resource: "the whole kind",
			issue: func(h *harness) (authority.Issued, error) { return h.root("boss", "legacy-store") },
			allow: &row{legacyKind, noOwner, []string{"read"}, nil}},
		{id: "M19e", principal: "person: organization administrator (every kind, every action) on own session", target: "module (shared kind)", resource: "shared kind",
			issue: func(h *harness) (authority.Issued, error) {
				return h.root("boss", "profiles", sc("profiles.profile", "read"))
			},
			allow: &row{"profiles.profile", noOwner, []string{"read"}, nil}},
		{id: "M19f", principal: "person: organization role granted on a solution installation", target: "module (owner-aware) through the solution", resource: "that installation's data",
			issue: func(h *harness) (authority.Issued, error) { return h.through("maya", "a", "store") },
			allow: &row{kind, ownerOf(acme, "a"), []string{"read"}, nil}},

		// --- the page hop ---------------------------------------------------
		{id: "M20", principal: "page hop: solution page", target: "module", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) { return h.page("maya", "a", "store") },
			allow: &row{kind, ownerOf(acme, "a"), []string{"read"}, nil}},
		{id: "M21", principal: "page hop: module page viewer", target: "module (owner-aware)", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) { return h.page("maya", "pages", "store") },
			allow: &row{kind, ownerOf(acme, "pages"), []string{"read"}, nil}},
		{id: "M22", principal: "page hop: module page viewer", target: "module (owner-aware)", resource: "a solution installation's data",
			issue: func(h *harness) (authority.Issued, error) {
				return h.page("maya", "pages", "store", owned(kind, h.principal(acme, "a"), []string{"read"}))
			}, refuse: "widens what its owner holds"},
		{id: "M23", principal: "page hop: module page viewer", target: "module (owner-aware)", resource: "another tenant's page installation",
			issue: func(h *harness) (authority.Issued, error) {
				return h.page("maya", "pages", "store", owned(kind, h.principal(globex, "pages"), []string{"read"}))
			}, refuse: "widens what its owner holds"},
		{id: "M24", principal: "page hop: module page viewer", target: "module (shared kind)", resource: "shared kind",
			issue: func(h *harness) (authority.Issued, error) {
				return h.page("maya", "pages", "profiles", sc("profiles.profile", "read"))
			}, allow: &row{"profiles.profile", noOwner, []string{"read"}, nil}},
		{id: "M25", principal: "page hop: no role on the page", target: "module", resource: "any",
			issue: func(h *harness) (authority.Issued, error) { return h.page("remi", "pages", "store") }, refuse: "holds no role on pages"},
		{id: "M26", principal: "page hop: undeclared edge (no binding)", target: "module", resource: "the person's own access",
			issue:  func(h *harness) (authority.Issued, error) { return h.page("rob", "pages", "store-elsewhere") },
			refuse: "declares no binding", skip: "RBAC-3 (undeclared-edge fallback: the page's call runs on the person's own access)"},
		{id: "M27", principal: "page hop: naming a binding the page does not declare to the audience", target: "module", resource: "the person's own access",
			issue: func(h *harness) (authority.Issued, error) {
				return h.svc.IssueForPage(h.ctx, h.person("rob"), "pages", authority.IssueRequest{Audience: "store-elsewhere", Binding: "store"})
			}, refuse: "declares no binding", skip: "RBAC-3 (a named, undeclared binding falls back to the person's own access)"},

		// --- a solution installation acting for itself ----------------------
		{id: "M30", principal: "installation: agent role", target: "solution", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) {
				return h.agent("a", "", owned(note("a"), h.principal(acme, "a"), []string{"read"}))
			},
			allow: &row{note("a"), ownerOf(acme, "a"), []string{"read"}, nil}},
		{id: "M31", principal: "installation: agent role through its binding", target: "module", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) {
				return h.agent("a", "store", owned(kind, h.principal(acme, "a"), []string{"read"}))
			},
			allow: &row{kind, ownerOf(acme, "a"), []string{"read"}, nil}},
		{id: "M32", principal: "installation: agent role", target: "module", resource: "another installation's data",
			issue: func(h *harness) (authority.Issued, error) {
				return h.agent("a", "store", owned(kind, h.principal(acme, "b"), []string{"read"}))
			},
			refuse: "widens what the owner holds"},
		{id: "M33", principal: "installation: another solution's installation id", target: "solution", resource: "another installation",
			issue: func(h *harness) (authority.Issued, error) {
				return h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: "a"}, h.inst(acme, "b").ID, authority.IssueRequest{Audience: "a"})
			}, refuse: "installation issuance requires the installed solution's workload"},
		{id: "M34", principal: "installation: another tenant's installation, named for this tenant", target: "solution", resource: "another tenant's data",
			issue: func(h *harness) (authority.Issued, error) {
				return h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: "a"}, h.inst(globex, "a").ID, authority.IssueRequest{Audience: "a", Organization: acme})
			}, refuse: "belongs to another organization"},
		{id: "M35", principal: "installation: headless", target: "module", resource: "any",
			issue: func(h *harness) (authority.Issued, error) {
				return h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: "a"}, h.inst(acme, "a").ID, authority.IssueRequest{Audience: "store", Binding: "store", Operation: "headless"})
			}, refuse: "headless scopes are a acting for nobody"},
		{id: "M36", principal: "installation: binding the solution does not declare", target: "module", resource: "any",
			issue: func(h *harness) (authority.Issued, error) {
				return h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: "a"}, h.inst(acme, "a").ID, authority.IssueRequest{Audience: "store", Binding: "undeclared"})
			}, refuse: `operation binding "undeclared" is not one a declares`},

		// --- a module's binding, headless ------------------------------------
		{id: "M40", principal: "module binding: headless, acting as itself", target: "module", resource: "the kind, for nobody",
			issue: func(h *harness) (authority.Issued, error) {
				return h.svc.IssueForWorkload(h.ctx, authority.Workload{Module: "store"}, authority.IssueRequest{Binding: "self", Operation: "headless", Organization: acme})
			}, allow: &row{kind, noOwner, []string{"read"}, nil}},
		{id: "M41", principal: "module binding: headless, wider than declared", target: "module", resource: "the kind",
			issue: func(h *harness) (authority.Issued, error) {
				return h.svc.IssueForWorkload(h.ctx, authority.Workload{Module: "store"}, authority.IssueRequest{Binding: "self", Operation: "headless", Organization: acme, Scopes: []*basev0.WorkScopeV1{sc(kind, "write")}})
			}, refuse: "asked beyond what the owner holds"},
		{id: "M42", principal: "module binding: credential bound to another tenant", target: "module", resource: "another tenant's data",
			issue: func(h *harness) (authority.Issued, error) {
				return h.svc.IssueForWorkload(h.ctx, authority.Workload{Module: "store", Organization: globex}, authority.IssueRequest{Binding: "self", Operation: "headless", Organization: acme})
			}, refuse: "bound to organization globex"},
		{id: "M43", principal: "module binding: undeclared binding", target: "module", resource: "any",
			issue: func(h *harness) (authority.Issued, error) {
				return h.svc.IssueForWorkload(h.ctx, authority.Workload{Module: "store"}, authority.IssueRequest{Binding: "undeclared", Audience: "store", Organization: acme})
			}, refuse: "undeclared"},

		// --- delegated / child ------------------------------------------------
		{id: "M50", principal: "child: hop on a token addressed elsewhere", target: "module", resource: "any",
			issue: func(h *harness) (authority.Issued, error) {
				root := h.must(h.root("maya", "a"))
				return h.svc.IssueChild(h.ctx, root.Token, authority.Workload{Module: "store"}, authority.IssueRequest{Binding: "self"})
			}, refuse: "hops only on a token addressed to it"},
		{id: "M51", principal: "child: narrowed parent, onward asks what it dropped", target: "module", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) {
				narrowed := h.must(h.through("remi", "a", "store", owned(kind, h.principal(acme, "a"), []string{"read"})))
				return h.hop(narrowed, "self", owned(kind, h.principal(acme, "a"), []string{"write"}))
			}, refuse: "widens what its owner holds"},
		{id: "M52", principal: "child: forged parent", target: "module", resource: "any",
			issue: func(h *harness) (authority.Issued, error) {
				root := h.must(h.root("maya", "a"))
				return h.svc.IssueChild(h.ctx, root.Token[:len(root.Token)-4]+"AAAA", authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store"})
			}, refuse: ""},
		{id: "M53", principal: "child: expired parent", target: "module", resource: "any",
			issue: func(h *harness) (authority.Issued, error) {
				root := h.must(h.root("maya", "a"))
				h.now = h.now.Add(2 * time.Hour)
				return h.svc.IssueChild(h.ctx, root.Token, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store"})
			}, refuse: ""},
		{id: "M54", principal: "delegation: revoked", target: "module", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) {
				d, err := h.svc.Delegate(h.ctx, h.person("maya"), "a", []*basev0.WorkScopeV1{owned(kind, h.principal(acme, "a"), []string{"read"})}, "matrix", 0)
				if err != nil {
					return authority.Issued{}, err
				}
				if _, err := h.svc.RevokeDelegation(h.ctx, h.person("maya"), d.ID); err != nil {
					return authority.Issued{}, err
				}
				return h.svc.IssueForDelegation(h.ctx, d.ID, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store"})
			}, refuse: "is revoked"},
		{id: "M55", principal: "delegation: granted to another module", target: "module", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) {
				d, err := h.svc.Delegate(h.ctx, h.person("maya"), "a", []*basev0.WorkScopeV1{owned(kind, h.principal(acme, "a"), []string{"read"})}, "matrix", 0)
				if err != nil {
					return authority.Issued{}, err
				}
				return h.svc.IssueForDelegation(h.ctx, d.ID, authority.Workload{Module: "b"}, authority.IssueRequest{Binding: "store"})
			}, refuse: "is granted to a, not b"},
		{id: "M56", principal: "delegation: grantor's role revoked since", target: "module", resource: "own installation",
			issue: func(h *harness) (authority.Issued, error) {
				d, err := h.svc.Delegate(h.ctx, h.person("maya"), "a", []*basev0.WorkScopeV1{owned(kind, h.principal(acme, "a"), []string{"read"})}, "matrix", 0)
				if err != nil {
					return authority.Issued{}, err
				}
				h.revoke("a", "viewer", "maya", "")
				return h.svc.IssueForDelegation(h.ctx, d.ID, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store"})
			}, refuse: "grants nothing maya still holds"},
	}
	for _, c := range cells {
		t.Run(c.id+" "+c.principal+" | "+c.target+" | "+c.resource, func(t *testing.T) {
			if c.skip != "" && os.Getenv("RBAC_UNSKIP") == "" {
				t.Skip(c.skip)
			}
			h := matrixHarness(t)
			got, err := c.issue(h)
			if c.allow == nil {
				if err == nil {
					t.Fatalf("issued %v; want refused (%s)", effective(got), c.refuse)
				}
				if c.refuse != "" && !strings.Contains(err.Error(), c.refuse) {
					t.Fatalf("refused for another reason: %v; want %q", err, c.refuse)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			exactly(t, got, c.allow.kind, c.allow.owner(h), c.allow.actions, c.allow.ids...)
			if err := h.check(got); err != nil {
				t.Fatalf("the issued capability does not check at its audience: %v", err)
			}
		})
	}
}

// matrixHarness is the harness with the matrix's grants: maya views a, remi
// edits a, the team views a (tam), maya views the module page, and a second
// module the page declares no binding to.
func matrixHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	pageReachingTheStore(t, h)
	// store-elsewhere checks no owner, so an own-session organization role holds
	// it (RBAC-4a): the RBAC-3 cells show the fallback to that access.
	elsewhere := domain.Module{Name: "store-elsewhere", Principal: "store-elsewhere", Kind: domain.KindModule, Generation: 1,
		ResourceKinds: []*basev0.WorkScopeV1{sc(kind+".elsewhere", "read")}}
	if _, err := h.svc.ApplyModule(h.ctx, elsewhere); err != nil {
		t.Fatal(err)
	}
	h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "elsewhere-reader", Scopes: []domain.RoleScope{{Kind: kind + ".elsewhere", Actions: []string{"read"}}}})
	h.store.PutPerson(domain.Person{ID: "rob", Organization: acme, Roles: []string{"store-reader", "ledger-reader", "elsewhere-reader"}})
	// accounts synthesizes an organization's owner and admin roles as every
	// kind and every action (postgres_authority_core.go OrgRole).
	h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "everything", Scopes: []domain.RoleScope{{Kind: "*", Actions: []string{"*"}}}})
	h.store.PutPerson(domain.Person{ID: "boss", Organization: acme, Roles: []string{"everything"}})
	h.grant("a", "viewer", "maya")
	h.grant("a", "editor", "remi")
	h.grantTeam("a", "viewer", "team")
	return h
}
