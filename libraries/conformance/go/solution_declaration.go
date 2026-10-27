package conformance

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// A solution's roles and permissions are its declaration, and nothing else:
// every host answers about an installed solution exactly what it declared, so
// the answers are the same on every host. The suite delivers one solution and
// the module it calls, installs the solution at Organization as AdminToken,
// and compares each host's answers with one expected value: the reviewed offer
// (OfferService.ReviewOffer) with a golden rendering, and what a grant of each
// role issues (InstallationService.GrantRole, then AuthorityService.Issue)
// with the declaration's scopes within the ceiling. A redelivery that changes
// the roles changes both answers to exactly the new declaration, and its
// narrowing refuses the capabilities issued before it.
//
// The holder is the fixture's UnentitledToken, a member with no role and no
// team, so what they are issued is the one role granted to them.
const (
	declaredSolution = "conformance-declared"
	declaredStore    = "conformance-declared-store"
	declaredBinding  = "store"
	declaredPage     = declaredSolution + ".page"
	declaredItem     = declaredStore + ".item"
)

// declaredRole is one role as the solution declares it.
type declaredRole struct {
	name string
	// scopes on the solution's own kind and on the store's, through its binding.
	scopes map[string][]string
	// attached are installation-owned scopes: only what is attached to the
	// installation, nothing until something is.
	attached map[string][]string
}

// declaration is one generation of the solution's authority document.
type declaration struct {
	generation uint64
	roles      []declaredRole
}

// declaredCeiling is the most the solution serves on its own kind and the most
// its binding may ask of the store. No role may exceed it.
var (
	declaredOwnCeiling     = []string{"list", "publish", "read", "write"}
	declaredBindingCeiling = []string{"read", "write"}
)

// declaredRoles is the first delivery: an installer, a role reaching the store
// through the binding (editor, viewer), an attached-only role (curator) and a
// role no operation is covered by, hence no capability and no tool (observer).
func declaredRoles() declaration {
	return declaration{generation: 1, roles: []declaredRole{
		{name: "installer", scopes: map[string][]string{declaredPage: {"publish", "read", "write"}, declaredItem: {"read", "write"}}},
		{name: "editor", scopes: map[string][]string{declaredPage: {"read", "write"}, declaredItem: {"read", "write"}}},
		{name: "viewer", scopes: map[string][]string{declaredPage: {"read"}, declaredItem: {"read"}}},
		{name: "curator", scopes: map[string][]string{declaredPage: {"read"}}, attached: map[string][]string{declaredItem: {"read", "write"}}},
		{name: "observer", scopes: map[string][]string{declaredPage: {"list"}}},
	}}
}

// redeclaredRoles is the redelivery: editor loses write everywhere, curator's
// attached scope loses write, observer is withdrawn; installer and viewer stay.
func redeclaredRoles() declaration {
	return declaration{generation: 2, roles: []declaredRole{
		{name: "installer", scopes: map[string][]string{declaredPage: {"publish", "read", "write"}, declaredItem: {"read", "write"}}},
		{name: "editor", scopes: map[string][]string{declaredPage: {"read"}, declaredItem: {"read"}}},
		{name: "viewer", scopes: map[string][]string{declaredPage: {"read"}, declaredItem: {"read"}}},
		{name: "curator", scopes: map[string][]string{declaredPage: {"read"}}, attached: map[string][]string{declaredItem: {"read"}}},
	}}
}

// The golden offers: what ReviewOffer answers for each declaration on every
// host, rendered by renderOffer. Each capability is a composed operation the
// role's scopes cover, a curator's attached scope included; observer's list
// covers none. No operation is a tool: the suite composes no Runnable binding,
// which is host configuration outside the declaration.
const declaredOfferV1 = `target conformance-declared generation 1
installation STATUS_ACTIVE roles [curator editor installer observer viewer]
ceiling store -> conformance-declared-store: conformance-declared-store.item [read write]
role curator
  scope conformance-declared-store.item [read write] attached-only ids []
  scope conformance-declared.page [read]
  capability conformance-declared GET /pages/{id} requires conformance-declared.page [read] tools []
  capability conformance-declared-store /conformance.declared.Store/Get requires conformance-declared-store.item [read] tools []
  capability conformance-declared-store /conformance.declared.Store/Put requires conformance-declared-store.item [write] tools []
role editor
  scope conformance-declared-store.item [read write]
  scope conformance-declared.page [read write]
  capability conformance-declared GET /pages/{id} requires conformance-declared.page [read] tools []
  capability conformance-declared PUT /pages/{id} requires conformance-declared.page [write] tools []
  capability conformance-declared-store /conformance.declared.Store/Get requires conformance-declared-store.item [read] tools []
  capability conformance-declared-store /conformance.declared.Store/Put requires conformance-declared-store.item [write] tools []
role installer
  scope conformance-declared-store.item [read write]
  scope conformance-declared.page [publish read write]
  capability conformance-declared GET /pages/{id} requires conformance-declared.page [read] tools []
  capability conformance-declared POST /pages/{id}/publish requires conformance-declared.page [publish] tools []
  capability conformance-declared PUT /pages/{id} requires conformance-declared.page [write] tools []
  capability conformance-declared-store /conformance.declared.Store/Get requires conformance-declared-store.item [read] tools []
  capability conformance-declared-store /conformance.declared.Store/Put requires conformance-declared-store.item [write] tools []
role observer
  scope conformance-declared.page [list]
role viewer
  scope conformance-declared-store.item [read]
  scope conformance-declared.page [read]
  capability conformance-declared GET /pages/{id} requires conformance-declared.page [read] tools []
  capability conformance-declared-store /conformance.declared.Store/Get requires conformance-declared-store.item [read] tools []
`

const declaredOfferV2 = `target conformance-declared generation 2
installation STATUS_ACTIVE roles [curator editor installer viewer]
ceiling store -> conformance-declared-store: conformance-declared-store.item [read write]
role curator
  scope conformance-declared-store.item [read] attached-only ids []
  scope conformance-declared.page [read]
  capability conformance-declared GET /pages/{id} requires conformance-declared.page [read] tools []
  capability conformance-declared-store /conformance.declared.Store/Get requires conformance-declared-store.item [read] tools []
role editor
  scope conformance-declared-store.item [read]
  scope conformance-declared.page [read]
  capability conformance-declared GET /pages/{id} requires conformance-declared.page [read] tools []
  capability conformance-declared-store /conformance.declared.Store/Get requires conformance-declared-store.item [read] tools []
role installer
  scope conformance-declared-store.item [read write]
  scope conformance-declared.page [publish read write]
  capability conformance-declared GET /pages/{id} requires conformance-declared.page [read] tools []
  capability conformance-declared POST /pages/{id}/publish requires conformance-declared.page [publish] tools []
  capability conformance-declared PUT /pages/{id} requires conformance-declared.page [write] tools []
  capability conformance-declared-store /conformance.declared.Store/Get requires conformance-declared-store.item [read] tools []
  capability conformance-declared-store /conformance.declared.Store/Put requires conformance-declared-store.item [write] tools []
role viewer
  scope conformance-declared-store.item [read]
  scope conformance-declared.page [read]
  capability conformance-declared GET /pages/{id} requires conformance-declared.page [read] tools []
  capability conformance-declared-store /conformance.declared.Store/Get requires conformance-declared-store.item [read] tools []
`

func (d declaration) document() map[string]any {
	var roles []any
	for _, r := range d.roles {
		role := map[string]any{"name": r.name, "scopes": scopeList(r.scopes)}
		if len(r.attached) > 0 {
			role["installation_owned_scopes"] = scopeList(r.attached)
		}
		roles = append(roles, role)
	}
	return map[string]any{
		"owner_aware":    true,
		"scope_ceilings": []any{scopeAsk(declaredPage, declaredOwnCeiling, nil)},
		"roles":          roles,
		"methods": []any{
			map[string]any{"method": "GET /pages/{id}", "requires": []any{scopeAsk(declaredPage, []string{"read"}, nil)}},
			map[string]any{"method": "PUT /pages/{id}", "requires": []any{scopeAsk(declaredPage, []string{"write"}, nil)}},
			map[string]any{"method": "POST /pages/{id}/publish", "requires": []any{scopeAsk(declaredPage, []string{"publish"}, nil)}},
			map[string]any{"method": "GET /status", "any_checked_caller": true},
		},
	}
}

func scopeList(scopes map[string][]string) []any {
	var out []any
	for _, kind := range sortedKeys(scopes) {
		out = append(out, scopeAsk(kind, scopes[kind], nil))
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// held is what a grant of the role issues where kind is served: its declared
// actions within the ceiling there. An attached-only scope holds nothing while
// nothing is attached to the installation.
func (r declaredRole) held(kind string) []string {
	ceiling := declaredOwnCeiling
	if kind == declaredItem {
		ceiling = declaredBindingCeiling
	}
	var out []string
	for _, action := range r.scopes[kind] {
		if slices.Contains(ceiling, action) {
			out = append(out, action)
		}
	}
	slices.Sort(out)
	return out
}

func (c *client) solutionDeclaration(t *testing.T, ctx context.Context, f Fixture) {
	t.Run("a solution's roles and permissions are exactly its declaration", func(t *testing.T) {
		if f.SignManifest == nil || f.SignAuthority == nil || f.DeliveryCredential == nil || f.AdminToken == "" || f.UnentitledToken == "" {
			t.Fatal("required conformance fixture missing: signed delivery, an administrator and a member holding no role (UnentitledToken)")
		}
		// The store serves the item kind; the solution calls it through one binding.
		store := map[string]any{"owner_aware": true, "scope_ceilings": []any{scopeAsk(declaredItem, []string{"admin", "read", "write"}, nil)},
			"methods": []any{
				map[string]any{"method": "/conformance.declared.Store/Get", "requires": []any{scopeAsk(declaredItem, []string{"read"}, nil)}},
				map[string]any{"method": "/conformance.declared.Store/Put", "requires": []any{scopeAsk(declaredItem, []string{"write"}, nil)}},
				map[string]any{"method": "/conformance.declared.Store/Purge", "requires": []any{scopeAsk(declaredItem, []string{"admin"}, nil)}},
				map[string]any{"method": "/conformance.declared.Store/Ping", "any_checked_caller": true},
			}}
		if _, err := c.deliver(ctx, f, declaredStore, "module", 1, []string{declaredItem}, store, 0); err != nil {
			t.Fatalf("deliver %s: %v", declaredStore, err)
		}
		binding := solutionhost.AuthorityBinding{ID: declaredBinding, Audience: declaredStore, Operations: map[string][]string{
			"invoke": {declaredItem + ":read", declaredItem + ":write"}}}
		deliver := func(t *testing.T, d declaration) {
			t.Helper()
			if _, err := c.deliver(ctx, f, declaredSolution, "solution", d.generation, []string{declaredPage}, d.document(), 0, binding); err != nil {
				t.Fatalf("deliver %s at %d: %v", declaredSolution, d.generation, err)
			}
		}
		first := declaredRoles()
		deliver(t, first)

		admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken})
		adminCtx := as(ctx, admin)
		inst := c.must(t, adminCtx, "host.installation.v1.InstallationService", "Install", map[string]any{
			"organization_id": f.Organization, "target": declaredSolution, "role": "viewer", "owner_person_id": str(admin, "person_id"),
			"approval": c.reviewInstallation(t, adminCtx, f.Organization, declaredSolution)})
		if enumName(inst, "status") != "STATUS_ACTIVE" {
			t.Fatalf("%s is %s; the host's install step must converge for the suite's solutions", declaredSolution, enumName(inst, "status"))
		}
		id, principal := str(inst, "id"), installationPrincipal(inst)
		holder := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.UnentitledToken})
		holderCtx := as(ctx, holder)
		role := func(t *testing.T, method, name string) error {
			t.Helper()
			_, err := c.call(adminCtx, "host.installation.v1.InstallationService", method, map[string]any{
				"organization_id": f.Organization, "installation_id": id, "role": name, "person_id": str(holder, "person_id")})
			return err
		}
		// issue is the holder's capability at the solution, or through its binding.
		issue := func(binding string, scopes []any) (protoreflect.Message, error) {
			fields := map[string]any{"person": map[string]any{}, "audience": declaredSolution, "operation_binding_id": binding}
			if scopes != nil {
				fields["scopes"] = scopes
			}
			return c.call(holderCtx, "host.authority.v1.AuthorityService", "Issue", fields)
		}

		t.Run("the installation lists exactly the declared roles", func(t *testing.T) {
			c.declaredInstallationRoles(t, adminCtx, f, id, first)
		})
		t.Run("the reviewed offer is exactly the declaration", func(t *testing.T) {
			c.reviewedOffer(t, adminCtx, f, principal, declaredOfferV1)
		})
		t.Run("each role grants exactly its declared scopes within the ceiling", func(t *testing.T) {
			for _, r := range first.roles {
				t.Run(r.name, func(t *testing.T) {
					if err := role(t, "GrantRole", r.name); err != nil {
						t.Fatal(err)
					}
					defer func() {
						if err := role(t, "RevokeRole", r.name); err != nil {
							t.Fatal(err)
						}
					}()
					c.grantedExactly(t, issue, r, principal)
				})
			}
		})
		t.Run("a redelivery changes the answers to exactly the new declaration", func(t *testing.T) {
			// The holder holds editor across the redelivery, with a live
			// capability at the solution and through its binding.
			if err := role(t, "GrantRole", "editor"); err != nil {
				t.Fatal(err)
			}
			own, err := issue("", nil)
			if err != nil {
				t.Fatal(err)
			}
			through, err := issue(declaredBinding, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, live := range []protoreflect.Message{own, through} {
				c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(live, "token"), "audience": declaredSolution})
			}
			second := redeclaredRoles()
			deliver(t, second)
			t.Run("a narrowing refuses the capabilities issued before it", func(t *testing.T) {
				for name, live := range map[string]protoreflect.Message{"at the solution": own, "through the binding": through} {
					_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(live, "token"), "audience": declaredSolution})
					if status.Code(err) != codes.PermissionDenied {
						t.Errorf("a capability %s issued before the narrowing: want PermissionDenied, got %v", name, err)
					} else {
						t.Logf("refusal %s: %v", name, err)
					}
				}
			})
			t.Run("the installation lists exactly the redeclared roles", func(t *testing.T) {
				c.declaredInstallationRoles(t, adminCtx, f, id, second)
			})
			t.Run("the reviewed offer is exactly the redeclaration", func(t *testing.T) {
				c.reviewedOffer(t, adminCtx, f, principal, declaredOfferV2)
			})
			t.Run("the held role issues exactly its redeclared scopes", func(t *testing.T) {
				c.grantedExactly(t, issue, second.roles[1], principal)
			})
			if err := role(t, "RevokeRole", "editor"); err != nil {
				t.Fatal(err)
			}
			t.Run("each redeclared role grants exactly its scopes within the ceiling", func(t *testing.T) {
				for _, r := range second.roles {
					if r.name == "editor" {
						continue
					}
					t.Run(r.name, func(t *testing.T) {
						if err := role(t, "GrantRole", r.name); err != nil {
							t.Fatal(err)
						}
						defer func() {
							if err := role(t, "RevokeRole", r.name); err != nil {
								t.Fatal(err)
							}
						}()
						c.grantedExactly(t, issue, r, principal)
					})
				}
			})
			t.Run("a withdrawn role is granted to nobody", func(t *testing.T) {
				err := role(t, "GrantRole", "observer")
				refused(t, err, codes.NotFound, `declares no role "observer"`)
			})
		})
	})
}

// declaredInstallationRoles requires the administrator's installation list to
// name exactly the declared roles.
func (c *client) declaredInstallationRoles(t *testing.T, adminCtx context.Context, f Fixture, id string, d declaration) {
	t.Helper()
	var want []string
	for _, r := range d.roles {
		want = append(want, r.name)
	}
	slices.Sort(want)
	list := c.must(t, adminCtx, "host.installation.v1.InstallationService", "List", map[string]any{"organization_id": f.Organization})
	for _, inst := range listMsgs(list, "installations") {
		if str(inst, "id") != id {
			continue
		}
		if got := listStrings(inst, "roles"); !slices.Equal(got, want) {
			t.Fatalf("installation roles = %v, want the declared %v", got, want)
		}
		return
	}
	t.Fatalf("installation %s is not listed at %s", id, f.Organization)
}

// reviewedOffer compares the host's ReviewOffer, normalized, with the golden
// offer every host answers. A host stating why it does not serve
// OfferService yet skips this line, by name.
func (c *client) reviewedOffer(t *testing.T, adminCtx context.Context, f Fixture, principal, golden string) {
	t.Helper()
	if f.ReviewOfferNotServed != "" {
		if _, err := c.call(adminCtx, "host.installation.v1.OfferService", "ReviewOffer", map[string]any{"organization_id": f.Organization, "target": declaredSolution}); status.Code(err) != codes.Unimplemented {
			t.Fatalf("the fixture says this host does not serve ReviewOffer (%s), but it answered %v: remove ReviewOfferNotServed", f.ReviewOfferNotServed, err)
		}
		t.Skipf("this host does not serve OfferService.ReviewOffer yet: %s", f.ReviewOfferNotServed)
	}
	offers := c.must(t, adminCtx, "host.installation.v1.OfferService", "ListOffers", map[string]any{"organization_id": f.Organization})
	listed := uint64(0)
	for _, o := range listMsgs(offers, "offers") {
		if str(o, "target") == declaredSolution {
			listed = u64(o, "generation")
		}
	}
	offer := c.must(t, adminCtx, "host.installation.v1.OfferService", "ReviewOffer", map[string]any{"organization_id": f.Organization, "target": declaredSolution})
	if a := msg(offer, "approval"); str(a, "target_id") == "" || str(a, "digest") == "" || u64(a, "generation") != listed {
		t.Errorf("the offer's approval %v names no target, digest, or the listed generation %d", a, listed)
	}
	if inst := msg(offer, "installation"); installationPrincipal(inst) != principal {
		t.Errorf("the offer's installation is principal %q, want the installed %q", installationPrincipal(inst), principal)
	}
	if got := renderOffer(offer); got != golden {
		t.Fatalf("the reviewed offer is not the declaration\n--- got\n%s--- want\n%s--- difference\n%s", got, golden, lineDiff(got, golden))
	}
}

// renderOffer is the host-independent text of a reviewed offer: the
// declaration and what it covers. Host identities (ids, the principal, the
// opaque digest) and tools_composed, which says whether the run composed any
// Runnable binding, are left out; a capability's tools are kept.
func renderOffer(offer protoreflect.Message) string {
	var b strings.Builder
	fmt.Fprintf(&b, "target %s generation %d\n", str(offer, "target"), u64(msg(offer, "approval"), "generation"))
	if inst := msg(offer, "installation"); str(inst, "id") != "" {
		fmt.Fprintf(&b, "installation %s roles %v\n", enumName(inst, "status"), listStrings(inst, "roles"))
	}
	var ceiling []string
	for _, cb := range listMsgs(offer, "ceiling") {
		ceiling = append(ceiling, fmt.Sprintf("ceiling %s -> %s: %s\n", str(cb, "binding"), str(cb, "module"), renderScopes(listMsgs(cb, "scopes"))))
	}
	slices.Sort(ceiling)
	b.WriteString(strings.Join(ceiling, ""))
	roles := listMsgs(offer, "roles")
	slices.SortFunc(roles, func(a, b protoreflect.Message) int { return strings.Compare(str(a, "name"), str(b, "name")) })
	for _, r := range roles {
		fmt.Fprintf(&b, "role %s\n", str(r, "name"))
		var lines []string
		for _, s := range listMsgs(r, "scopes") {
			lines = append(lines, "  scope "+renderScope(s)+"\n")
		}
		slices.Sort(lines)
		b.WriteString(strings.Join(lines, ""))
		lines = nil
		for _, cp := range listMsgs(r, "capabilities") {
			var tools []string
			for _, tool := range listMsgs(cp, "tools") {
				tools = append(tools, fmt.Sprintf("%s(%s write=%t)", str(tool, "name"), str(tool, "binding"), field(tool, "write").Bool()))
			}
			slices.Sort(tools)
			lines = append(lines, fmt.Sprintf("  capability %s %s requires %s tools [%s]\n", str(cp, "module"), str(cp, "operation"), renderScopes(listMsgs(cp, "requires")), strings.Join(tools, " ")))
		}
		slices.Sort(lines)
		b.WriteString(strings.Join(lines, ""))
	}
	return b.String()
}

func renderScopes(scopes []protoreflect.Message) string {
	var out []string
	for _, s := range scopes {
		out = append(out, renderScope(s))
	}
	slices.Sort(out)
	return strings.Join(out, "; ")
}

func renderScope(s protoreflect.Message) string {
	actions := listStrings(s, "actions")
	slices.Sort(actions)
	out := fmt.Sprintf("%s %v", str(s, "resource_kind"), actions)
	if field(s, "attached_only").Bool() {
		ids := listStrings(s, "resource_ids")
		slices.Sort(ids)
		out += fmt.Sprintf(" attached-only ids %v", ids)
	}
	return out
}

// lineDiff names each line only one side has.
func lineDiff(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	var b strings.Builder
	for _, line := range g {
		if line != "" && !slices.Contains(w, line) {
			fmt.Fprintf(&b, "+ %s\n", line)
		}
	}
	for _, line := range w {
		if line != "" && !slices.Contains(g, line) {
			fmt.Fprintf(&b, "- %s\n", line)
		}
	}
	return b.String()
}

// grantedExactly requires the holder, holding r alone, to be issued exactly
// r's scopes within the ceiling, owned by the installation's principal: at the
// solution for its own kind, through the binding for the store's. Every
// action of the ceiling r does not hold is refused, by name.
func (c *client) grantedExactly(t *testing.T, issue func(string, []any) (protoreflect.Message, error), r declaredRole, principal string) {
	t.Helper()
	for _, at := range []struct{ binding, kind string }{{"", declaredPage}, {declaredBinding, declaredItem}} {
		want := r.held(at.kind)
		out, err := issue(at.binding, nil)
		switch {
		case len(want) == 0:
			// Holding nothing there, an empty ask is refused, not issued empty.
			refused(t, err, codes.PermissionDenied, "holds nothing")
		case err != nil:
			t.Fatalf("%s's capability (binding %q): %v", r.name, at.binding, err)
		default:
			if got := heldScope(msg(out, "context"), at.kind, principal); !slices.Equal(got, want) {
				t.Errorf("%s's capability (binding %q) holds %s %v, want exactly the declared %v", r.name, at.binding, at.kind, got, want)
			}
		}
		ceiling := declaredOwnCeiling
		if at.kind == declaredItem {
			ceiling = declaredBindingCeiling
		}
		for _, action := range ceiling {
			ask := []any{ownedBy(scopeAsk(at.kind, []string{action}, nil), principal)}
			_, err := issue(at.binding, ask)
			switch {
			case slices.Contains(want, action) && err != nil:
				t.Errorf("%s asking %s %s (binding %q) must be issued: %v", r.name, at.kind, action, at.binding, err)
			case !slices.Contains(want, action) && status.Code(err) != codes.PermissionDenied:
				t.Errorf("%s asking %s %s (binding %q) must be refused as PermissionDenied, got %v", r.name, at.kind, action, at.binding, err)
			}
		}
	}
}

// heldScope is the sorted actions a context holds on kind, requiring each row
// on it to be owned by the installation's principal and to name no ids.
func heldScope(wc protoreflect.Message, kind, principal string) []string {
	var actions []string
	for _, s := range listMsgs(wc, "authority_scopes") {
		if str(s, "resource_kind") != kind || field(s, "actions").List().Len() == 0 {
			continue
		}
		row := listStrings(s, "actions")
		if owner := str(s, "resource_owner_id"); owner != principal {
			row = []string{fmt.Sprintf("owner %q", owner)}
		}
		if ids := listStrings(s, "resource_ids"); len(ids) > 0 {
			row = append(row, fmt.Sprintf("ids %v", ids))
		}
		actions = append(actions, row...)
	}
	slices.Sort(actions)
	return slices.Compact(actions)
}
