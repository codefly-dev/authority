package conformance

import (
	"context"
	"slices"
	"testing"

	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// InstallationResourcesCase proves a role scope a solution declares
// installation-owned. The host seeds two active installations, A and B, of two
// solutions at Organization: Owner installed both, and Viewer is entitled to A
// alone, through A's viewer role. The suite delivers both solutions and Store,
// the module serving Kind, so their declarations are exactly the suite's. Each
// solution serves its own kind, "<solution>.note": a kind has one serving module.
type InstallationResourcesCase struct {
	Owner, Viewer string // fixture tokens
	A, B          OwnedInstallation
	// Store is the module serving Kind; StoreCredential is its workload.
	Store, StoreCredential, Kind string
	// Generation the suite delivers Store, A and B at.
	Generation uint64
	// ResourceA and ResourceA2 are created through A, ResourceB through B.
	// ResourceX and ResourceY exist and no installation owns them: Owner, as
	// A's installer, administers both, and attaches X only.
	ResourceA, ResourceA2, ResourceB, ResourceX, ResourceY string
}

// OwnedInstallation is one installed solution of the case.
type OwnedInstallation struct {
	Solution, Credential, Installation string
}

func (c *client) installationResources(t *testing.T, ctx context.Context, fixture Fixture) {
	f := fixture.InstallationResources
	if f == nil || fixture.SignManifest == nil || fixture.SignAuthority == nil || f.Owner == "" || f.Viewer == "" || f.A.Installation == "" || f.B.Installation == "" ||
		f.StoreCredential == "" || f.Generation == 0 || len(slices.Compact(slices.Sorted(slices.Values([]string{f.ResourceA, f.ResourceA2, f.ResourceB, f.ResourceX, f.ResourceY, ""})))) != 6 {
		t.Fatal("required conformance fixture missing: signed delivery, two owned installations and five distinct resources")
	}
	const binding, self = "store", "self"
	create, read, admin := scopeAsk(f.Kind, []string{"create"}, nil), scopeAsk(f.Kind, []string{"read"}, nil), scopeAsk(f.Kind, []string{"admin"}, nil)
	// Store serves Kind; its self binding lets it hop on, and work headless.
	both := []string{f.Kind + ":create", f.Kind + ":read"}
	if _, err := c.deliver(ctx, fixture, f.Store, "module", f.Generation, []string{f.Kind},
		map[string]any{"scope_ceilings": []any{scopeAsk(f.Kind, []string{"admin", "create", "read"}, nil)}}, 0,
		solutionhost.AuthorityBinding{ID: self, Audience: f.Store, Operations: map[string][]string{"invoke": both, "headless": both}}); err != nil {
		t.Fatalf("deliver %s: %v", f.Store, err)
	}
	// Each installer may create, and reads and administers every resource of
	// the kind; a viewer reads only what its own installation owns.
	for _, s := range []OwnedInstallation{f.A, f.B} {
		own := scopeAsk(s.Solution+".note", []string{"read"}, nil)
		doc := map[string]any{
			"scope_ceilings": []any{own},
			"roles": []any{
				map[string]any{"name": "installer", "scopes": []any{own, create, read, admin}},
				map[string]any{"name": "viewer", "scopes": []any{own}, "installation_owned_scopes": []any{read}},
			},
		}
		if _, err := c.deliver(ctx, fixture, s.Solution, "solution", f.Generation, []string{s.Solution + ".note"}, doc, 0,
			solutionhost.AuthorityBinding{ID: binding, Audience: f.Store, Operations: map[string][]string{"invoke": append(both, f.Kind+":admin")}}); err != nil {
			t.Fatalf("deliver %s: %v", s.Solution, err)
		}
	}
	signIn := func(token string) context.Context {
		return as(ctx, c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": token}))
	}
	owner, viewer := signIn(f.Owner), signIn(f.Viewer)
	issue := func(fields map[string]any) (protoreflect.Message, error) {
		return c.call(ctx, "host.authority.v1.AuthorityService", "Issue", fields)
	}
	// through issues person at s's root, then s's hop to Store asking scopes.
	through := func(t *testing.T, person context.Context, s OwnedInstallation, scopes ...any) (protoreflect.Message, error) {
		t.Helper()
		root := c.must(t, person, "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": s.Solution})
		return issue(map[string]any{"parent_token": str(root, "token"), "actor": map[string]any{"credential": s.Credential},
			"operation_binding_id": binding, "audience": f.Store, "scopes": scopes})
	}
	hop := func(parent protoreflect.Message, scopes ...any) (protoreflect.Message, error) {
		return issue(map[string]any{"parent_token": str(parent, "token"), "actor": map[string]any{"credential": f.StoreCredential},
			"operation_binding_id": self, "audience": f.Store, "scopes": scopes})
	}
	attach := func(token, credential, id string) (protoreflect.Message, error) {
		return c.call(ctx, "host.authority.v1.AuthorityService", "AttachResource", map[string]any{"token": token,
			"actor": map[string]any{"credential": credential}, "resource_kind": f.Kind, "resource_id": id})
	}

	t.Run("a resource created through an installation is attached to it, read from provenance", func(t *testing.T) {
		for s, ids := range map[OwnedInstallation][]string{f.A: {f.ResourceA, f.ResourceA2}, f.B: {f.ResourceB}} {
			created, err := through(t, owner, s, create)
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range ids {
				out, err := attach(str(created, "token"), f.StoreCredential, id)
				if err != nil {
					t.Fatal(err)
				}
				if got := str(out, "installation_id"); got != s.Installation {
					t.Fatalf("%s attached to %s, want %s", id, got, s.Installation)
				}
			}
		}
	})
	t.Run("an existing resource is never pulled into another installation, by name", func(t *testing.T) {
		// A read-only capability attaches nothing: A's viewer cannot pull B's
		// collection into A, nor a read through B pull A's into B.
		viewed, err := through(t, viewer, f.A)
		if err != nil {
			t.Fatal(err)
		}
		_, err = attach(str(viewed, "token"), f.StoreCredential, f.ResourceB)
		refused(t, err, codes.PermissionDenied, "holds neither")
		readB, err := through(t, owner, f.B, scopeAsk(f.Kind, []string{"read"}, []string{f.ResourceB}))
		if err != nil {
			t.Fatal(err)
		}
		_, err = attach(str(readB, "token"), f.StoreCredential, f.ResourceA)
		refused(t, err, codes.PermissionDenied, "holds neither")
		// A creating capability, or one administering the very id, attaches
		// only what no other installation owns.
		for s, foreign := range map[OwnedInstallation]string{f.A: f.ResourceB, f.B: f.ResourceA} {
			for _, ask := range []any{create, scopeAsk(f.Kind, []string{"admin"}, []string{foreign})} {
				capability, err := through(t, owner, s, ask)
				if err != nil {
					t.Fatal(err)
				}
				_, err = attach(str(capability, "token"), f.StoreCredential, foreign)
				refused(t, err, codes.PermissionDenied, "owned by")
			}
		}
	})
	t.Run("an attachment is refused without a serving module or an installation, by name", func(t *testing.T) {
		created, err := through(t, owner, f.A, create)
		if err != nil {
			t.Fatal(err)
		}
		_, err = attach(str(created, "token"), f.A.Credential, f.ResourceB)
		refused(t, err, codes.PermissionDenied, "does not serve")
		headless, err := issue(map[string]any{"workload": map[string]any{"credential": f.StoreCredential}, "organization_id": fixture.Organization,
			"operation_binding_id": self, "audience": f.Store, "operation": "headless"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = attach(str(headless, "token"), f.StoreCredential, f.ResourceB)
		refused(t, err, codes.PermissionDenied, "no installation")
	})
	t.Run("a viewer of an installation reads exactly what it owns", func(t *testing.T) {
		out, err := through(t, viewer, f.A)
		if err != nil {
			t.Fatal(err)
		}
		exactEffectiveScope(t, msg(out, "context"), f.Kind, []string{"read"}, []string{f.ResourceA, f.ResourceA2})
		c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": f.Store})
		listed := c.must(t, ctx, "host.authority.v1.AuthorityService", "ListResources", map[string]any{"token": str(out, "token"), "audience": f.Store, "resource_kind": f.Kind, "action": "read"})
		var ids []string
		for _, g := range grantsOf(listed) {
			if g.ID == "" {
				t.Fatalf("an installation-owned read listed a grant beyond ids: %+v", g)
			}
			ids = append(ids, g.ID)
		}
		if slices.Sort(ids); !slices.Equal(ids, slices.Sorted(slices.Values([]string{f.ResourceA, f.ResourceA2}))) {
			t.Fatalf("listed %v, want exactly %s's resources", ids, f.A.Installation)
		}
	})
	t.Run("the same viewer is refused another installation's resource, by name", func(t *testing.T) {
		_, err := through(t, viewer, f.A, scopeAsk(f.Kind, []string{"read"}, []string{f.ResourceB}))
		refused(t, err, codes.PermissionDenied, "widens")
		_, err = through(t, viewer, f.A, read)
		refused(t, err, codes.PermissionDenied, "widens")
		_, err = c.call(viewer, "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.B.Solution})
		refused(t, err, codes.PermissionDenied, "holds nothing")
	})
	t.Run("a child context never widens an installation-owned grant it narrowed", func(t *testing.T) {
		narrowed, err := through(t, viewer, f.A, scopeAsk(f.Kind, []string{"read"}, []string{f.ResourceA}))
		if err != nil {
			t.Fatal(err)
		}
		next, err := hop(narrowed)
		if err != nil {
			t.Fatal(err)
		}
		exactEffectiveScope(t, msg(next, "context"), f.Kind, []string{"read"}, []string{f.ResourceA})
		for _, ask := range []any{scopeAsk(f.Kind, []string{"read"}, []string{f.ResourceA2}), scopeAsk(f.Kind, []string{"read"}, []string{f.ResourceB}), read} {
			_, err := hop(narrowed, ask)
			refused(t, err, codes.PermissionDenied, "widens")
		}
	})
	t.Run("an administrator of an existing resource attaches it, and only it", func(t *testing.T) {
		reads, err := through(t, owner, f.A, scopeAsk(f.Kind, []string{"read"}, []string{f.ResourceX}))
		if err != nil {
			t.Fatal(err)
		}
		_, err = attach(str(reads, "token"), f.StoreCredential, f.ResourceX)
		refused(t, err, codes.PermissionDenied, "holds neither")
		administers, err := through(t, owner, f.A, scopeAsk(f.Kind, []string{"admin"}, []string{f.ResourceX}))
		if err != nil {
			t.Fatal(err)
		}
		_, err = attach(str(administers, "token"), f.StoreCredential, f.ResourceY)
		refused(t, err, codes.PermissionDenied, "holds neither")
		out, err := attach(str(administers, "token"), f.StoreCredential, f.ResourceX)
		if err != nil {
			t.Fatal(err)
		}
		if got := str(out, "installation_id"); got != f.A.Installation {
			t.Fatalf("%s attached to %s, want %s", f.ResourceX, got, f.A.Installation)
		}
		viewed, err := through(t, viewer, f.A)
		if err != nil {
			t.Fatal(err)
		}
		exactEffectiveScope(t, msg(viewed, "context"), f.Kind, []string{"read"}, []string{f.ResourceA, f.ResourceA2, f.ResourceX})
	})
	t.Run("a deleted resource is detached by its serving module and may be attached again", func(t *testing.T) {
		detach := func(credential, id string) (protoreflect.Message, error) {
			return c.call(ctx, "host.authority.v1.AuthorityService", "DetachResource", map[string]any{"actor": map[string]any{"credential": credential},
				"organization_id": fixture.Organization, "resource_kind": f.Kind, "resource_id": id})
		}
		_, err := detach(f.A.Credential, f.ResourceA2)
		refused(t, err, codes.PermissionDenied, "does not serve")
		out, err := detach(f.StoreCredential, f.ResourceA2)
		if err != nil {
			t.Fatal(err)
		}
		if got := str(out, "installation_id"); got != f.A.Installation {
			t.Fatalf("%s detached from %q, want %s", f.ResourceA2, got, f.A.Installation)
		}
		viewed, err := through(t, viewer, f.A)
		if err != nil {
			t.Fatal(err)
		}
		exactEffectiveScope(t, msg(viewed, "context"), f.Kind, []string{"read"}, []string{f.ResourceA, f.ResourceX})
		created, err := through(t, owner, f.B, create)
		if err != nil {
			t.Fatal(err)
		}
		if out, err = attach(str(created, "token"), f.StoreCredential, f.ResourceA2); err != nil || str(out, "installation_id") != f.B.Installation {
			t.Fatalf("a re-created id attaches to its new owner: %v %v", out, err)
		}
		if out, err = detach(f.StoreCredential, f.ResourceY); err != nil || str(out, "installation_id") != "" {
			t.Fatalf("detaching an id nobody owns answers no installation: %v %v", out, err)
		}
	})
}
