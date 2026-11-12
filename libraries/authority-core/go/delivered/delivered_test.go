package delivered_test

import (
	"crypto"
	"crypto/ed25519"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/delivered"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	delivery "github.com/codefly-dev/authority/libraries/delivery/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/solutionhost"
)

func ws(kind string, actions ...string) *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: kind, Actions: actions}
}

func code(t *testing.T, err error, want domain.Code) {
	t.Helper()
	if got, ok := domain.CodeOf(err); !ok || got != want {
		t.Fatalf("want code %v, got %v (%v)", want, got, err)
	}
}

// Core's manifest writes a binding's operations as operation → "<kind>:<action>"
// entries; they are read as invoke, headless and lookup scopes.
func TestCoreBindingOperationsAreReadAsScopesPerOperation(t *testing.T) {
	m := delivered.FromCore(&solutionhost.ModuleManifest{Alias: "robin", Kind: solutionhost.KindModule, Generation: 3,
		Authority: &solutionhost.Authority{Principal: "robin-principal", ResourceKinds: []string{"robin.chat"}, Bindings: []solutionhost.AuthorityBinding{{
			ID: "model", Audience: "model",
			Operations: map[string][]string{
				"invoke":   {"modelservice.profiles:invoke", "modelservice.profiles:read", "malformed"},
				"lookup":   {"modelservice.profiles:read"},
				"headless": {"modelservice.profiles:read"},
			},
		}}}})
	if m.Name != "robin" || m.Principal != "robin-principal" || m.Kind != domain.KindModule || m.Generation != 3 {
		t.Fatalf("module %+v", m)
	}
	if !scope.Same(m.ResourceKinds, scope.Normalize([]*basev0.WorkScopeV1{ws("robin.chat", scope.AnyAction)})) {
		t.Fatalf("a declared kind serves any action until ceiled: %v", m.ResourceKinds)
	}
	b := m.Bindings["model"]
	if b.Audience != "model" || !scope.Same(b.InvokeScopes, scope.Normalize([]*basev0.WorkScopeV1{ws("modelservice.profiles", "invoke", "read")})) ||
		!scope.Same(b.HeadlessScopes, scope.Normalize([]*basev0.WorkScopeV1{ws("modelservice.profiles", "read")})) || !scope.Same(b.LookupScopes, b.HeadlessScopes) {
		t.Fatalf("binding %+v", b)
	}
	if bare := delivered.FromCore(&solutionhost.ModuleManifest{Alias: "bare", Generation: 1}); bare.Principal != "bare" || len(bare.Bindings) != 0 || bare.Page {
		t.Fatalf("a manifest without authority composes its alias alone: %+v", bare)
	}
	if page := delivered.FromCore(&solutionhost.ModuleManifest{Alias: "page", Generation: 1, Frontend: &solutionhost.Frontend{Title: "Page", ExposedModule: "./Page", HostContract: 1}}); !page.Page {
		t.Fatal("a manifest declaring a frontend is not read as a page")
	}
}

func TestScopeCeilingsGiveTheModulesKindsTheirActions(t *testing.T) {
	m := delivered.FromCore(&solutionhost.ModuleManifest{Alias: "runtime", Kind: solutionhost.KindModule, Generation: 1,
		Authority: &solutionhost.Authority{Principal: "runtime", ResourceKinds: []string{"runtime.tasks", "runtime.queues"}}})
	got, err := delivered.Ceiled(m, []*basev0.WorkScopeV1{ws("runtime.tasks", "start", "execute")})
	if err != nil {
		t.Fatal(err)
	}
	if !scope.Same(got.ResourceKinds, scope.Normalize([]*basev0.WorkScopeV1{ws("runtime.tasks", "execute", "start"), ws("runtime.queues", scope.AnyAction)})) {
		t.Fatalf("served %v", got.ResourceKinds)
	}
	for name, ceilings := range map[string][]*basev0.WorkScopeV1{
		"a kind core does not declare": {ws("records.records", "write")},
		"a kind with no action":        {ws("runtime.tasks")},
	} {
		_, err := delivered.Ceiled(m, ceilings)
		code(t, err, domain.Invalid)
		if !strings.Contains(err.Error(), "ceils") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func solutionManifest() *solutionhost.ModuleManifest {
	return &solutionhost.ModuleManifest{Alias: "pages", Kind: solutionhost.KindSolution, Generation: 2,
		Authority: &solutionhost.Authority{Principal: "pages", ResourceKinds: []string{"pages.page"}}}
}

func TestADocumentCompletesTheModule(t *testing.T) {
	doc := &delivered.Document{Module: "pages", Generation: 2, OwnerAware: true,
		ScopeCeilings: []*basev0.WorkScopeV1{ws("pages.page", "read", "write")},
		Methods:       []delivered.Method{{Method: "GET /p/{id}", Requires: []*basev0.WorkScopeV1{ws("pages.page", "read")}}, {Method: "/x/Ping", AnyCheckedCaller: true}},
		Roles: []delivered.Role{{Name: "installer", Scopes: []*basev0.WorkScopeV1{ws("pages.page", "write", "read")}},
			{Name: "viewer", Scopes: []*basev0.WorkScopeV1{ws("pages.page", "read")}, InstallationOwned: []*basev0.WorkScopeV1{ws("store.item", "read")}}},
	}
	m, err := delivered.Module(solutionManifest(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if !m.OwnerAware || len(m.Methods) != 2 || !m.Methods["/x/Ping"].AnyCheckedCaller || len(m.Roles) != 2 ||
		!slices.Equal(m.Roles["installer"][0].GetActions(), []string{"read", "write"}) || len(m.OwnedRoles["viewer"]) != 1 || len(m.OwnedRoles["installer"]) != 0 {
		t.Fatalf("module %+v", m)
	}
	if !scope.Same(m.ResourceKinds, scope.Normalize([]*basev0.WorkScopeV1{ws("pages.page", "read", "write")})) {
		t.Fatalf("served %v", m.ResourceKinds)
	}
	plain, err := delivered.Module(solutionManifest(), nil)
	if err != nil || plain.Roles != nil || plain.OwnerAware {
		t.Fatalf("no document: %+v %v", plain, err)
	}
}

func TestADocumentIsRefusedByName(t *testing.T) {
	removed := solutionManifest()
	removed.Removed = true
	for _, tc := range []struct {
		name     string
		manifest *solutionhost.ModuleManifest
		doc      delivered.Document
		code     domain.Code
		reason   string
	}{
		{"a method twice", solutionManifest(), delivered.Document{Methods: []delivered.Method{{Method: "/a"}, {Method: "/a"}}}, domain.Invalid, "twice or unnamed"},
		{"an unnamed method", solutionManifest(), delivered.Document{Methods: []delivered.Method{{}}}, domain.Invalid, "twice or unnamed"},
		{"a role twice", solutionManifest(), delivered.Document{Roles: []delivered.Role{{Name: "r"}, {Name: "r"}}}, domain.Invalid, "twice or unnamed"},
		{"a ceiling naming an owner", solutionManifest(), delivered.Document{ScopeCeilings: []*basev0.WorkScopeV1{{ResourceKind: "pages.page", Actions: []string{"read"}, ResourceOwnerId: "u"}}}, domain.Denied, "never selects an owner"},
		{"a withdrawal declaring roles", removed, delivered.Document{Roles: []delivered.Role{{Name: "installer"}}}, domain.Invalid, "withdrawal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := delivered.Module(tc.manifest, &tc.doc)
			code(t, err, tc.code)
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatal(err)
			}
		})
	}
}

// A document is signed by the key that signed the carrier, and names the
// carrier's module, generation and digest.
func TestADocumentIsPairedWithItsCarrier(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPrivate, _ := ed25519.GenerateKey(nil)
	sign := func(key ed25519.PrivateKey) func([]byte) ([]byte, error) {
		return func(b []byte) ([]byte, error) { return ed25519.Sign(key, b), nil }
	}
	keys := map[string]crypto.PublicKey{"release": public}
	document := []byte("the authority's document")
	envelope, err := delivery.Sign(document, "release", sign(private))
	if err != nil {
		t.Fatal(err)
	}
	if err := delivered.VerifyDocument(document, envelope, keys, "release"); err != nil {
		t.Fatal(err)
	}
	code(t, delivered.VerifyDocument(document, envelope, keys, "another"), domain.Denied)
	forged, _ := delivery.Sign(document, "release", sign(otherPrivate))
	code(t, delivered.VerifyDocument(document, forged, keys, "release"), domain.Denied)

	carrier := []byte("core's manifest")
	m := solutionManifest()
	good := delivered.Document{Module: "pages", Generation: 2, CoreManifestDigest: delivery.Digest(carrier)}
	if err := delivered.Pair(good, carrier, m); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]delivered.Document{
		"another module":     {Module: "other", Generation: 2, CoreManifestDigest: good.CoreManifestDigest},
		"another generation": {Module: "pages", Generation: 1, CoreManifestDigest: good.CoreManifestDigest},
		"another manifest":   {Module: "pages", Generation: 2, CoreManifestDigest: delivery.Digest([]byte("other"))},
	} {
		t.Run(name, func(t *testing.T) { code(t, delivered.Pair(doc, carrier, m), domain.Denied) })
	}
}

// A role's scopes named through a binding are part of its grant, and the
// module keeps how each is reached (domain.Module.Through); an empty through
// is refused by name.
func TestARoleNamesWhatItReachesThroughABinding(t *testing.T) {
	doc := &delivered.Document{Module: "pages", Generation: 2, OwnerAware: true,
		ScopeCeilings: []*basev0.WorkScopeV1{ws("pages.page", "read")},
		Roles: []delivered.Role{{Name: "installer", Scopes: []*basev0.WorkScopeV1{ws("pages.page", "read")}},
			{Name: "viewer", Scopes: []*basev0.WorkScopeV1{ws("pages.page", "read")},
				Through: map[string]delivered.Scopes{"agent": {ws("model.profiles", "invoke"), ws("docs.doc", "read")}}}},
	}
	m, err := delivered.Module(solutionManifest(), doc)
	if err != nil {
		t.Fatal(err)
	}
	want := scope.Normalize([]*basev0.WorkScopeV1{ws("pages.page", "read"), ws("model.profiles", "invoke"), ws("docs.doc", "read")})
	if !scope.Same(m.Roles["viewer"], want) || len(m.Through) != 1 || len(m.Through["viewer"]["agent"]) != 2 {
		t.Fatalf("roles %v through %v", m.Roles, m.Through)
	}
	doc.Roles[1].Through = map[string]delivered.Scopes{"agent": nil}
	_, err = delivered.Module(solutionManifest(), doc)
	code(t, err, domain.Invalid)
}

// A page the host bundles (solutionhost.Frontend.Bundled) is a page exactly
// as a remote it loads is: the roles delivered with it are admitted. This is
// the manifest shape of a module whose page is a package the host builds
// into its own frontend, which before this read as headless and was refused
// its roles with "declares roles and no page".
func TestAPageTheHostBundlesIsAPage(t *testing.T) {
	bundled := &solutionhost.ModuleManifest{Alias: "models", Kind: solutionhost.KindModule, Generation: 1,
		Authority: &solutionhost.Authority{Principal: "models", ResourceKinds: []string{"models.profiles"}, InstallationRole: "none"},
		Frontend:  &solutionhost.Frontend{Title: "Installed models", Order: 60, Bundled: &solutionhost.FrontendBundled{Package: "@acme/models-ui", Export: "modelsPlugin"}}}
	if m := delivered.FromCore(bundled); !m.Page {
		t.Fatal("a bundled page is not a page")
	}
	doc := &delivered.Document{Module: "models", Generation: 1, InstallationRole: "none",
		ScopeCeilings: []*basev0.WorkScopeV1{ws("models.profiles", "invoke", "read")},
		Roles: []delivered.Role{{Name: "installer", Scopes: []*basev0.WorkScopeV1{ws("models.profiles", "invoke", "read")}},
			{Name: "editor", Scopes: []*basev0.WorkScopeV1{ws("models.profiles", "invoke", "read")}},
			{Name: "viewer", Scopes: []*basev0.WorkScopeV1{ws("models.profiles", "read")}}}}
	m, err := delivered.Module(bundled, doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := decide.ValidateModule(m); err != nil || len(m.Roles) != 3 {
		t.Fatalf("a bundled page's three roles: %v, %v", err, m.Roles)
	}
	headless := *bundled
	headless.Frontend = nil
	m, err = delivered.Module(&headless, doc)
	if err != nil {
		t.Fatal(err)
	}
	code(t, decide.ValidateModule(m), domain.Denied)
}

// A module page delivered with no roles composes with the standard three
// derived from what it serves (decide.StandardRoles); a declaration wins; a
// solution and a module without a page derive none.
func TestAModulePageWithoutRolesGetsTheStandardOnes(t *testing.T) {
	page := &solutionhost.ModuleManifest{Alias: "notes", Kind: solutionhost.KindModule, Generation: 1,
		Authority: &solutionhost.Authority{Principal: "notes", ResourceKinds: []string{"notes.entry"}, InstallationRole: "none"},
		Frontend:  &solutionhost.Frontend{Title: "Notes", ExposedModule: "./Page", HostContract: 1}}
	doc := &delivered.Document{Module: "notes", Generation: 1, InstallationRole: "none", ScopeCeilings: []*basev0.WorkScopeV1{ws("notes.entry", "read", "write")}}
	m, err := delivered.Module(page, doc)
	if err != nil {
		t.Fatal(err)
	}
	if !scope.Same(m.Roles[decide.ViewerRole], []*basev0.WorkScopeV1{ws("notes.entry", "read")}) ||
		!scope.Same(m.Roles[decide.EditorRole], []*basev0.WorkScopeV1{ws("notes.entry", "read", "write")}) ||
		!scope.Same(m.Roles[domain.InstallerRole], []*basev0.WorkScopeV1{ws("notes.entry", "read", "write")}) {
		t.Fatalf("derived %v", m.Roles)
	}
	if err := decide.ValidateModule(m); err != nil || !decide.RoleGated(m) {
		t.Fatalf("the derived roles: %v, gated %v", err, decide.RoleGated(m))
	}
	declared := *doc
	declared.Roles = []delivered.Role{{Name: "installer", Scopes: []*basev0.WorkScopeV1{ws("notes.entry", "read")}}}
	if m, err = delivered.Module(page, &declared); err != nil || len(m.Roles) != 1 {
		t.Fatalf("a declaration wins: %v %v", m.Roles, err)
	}
	headless := *page
	headless.Frontend = nil
	if m, err = delivered.Module(&headless, doc); err != nil || m.Roles != nil {
		t.Fatalf("a module without a page derives roles: %v %v", m.Roles, err)
	}
	if m, err = delivered.Module(solutionManifest(), nil); err != nil || m.Roles != nil {
		t.Fatalf("a solution derives roles: %v %v", m.Roles, err)
	}
}
