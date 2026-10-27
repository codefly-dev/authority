package delivered_test

import (
	"crypto"
	"crypto/ed25519"
	"slices"
	"strings"
	"testing"

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
	if bare := delivered.FromCore(&solutionhost.ModuleManifest{Alias: "bare", Generation: 1}); bare.Principal != "bare" || len(bare.Bindings) != 0 {
		t.Fatalf("a manifest without authority composes its alias alone: %+v", bare)
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
