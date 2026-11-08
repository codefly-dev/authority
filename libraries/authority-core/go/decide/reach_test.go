package decide_test

import (
	"fmt"
	"maps"
	"math/rand"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

func rs(kind string, actions ...string) *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: kind, Actions: actions}
}

func byPrincipal(modules ...domain.Module) map[string]domain.Module {
	out := map[string]domain.Module{}
	for _, m := range modules {
		out[m.Principal] = m
	}
	return out
}

func rowAt(rows []domain.ReachRow, via, confinement string, path ...string) *domain.ReachRow {
	for i := range rows {
		if rows[i].Module == path[len(path)-1] && rows[i].Via == via && rows[i].Confinement == confinement {
			return &rows[i]
		}
	}
	return nil
}

// app is a solution whose editor writes its own notes and reaches docs
// through its binding; docs reaches model through its own.
func reachComposition() (domain.Module, map[string]domain.Module) {
	app := domain.Module{Name: "app", Principal: "app", Kind: domain.KindSolution,
		ResourceKinds: []*basev0.WorkScopeV1{rs("app.note", "read", "write")},
		Roles: map[string][]*basev0.WorkScopeV1{
			domain.InstallerRole: {rs("app.note", "read", "write")},
			"editor":             {rs("app.note", "read", "write"), rs("docs.doc", "read", "write"), rs("model.profile", "read")},
			"viewer":             {rs("app.note", "read")},
		},
		OwnedRoles:       map[string][]*basev0.WorkScopeV1{"editor": {rs("app.note", "write")}},
		Bindings:         map[string]domain.Binding{"docs": {ID: "docs", Audience: "docs", InvokeScopes: []*basev0.WorkScopeV1{rs("docs.doc", "read", "write")}}},
		EdgeDependencies: []domain.EdgeDependency{{Module: "directory", Presence: "required"}},
		Methods:          map[string]domain.MethodPolicy{"/app.v1.App/Edit": {Requires: []*basev0.WorkScopeV1{rs("app.note", "write")}}}}
	docs := domain.Module{Name: "docs", Principal: "docs", Kind: domain.KindModule,
		ResourceKinds: []*basev0.WorkScopeV1{rs("docs.doc", "read", "write", "admin")},
		Bindings:      map[string]domain.Binding{"model": {ID: "model", Audience: "model", InvokeScopes: []*basev0.WorkScopeV1{rs("model.profile", "read")}}},
		Methods: map[string]domain.MethodPolicy{
			"/docs.v1.Docs/Get":   {Requires: []*basev0.WorkScopeV1{rs("docs.doc", "read")}},
			"/docs.v1.Docs/Purge": {Requires: []*basev0.WorkScopeV1{rs("docs.doc", "admin")}},
			"GET /docs/{id}":      {Requires: []*basev0.WorkScopeV1{rs("docs.doc", "read")}},
		}}
	model := domain.Module{Name: "model", Principal: "model", Kind: domain.KindModule,
		ResourceKinds: []*basev0.WorkScopeV1{rs("model.profile", "read", "write")},
		Methods:       map[string]domain.MethodPolicy{"/model.v1.Model/Profiles": {Requires: []*basev0.WorkScopeV1{rs("model.profile", "read")}}}}
	directory := domain.Module{Name: "directory", Principal: "directory", Kind: domain.KindModule, Page: true,
		ResourceKinds: []*basev0.WorkScopeV1{rs("directory.entry", "read")}}
	unreached := domain.Module{Name: "unreached", Principal: "unreached", Kind: domain.KindModule,
		ResourceKinds: []*basev0.WorkScopeV1{rs("docs.doc", "read")}}
	return app, byPrincipal(app, docs, model, directory, unreached)
}

// Reach on the target is the role's own scopes within what the target
// serves, with their confinement: a solution's literal scopes confined to
// its installation's data, its installation-owned ones to what is attached;
// a module page's confined to nothing. A kind the role names only to reach
// it through a binding is not reached on the target.
func TestReachOnTheTargetIsTheRolesOwnScopes(t *testing.T) {
	app, modules := reachComposition()
	rows, err := decide.Reach(app, "editor", modules)
	if err != nil {
		t.Fatal(err)
	}
	own := rowAt(rows, decide.ReachRole, decide.ConfinedToInstallation, "app")
	if own == nil || !sameScopes(own.Scopes, []*basev0.WorkScopeV1{rs("app.note", "read", "write")}) || !slices.Equal(own.Operations, []string{"/app.v1.App/Edit"}) {
		t.Fatalf("the editor's own row is %+v", own)
	}
	if attached := rowAt(rows, decide.ReachRole, decide.ConfinedToAttached, "app"); attached == nil || !sameScopes(attached.Scopes, []*basev0.WorkScopeV1{rs("app.note", "write")}) {
		t.Fatalf("the editor's attached row is %+v", attached)
	}
	page := domain.Module{Name: "pages", Principal: "pages", Kind: domain.KindModule, Page: true,
		ResourceKinds: []*basev0.WorkScopeV1{rs("pages.note", "read", "write")},
		Roles:         map[string][]*basev0.WorkScopeV1{domain.InstallerRole: {rs("pages.note", "read", "write")}, "viewer": {rs("pages.note", "read")}}}
	rows, err = decide.Reach(page, "viewer", byPrincipal(page))
	if err != nil || len(rows) != 1 || rows[0].Via != decide.ReachRole || rows[0].Confinement != "" || !sameScopes(rows[0].Scopes, []*basev0.WorkScopeV1{rs("pages.note", "read")}) {
		t.Fatalf("a module page's viewer reaches %+v (%v)", rows, err)
	}
	if _, err := decide.Reach(app, "nobody", modules); err == nil {
		t.Fatal("an undeclared role has a reach")
	}
}

// Through the target's bindings the role reaches what each hop can carry:
// the role within what the module serves, cut to the binding and to every
// limit before it; the walk goes on through each reached module's own
// bindings. An edge on the holder's session carries no scopes, and a module
// no binding or edge reaches is absent.
func TestReachThroughBindingsAndEdges(t *testing.T) {
	app, modules := reachComposition()
	rows, err := decide.Reach(app, "editor", modules)
	if err != nil {
		t.Fatal(err)
	}
	docs := rowAt(rows, decide.ReachBinding, "", "app", "docs")
	if docs == nil || !sameScopes(docs.Scopes, []*basev0.WorkScopeV1{rs("docs.doc", "read", "write")}) ||
		!slices.Equal(docs.Operations, []string{"/docs.v1.Docs/Get", "GET /docs/{id}"}) {
		t.Fatalf("through app, docs is reached as %+v", docs)
	}
	if model := rowAt(rows, decide.ReachBinding, "", "app", "docs", "model"); model == nil || !sameScopes(model.Scopes, []*basev0.WorkScopeV1{rs("model.profile", "read")}) {
		t.Fatalf("through docs, model is reached as %+v", model)
	}
	viewer, err := decide.Reach(app, "viewer", modules)
	if err != nil || rowAt(viewer, decide.ReachBinding, "", "app", "docs") != nil || rowAt(viewer, decide.ReachBinding, "", "app", "docs", "model") != nil {
		t.Fatalf("the viewer, whose role names nothing docs serves, reaches %+v (%v)", viewer, err)
	}
	for _, r := range rows {
		if r.Module == "unreached" {
			t.Fatalf("a module with no path is reached: %+v", r)
		}
	}
}

// Reach on the person's session carries no scopes: the holder's own grants
// at the edge's module decide, so the row says so and lists nothing.
func TestReachOnThePersonsSessionCarriesNoScopes(t *testing.T) {
	app, modules := reachComposition()
	for _, role := range []string{"editor", "viewer"} {
		rows, err := decide.Reach(app, role, modules)
		if err != nil {
			t.Fatal(err)
		}
		person := rowAt(rows, decide.ReachPerson, "", "app", "directory")
		if person == nil || person.Scopes != nil || person.Operations != nil {
			t.Fatalf("the %s's row on the holder's session is %+v", role, person)
		}
	}
}

// One operation on two faces is one capability: a module declaring its gRPC
// procedure and its Connect route lists the operation once, and two
// bindings to the same module make one row.
func TestOneOperationOnTwoFacesIsOneCapability(t *testing.T) {
	app, modules := reachComposition()
	docs := modules["docs"]
	docs.Methods = maps.Clone(docs.Methods)
	docs.Methods["POST /docs.v1.Docs/Get"] = docs.Methods["/docs.v1.Docs/Get"]
	modules["docs"] = docs
	app.Bindings = map[string]domain.Binding{
		"docs-connect": {ID: "docs-connect", Audience: "docs", InvokeScopes: []*basev0.WorkScopeV1{rs("docs.doc", "read")}},
		"docs-grpc":    {ID: "docs-grpc", Audience: "docs", InvokeScopes: []*basev0.WorkScopeV1{rs("docs.doc", "read")}},
	}
	rows, err := decide.Reach(app, "editor", modules)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rows {
		if r.Module == "docs" {
			n++
			if !slices.Equal(r.Operations, []string{"/docs.v1.Docs/Get", "GET /docs/{id}"}) {
				t.Fatalf("docs lists %v, want the procedure once whatever face serves it", r.Operations)
			}
		}
	}
	if n != 1 {
		t.Fatalf("docs is reached in %d rows, want one", n)
	}
	if decide.Operation("POST /docs.v1.Docs/Get") != "/docs.v1.Docs/Get" || decide.Operation("POST /docs/{id}") != "POST /docs/{id}" || decide.Operation("GET /docs.v1.Docs/Get") != "GET /docs.v1.Docs/Get" {
		t.Fatal("Operation names a face wrongly")
	}
}

// Reach terminates on a cycle and accounts for re-entry: docs is entered
// from app for its documents alone, then again from model for its notes,
// and through its own binding; the walk ends, and docs' row holds both
// kinds, as issuance would carry them.
func TestReachTerminatesOnACycle(t *testing.T) {
	app, modules := reachComposition()
	app.Roles["editor"] = append(app.Roles["editor"], rs("docs.note", "read"), rs("docs.draft", "read"))
	docs, model := modules["docs"], modules["model"]
	docs.ResourceKinds = append(docs.ResourceKinds, rs("docs.note", "read"), rs("docs.draft", "read"))
	docs.Bindings = maps.Clone(docs.Bindings)
	docs.Bindings["self"] = domain.Binding{ID: "self", Audience: "docs", InvokeScopes: []*basev0.WorkScopeV1{rs("docs.draft", "read")}}
	model.Bindings = map[string]domain.Binding{
		"docs": {ID: "docs", Audience: "docs", InvokeScopes: []*basev0.WorkScopeV1{rs("docs.note", "read")}},
		"app":  {ID: "app", Audience: "app", InvokeScopes: []*basev0.WorkScopeV1{rs("app.note", "read")}},
	}
	modules["docs"], modules["model"] = docs, model
	rows, err := decide.Reach(app, "editor", modules)
	if err != nil {
		t.Fatal(err)
	}
	row := rowAt(rows, decide.ReachBinding, "", "docs")
	if row == nil || !sameScopes(row.Scopes, []*basev0.WorkScopeV1{rs("docs.doc", "read", "write"), rs("docs.note", "read"), rs("docs.draft", "read")}) {
		t.Fatalf("docs, re-entered, is reached as %+v", row)
	}
	if back := rowAt(rows, decide.ReachBinding, "", "app"); back == nil || !sameScopes(back.Scopes, []*basev0.WorkScopeV1{rs("app.note", "read")}) {
		t.Fatalf("app, re-entered through model, is reached as %+v", back)
	}
}

// randomComposition is a solution and modules over three kinds, with
// random served scopes, roles and bindings, cycles included.
func randomComposition(r *rand.Rand) (domain.Module, map[string]domain.Module) {
	kinds, actions := []string{"k1", "k2", "k3"}, []string{"read", "write", "admin"}
	some := func() []*basev0.WorkScopeV1 {
		var out []*basev0.WorkScopeV1
		for _, k := range kinds {
			if r.Intn(3) == 0 {
				continue
			}
			var acts []string
			for _, a := range actions {
				if r.Intn(2) == 0 {
					acts = append(acts, a)
				}
			}
			if len(acts) > 0 {
				out = append(out, rs(k, acts...))
			}
		}
		return out
	}
	names := []string{"s", "m1", "m2", "m3", "m4"}
	modules := map[string]domain.Module{}
	for i, name := range names {
		m := domain.Module{Name: name, Principal: name, Kind: domain.KindModule, ResourceKinds: some(), Bindings: map[string]domain.Binding{},
			Methods: map[string]domain.MethodPolicy{"/" + name + "/Op": {Requires: some()}}}
		if i == 0 {
			m.Kind, m.Roles = domain.KindSolution, map[string][]*basev0.WorkScopeV1{"r": some()}
		}
		for _, other := range names {
			if r.Intn(3) == 0 {
				m.Bindings[other] = domain.Binding{ID: other, Audience: other, InvokeScopes: some(), LookupScopes: nil}
			}
		}
		modules[name] = m
	}
	return modules["s"], modules
}

// Reach through a binding never exceeds the role, what the module serves,
// or the bindings into the module; and reach is monotone: removing a
// binding never adds a row or widens one.
func TestReachThroughABindingNeverExceedsTheRoleOrAnyBindingOnThePath(t *testing.T) {
	for seed := int64(0); seed < 300; seed++ {
		target, modules := randomComposition(rand.New(rand.NewSource(seed)))
		rows, err := decide.Reach(target, "r", modules)
		if err != nil {
			t.Fatal(err)
		}
		role := target.Roles["r"]
		for _, row := range rows {
			if row.Via != decide.ReachBinding {
				continue
			}
			if !scope.Attenuates(row.Scopes, role) || !scope.Attenuates(row.Scopes, modules[row.Module].ResourceKinds) {
				t.Fatalf("seed %d: %v reaches %v beyond the role %v or what it serves", seed, row.Path, row.Scopes, role)
			}
			// Whatever path reached it, a hop's scopes come from one binding
			// into the module.
			var into []*basev0.WorkScopeV1
			for _, m := range modules {
				for _, b := range m.Bindings {
					if b.Audience == row.Module {
						into = append(into, b.InvokeScopes...)
						into = append(into, b.LookupScopes...)
					}
				}
			}
			if !scope.Attenuates(row.Scopes, into) {
				t.Fatalf("seed %d: %s is reached with %v beyond every binding into it (%v)", seed, row.Module, row.Scopes, into)
			}
		}
	}
}

func TestReachIsMonotone(t *testing.T) {
	for seed := int64(0); seed < 200; seed++ {
		target, modules := randomComposition(rand.New(rand.NewSource(seed)))
		all, err := decide.ReachOf(target, slices.Collect(maps.Values(modules)))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range slices.Sorted(maps.Keys(modules)) {
			for _, id := range slices.Sorted(maps.Keys(modules[name].Bindings)) {
				cut := maps.Clone(modules)
				m := cut[name]
				m.Bindings = maps.Clone(m.Bindings)
				delete(m.Bindings, id)
				cut[name] = m
				reduced := cut[target.Principal]
				less, err := decide.ReachOf(reduced, slices.Collect(maps.Values(cut)))
				if err != nil {
					t.Fatal(err)
				}
				if w := decide.ReachWidens(all, less); len(w) > 0 {
					t.Fatalf("seed %d: removing %s's binding %s widened the reach: %v", seed, name, id, w)
				}
			}
		}
	}
}

// The canonical text a consent records reads back as the same reach, and
// its digest moves when the reach does.
func TestReachEncodesCanonically(t *testing.T) {
	app, modules := reachComposition()
	all, err := decide.ReachOf(app, slices.Collect(maps.Values(modules)))
	if err != nil {
		t.Fatal(err)
	}
	text, digest, err := decide.EncodeReach(all)
	if err != nil {
		t.Fatal(err)
	}
	back, err := decide.DecodeReach(text)
	if err != nil || len(decide.ReachWidens(all, back)) != 0 || len(decide.ReachWidens(back, all)) != 0 {
		t.Fatalf("decoded %v (%v)", back, err)
	}
	// The text names explicit fields, never a generated type's own marshaling.
	if !strings.Contains(text, `"scopes":[{"kind":"docs.doc","actions":["read","write"]}]`) || strings.Contains(text, "ResourceKind") || strings.Contains(text, "resource_kind") {
		t.Fatalf("the recorded reach is not the explicit encoding: %s", text)
	}
	again, digestAgain, _ := decide.EncodeReach(back)
	if again != text || digestAgain != digest {
		t.Fatal("the encoding is not canonical")
	}
	docs := modules["docs"]
	docs.Methods = maps.Clone(docs.Methods)
	docs.Methods["/docs.v1.Docs/Purge"] = domain.MethodPolicy{Requires: []*basev0.WorkScopeV1{rs("docs.doc", "write")}}
	modules["docs"] = docs
	wider, _ := decide.ReachOf(app, slices.Collect(maps.Values(modules)))
	if _, d, _ := decide.EncodeReach(wider); d == digest || fmt.Sprint(decide.ReachWidens(all, wider)) != "[role editor reaches /docs.v1.Docs/Purge at app > docs]" {
		t.Fatalf("a relaxed method policy is not a widening: %v", decide.ReachWidens(all, wider))
	}
}

// sameScopes: each attenuates the other.
func sameScopes(a, b []*basev0.WorkScopeV1) bool {
	return scope.Attenuates(a, b) && scope.Attenuates(b, a)
}
