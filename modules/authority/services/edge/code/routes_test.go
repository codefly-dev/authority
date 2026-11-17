package main

import (
	"net/http"
	"strings"
	"testing"
)

// generated is the edge-routes document Codefly generates, byte for byte the
// one its own test holds (cli, pkg/orchestration/edge_routes_test.go).
const generated = `{"schema":"codefly.dev/edge-routes/v1","modules":[{"audience":"owner","procedures":["/chat.v1.Service/Call","/worker.v1.Service/Call"]}]}`

func composition(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

// The edge routes what a module declares: the procedures Codefly generated
// from the module's published catalog. The composition names where the
// module's Connect face is and nothing about what it serves; a <MODULE>_RPC
// line it still carries is read by nobody.
func TestTheEdgeMountsTheProceduresCodeflyGenerated(t *testing.T) {
	modules, err := mount(composition(map[string]string{
		"MODULES":       "owner, page",
		"OWNER_CONNECT": "127.0.0.1:8081",
		"OWNER_RPC":     "typed.v1.ByHand",
		"PAGE_REST":     "127.0.0.1:8082",
		"PAGE_RPC":      "typed.v1.ByHand",
	}), generated)
	if err != nil {
		t.Fatal(err)
	}
	e := &Edge{Modules: modules}
	for _, procedure := range []string{"/chat.v1.Service/Call", "/worker.v1.Service/Call"} {
		module, target, ok := e.route(procedure)
		if !ok || module.Name != "owner" || target.Host != "127.0.0.1:8081" {
			t.Fatalf("%s is routed to %q at %v (%v)", procedure, module.Name, target, ok)
		}
	}
	// What no catalog publishes is routed nowhere: a service the composition
	// typed, and a method of a published service the module does not declare.
	for _, procedure := range []string{"/typed.v1.ByHand/Call", "/chat.v1.Service/Undeclared", "/chat.v1.Service", "/chat.v1.Service/Call/more"} {
		if module, _, ok := e.route(procedure); ok {
			t.Fatalf("%s is routed to %s, which no catalog publishes it for", procedure, module.Name)
		}
	}
	// A module mounted for its REST face alone keeps it.
	if module, target, ok := e.route("/v1/page/things"); !ok || module.Name != "page" || target.Host != "127.0.0.1:8082" {
		t.Fatalf("the REST face of page is routed to %q at %v (%v)", module.Name, target, ok)
	}
}

// An edge handed no document runs under a Codefly that generates none. It
// does not start on the hand-written list: what it would route is what a
// composition remembered to type.
func TestTheEdgeRefusesToStartWithoutGeneratedRoutes(t *testing.T) {
	values := composition(map[string]string{"MODULES": "owner", "OWNER_CONNECT": "127.0.0.1:8081", "OWNER_RPC": "chat.v1.Service"})
	_, err := mount(values, "")
	if err == nil || !strings.Contains(err.Error(), "edge-routes/ROUTES is empty") || !strings.Contains(err.Error(), "OWNER_RPC is no longer read") {
		t.Fatalf("an edge with no generated routes answered %v", err)
	}
	for name, raw := range map[string]string{
		"another schema":  `{"schema":"codefly.dev/hop-routes/v1","modules":[]}`,
		"unknown field":   `{"schema":"codefly.dev/edge-routes/v1","modules":[],"addresses":{}}`,
		"trailing":        generated + `{}`,
		"no audience":     `{"schema":"codefly.dev/edge-routes/v1","modules":[{"audience":"","procedures":[]}]}`,
		"twice":           `{"schema":"codefly.dev/edge-routes/v1","modules":[{"audience":"owner","procedures":[]},{"audience":"owner","procedures":[]}]}`,
		"not a procedure": `{"schema":"codefly.dev/edge-routes/v1","modules":[{"audience":"owner","procedures":["chat.v1.Service"]}]}`,
	} {
		if _, err := mount(values, raw); err == nil || !strings.Contains(err.Error(), "edge-routes") {
			t.Fatalf("%s: a malformed document answered %v", name, err)
		}
	}
}

// What the composition says and what the catalogs say must agree, by name,
// before the edge serves anything.
func TestTheEdgeRefusesACompositionItsRoutesContradict(t *testing.T) {
	// A Connect face for a module that publishes no procedure through the hop.
	_, err := mount(composition(map[string]string{"MODULES": "page", "PAGE_CONNECT": "127.0.0.1:8082"}), generated)
	if err == nil || !strings.Contains(err.Error(), "PAGE_CONNECT names a Connect face") || !strings.Contains(err.Error(), "hop/MODULES") {
		t.Fatalf("a Connect face nothing is published on answered %v", err)
	}
	// Two mounted modules publishing one procedure: a page's path names no
	// module to choose between them.
	twice := `{"schema":"codefly.dev/edge-routes/v1","modules":[{"audience":"one","procedures":["/chat.v1.Service/Call"]},{"audience":"two","procedures":["/chat.v1.Service/Call"]}]}`
	_, err = mount(composition(map[string]string{"MODULES": "one,two", "ONE_CONNECT": "127.0.0.1:8081", "TWO_CONNECT": "127.0.0.1:8082"}), twice)
	if err == nil || !strings.Contains(err.Error(), "/chat.v1.Service/Call is published by both one and two") {
		t.Fatalf("one procedure published by two modules answered %v", err)
	}
	// A module that publishes procedures but is mounted for REST alone is
	// served at REST alone: the composition named no Connect face for it.
	modules, err := mount(composition(map[string]string{"MODULES": "owner", "OWNER_REST": "127.0.0.1:8081"}), generated)
	if err != nil {
		t.Fatal(err)
	}
	if module, _, ok := (&Edge{Modules: modules}).route("/chat.v1.Service/Call"); ok {
		t.Fatalf("a module with no Connect face is routed %s", module.Name)
	}
}

// A method a mounted module's catalog does not declare is no module's: the
// edge answers it, and neither the authority nor the module is asked.
func TestAMethodAModuleDoesNotDeclareIsServedByNoModule(t *testing.T) {
	f := newFixture(t)
	cookie := f.signIn(t)
	header := http.Header{"Cookie": {cookie.String()}, "Origin": {f.edge.URL}, "Content-Type": {"application/json"}, "Connect-Protocol-Version": {"1"}}
	res, body := f.do(t, http.MethodPost, "/api/solutions/org-directory/proxy/_browser/records.v1.RecordsService/Undeclared", header)
	if res.StatusCode != http.StatusNotImplemented || !strings.Contains(body, "no module serves /records.v1.RecordsService/Undeclared") {
		t.Fatalf("an undeclared method answered %d: %s", res.StatusCode, body)
	}
	if len(f.authority.issued) != 0 || len(f.connect.path) != 0 {
		t.Fatalf("an undeclared method reached the authority (%v) or the module (%v)", f.authority.issued, f.connect.path)
	}
}
