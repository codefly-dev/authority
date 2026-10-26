package host

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const hostImport = "github.com/codefly-dev/authority/libraries/authority-client/go/host"

// generatedSelfDials are the only files allowed to dial without host's seams:
// the go-grpc agent's generated gateways, which self-dial 0.0.0.0 (and pass the
// same options to the generated *.pb.gw.go FromEndpoint helpers under gen/).
// They are generated, so they are fixed in the agent's gatewayDialOptions
// template (codefly-dev/service-go-grpc) and regenerated, never hand-edited.
// TestTheSelfDialAllowlistOnlyShrinks fails once a listed file carries
// grpc.WithNoProxy(), so its entry is removed with the regeneration.
var generatedSelfDials = map[string]bool{
	"modules/authority/services/hop/code/pkg/adapters/rest_gen.go":      true,
	"modules/authority/services/local/code/pkg/adapters/connect_gen.go": true,
	"modules/authority/services/local/code/pkg/adapters/rest_gen.go":    true,
	"modules/console/services/api/code/pkg/adapters/connect_gen.go":     true,
}

// The no-proxy gate (reviews r99, r101, r105): no non-test Go code in this
// repository makes an HTTP request or a gRPC dial except through
// host.HTTPTransport and host.DialOptions, the two seams that never follow a
// proxy from the environment. It is syntactic, over whole classes of use rather
// than call shapes, and refuses by file and line:
//
//  1. Any use (a call, a method value, a reference) of http.DefaultClient,
//     http.ProxyFromEnvironment, http.Get, http.Head, http.Post, http.PostForm
//     and httputil.NewSingleHostReverseProxy; and of http.DefaultTransport
//     anywhere but host.go, the one place that clones it.
//  2. Any use of grpc.NewClient, grpc.Dial and grpc.DialContext other than a
//     call with host.DialOptions(...) among its options (method values
//     included); only the generated self-dials above are allowlisted.
//  3. A dot-import of net/http, net/http/httputil or google.golang.org/grpc,
//     which would hide every name above.
//  4. The types http.Client and httputil.ReverseProxy anywhere except behind a
//     pointer or as the type of a composite literal: a value of them is a zero
//     value on http.DefaultTransport (var, new, fields, parameters, type
//     definitions and aliases, arrays, slices, maps, make). Such a literal must
//     set Transport: host.HTTPTransport().
//  5. The type http.Transport anywhere except behind a pointer: no second
//     transport is built (literal, new, var).
//  6. An assignment to any .Transport field of anything but host.HTTPTransport().
//
// host.HTTPTransport and host.DialOptions count only when they resolve to this
// package's import: an alias counts; a local function, another package's
// function or a local variable shadowing the import name does not.
//
// Known misses, by design of a syntactic gate: a raw net.Dial (or any other
// socket API), third-party HTTP or gRPC clients, and reflection.
func TestNoRequestOrDialBypassesTheNoProxySeams(t *testing.T) {
	root := repositoryRoot(t)
	var violations []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case "node_modules", ".git", "gen", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative, _ := filepath.Rel(root, path)
		relative = filepath.ToSlash(relative)
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		violations = append(violations, inspect(t, relative, source)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, violation := range violations {
		t.Error(violation)
	}
}

func inspect(t *testing.T, relative string, source []byte) []string {
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, relative, source, 0)
	if err != nil {
		t.Fatalf("%s: %v", relative, err)
	}
	var violations []string
	refuse := func(node ast.Node, what string) {
		violations = append(violations, fmt.Sprintf("%s:%d: %s", relative, files.Position(node.Pos()).Line, what))
	}
	names := map[string]string{} // local package name -> import path
	for _, spec := range file.Imports {
		importPath, _ := strconv.Unquote(spec.Path.Value)
		name := importPath[strings.LastIndex(importPath, "/")+1:]
		if importPath == hostImport {
			name = "host"
		}
		if spec.Name != nil {
			name = spec.Name.Name
		}
		names[name] = importPath
		if name == "." && (importPath == "net/http" || importPath == "net/http/httputil" || importPath == "google.golang.org/grpc") {
			refuse(spec, "a dot-import of "+importPath+" hides the names this gate refuses; import it by name")
		}
	}
	// is reports whether expression is pkg.selector for the import importPath.
	// The identifier must be one the parser bound to no local object, so a
	// local variable shadowing the import name is not taken for it.
	is := func(expression ast.Expr, importPath, selector string) bool {
		s, ok := expression.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		x, ok := s.X.(*ast.Ident)
		return ok && x.Obj == nil && names[x.Name] == importPath && s.Sel.Name == selector
	}
	inHost := relative == "libraries/authority-client/go/host/host.go"
	// seam reports whether expression is a call of host's function name:
	// through the import, or unqualified inside host.go itself.
	seam := func(expression ast.Expr, name string) bool {
		call, ok := expression.(*ast.CallExpr)
		if !ok {
			return false
		}
		if is(call.Fun, hostImport, name) {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		return ok && inHost && id.Name == name
	}
	containsSeam := func(expression ast.Expr, name string) bool {
		found := false
		ast.Inspect(expression, func(node ast.Node) bool {
			if e, ok := node.(ast.Expr); ok && seam(e, name) {
				found = true
			}
			return !found
		})
		return found
	}
	var stack []ast.Node
	ast.Inspect(file, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		var parent ast.Node
		if len(stack) > 0 {
			parent = stack[len(stack)-1]
		}
		stack = append(stack, node)
		switch n := node.(type) {
		case *ast.SelectorExpr:
			// Rule 1: banned names, any use.
			for _, name := range []string{"DefaultClient", "ProxyFromEnvironment", "Get", "Head", "Post", "PostForm"} {
				if is(n, "net/http", name) {
					refuse(n, "http."+name+" follows the environment proxy; use host.HTTPTransport()")
				}
			}
			if is(n, "net/http", "DefaultTransport") && !inHost {
				refuse(n, "http.DefaultTransport follows the environment proxy; use host.HTTPTransport()")
			}
			if is(n, "net/http/httputil", "NewSingleHostReverseProxy") {
				refuse(n, "httputil.NewSingleHostReverseProxy uses http.DefaultTransport; build a ReverseProxy with Transport: host.HTTPTransport()")
			}
			// Rule 2: gRPC dials, any use but a call dialling with host.DialOptions.
			for _, name := range []string{"NewClient", "Dial", "DialContext"} {
				if !is(n, "google.golang.org/grpc", name) || generatedSelfDials[relative] {
					continue
				}
				dials := false
				if call, ok := parent.(*ast.CallExpr); ok && call.Fun == n {
					for _, argument := range call.Args[1:] {
						dials = dials || containsSeam(argument, "DialOptions")
					}
				}
				if !dials {
					refuse(n, "grpc."+name+" must be called with host.DialOptions(transport)")
				}
			}
			// Rules 4 and 5: the client, proxy and transport types.
			if is(n, "net/http", "Client") || is(n, "net/http/httputil", "ReverseProxy") {
				_, pointer := parent.(*ast.StarExpr)
				literal, isLiteral := parent.(*ast.CompositeLit)
				switch {
				case pointer:
				case isLiteral && literal.Type == n:
					if !transportIsHost(literal, seam) {
						refuse(literal, "an http.Client or httputil.ReverseProxy literal must set Transport: host.HTTPTransport()")
					}
				default:
					refuse(n, "a value of http.Client or httputil.ReverseProxy is a zero value on http.DefaultTransport; hold a pointer to a literal with Transport: host.HTTPTransport()")
				}
			}
			if is(n, "net/http", "Transport") {
				if _, pointer := parent.(*ast.StarExpr); !pointer {
					refuse(n, "an http.Transport value is a second transport; use host.HTTPTransport()")
				}
			}
		case *ast.AssignStmt:
			// Rule 6: a .Transport field is only ever set to the seam.
			for index, left := range n.Lhs {
				if s, ok := left.(*ast.SelectorExpr); ok && s.Sel.Name == "Transport" {
					if index >= len(n.Rhs) || !seam(n.Rhs[index], "HTTPTransport") {
						refuse(n, "a .Transport field may only be set to host.HTTPTransport()")
					}
				}
			}
		}
		return true
	})
	return violations
}

// TestTheSelfDialAllowlistOnlyShrinks: every allowlisted file exists and still
// dials without grpc.WithNoProxy(); once regenerated with it, its entry goes.
func TestTheSelfDialAllowlistOnlyShrinks(t *testing.T) {
	root := repositoryRoot(t)
	for relative := range generatedSelfDials {
		source, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Errorf("%s is allowlisted but cannot be read: %v", relative, err)
			continue
		}
		if !strings.Contains(string(source), "grpc.NewClient") && !strings.Contains(string(source), "FromEndpoint(") {
			t.Errorf("%s is allowlisted but no longer dials; remove its entry", relative)
		}
		if strings.Contains(string(source), "WithNoProxy()") {
			t.Errorf("%s now dials with grpc.WithNoProxy(); remove its entry from generatedSelfDials", relative)
		}
	}
}

// transportIsHost reports whether literal sets Transport to host.HTTPTransport().
func transportIsHost(literal *ast.CompositeLit, seam func(ast.Expr, string) bool) bool {
	for _, element := range literal.Elts {
		if field, ok := element.(*ast.KeyValueExpr); ok {
			if key, ok := field.Key.(*ast.Ident); ok && key.Name == "Transport" {
				return seam(field.Value, "HTTPTransport")
			}
		}
	}
	return false
}

func repositoryRoot(t *testing.T) string {
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "workspace.codefly.yaml")); err == nil {
			if _, err := os.Stat(filepath.Join(directory, "libraries")); err == nil {
				return directory
			}
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("the authority repository root (workspace.codefly.yaml beside libraries/) was not found")
		}
		directory = parent
	}
}

// The HTTP seam cannot be unwrapped into a *http.Transport to reconfigure.
func TestHTTPTransportCannotBeReconfigured(t *testing.T) {
	if _, ok := HTTPTransport().(*http.Transport); ok {
		t.Fatal("HTTPTransport exposes the shared *http.Transport")
	}
}

// The gate itself, on sources written to bypass it (reviews r99, r101, r105):
// each is refused for its reason, and the approved forms pass.
func TestTheGateRefusesEachBypass(t *testing.T) {
	const header = "package x\nimport (\n\t\"net/http\"\n\t\"net/http/httputil\"\n\t\"google.golang.org/grpc\"\n\thost \"" + hostImport + "\"\n)\n" +
		"var _ = &httputil.ReverseProxy{Transport: host.HTTPTransport()}\n"
	const zero = "zero value on http.DefaultTransport"
	if violations := inspect(t, "x/x.go", []byte(header)); len(violations) != 0 {
		t.Fatalf("the shared header must pass, so each refusal below is its case's own: %v", violations)
	}
	for name, c := range map[string]struct{ source, reason string }{
		// Rule 1: banned names, any use.
		"DefaultClient":                   {"var _ = http.DefaultClient", "http.DefaultClient"},
		"DefaultTransport":                {"var _ = http.DefaultTransport", "http.DefaultTransport"},
		"ProxyFromEnvironment":            {"var _ = http.ProxyFromEnvironment", "ProxyFromEnvironment"},
		"http.Get called":                 {"func f() { _, _ = http.Get(\"u\") }", "http.Get"},
		"http.Get as a method value":      {"var get = http.Get", "http.Get"},
		"http.PostForm as a method value": {"var post = http.PostForm", "http.PostForm"},
		"NewSingleHostReverseProxy value": {"var p = httputil.NewSingleHostReverseProxy", "NewSingleHostReverseProxy"},
		// Rule 2: gRPC dials.
		"grpc.NewClient without the seam": {"func f() { _, _ = grpc.NewClient(\"t\") }", "grpc.NewClient must be called"},
		"grpc.Dial as a method value":     {"var dial = grpc.Dial", "grpc.Dial must be called"},
		// Rule 3: dot-imports.
		"dot-import of net/http": {"", "dot-import of net/http"},
		// Rule 4: client and proxy values.
		"zero-value client":                {"var c http.Client", zero},
		"zero-value proxy":                 {"var p httputil.ReverseProxy", zero},
		"new(http.Client)":                 {"var _ = new(http.Client)", zero},
		"new(httputil.ReverseProxy)":       {"var _ = new(httputil.ReverseProxy)", zero},
		"value-typed field":                {"type s struct{ c http.Client }", zero},
		"type definition":                  {"type myC http.Client", zero},
		"type alias":                       {"type C = http.Client", zero},
		"array":                            {"var cs [1]http.Client", zero},
		"make of a slice":                  {"var cs = make([]http.Client, 1)", zero},
		"map":                              {"var m map[string]httputil.ReverseProxy", zero},
		"client literal without transport": {"var _ = &http.Client{}", "literal must set Transport"},
		"a local HTTPTransport":            {"func HTTPTransport() http.RoundTripper { return nil }\nvar _ = &http.Client{Transport: HTTPTransport()}", "literal must set Transport"},
		"another package's HTTPTransport":  {"var _ = &http.Client{Transport: other.HTTPTransport()}", "literal must set Transport"},
		"a local variable shadowing host":  {"func f() { host := evil{}; _ = &http.Client{Transport: host.HTTPTransport()} }", "literal must set Transport"},
		// Rule 5: no second transport.
		"http.Transport literal": {"var _ = &http.Transport{}", "second transport"},
		"new(http.Transport)":    {"var _ = new(http.Transport)", "second transport"},
		// Rule 6: .Transport reassigned.
		"client Transport set to nil":    {"func f() { c := &http.Client{Transport: host.HTTPTransport()}; c.Transport = nil }", "may only be set to host.HTTPTransport()"},
		"proxy Transport set to another": {"func f(t http.RoundTripper) { p := &httputil.ReverseProxy{Transport: host.HTTPTransport()}; p.Transport = t }", "may only be set to host.HTTPTransport()"},
	} {
		t.Run(name, func(t *testing.T) {
			source := header + c.source + "\n"
			switch name {
			case "another package's HTTPTransport":
				source = strings.Replace(source, "\thost \"", "\tother \"example.com/other/host\"\n\thost \"", 1)
			case "dot-import of net/http":
				source = strings.Replace(source, "\t\"net/http\"\n", "\t. \"net/http\"\n", 1)
			}
			violations := inspect(t, "x/x.go", []byte(source))
			found := false
			for _, violation := range violations {
				found = found || strings.Contains(violation, c.reason)
			}
			if !found {
				t.Fatalf("want a refusal naming %q, got %v", c.reason, violations)
			}
		})
	}
	approved := map[string]string{
		"the host seam":                "var _ = &http.Client{Transport: host.HTTPTransport()}",
		"pointers":                     "type s struct{ c *http.Client }\nvar p *httputil.ReverseProxy\nvar t *http.Transport",
		"Transport set to the seam":    "func f(c *http.Client) { c.Transport = host.HTTPTransport() }",
		"a gRPC dial with DialOptions": "func f() { _, _ = grpc.NewClient(\"t\", host.DialOptions(nil)...) }",
	}
	for name, body := range approved {
		source := header + body + "\n"
		if violations := inspect(t, "x/x.go", []byte(source)); len(violations) != 0 {
			t.Errorf("%s: refused %v", name, violations)
		}
	}
	aliased := strings.NewReplacer("\thost \"", "\th \"", "host.HTTPTransport()", "h.HTTPTransport()").Replace(header) + "var _ = &http.Client{Transport: h.HTTPTransport()}\n"
	if violations := inspect(t, "x/x.go", []byte(aliased)); len(violations) != 0 {
		t.Errorf("an aliased host import: refused %v", violations)
	}
}
