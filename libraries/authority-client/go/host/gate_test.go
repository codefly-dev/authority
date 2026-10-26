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

// A generated adapter (pkg/adapters/*_gen.go, rendered by the go-grpc agent)
// self-dials its own gRPC server through the package's generated
// gatewayDialOptions rather than host.DialOptions: it is generated, so it is
// fixed in the agent's template (codefly-dev/service-go-grpc) and regenerated,
// never hand-edited. The gate accepts such a dial only when that package's
// gatewayDialOptions carries grpc.WithNoProxy(), which the agent renders from
// 0.1.67; an adapter rendered by an older agent is refused.

// The no-proxy gate (review r99): no non-test Go code in this repository makes
// an HTTP request or a gRPC dial except through host.HTTPTransport and
// host.DialOptions, the two seams that never follow a proxy from the
// environment. It refuses, by file and line:
//   - http.DefaultTransport and http.DefaultClient, and http.Get/Head/Post/PostForm
//     (which use them), anywhere but host.go, the one place that clones it;
//   - an http.Client or httputil.ReverseProxy literal whose Transport is not
//     host.HTTPTransport(), and httputil.NewSingleHostReverseProxy;
//   - grpc.NewClient, grpc.Dial and grpc.DialContext without host.DialOptions(...)
//     among their options, except a generated adapter's self-dial through a
//     gatewayDialOptions that carries grpc.WithNoProxy().
func TestNoRequestOrDialBypassesTheNoProxySeams(t *testing.T) {
	root := repositoryRoot(t)
	seams := adapterSeams{dialsThrough: map[string]string{}, noProxy: map[string]bool{}}
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
		violations = append(violations, inspect(t, path, relative, &seams)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	violations = append(violations, seams.violations()...)
	for _, violation := range violations {
		t.Error(violation)
	}
}

// adapterSeams records, per generated adapter package, where a self-dial goes
// through gatewayDialOptions and whether that package's gatewayDialOptions
// carries grpc.WithNoProxy().
type adapterSeams struct {
	dialsThrough map[string]string // package directory -> first such dial, file:line
	noProxy      map[string]bool   // package directory -> gatewayDialOptions carries grpc.WithNoProxy()
}

// violations names every adapter package that self-dials through a
// gatewayDialOptions without grpc.WithNoProxy().
func (s adapterSeams) violations() []string {
	var violations []string
	for directory, where := range s.dialsThrough {
		if !s.noProxy[directory] {
			violations = append(violations, fmt.Sprintf("%s: dials through gatewayDialOptions, which does not carry grpc.WithNoProxy(); regenerate with go-grpc 0.1.67 or later", where))
		}
	}
	return violations
}

func inspect(t *testing.T, path, relative string, seams *adapterSeams) []string {
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, path, nil, 0)
	if err != nil {
		t.Fatalf("%s: %v", relative, err)
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
	}
	is := func(expression ast.Expr, importPath, selector string) bool {
		s, ok := expression.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		x, ok := s.X.(*ast.Ident)
		return ok && names[x.Name] == importPath && s.Sel.Name == selector
	}
	calls := func(node ast.Node, importPath, selector string) bool {
		found := false
		ast.Inspect(node, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok && is(call.Fun, importPath, selector) {
				found = true
			}
			return !found
		})
		return found
	}
	inHost := relative == "libraries/authority-client/go/host/host.go"
	directory := filepath.ToSlash(filepath.Dir(relative))
	generatedAdapter := strings.HasSuffix(relative, "_gen.go") && strings.HasSuffix(directory, "/pkg/adapters")
	// The identifiers a generated adapter assigns from gatewayDialOptions(...).
	fromSeam := map[string]bool{}
	if generatedAdapter {
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.AssignStmt:
				if len(n.Lhs) == len(n.Rhs) {
					for i, rhs := range n.Rhs {
						if id, ok := n.Lhs[i].(*ast.Ident); ok && callsLocal(rhs, "gatewayDialOptions") {
							fromSeam[id.Name] = true
						}
					}
				}
			case *ast.FuncDecl:
				if n.Recv == nil && n.Name.Name == "gatewayDialOptions" && n.Body != nil {
					seams.noProxy[directory] = calls(n.Body, "google.golang.org/grpc", "WithNoProxy")
				}
			}
			return true
		})
	}
	throughSeam := func(argument ast.Expr) bool {
		if !generatedAdapter {
			return false
		}
		if id, ok := argument.(*ast.Ident); ok && fromSeam[id.Name] {
			return true
		}
		return callsLocal(argument, "gatewayDialOptions")
	}
	var violations []string
	refuse := func(node ast.Node, what string) {
		violations = append(violations, fmt.Sprintf("%s:%d: %s", relative, files.Position(node.Pos()).Line, what))
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.SelectorExpr:
			for _, name := range []string{"DefaultTransport", "DefaultClient"} {
				if is(n, "net/http", name) && !inHost {
					refuse(n, "http."+name+" follows the environment proxy; use host.HTTPTransport()")
				}
			}
		case *ast.CompositeLit:
			if is(n.Type, "net/http", "Client") || is(n.Type, "net/http/httputil", "ReverseProxy") {
				if !transportIsHost(n, calls) {
					refuse(n, "an http.Client or httputil.ReverseProxy must set Transport: host.HTTPTransport()")
				}
			}
		case *ast.CallExpr:
			for _, name := range []string{"Get", "Head", "Post", "PostForm"} {
				if is(n.Fun, "net/http", name) {
					refuse(n, "http."+name+" uses http.DefaultClient; build a client on host.HTTPTransport()")
				}
			}
			if is(n.Fun, "net/http/httputil", "NewSingleHostReverseProxy") {
				refuse(n, "httputil.NewSingleHostReverseProxy uses http.DefaultTransport; set Transport: host.HTTPTransport()")
			}
			for _, name := range []string{"NewClient", "Dial", "DialContext"} {
				if is(n.Fun, "google.golang.org/grpc", name) {
					dials, seamed := false, false
					for _, argument := range n.Args[1:] {
						dials = dials || calls(argument, hostImport, "DialOptions") || inHost && callsLocal(argument, "DialOptions")
						seamed = seamed || throughSeam(argument)
					}
					if !dials && seamed {
						if _, seen := seams.dialsThrough[directory]; !seen {
							seams.dialsThrough[directory] = fmt.Sprintf("%s:%d", relative, files.Position(n.Pos()).Line)
						}
						dials = true
					}
					if !dials {
						refuse(n, "grpc."+name+" must dial with host.DialOptions(transport)")
					}
				}
			}
		}
		return true
	})
	return violations
}

func callsLocal(expression ast.Expr, name string) bool {
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == name {
				found = true
			}
		}
		return !found
	})
	return found
}

// A generated adapter's self-dial passes only while its package's
// gatewayDialOptions carries grpc.WithNoProxy(); outside a generated adapter,
// gatewayDialOptions is no seam at all.
func TestAGeneratedSelfDialNeedsTheNoProxySeam(t *testing.T) {
	const dial = `package adapters

import "google.golang.org/grpc"

func health() {
	opts := gatewayDialOptions()
	_, _ = grpc.NewClient("127.0.0.1:1", opts...)
	_, _ = grpc.NewClient("127.0.0.1:1", gatewayDialOptions()...)
}
`
	options := func(body string) string {
		return "package adapters\n\nimport \"google.golang.org/grpc\"\n\nfunc gatewayDialOptions(extra ...grpc.DialOption) []grpc.DialOption {\n\t" + body + "\n}\n"
	}
	for _, c := range []struct {
		name, adapters, options string
		refusals                int
	}{
		{"with the seam", "svc/pkg/adapters", options("return append([]grpc.DialOption{grpc.WithNoProxy()}, extra...)"), 0},
		{"without the seam", "svc/pkg/adapters", options("return extra"), 1},
		{"outside a generated adapter", "svc/pkg/other", options("return append([]grpc.DialOption{grpc.WithNoProxy()}, extra...)"), 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			seams := adapterSeams{dialsThrough: map[string]string{}, noProxy: map[string]bool{}}
			var violations []string
			for name, source := range map[string]string{"rest_gen.go": dial, "grpc_gen.go": c.options} {
				relative := c.adapters + "/" + name
				path := filepath.Join(root, filepath.FromSlash(relative))
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
					t.Fatal(err)
				}
				violations = append(violations, inspect(t, path, relative, &seams)...)
			}
			violations = append(violations, seams.violations()...)
			if len(violations) != c.refusals {
				t.Fatalf("got %d refusals, want %d: %q", len(violations), c.refusals, violations)
			}
		})
	}
}

func transportIsHost(literal *ast.CompositeLit, calls func(ast.Node, string, string) bool) bool {
	for _, element := range literal.Elts {
		field, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := field.Key.(*ast.Ident); ok && key.Name == "Transport" {
			if call, ok := field.Value.(*ast.CallExpr); ok {
				if s, ok := call.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "HTTPTransport" {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "HTTPTransport" {
					return true // inside the host package itself
				}
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
