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

// The no-proxy gate (review r99): no non-test Go code in this repository makes
// an HTTP request or a gRPC dial except through host.HTTPTransport and
// host.DialOptions, the two seams that never follow a proxy from the
// environment. It refuses, by file and line:
//   - http.DefaultTransport and http.DefaultClient, and http.Get/Head/Post/PostForm
//     (which use them), anywhere but host.go, the one place that clones it;
//   - an http.Client or httputil.ReverseProxy literal whose Transport is not
//     host.HTTPTransport(), and httputil.NewSingleHostReverseProxy;
//   - grpc.NewClient, grpc.Dial and grpc.DialContext without host.DialOptions(...)
//     among their options.
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
		violations = append(violations, inspect(t, path, relative)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, violation := range violations {
		t.Error(violation)
	}
}

func inspect(t *testing.T, path, relative string) []string {
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
	calls := func(expression ast.Expr, importPath, selector string) bool {
		found := false
		ast.Inspect(expression, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok && is(call.Fun, importPath, selector) {
				found = true
			}
			return !found
		})
		return found
	}
	inHost := relative == "libraries/authority-client/go/host/host.go"
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
				if is(n.Fun, "google.golang.org/grpc", name) && !generatedSelfDials[relative] {
					dials := false
					for _, argument := range n.Args[1:] {
						dials = dials || calls(argument, hostImport, "DialOptions") || inHost && callsLocal(argument, "DialOptions")
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

func transportIsHost(literal *ast.CompositeLit, calls func(ast.Expr, string, string) bool) bool {
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
