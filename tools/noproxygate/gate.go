// Package noproxygate is the repository's no-proxy gate (reviews r99, r101,
// r105, r114): no hand-written Go code in this repository makes an HTTP
// request, a gRPC dial or a subprocess except through host.HTTPTransport and
// host.DialOptions, the two seams that never follow a proxy from the
// environment.
//
// It judges type-checked code (golang.org/x/tools/go/packages and go/types), so
// a name is what it resolves to, not how it is spelled: aliases, dot-imports,
// shadowing, elided literals, indirect writes, conversions and inferred
// generics all resolve to the same objects and types. It refuses, by file and
// line:
//
//  1. Any use (call, method value, reference) of http.DefaultClient,
//     http.ProxyFromEnvironment, http.Get/Head/Post/PostForm,
//     httputil.NewSingleHostReverseProxy, os/exec.Command/CommandContext,
//     os.StartProcess and syscall.Exec/ForkExec/StartProcess; and of
//     http.DefaultTransport outside host.go, the one place that clones it.
//  2. Any use of grpc.NewClient, grpc.Dial and grpc.DialContext but a call whose
//     final, variadic argument is host.DialOptions(x)... or
//     append(host.DialOptions(x), ...)...; and any call of a
//     Register…HandlerFromEndpoint whose options are not host.DialOptions(x) or
//     append(host.DialOptions(x), ...). Options appended after the seam may not
//     set the transport: grpc.WithTransportCredentials, WithCredentialsBundle,
//     WithInsecure, WithDialer and WithContextDialer are refused there. No
//     function is exempt by its name: the generated self-dials in
//     GeneratedSelfDials are the one listed exception, and a genuine
//     grpc-gateway Register…HandlerFromEndpoint may dial its own endpoint and
//     options parameters because every call of it is held to this rule.
//  3. A dot-import of net/http, net/http/httputil or google.golang.org/grpc; and,
//     in any file that is not genuinely generated, import "unsafe", import "C"
//     and a //go:linkname directive.
//  4. Any composite literal, type expression or declaration (variable, field,
//     parameter, result, alias) whose type holds http.Client,
//     httputil.ReverseProxy or http.Transport by value, at any depth of
//     arrays, slices, maps, channels and unnamed structs: such a value is a zero
//     value on http.DefaultTransport, or a second transport. The one exception
//     is a literal of http.Client or httputil.ReverseProxy itself, elided or
//     not, that sets Transport: host.HTTPTransport().
//  5. A conversion to or from one of those types, a type identical to one, a
//     pointer to either, or a type parameter whose constraint admits one; a type
//     declared identical to one; and a generic instantiation with one as a type
//     argument.
//  6. Any write to the Transport field of an http.Client or
//     httputil.ReverseProxy, through any addressable expression, of anything but
//     host.HTTPTransport(); and taking that field's address.
//  7. Any production .go file in the module that the type-checked load did not
//     judge: a file excluded by a build constraint, or in a directory the go tool
//     ignores (names starting with _ or ., and testdata).
//
// Every file the load returns is judged, generated or not. A generated-code
// marker is believed only when it names a known generator and the file has that
// generator's suffix (generatedBy); only such a file is exempt from rule 3's
// unsafe, cgo and linkname refusals and may hold the one generated dial above.
//
// Blind spots, by class: _test.go files (test code is not judged); raw sockets
// (net.Dial and other socket APIs); reflection; subprocesses started by means
// other than the APIs in rule 1; third-party HTTP or gRPC clients; option slices
// built elsewhere and spread after the seam (append(host.DialOptions(x), opts...)
// is trusted); and what dependencies (codefly core, sdk-go, grpc) do on the
// repository's behalf. A green gate means none of the refused forms appears; it
// does not prove that no request can bypass the seams.
package noproxygate

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// HostImport is the package that owns the two seams.
const HostImport = "github.com/codefly-dev/authority/libraries/authority-client/go/host"

// hostFile is the one file allowed to name http.DefaultTransport: it clones it.
const hostFile = "libraries/authority-client/go/host/host.go"

// GeneratedSelfDials are the go-grpc agent's generated gateways, which
// self-dial 0.0.0.0 without the seam. They carry no generated-code marker, so
// they are read like any file, and only rule 2 is waived for them. They are
// fixed in the agent's gatewayDialOptions template (codefly-dev/service-go-grpc)
// and regenerated, never hand-edited; an entry is removed once its file carries
// grpc.WithNoProxy() (TestTheSelfDialAllowlistOnlyShrinks).
var GeneratedSelfDials = map[string]bool{
	"modules/authority/services/hop/code/pkg/adapters/rest_gen.go":      true,
	"modules/authority/services/local/code/pkg/adapters/connect_gen.go": true,
	"modules/authority/services/local/code/pkg/adapters/rest_gen.go":    true,
	"modules/console/services/api/code/pkg/adapters/connect_gen.go":     true,
}

// A Violation is one refused form.
type Violation struct {
	File   string // relative to the repository root
	Line   int
	Reason string
}

func (v Violation) String() string { return fmt.Sprintf("%s:%d: %s", v.File, v.Line, v.Reason) }

const followsProxy = "follows the environment proxy; use host.HTTPTransport()"

// banned are the package-level functions and variables refused on any use.
var banned = map[string]string{
	"net/http.DefaultClient":                      followsProxy,
	"net/http.ProxyFromEnvironment":               "reads the environment proxy; use host.HTTPTransport()",
	"net/http.Get":                                "uses http.DefaultClient, which " + followsProxy,
	"net/http.Head":                               "uses http.DefaultClient, which " + followsProxy,
	"net/http.Post":                               "uses http.DefaultClient, which " + followsProxy,
	"net/http.PostForm":                           "uses http.DefaultClient, which " + followsProxy,
	"net/http/httputil.NewSingleHostReverseProxy": "uses http.DefaultTransport, which " + followsProxy,
	"os/exec.Command":                             "starts a subprocess, which may follow the environment proxy",
	"os/exec.CommandContext":                      "starts a subprocess, which may follow the environment proxy",
	"os.StartProcess":                             "starts a subprocess, which may follow the environment proxy",
	"syscall.Exec":                                "starts a subprocess, which may follow the environment proxy",
	"syscall.ForkExec":                            "starts a subprocess, which may follow the environment proxy",
	"syscall.StartProcess":                        "starts a subprocess, which may follow the environment proxy",
}

var dials = map[string]bool{
	"google.golang.org/grpc.NewClient":   true,
	"google.golang.org/grpc.Dial":        true,
	"google.golang.org/grpc.DialContext": true,
}

var fromEndpoint = regexp.MustCompile(`^Register\w+HandlerFromEndpoint$`)

// generators are the code generators whose marker the gate believes, each with
// the suffix it writes; any other marker is read as hand-written code.
var generators = map[string]string{
	"protoc-gen-go":           ".pb.go",
	"protoc-gen-go-grpc":      "_grpc.pb.go",
	"protoc-gen-grpc-gateway": ".pb.gw.go",
	"protoc-gen-connect-go":   ".connect.go",
}

var marker = regexp.MustCompile(`^// Code generated by (.+?)\. DO NOT EDIT\.$`)

// generatedBy is the known generator that wrote file at name, or "" when the
// file carries no marker, an unknown generator's, or a known one with another
// generator's suffix (a marker a hand could have written).
func generatedBy(name string, file *ast.File) string {
	if !ast.IsGenerated(file) {
		return ""
	}
	for _, group := range file.Comments {
		if group.Pos() > file.Package {
			break
		}
		for _, comment := range group.List {
			if m := marker.FindStringSubmatch(comment.Text); m != nil {
				if suffix, ok := generators[m[1]]; ok && strings.HasSuffix(name, suffix) {
					return m[1]
				}
				return ""
			}
		}
	}
	return ""
}

// transportOptions may not follow the seam's options: each would replace the
// transport host.DialOptions chose.
var transportOptions = map[string]bool{
	"google.golang.org/grpc.WithTransportCredentials": true,
	"google.golang.org/grpc.WithCredentialsBundle":    true,
	"google.golang.org/grpc.WithInsecure":             true,
	"google.golang.org/grpc.WithDialer":               true,
	"google.golang.org/grpc.WithContextDialer":        true,
}

// bannedTypes are the types refused by value, by package path and name.
var bannedTypes = map[string]string{
	"net/http.Client":                "http.Client",
	"net/http.Transport":             "http.Transport",
	"net/http/httputil.ReverseProxy": "httputil.ReverseProxy",
}

// Check type-checks the packages patterns name in the module at dir (with
// overlay, for tests) and returns every violation, paths relative to root. A
// package that does not load or type-check is an error, never a pass.
func Check(root, dir string, overlay map[string][]byte, patterns ...string) ([]Violation, error) {
	config := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedTypesSizes,
		Dir:     dir,
		Overlay: overlay,
	}
	loaded, err := packages.Load(config, patterns...)
	if err != nil {
		return nil, err
	}
	var problems []string
	var violations []Violation
	judged := map[string]bool{}
	for _, p := range loaded {
		for _, e := range p.Errors {
			problems = append(problems, e.Error())
		}
		if len(p.Errors) > 0 {
			continue
		}
		for _, file := range p.Syntax {
			name := p.Fset.File(file.Pos()).Name()
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			judged[name] = true
			relative, err := filepath.Rel(root, name)
			if err != nil {
				return nil, err
			}
			c := &checker{pkg: p, file: file, relative: filepath.ToSlash(relative), generator: generatedBy(name, file)}
			violations = append(violations, c.check()...)
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("packages in %s do not load or type-check, so the gate cannot judge them:\n%s", dir, strings.Join(problems, "\n"))
	}
	if len(patterns) == 1 && patterns[0] == "./..." {
		unjudged, err := Unjudged(root, dir, judged)
		if err != nil {
			return nil, err
		}
		violations = append(violations, unjudged...)
	}
	sort.Slice(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}

// Unjudged is rule 7: every production .go file of the module at dir that is
// not in judged (the files the type-checked load returned) — a file excluded by
// a build constraint, or in a directory the go tool ignores. Nested modules
// are their own and are skipped. A cgo file is among them: the load judges its
// rewrite, not the file.
func Unjudged(root, dir string, judged map[string]bool) ([]Violation, error) {
	var violations []Violation
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "node_modules" || entry.Name() == ".git" {
				return filepath.SkipDir
			}
			if path != dir {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || judged[path] {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		violations = append(violations, Violation{File: filepath.ToSlash(relative), Line: 1,
			Reason: "this production file was not judged: it is excluded by a build constraint, uses cgo, or sits in a directory the go tool ignores (_, ., testdata); move it where the gate type-checks it"})
		return nil
	})
	return violations, err
}

type checker struct {
	pkg        *packages.Package
	file       *ast.File
	relative   string
	generator  string // the known generator that wrote this file, or ""
	violations []Violation
	seen       map[string]bool
}

func (c *checker) refuse(node ast.Node, reason string) {
	v := Violation{File: c.relative, Line: c.pkg.Fset.Position(node.Pos()).Line, Reason: reason}
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	if !c.seen[v.String()] {
		c.seen[v.String()] = true
		c.violations = append(c.violations, v)
	}
}

func (c *checker) info() *types.Info { return c.pkg.TypesInfo }

// key names a package-level function or variable "path.Name"; "" otherwise.
func key(obj types.Object) string {
	if obj == nil || obj.Pkg() == nil || obj.Parent() != obj.Pkg().Scope() {
		return ""
	}
	switch obj.(type) {
	case *types.Func, *types.Var:
		return obj.Pkg().Path() + "." + obj.Name()
	}
	return ""
}

// bannedName is the display name of t when it is a refused type itself.
func bannedName(t types.Type) string {
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return ""
	}
	return bannedTypes[named.Obj().Pkg().Path()+"."+named.Obj().Name()]
}

// holds is the refused type t holds by value, at any depth of composite types
// that store their elements inline or zero them (not behind a pointer); "".
func holds(t types.Type) string {
	if name := bannedName(t); name != "" {
		return name
	}
	switch u := types.Unalias(t).(type) {
	case *types.Array:
		return holds(u.Elem())
	case *types.Slice:
		return holds(u.Elem())
	case *types.Chan:
		return holds(u.Elem())
	case *types.Map:
		if name := holds(u.Key()); name != "" {
			return name
		}
		return holds(u.Elem())
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if name := holds(u.Field(i).Type()); name != "" {
				return name
			}
		}
	}
	return ""
}

func valueReason(name string) string {
	if name == "http.Transport" {
		return "an http.Transport value is a second transport; use host.HTTPTransport()"
	}
	return "a value of type " + name + " is a zero value on http.DefaultTransport; hold a pointer to a literal with Transport: host.HTTPTransport()"
}

// seam reports whether e is a call of the host package's function name, as
// resolved by the type checker.
func (c *checker) seam(e ast.Expr, name string) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok {
		return false
	}
	fn, ok := c.info().Uses[calleeIdent(call)].(*types.Func)
	return ok && key(fn) == HostImport+"."+name
}

func calleeIdent(call *ast.CallExpr) *ast.Ident {
	switch f := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		return f
	case *ast.SelectorExpr:
		return f.Sel
	case *ast.IndexExpr: // an instantiated generic function
		if id, ok := f.X.(*ast.Ident); ok {
			return id
		}
	}
	return nil
}

// seamOptions reports whether e is host.DialOptions(x) or
// append(host.DialOptions(x), ...): the seam's options, whole.
func (c *checker) seamOptions(e ast.Expr) bool {
	if c.seam(e, "DialOptions") {
		return true
	}
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	builtin, ok := c.info().Uses[calleeIdent(call)].(*types.Builtin)
	if !ok || builtin.Name() != "append" || !c.seam(call.Args[0], "DialOptions") {
		return false
	}
	for _, option := range call.Args[1:] {
		if inner, ok := ast.Unparen(option).(*ast.CallExpr); ok && transportOptions[key(c.info().Uses[calleeIdent(inner)])] {
			return false // it would replace the seam's transport
		}
	}
	return true
}

// transportField reports whether sel selects the Transport field of an
// http.Client or httputil.ReverseProxy, however it is reached.
func (c *checker) transportField(e ast.Expr) bool {
	sel, ok := ast.Unparen(e).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	selection, ok := c.info().Selections[sel]
	if !ok || selection.Kind() != types.FieldVal {
		return false
	}
	field := selection.Obj()
	return field.Name() == "Transport" && field.Pkg() != nil &&
		(field.Pkg().Path() == "net/http" || field.Pkg().Path() == "net/http/httputil")
}

// literalSetsSeam reports whether a client or proxy literal sets
// Transport: host.HTTPTransport().
func (c *checker) literalSetsSeam(literal *ast.CompositeLit) bool {
	for _, element := range literal.Elts {
		if field, ok := element.(*ast.KeyValueExpr); ok {
			if k, ok := field.Key.(*ast.Ident); ok && k.Name == "Transport" {
				return c.seam(field.Value, "HTTPTransport")
			}
		}
	}
	return false
}

func (c *checker) check() []Violation {
	info := c.info()
	for _, spec := range c.file.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		if spec.Name != nil && spec.Name.Name == "." && (path == "net/http" || path == "net/http/httputil" || path == "google.golang.org/grpc") {
			c.refuse(spec, "a dot-import of "+path+" hides names this gate checks; import it by name")
		}
		if c.generator == "" && (path == "unsafe" || path == "C") {
			c.refuse(spec, "import \""+path+"\" lets code reach past the type system this gate judges; it is refused in hand-written files")
		}
	}
	if c.generator == "" {
		for _, group := range c.file.Comments {
			for _, comment := range group.List {
				if strings.HasPrefix(comment.Text, "//go:linkname") {
					c.refuse(comment, "a //go:linkname directive reaches unexported code this gate cannot judge; it is refused in hand-written files")
				}
			}
		}
	}
	identical := c.bannedUnderlying()
	var stack []ast.Node
	ast.Inspect(c.file, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		parent := ast.Node(nil)
		if len(stack) > 0 {
			parent = stack[len(stack)-1]
		}
		stack = append(stack, node)
		switch n := node.(type) {
		case *ast.Ident:
			c.use(n, stack)
			c.definition(n, identical)
		case *ast.CompositeLit:
			if tv, ok := info.Types[n]; ok {
				literal := tv.Type
				if pointer, ok := types.Unalias(literal).(*types.Pointer); ok {
					literal = pointer.Elem() // an element elided under []*T stands for &T{}
				}
				switch name := holds(literal); {
				case name == "":
				case bannedName(literal) != "" && name != "http.Transport":
					if !c.literalSetsSeam(n) {
						c.refuse(n, "an "+name+" literal must set Transport: host.HTTPTransport()")
					}
				default:
					c.refuse(n, valueReason(name))
				}
			}
		case *ast.CallExpr:
			if tv, ok := info.Types[n.Fun]; ok && tv.IsType() && len(n.Args) == 1 {
				if operand, ok := info.Types[n.Args[0]]; ok && !types.Identical(tv.Type, operand.Type) {
					for _, t := range []types.Type{tv.Type, operand.Type} {
						if name := c.convertible(t, identical); name != "" {
							c.refuse(n, "a conversion to or from "+name+" yields a client, proxy or transport this gate cannot vouch for, or reaches its Transport field by another name; build a literal with Transport: host.HTTPTransport()")
							break
						}
					}
				}
			}
		case *ast.AssignStmt:
			for i, left := range n.Lhs {
				if !c.transportField(stripDeref(left)) {
					continue
				}
				if len(n.Rhs) != len(n.Lhs) || !c.seam(n.Rhs[i], "HTTPTransport") {
					c.refuse(n, "a Transport field may only be set to host.HTTPTransport()")
				}
			}
		case *ast.UnaryExpr:
			if n.Op == token.AND && c.transportField(n.X) {
				c.refuse(n, "taking the address of a Transport field lets it be reset; set it only to host.HTTPTransport()")
			}
		}
		if e, ok := node.(ast.Expr); ok {
			c.typeExpression(e, parent)
		}
		return true
	})
	for id, instance := range info.Instances {
		if c.pkg.Fset.File(id.Pos()) != c.pkg.Fset.File(c.file.Pos()) {
			continue
		}
		for i := 0; i < instance.TypeArgs.Len(); i++ {
			if name := holds(instance.TypeArgs.At(i)); name != "" {
				c.refuse(id, "a generic instantiated with "+name+" makes a value of it; hold a pointer to a literal with Transport: host.HTTPTransport()")
			}
		}
	}
	return c.violations
}

// convertible is the refused type t is, or is identical to, possibly behind one
// pointer, or that a type parameter's constraint admits; "".
func (c *checker) convertible(t types.Type, identical map[string]types.Type) string {
	t = types.Unalias(t)
	if pointer, ok := t.Underlying().(*types.Pointer); ok {
		t = types.Unalias(pointer.Elem())
	}
	if parameter, ok := t.(*types.TypeParam); ok {
		return c.admits(parameter.Constraint(), identical, 0)
	}
	if name := bannedName(t); name != "" {
		return name
	}
	for name, underlying := range identical {
		if types.Identical(t.Underlying(), underlying) {
			return name
		}
	}
	return ""
}

// admits is the refused type a constraint's type set may hold (a term of it,
// possibly behind a pointer or another type parameter); "".
func (c *checker) admits(constraint types.Type, identical map[string]types.Type, depth int) string {
	face, ok := constraint.Underlying().(*types.Interface)
	if !ok || depth > 8 {
		return ""
	}
	for i := 0; i < face.NumEmbeddeds(); i++ {
		switch embedded := face.EmbeddedType(i).(type) {
		case *types.Union:
			for j := 0; j < embedded.Len(); j++ {
				if name := c.convertible(embedded.Term(j).Type(), identical); name != "" {
					return name
				}
			}
		default:
			if name := c.convertible(embedded, identical); name != "" {
				return name
			}
			if name := c.admits(embedded, identical, depth+1); name != "" {
				return name
			}
		}
	}
	return ""
}

// stripDeref removes parentheses and *& around an assigned expression.
func stripDeref(e ast.Expr) ast.Expr {
	for {
		e = ast.Unparen(e)
		star, ok := e.(*ast.StarExpr)
		if !ok {
			return e
		}
		address, ok := ast.Unparen(star.X).(*ast.UnaryExpr)
		if !ok || address.Op != token.AND {
			return e
		}
		e = address.X
	}
}

// use applies rules 1 and 2 to an identifier that resolves to a package-level
// object.
func (c *checker) use(id *ast.Ident, stack []ast.Node) {
	obj := c.info().Uses[id]
	k := key(obj)
	if k == "" {
		return
	}
	display := obj.Pkg().Name() + "." + obj.Name()
	if reason, ok := banned[k]; ok {
		c.refuse(id, display+" "+reason)
		return
	}
	if k == "net/http.DefaultTransport" && c.relative != hostFile {
		c.refuse(id, display+" "+followsProxy)
		return
	}
	_, isFunc := obj.(*types.Func)
	isDial, isEndpoint := dials[k], isFunc && fromEndpoint.MatchString(obj.Name())
	if !isDial && !isEndpoint || GeneratedSelfDials[c.relative] {
		return
	}
	call := calling(id, stack)
	switch {
	case isDial && call != nil && c.generator == "protoc-gen-grpc-gateway" && c.gatewayDial(call, stack):
		// A genuine grpc-gateway Register…HandlerFromEndpoint dialling its own
		// parameters: every call of it is held to this rule instead.
	case isDial && (call == nil || !call.Ellipsis.IsValid() || len(call.Args) < 2 || !c.seamOptions(call.Args[len(call.Args)-1])):
		c.refuse(id, display+" must be called with host.DialOptions(x)... or append(host.DialOptions(x), ...)... as its final argument, with no option after the seam that sets the transport")
	case isEndpoint && (call == nil || len(call.Args) == 0 || !c.seamOptions(call.Args[len(call.Args)-1])):
		c.refuse(id, display+" must be passed host.DialOptions(x) or append(host.DialOptions(x), ...) as its options, with no option after the seam that sets the transport")
	}
}

// calling is the call whose callee is id (through a selector and parentheses),
// or nil when id is used some other way (a method value).
func calling(id *ast.Ident, stack []ast.Node) *ast.CallExpr {
	var callee ast.Node = id
	for i := len(stack) - 2; i >= 0; i-- {
		switch p := stack[i].(type) {
		case *ast.SelectorExpr:
			if p.Sel != callee {
				return nil
			}
			callee = p
		case *ast.ParenExpr:
			callee = p
		case *ast.CallExpr:
			if p.Fun == callee {
				return p
			}
			return nil
		default:
			return nil
		}
	}
	return nil
}

// gatewayDial reports whether call is grpc.NewClient(endpoint, opts...) inside a
// generated Register…HandlerFromEndpoint, on that function's own endpoint and
// options parameters.
func (c *checker) gatewayDial(call *ast.CallExpr, stack []ast.Node) bool {
	if len(call.Args) != 2 || !call.Ellipsis.IsValid() {
		return false
	}
	for i := len(stack) - 1; i >= 0; i-- {
		declaration, ok := stack[i].(*ast.FuncDecl)
		if !ok {
			continue
		}
		if !fromEndpoint.MatchString(declaration.Name.Name) {
			return false
		}
		parameters := map[types.Object]bool{}
		for _, field := range declaration.Type.Params.List {
			for _, name := range field.Names {
				parameters[c.info().Defs[name]] = true
			}
		}
		for _, argument := range call.Args {
			id, ok := ast.Unparen(argument).(*ast.Ident)
			if !ok || !parameters[c.info().Uses[id]] {
				return false
			}
		}
		return true
	}
	return false
}

// definition applies rules 4 and 5 to declared objects: variables, fields,
// parameters and results holding a refused type by value, aliases of one, and
// types declared identical to one.
func (c *checker) definition(id *ast.Ident, identical map[string]types.Type) {
	switch obj := c.info().Defs[id].(type) {
	case *types.Var:
		if name := holds(obj.Type()); name != "" {
			c.refuse(id, valueReason(name))
		}
	case *types.TypeName:
		if name := holds(types.Unalias(obj.Type())); name != "" {
			c.refuse(id, valueReason(name))
			return
		}
		for name, underlying := range identical {
			if types.Identical(obj.Type().Underlying(), underlying) {
				c.refuse(id, "a type declared identical to "+name+" converts to one on http.DefaultTransport")
			}
		}
	}
}

// typeExpression applies rule 4 to a type written in place (new(T), make,
// []T, map[K]T, a type argument, a result type): only *T and the type of a
// checked literal are allowed.
func (c *checker) typeExpression(e ast.Expr, parent ast.Node) {
	tv, ok := c.info().Types[e]
	if !ok || !tv.IsType() {
		return
	}
	name := holds(tv.Type)
	if name == "" {
		return
	}
	switch p := parent.(type) {
	case *ast.StarExpr:
		if p.X == e {
			return
		}
	case *ast.CompositeLit:
		if p.Type == e {
			return
		}
	}
	c.refuse(e, valueReason(name))
}

// bannedUnderlying is the struct underlying each refused type this package can
// name, for rule 5's identical declarations.
func (c *checker) bannedUnderlying() map[string]types.Type {
	out := map[string]types.Type{}
	for _, imported := range c.pkg.Types.Imports() {
		for full, name := range bannedTypes {
			dot := strings.LastIndex(full, ".")
			if imported.Path() != full[:dot] {
				continue
			}
			if obj := imported.Scope().Lookup(full[dot+1:]); obj != nil {
				out[name] = obj.Type().Underlying()
			}
		}
	}
	return out
}
