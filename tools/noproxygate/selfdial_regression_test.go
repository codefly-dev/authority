package noproxygate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func checkSyntaxSelfDials(t *testing.T, root, directory string) []string {
	// Single-package syntax fixtures deliberately include ill-typed refusals.
	files := token.NewFileSet()
	var parsed []*ast.File
	generated := map[*ast.File]bool{}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		full := filepath.Join(directory, name)
		file, err := parser.ParseFile(files, full, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", full, err)
		}
		relative, _ := filepath.Rel(root, full)
		generated[file] = isAgentAdapter(file, filepath.ToSlash(relative))
		parsed = append(parsed, file)
	}
	c := selfDials{refusals: map[Violation]bool{}, checkedDials: map[*ast.CallExpr]bool{}, root: root, files: files, generated: generated, info: &types.Info{
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}}
	// Imports resolve to empty packages: the check needs the identity of this
	// package's own objects and of the grpc package name, not the imported API,
	// so the type errors that follow are expected and ignored.
	config := types.Config{Importer: emptyPackages{}, Error: func(error) {}}
	c.pkg, _ = config.Check(directory, files, parsed, c.info)
	c.parsed = parsed
	var out []string
	for _, v := range c.violations() {
		out = append(out, v.String())
	}
	return out
}

// emptyPackages imports every path as an empty, complete package named by its
// last path element (grpc for google.golang.org/grpc).
type emptyPackages struct{}

func (emptyPackages) Import(importPath string) (*types.Package, error) {
	name := importPath[strings.LastIndex(importPath, "/")+1:]
	if importPath == grpcImport {
		name = "grpc"
	}
	pkg := types.NewPackage(importPath, name)
	pkg.MarkComplete()
	return pkg, nil
}

// judgeSyntax exercises the same self-dial proof on deliberately ill-typed
// refusals. Production and the indirect-dial fixtures use the full module loader.
func judgeSyntax(t *testing.T, sources map[string]string) []string {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "svc", "pkg", "adapters")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, source := range sources {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return checkSyntaxSelfDials(t, root, directory)
}

func TestIndependentReviewSliceMutation(t *testing.T) {
	for name, change := range map[string]string{
		"alias erases loopback credentials": "alias := opts\n\talias[len(alias)-1] = grpc.WithTransportCredentials(insecure.NewCredentials())",
		"copy erases loopback credentials":  "copy(opts[len(opts)-1:], []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())})",
	} {
		t.Run(name, func(t *testing.T) {
			dials := strings.Replace(fixtureDials, "\"context\"", "\"context\"\n\"google.golang.org/grpc/credentials/insecure\"", 1)
			dials = strings.Replace(dials, "opts := gatewayDialOptions(extra...)", "opts := gatewayDialOptions(extra...)\n\t"+change, 1)
			got := judgeSyntax(t, map[string]string{"grpc_gen.go": fixtureSeam, "rest_gen.go": dials})
			if len(got) == 0 {
				t.Fatal("unsafe mutable slice accepted with zero violations")
			} else {
				t.Log(got)
			}
		})
	}
	t.Run("seam refuses indexed assignment", func(t *testing.T) {
		seam := strings.Replace(fixtureSeam, "options = append(options, extra...)", "options[0] = grpc.WithTransportCredentials(insecure.NewCredentials())\n\toptions = append(options, extra...)", 1)
		got := judgeSyntax(t, map[string]string{"grpc_gen.go": seam, "rest_gen.go": fixtureDials})
		if len(got) == 0 {
			t.Fatal("indexed assignment in seam accepted with zero violations")
		} else {
			t.Log(got)
		}
	})
}

func TestSelfDialOptionsCannotEscape(t *testing.T) {
	for name, use := range map[string]string{
		"alias without a visible write": "alias := opts; _ = alias",
		"indexed read":                  "_ = opts[0]",
		"indexed write":                 "opts[0] = extra[0]",
		"slice":                         "_ = opts[:]",
		"full slice":                    "_ = opts[:len(opts):cap(opts)]",
		"copy destination":              "copy(opts, extra)",
		"copy source":                   "copy(extra, opts)",
		"mutating call":                 "mutate(opts)",
		"variadic call":                 "mutateVariadic(opts...)",
		"address":                       "_ = &opts",
		"element address":               "_ = &opts[0]",
		"closure alias":                 "f := func() { mutate(opts) }; f()",
		"return escape":                 "f := func() []grpc.DialOption { return opts }; _ = f",
		"channel escape":                "ch := make(chan []grpc.DialOption, 1); ch <- opts",
		"append alias":                  "alias := append(opts, extra...); _ = alias",
		"dial target is not options":    "_, _ = grpc.NewClient(opts, gatewayDialOptions()...)",
		"deferred mutation":             "defer mutate(opts)",
	} {
		t.Run(name, func(t *testing.T) {
			dials := strings.Replace(fixtureDials, "opts := gatewayDialOptions(extra...)",
				"opts := gatewayDialOptions(extra...)\n\t"+use, 1)
			dials += "\nfunc mutate(options []grpc.DialOption) { options[0] = nil }\nfunc mutateVariadic(options ...grpc.DialOption) { options[0] = nil }\n"
			violations := judgeSyntax(t, map[string]string{"grpc_gen.go": fixtureSeam, "rest_gen.go": dials})
			if !strings.Contains(strings.Join(violations, "\n"), "used only as dial options") {
				t.Fatalf("want a refusal explaining restricted options use, got %q", violations)
			}
		})
	}
}

func TestGatewayDialOptionsRefusesBackingArrayMutation(t *testing.T) {
	for name, use := range map[string]string{
		"copy statement":                   "copy(options, extra)",
		"copy expression":                  "n := copy(options, extra); _ = n",
		"copy in closure":                  "f := func() { copy(options, extra) }; f()",
		"indexed assignment":               "options[0] = extra[0]",
		"parenthesized indexed assignment": "(options[0]) = extra[0]",
		"slice assignment":                 "options[:] = extra",
		"alias":                            "alias := options; alias[0] = extra[0]",
		"call mutating backing array":      "mutate(options)",
		"mutation in append argument":      "options = append(options, mutate(options)...)",
		"address in append argument":       "options = append(options, mutatePointer(&options)...)",
		"reslice in append":                "options = append(options[:0], extra...)",
	} {
		t.Run(name, func(t *testing.T) {
			seam := strings.Replace(fixtureSeam, "options = append(options, extra...)",
				use+"\n\toptions = append(options, extra...)", 1)
			seam += "\nfunc mutate(options []grpc.DialOption) []grpc.DialOption { options[0] = nil; return options }\nfunc mutatePointer(options *[]grpc.DialOption) []grpc.DialOption { *options = nil; return nil }\n"
			violations := judgeSyntax(t, map[string]string{"grpc_gen.go": seam, "rest_gen.go": fixtureDials})
			if !strings.Contains(strings.Join(violations, "\n"), "gatewayDialOptions ") {
				t.Fatalf("want a reason for refusing the seam, got %q", violations)
			}
		})
	}
}

func TestSelfDialOptionsAcceptsEachDial(t *testing.T) {
	for _, dial := range []string{
		`grpc.NewClient("127.0.0.1:1", OPTIONS...)`,
		`grpc.Dial("127.0.0.1:1", OPTIONS...)`,
		`grpc.DialContext(ctx, "127.0.0.1:1", OPTIONS...)`,
		`gen.RegisterSvcServiceHandlerFromEndpoint(ctx, nil, "127.0.0.1:1", OPTIONS)`,
	} {
		for _, options := range []string{"opts", "gatewayDialOptions(extra...)"} {
			t.Run(dial+options, func(t *testing.T) {
				dials := strings.Replace(fixtureDials,
					`_, _ = grpc.NewClient("127.0.0.1:1", opts...)`,
					strings.Replace(dial, "OPTIONS", options, 1), 1)
				if violations := judgeSyntax(t, map[string]string{"grpc_gen.go": fixtureSeam, "rest_gen.go": dials}); len(violations) != 0 {
					t.Fatalf("refused direct or unescaped local options: %q", violations)
				}
			})
		}
	}
}

// The generated forwarding shape is accepted by declaration identity, never
// by the spelling RegisterREST. Anonymous interfaces remain unchecked escapes;
// the module-wide named plugin-interface proof is exercised separately.
func TestGeneratedOptionsForwarders(t *testing.T) {
	const forwarder = `
func RegisterREST(ctx context.Context, mux interface{}, endpoint string, opts []grpc.DialOption) error {
	return gen.RegisterSvcServiceHandlerFromEndpoint(ctx, mux, endpoint, opts)
}
`
	const call = `RegisterREST(ctx, nil, "127.0.0.1:1", opts)`
	base := strings.Replace(fixtureDials, "opts := gatewayDialOptions(extra...)",
		"opts := gatewayDialOptions(extra...)\n\t_ = "+call, 1)
	for _, tc := range []struct {
		name string
		body string
		use  string
		file string
		pass bool
	}{
		{"generated RegisterREST", forwarder, call, "server_gen.go", true},
		{"direct seam argument", forwarder, strings.Replace(call, "opts)", "gatewayDialOptions(extra...))", 1), "server_gen.go", true},
		{"variadic forwarder", strings.Replace(forwarder, "opts []grpc.DialOption", "opts ...grpc.DialOption", 1), strings.Replace(call, "opts)", "opts...)", 1), "server_gen.go", true},
		{"gRPC terminal", strings.Replace(forwarder,
			"return gen.RegisterSvcServiceHandlerFromEndpoint(ctx, mux, endpoint, opts)",
			"_, err := grpc.NewClient(endpoint, opts...); return err", 1), call, "server_gen.go", true},
		{"recursive checking", strings.Replace(forwarder, "return gen.RegisterSvcServiceHandlerFromEndpoint(ctx, mux, endpoint, opts)",
			"return next(ctx, mux, endpoint, opts)", 1) + strings.Replace(forwarder, "func RegisterREST", "func next", 1), call, "server_gen.go", true},
		{"hand-written forwarder", forwarder, call, "forward.go", false},
		{"wrong template filename", forwarder, call, "mine_gen.go", false},
		{"no generated marker", forwarder, call, "server_gen.go", false},
		{"recursive cycle", strings.Replace(forwarder, "gen.RegisterSvcServiceHandlerFromEndpoint", "RegisterREST", 1), call, "server_gen.go", false},
		{"function value", forwarder, "func() error { f := RegisterREST; return f(ctx, nil, \"127.0.0.1:1\", opts) }()", "server_gen.go", false},
		{"unsafe second caller", forwarder + `
func unsafe(ctx context.Context, raw []grpc.DialOption) { _ = RegisterREST(ctx, nil, "127.0.0.1:1", raw) }
`, call, "server_gen.go", false},
		{"shadowed function", forwarder, "func() error { RegisterREST := func(ctx context.Context, mux interface{}, endpoint string, opts []grpc.DialOption) error { opts[0] = nil; return nil }; return " + call + " }()", "server_gen.go", false},
		{"imported plugin interface", "", "func(p interface { RegisterREST(context.Context, interface{}, string, []grpc.DialOption) error }) error { return p.RegisterREST(ctx, nil, \"127.0.0.1:1\", opts) }(nil)", "server_gen.go", false},
		{"concrete generated method", "type registrar struct{}\n" + strings.Replace(forwarder, "func RegisterREST", "func (r registrar) RegisterREST", 1), "registrar{}." + call, "server_gen.go", true},
		{"method named like terminal", "type registrar struct{}\n" + strings.Replace(strings.Replace(forwarder, "func RegisterREST", "func (r registrar) RegisterSvcServiceHandlerFromEndpoint", 1), "return gen.RegisterSvcServiceHandlerFromEndpoint(ctx, mux, endpoint, opts)", "opts[0] = nil; return nil", 1), "registrar{}." + strings.Replace(call, "RegisterREST", "RegisterSvcServiceHandlerFromEndpoint", 1), "server_gen.go", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := fixtureDials[:strings.Index(fixtureDials, "func rest(")]
			if tc.name == "no generated marker" || tc.file == "forward.go" {
				header = strings.Replace(header, fixtureMarker, "", 1)
			}
			got := judgeSyntax(t, map[string]string{"grpc_gen.go": fixtureSeam,
				"rest_gen.go": strings.Replace(base, call, tc.use, 1), tc.file: header + tc.body})
			if (len(got) == 0) != tc.pass {
				t.Fatalf("want pass=%v, got %q", tc.pass, got)
			}
			if !tc.pass && !strings.Contains(strings.Join(got, "\n"), "a generated self-dial must pass gatewayDialOptions") {
				t.Fatalf("want self-dial refusal with reason, got %q", got)
			}
		})
	}
	for name, mutation := range map[string]string{
		"replace":          "opts = nil",
		"index":            "opts[0] = nil",
		"alias":            "alias := opts; alias[0] = nil",
		"slice":            "_ = opts[:]",
		"copy into":        "copy(opts, []grpc.DialOption{nil})",
		"copy out":         "copy([]grpc.DialOption{nil}, opts)",
		"append overwrite": "opts = append(opts[:0], nil)",
		"address":          "_ = &opts",
		"mutating call":    "mutate(opts)",
		"closure mutation": "func() { opts[0] = nil }()",
		"return escape":    "_ = func() []grpc.DialOption { return opts }",
	} {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(forwarder, "return gen.", mutation+"\n\treturn gen.", 1)
			body += "\nfunc mutate(opts []grpc.DialOption) { opts[0] = nil }\n"
			// Exercise the recursively checked parameter, too.
			body = strings.Replace(body, "func RegisterREST", "func next", 1) + strings.Replace(forwarder,
				"gen.RegisterSvcServiceHandlerFromEndpoint", "next", 1)
			got := judgeSyntax(t, map[string]string{"grpc_gen.go": fixtureSeam, "rest_gen.go": base + body})
			if !strings.Contains(strings.Join(got, "\n"), "a generated self-dial must pass gatewayDialOptions") {
				t.Fatalf("want refusal of modified forwarded options, got %q", got)
			}
		})
	}
}

// These fixtures use the production module loader and real grpc types. The
// generated interface is imported across packages; Hidden is never registered.
func TestModulePluginOptions(t *testing.T) {
	const terminal = `return gen.RegisterSvcServiceHandlerFromEndpoint(ctx, mux, endpoint, opts)`
	const ownDial = `_, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials())); return err`
	for _, tc := range []struct {
		name, body, extra string
		pass              bool
	}{
		{"unchanged endpoint registration", terminal, "", true},
		{"unchanged grpc dial", `_, err := grpc.NewClient(endpoint, opts...); return err`, "", true},
		{"grpc-only no-op", `return nil`, "", true},
		{"direct seam", terminal, "", true},
		{"direct seam mutation", `opts = nil; ` + terminal, "", false},
		{"blank options with own dial", ownDial, "", false},
		{"append insecure credentials", `opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials())); ` + terminal, "", false},
		{"ignore options and dial independently", ownDial, "", false},
		{"forward once then dial independently", `_ = gen.RegisterSvcServiceHandlerFromEndpoint(ctx, mux, endpoint, opts); ` + ownDial, "", false},

		{"function value dial after forwarding", `_ = gen.RegisterSvcServiceHandlerFromEndpoint(ctx, mux, endpoint, opts); dial := grpc.NewClient; _, err := dial(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials())); return err`, "", false},
		{"struct field dial after forwarding", `_ = gen.RegisterSvcServiceHandlerFromEndpoint(ctx, mux, endpoint, opts); holder := struct { Dial func(string, ...grpc.DialOption) (*grpc.ClientConn, error); Options []grpc.DialOption }{grpc.NewClient, []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}}; _, err := holder.Dial(endpoint, holder.Options...); return err`, "", false},
		{"package function value after forwarding", `_ = gen.RegisterSvcServiceHandlerFromEndpoint(ctx, mux, endpoint, opts); _, err := dial(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials())); return err`, `var dial = grpc.NewClient`, false},
		{"endpoint function value", `register := gen.RegisterSvcServiceHandlerFromEndpoint; return register(ctx, mux, endpoint, opts)`, "", false},
		{"replace", `opts = nil; ` + terminal, "", false},
		{"alias", `alias := opts; alias[0] = nil; ` + terminal, "", false},
		{"index", `opts[0] = nil; ` + terminal, "", false},
		{"copy", `copy(opts, []grpc.DialOption{nil}); ` + terminal, "", false},
		{"reslice append overwrite", `opts = append(opts[:0], nil); ` + terminal, "", false},
		{"address", `_ = &opts; ` + terminal, "", false},
		{"handwritten forwarder", `return forward(ctx, mux, endpoint, opts)`, `
func forward(ctx context.Context, mux interface{}, endpoint string, opts []grpc.DialOption) error {
 return gen.RegisterSvcServiceHandlerFromEndpoint(ctx, mux, endpoint, opts)
}`, false},
		{"unregistered implementation", terminal, `
type Hidden struct{}
func (Hidden) RegisterREST(ctx context.Context, mux interface{}, endpoint string, opts []grpc.DialOption) error {
 opts = nil
 return gen.RegisterSvcServiceHandlerFromEndpoint(ctx, mux, endpoint, opts)
}`, false},
		{"promoted method", terminal, `
type Hidden struct{ Plugin }
`, true},
		{"promoted unsafe method", `opts = nil; ` + terminal, "type Hidden struct{ Plugin }", false},
		{"anonymous promoted method", terminal, "var _ = struct{ *Plugin }{}", true},
		{"anonymous interface embedding", terminal, "var _ = struct{ framework.Plugin }{}", false},
		{"generic implementation", terminal, `
type Hidden[T any] struct{}
func (*Hidden[T]) RegisterREST(ctx context.Context, mux interface{}, endpoint string, opts []grpc.DialOption) error {
 return gen.RegisterSvcServiceHandlerFromEndpoint(ctx, mux, endpoint, opts)
}
var _ = new(Hidden[int])
`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			moduleDir := filepath.Join(root, "svc")
			dials := strings.Replace(fixtureDials, `gen "svc/pkg/gen"`, `gen "svc/pkg/gen"
 "svc/pkg/framework"
 "svc/plugins/example"`, 1)
			dials = strings.Replace(dials, "opts := gatewayDialOptions(extra...)", `opts := gatewayDialOptions(extra...)
 var p framework.Plugin = new(example.Plugin)
 _ = p.RegisterREST(ctx, nil, "", opts)`, 1)
			sources := map[string]string{
				"go.mod":                   "module svc\n\ngo 1.27.3\n\nrequire google.golang.org/grpc v1.84.0\n",
				"pkg/adapters/grpc_gen.go": fixtureSeam,
				"pkg/adapters/rest_gen.go": dials,
				"pkg/framework/plugin.go": `package framework
import ("context"; "google.golang.org/grpc")
type Plugin interface { RegisterREST(context.Context, interface{}, string, []grpc.DialOption) error }
`,
				"pkg/gen/handler.go": `package gen
import ("context"; "google.golang.org/grpc")
const Unused = 0
func RegisterSvcServiceHandlerFromEndpoint(context.Context, interface{}, string, []grpc.DialOption) error { return nil }
`,
				"plugins/example/plugin.go": `package example
import ("context"; "google.golang.org/grpc"; "google.golang.org/grpc/credentials/insecure"; gen "svc/pkg/gen"; "svc/pkg/framework")
var _ framework.Plugin = new(Plugin)
var _ = gen.Unused
var _ = insecure.NewCredentials
type Plugin struct{}
func (*Plugin) RegisterREST(ctx context.Context, mux interface{}, endpoint string, opts []grpc.DialOption) error {
` + tc.body + "\n}\n" + tc.extra,
			}

			if strings.HasPrefix(tc.name, "direct seam") {
				sources["pkg/adapters/rest_gen.go"] = dials[:strings.Index(dials, "func rest(")] + `
func rest(ctx context.Context, extra []grpc.DialOption) {
 var p framework.Plugin = new(example.Plugin)
 _ = p.RegisterREST(ctx, nil, "", gatewayDialOptions(extra...))
}
var _ = gen.Unused
`
			}
			if tc.name == "blank options with own dial" {
				sources["plugins/example/plugin.go"] = strings.Replace(sources["plugins/example/plugin.go"], "opts []grpc.DialOption", "_ []grpc.DialOption", 1)
			}
			for name, source := range sources {
				filename := filepath.Join(moduleDir, name)
				if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filename, []byte(source), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			trusted := map[string]string{}
			for name, source := range sources {
				trusted["svc/"+name] = digest([]byte(source))
			}
			// These disposable modules have no sums. Load with explicit writable
			// dependency resolution, independent of the invoking CI GOFLAGS.
			result, err := checkWithFlags(root, moduleDir, nil, trusted, []string{"-mod=mod"}, "./...")
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, v := range result {
				got = append(got, v.String())
			}
			if (len(got) == 0) != tc.pass {
				t.Fatalf("want pass=%v, got %q", tc.pass, got)
			}
			if !tc.pass {
				typeName := "Plugin"
				if tc.name == "unregistered implementation" || tc.name == "promoted unsafe method" {
					typeName = "Hidden"
				}
				expected := "svc/plugins/example." + typeName + ".RegisterREST refuses"
				if tc.name == "anonymous interface embedding" {
					expected = "struct{svc/pkg/framework.Plugin}.RegisterREST refuses"
				}
				if !strings.Contains(strings.Join(got, "\n"), expected) {
					t.Fatalf("refusal must name concrete type and method: %q", got)
				}
			}
		})
	}
}

// The review's adapter overlays must refuse even when there is no direct dial
// left for the provenance check to discover.
func TestIndirectAdapterDials(t *testing.T) {
	for name, code := range map[string]string{
		"copied options":           `opts := gatewayDialOptions(); copied := append([]grpc.DialOption(nil), opts...); copied[len(copied)-1] = grpc.WithTransportCredentials(insecure.NewCredentials()); dial := grpc.NewClient; _, _ = dial("remote.example:443", copied...)`,
		"struct field overwritten": `holder := struct { Dial func(string, ...grpc.DialOption) (*grpc.ClientConn, error); Options []grpc.DialOption }{grpc.NewClient, gatewayDialOptions()}; holder.Options[len(holder.Options)-1] = grpc.WithTransportCredentials(insecure.NewCredentials()); _, _ = holder.Dial("remote.example:443", holder.Options...)`,
		"endpoint function value":  `register := gen.RegisterSvcServiceHandlerFromEndpoint; _ = register(ctx, nil, "", gatewayDialOptions())`,
		"Dial alias":               `dial := grpc.Dial; _, _ = dial("", gatewayDialOptions()...)`,
		"DialContext alias":        `dial := grpc.DialContext; _, _ = dial(ctx, "", gatewayDialOptions()...)`,
	} {
		t.Run(name, func(t *testing.T) {
			source := `package adapters;` + fixtureMarker + `import ("context"; "google.golang.org/grpc"; "google.golang.org/grpc/credentials/insecure"; gen "svc/pkg/gen"); func rest(ctx context.Context) {` + code + `}; var _ = insecure.NewCredentials; var _ []grpc.DialOption; var _ = gen.Unused`
			got := judge(t, map[string]string{"grpc_gen.go": fixtureSeam, "rest_gen.go": source})
			if !strings.Contains(strings.Join(got, "\n"), "indirect dial function references can bypass loopback credentials") {
				t.Fatalf("want indirect dial refusal, got %q", got)
			}
		})
	}
}
