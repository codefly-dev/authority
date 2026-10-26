package noproxygate

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// The repository holds the rule: every Go module in it type-checks and shows
// none of the refused forms.
func TestTheRepositoryHoldsTheNoProxyRule(t *testing.T) {
	root := repositoryRoot(t)
	modules := goModules(t, root)
	if len(modules) < 9 {
		t.Fatalf("found %d Go modules under %s; the repository has at least 9", len(modules), root)
	}
	for _, module := range modules {
		relative, _ := filepath.Rel(root, module)
		t.Run(filepath.ToSlash(relative), func(t *testing.T) {
			violations, err := Check(root, module, nil, "./...")
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range violations {
				t.Error(v)
			}
		})
	}

}

// A case is one package written to bypass the gate (or to pass it).
type gateCase struct {
	name    string
	imports []string // beyond the header's
	body    string
	source  string // a whole file, in place of header and body
	dir     string // in place of a numbered directory
	file    string // in place of case.go
	reason  string // "" for a form the gate must pass
}

const header = `
	"net/http"
	"net/http/httputil"

	"google.golang.org/grpc"
	host "github.com/codefly-dev/authority/libraries/authority-client/go/host"
`

// headerUses keeps every header import used, with forms the gate allows.
const headerUses = "var _ = http.MethodGet\nvar _ httputil.BufferPool\nvar _ = grpc.WithTransportCredentials\nvar _ = host.HTTPTransport\n"

const zero = "is a zero value on http.DefaultTransport"

var refused = []gateCase{
	{name: "conversion from a constrained type parameter", body: `func erase[P ~*http.Client](p P) any { return any(p) }`, reason: "conversion to or from http.Client"},
	{name: "conversion from a transport pointer", body: `func erase(p *http.Transport) any { return any(p) }`, reason: "conversion to or from http.Transport"},
	{name: "raw unsafe import", source: "package %s\nimport `unsafe`\nvar _ = unsafe.Sizeof(0)\n", reason: `import "unsafe"`},
	// Earlier rounds (r99, r101, r105): every one stays refused.
	{name: "DefaultClient", body: "var _ = http.DefaultClient", reason: "http.DefaultClient follows"},
	{name: "DefaultTransport", body: "var _ = http.DefaultTransport", reason: "http.DefaultTransport follows"},
	{name: "ProxyFromEnvironment", body: "var _ = http.ProxyFromEnvironment", reason: "http.ProxyFromEnvironment reads"},
	{name: "http.Get called", body: "func f() { _, _ = http.Get(\"u\") }", reason: "http.Get uses"},
	{name: "http.Get as a method value", body: "var get = http.Get", reason: "http.Get uses"},
	{name: "http.PostForm as a method value", body: "var post = http.PostForm", reason: "http.PostForm uses"},
	{name: "NewSingleHostReverseProxy value", body: "var p = httputil.NewSingleHostReverseProxy", reason: "httputil.NewSingleHostReverseProxy uses"},
	{name: "grpc.NewClient without the seam", body: "func f() { _, _ = grpc.NewClient(\"t\") }", reason: "grpc.NewClient must be called"},
	{name: "grpc.Dial as a method value", body: "var dial = grpc.Dial", reason: "grpc.Dial must be called"},
	{name: "dot-import of net/http", source: "package %s\n\nimport . \"net/http\"\n\nvar _ = MethodGet\n", reason: "dot-import of net/http"},
	{name: "zero-value client", body: "var c http.Client", reason: zero},
	{name: "zero-value proxy", body: "var p httputil.ReverseProxy", reason: zero},
	{name: "new(http.Client)", body: "var _ = new(http.Client)", reason: zero},
	{name: "new(httputil.ReverseProxy)", body: "var _ = new(httputil.ReverseProxy)", reason: zero},
	{name: "value-typed field", body: "type s struct{ c http.Client }", reason: zero},
	{name: "type definition", body: "type myC http.Client", reason: "declared identical to http.Client"},
	{name: "type alias", body: "type C = http.Client", reason: zero},
	{name: "array", body: "var cs [1]http.Client", reason: zero},
	{name: "make of a slice", body: "var cs = make([]http.Client, 1)", reason: zero},
	{name: "map", body: "var m map[string]httputil.ReverseProxy", reason: zero},
	{name: "client literal without transport", body: "var _ = &http.Client{}", reason: "literal must set Transport"},
	{name: "a local HTTPTransport", body: "func HTTPTransport() http.RoundTripper { return nil }\n\nvar _ = &http.Client{Transport: HTTPTransport()}", reason: "literal must set Transport"},
	{name: "another package's HTTPTransport", imports: []string{`other "github.com/codefly-dev/authority/tools/noproxygate/zzcases/otherhost"`}, body: "var _ = &http.Client{Transport: other.HTTPTransport()}", reason: "literal must set Transport"},
	{name: "a local variable shadowing host", body: "type evil struct{}\n\nfunc (evil) HTTPTransport() http.RoundTripper { return nil }\n\nfunc f() { host := evil{}; _ = &http.Client{Transport: host.HTTPTransport()} }", reason: "literal must set Transport"},
	{name: "http.Transport literal", body: "var _ = &http.Transport{}", reason: "second transport"},
	{name: "new(http.Transport)", body: "var _ = new(http.Transport)", reason: "second transport"},
	{name: "client Transport set to nil", body: "func f() { c := &http.Client{Transport: host.HTTPTransport()}; c.Transport = nil }", reason: "may only be set to host.HTTPTransport()"},
	{name: "proxy Transport set to another", body: "func f(t http.RoundTripper) { p := &httputil.ReverseProxy{Transport: host.HTTPTransport()}; p.Transport = t }", reason: "may only be set to host.HTTPTransport()"},

	// Review r114's fifteen, from its evidence sources.
	{name: "S1 elided slice literal", body: "func s() *http.Client { return []*http.Client{{}}[0] }", reason: "literal must set Transport"},
	{name: "S2 elided map literal", body: "func s() *http.Client { return map[string]*http.Client{\"x\": {}}[\"x\"] }", reason: "literal must set Transport"},
	{name: "S3 pointer conversion from an identical struct", imports: []string{`"time"`}, body: "type fakeClient struct {\n\tTransport     http.RoundTripper\n\tCheckRedirect func(req *http.Request, via []*http.Request) error\n\tJar           http.CookieJar\n\tTimeout       time.Duration\n}\n\nfunc s() *http.Client { return (*http.Client)(&fakeClient{}) }", reason: "conversion to or from http.Client"},
	{name: "S4 inferred generic new", body: "func newOf[T any](_ *T) *T { return new(T) }\n\nfunc s() *http.Client { return newOf((*http.Client)(nil)) }", reason: "generic instantiated with http.Client"},
	{name: "S5 parenthesised Transport write", body: "func s() *http.Client {\n\tc := &http.Client{Transport: host.HTTPTransport()}\n\t(c.Transport) = nil\n\treturn c\n}", reason: "may only be set to host.HTTPTransport()"},
	{name: "S6 Transport write through *&", body: "func s() *http.Client {\n\tc := &http.Client{Transport: host.HTTPTransport()}\n\t*&c.Transport = nil\n\treturn c\n}", reason: "may only be set to host.HTTPTransport()"},
	{name: "S7 Transport write through a pointer to the field", body: "func s() *http.Client {\n\tc := &http.Client{Transport: host.HTTPTransport()}\n\tp := &c.Transport\n\t*p = nil\n\treturn c\n}", reason: "address of a Transport field"},
	{name: "S8 proxy pointer conversion", imports: []string{`"log"`, `"net/url"`, `"time"`}, body: "type fakeProxy struct {\n\tRewrite        func(*httputil.ProxyRequest)\n\tTransport      http.RoundTripper\n\tFlushInterval  time.Duration\n\tErrorLog       *log.Logger\n\tBufferPool     httputil.BufferPool\n\tModifyResponse func(*http.Response) error\n\tErrorHandler   func(http.ResponseWriter, *http.Request, error)\n\tDirector       func(*http.Request)\n}\n\nfunc s(target *url.URL) *httputil.ReverseProxy {\n\tf := &fakeProxy{Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(target) }}\n\treturn (*httputil.ReverseProxy)(f)\n}", reason: "conversion to or from httputil.ReverseProxy"},
	{name: "S9 elided proxy literal", imports: []string{`"net/url"`}, body: "func s(target *url.URL) *httputil.ReverseProxy {\n\treturn []*httputil.ReverseProxy{{Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(target) }}}[0]\n}", reason: "literal must set Transport"},
	{name: "S10 elided second transport", imports: []string{`"net/url"`, `"os"`}, body: "func s() *http.Client {\n\tts := []*http.Transport{{Proxy: func(*http.Request) (*url.URL, error) { return url.Parse(os.Getenv(\"HTTP_PROXY\")) }}}\n\treturn []*http.Client{{Transport: ts[0]}}[0]\n}", reason: "second transport"},
	{name: "S11 seam in a dead branch", imports: []string{`"google.golang.org/grpc/credentials/insecure"`}, body: "func s(target string) (*grpc.ClientConn, error) {\n\treturn grpc.NewClient(target, func() []grpc.DialOption {\n\t\tif false {\n\t\t\treturn host.DialOptions(nil)\n\t\t}\n\t\treturn []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}\n\t}()...)\n}", reason: "grpc.NewClient must be called"},
	{name: "S12 seam sliced away", imports: []string{`"google.golang.org/grpc/credentials/insecure"`}, body: "func s(target string) (*grpc.ClientConn, error) {\n\treturn grpc.NewClient(target, append(host.DialOptions(nil)[:0], grpc.WithTransportCredentials(insecure.NewCredentials()))...)\n}", reason: "grpc.NewClient must be called"},
	{name: "S13 a dial under a directory named gen", dir: "s13/gen", source: "package gen\n\nimport \"google.golang.org/grpc\"\n\nfunc FromEndpoint(endpoint string, opts []grpc.DialOption) (*grpc.ClientConn, error) {\n\treturn grpc.NewClient(endpoint, opts...)\n}\n", reason: "grpc.NewClient must be called"},
	{name: "S14 a request under a directory named gen", dir: "s14/gen", source: "package gen\n\nimport \"net/http\"\n\nfunc Fetch(u string) (*http.Response, error) { return http.Get(u) }\n", reason: "http.Get uses"},
	{name: "S15 a subprocess", imports: []string{`"context"`, `"os/exec"`}, body: "func s(ctx context.Context, u string) ([]byte, error) {\n\treturn exec.CommandContext(ctx, \"curl\", \"-s\", u).Output()\n}", reason: "exec.CommandContext starts a subprocess"},

	// The FromEndpoint rule (r114 f3).
	{name: "FromEndpoint with its own options", imports: []string{`"context"`}, body: "func RegisterThingHandlerFromEndpoint(context.Context, any, string, []grpc.DialOption) error { return nil }\n\nfunc f(ctx context.Context) { _ = RegisterThingHandlerFromEndpoint(ctx, nil, \"t\", []grpc.DialOption{}) }", reason: "must be passed host.DialOptions"},

	// Review r149's probes and minors.
	{name: "N01 client converted to an identical unnamed struct, then reset", imports: []string{`"time"`}, body: "func s() {\n\tc := &http.Client{Transport: host.HTTPTransport()}\n\t(*struct {\n\tTransport     http.RoundTripper\n\tCheckRedirect func(*http.Request, []*http.Request) error\n\tJar           http.CookieJar\n\tTimeout       time.Duration\n})(c).Transport = nil\n}", reason: "conversion to or from http.Client"},
	{name: "N02 proxy converted to an identical unnamed struct, then reset", imports: []string{`"log"`, `"time"`}, body: "func s() {\n\tp := &httputil.ReverseProxy{Transport: host.HTTPTransport()}\n\t(*struct {\n\tRewrite        func(*httputil.ProxyRequest)\n\tTransport      http.RoundTripper\n\tFlushInterval  time.Duration\n\tErrorLog       *log.Logger\n\tBufferPool     httputil.BufferPool\n\tModifyResponse func(*http.Response) error\n\tErrorHandler   func(http.ResponseWriter, *http.Request, error)\n\tDirector       func(*http.Request)\n})(p).Transport = nil\n}", reason: "conversion to or from httputil.ReverseProxy"},
	{name: "N03 conversion to a type parameter", imports: []string{`"time"`}, body: "func conv[P ~*http.Client, Q ~*struct {\n\tTransport     http.RoundTripper\n\tCheckRedirect func(*http.Request, []*http.Request) error\n\tJar           http.CookieJar\n\tTimeout       time.Duration\n}](q Q) P { return P(q) }\n\nfunc s() *http.Client { return conv[*http.Client](&struct {\n\tTransport     http.RoundTripper\n\tCheckRedirect func(*http.Request, []*http.Request) error\n\tJar           http.CookieJar\n\tTimeout       time.Duration\n}{}) }", reason: "conversion to or from http.Client"},
	{name: "N04 a RegisterREST forwarding its caller's options", imports: []string{`"context"`, `"google.golang.org/grpc/credentials/insecure"`}, body: "func RegisterThingHandlerFromEndpoint(context.Context, any, string, []grpc.DialOption) error { return nil }\n\nfunc RegisterREST(ctx context.Context, mux any, endpoint string, opts []grpc.DialOption) error {\n\treturn RegisterThingHandlerFromEndpoint(ctx, mux, endpoint, opts)\n}\n\nfunc f(ctx context.Context) { _ = RegisterREST(ctx, nil, \"t\", []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}) }", reason: "must be passed host.DialOptions"},
	{name: "m1 import unsafe", imports: []string{`"unsafe"`}, body: "var _ = unsafe.Sizeof(0)", reason: "import \"unsafe\""},
	{name: "m1 go:linkname", imports: []string{`_ "unsafe"`}, body: "//go:linkname nanotime runtime.nanotime\nfunc nanotime() int64", reason: "go:linkname"},
	{name: "m2 credentials appended after the seam", imports: []string{`"google.golang.org/grpc/credentials/insecure"`}, body: "func f() { _, _ = grpc.NewClient(\"t\", append(host.DialOptions(nil), grpc.WithTransportCredentials(insecure.NewCredentials()))...) }", reason: "no option after the seam that sets the transport"},
	{name: "a forged generated marker", source: "// Code generated by protoc-gen-go. DO NOT EDIT.\n\npackage %s\n\nimport \"net/http\"\n\nfunc s() { _, _ = http.Get(\"u\") }\n", reason: "http.Get uses"},
	{name: "a forged marker on a .pb.go file", file: "forged.pb.go", source: "// Code generated by protoc-gen-go. DO NOT EDIT.\n\npackage %s\n\nimport \"unsafe\"\n\nimport \"net/http\"\n\nvar _ = unsafe.Sizeof(0)\n\nfunc s() { _, _ = http.Get(\"u\") }\n", reason: "http.Get uses"},
	{name: "a gateway forwarder under a forged marker", source: "// Code generated by protoc-gen-grpc-gateway. DO NOT EDIT.\n\npackage %s\n\nimport (\n\t\"context\"\n\n\t\"google.golang.org/grpc\"\n)\n\nfunc RegisterThingHandlerFromEndpoint(ctx context.Context, mux any, endpoint string, opts []grpc.DialOption) error {\n\tconn, err := grpc.NewClient(endpoint, opts...)\n\t_ = conn\n\treturn err\n}\n", reason: "grpc.NewClient must be called"},
	{name: "forged marker and suffix cannot authorize unsafe", file: "forged.pb.go", source: "// Code generated by protoc-gen-go. DO NOT EDIT.\npackage %s\nimport \"unsafe\"\nvar _ = unsafe.Sizeof(0)\n", reason: `import "unsafe"`},
	{name: "forged gateway marker and suffix cannot authorize a forwarder", file: "forged.pb.gw.go", source: "// Code generated by protoc-gen-grpc-gateway. DO NOT EDIT.\npackage %s\nimport \"google.golang.org/grpc\"\nfunc RegisterThingHandlerFromEndpoint(endpoint string, opts []grpc.DialOption) (*grpc.ClientConn,error) { return grpc.NewClient(endpoint,opts...) }\n", reason: "grpc.NewClient must be called"},
	{name: "credential constructor alias after seam", body: `func f() { credentials := grpc.WithTransportCredentials; _, _ = grpc.NewClient("t", append(host.DialOptions(nil), credentials(nil))...) }`, reason: "no option after the seam"},
	{name: "credential option variable after seam", body: `func f() { credentials := grpc.WithTransportCredentials(nil); _, _ = grpc.NewClient("t", append(host.DialOptions(nil), credentials)...) }`, reason: "no option after the seam"},
	{name: "opaque option slice after seam", body: `func f(options []grpc.DialOption) { _, _ = grpc.NewClient("t", append(host.DialOptions(nil), options...)...) }`, reason: "no option after the seam"},
	{name: "credentials bundle after seam", body: `func f() { _, _ = grpc.NewClient("t", append(host.DialOptions(nil), grpc.WithCredentialsBundle(nil))...) }`, reason: "no option after the seam"},
	{name: "insecure option after seam", body: `func f() { _, _ = grpc.NewClient("t", append(host.DialOptions(nil), grpc.WithInsecure())...) }`, reason: "no option after the seam"},
	{name: "custom dialer after seam", body: `func f() { _, _ = grpc.NewClient("t", append(host.DialOptions(nil), grpc.WithContextDialer(nil))...) }`, reason: "no option after the seam"},
}

var allowed = []gateCase{
	{name: "the host seam", body: "var _ = &http.Client{Transport: host.HTTPTransport()}"},
	{name: "an elided literal with the seam", body: "var _ = []*http.Client{{Transport: host.HTTPTransport()}}"},
	{name: "pointers", body: "type s struct{ c *http.Client }\n\nvar p *httputil.ReverseProxy\n\nvar t *http.Transport"},
	{name: "Transport set to the seam", body: "func f(c *http.Client) { c.Transport = host.HTTPTransport() }"},
	{name: "a gRPC dial with DialOptions", body: "func f() { _, _ = grpc.NewClient(\"t\", host.DialOptions(nil)...) }"},
	{name: "a gRPC dial appending to DialOptions", body: "func f() { _, _ = grpc.NewClient(\"t\", append(host.DialOptions(nil), grpc.WithUserAgent(\"x\"))...) }"},
	{name: "an aliased host import", source: "package %s\n\nimport (\n\t\"net/http\"\n\n\th \"github.com/codefly-dev/authority/libraries/authority-client/go/host\"\n)\n\nvar _ = &http.Client{Transport: h.HTTPTransport()}\n"},
	{name: "a plugin dialling its gateway with the seam", imports: []string{`"context"`, `"google.golang.org/grpc/credentials/insecure"`}, body: "func RegisterThingHandlerFromEndpoint(context.Context, any, string, []grpc.DialOption) error { return nil }\n\ntype plugin struct{}\n\nfunc (plugin) RegisterREST(ctx context.Context, mux any, endpoint string, _ []grpc.DialOption) error {\n\treturn RegisterThingHandlerFromEndpoint(ctx, mux, endpoint, host.DialOptions(insecure.NewCredentials()))\n}"},
	{name: "a genuine grpc-gateway forwarder", file: "thing.pb.gw.go", source: "// Code generated by protoc-gen-grpc-gateway. DO NOT EDIT.\n\npackage %s\n\nimport (\n\t\"context\"\n\n\t\"google.golang.org/grpc\"\n)\n\nfunc RegisterThingHandlerFromEndpoint(ctx context.Context, mux any, endpoint string, opts []grpc.DialOption) error {\n\tconn, err := grpc.NewClient(endpoint, opts...)\n\t_ = conn\n\treturn err\n}\n"},
}

// The gate itself, on sources written to bypass it: each refused case fails
// for its own reason, and each allowed case passes.
func TestTheGateRefusesEachBypass(t *testing.T) {
	root := repositoryRoot(t)
	module, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	overlay := map[string][]byte{
		filepath.Join(module, "zzcases", "otherhost", "host.go"): []byte("package host\n\nimport \"net/http\"\n\nfunc HTTPTransport() http.RoundTripper { return nil }\n"),
	}
	trusted := generatedDigests()
	dirs := map[string]gateCase{}
	var patterns []string
	all := append(append([]gateCase{}, refused...), allowed...)
	for i, c := range all {
		dir := c.dir
		if dir == "" {
			dir = fmt.Sprintf("c%02d", i)
		}
		pkg := filepath.Base(dir)
		source := c.source
		switch {
		case source != "" && strings.Contains(source, "%s"):
			source = fmt.Sprintf(source, pkg)
		case source == "":
			source = "package " + pkg + "\n\nimport (" + header
			for _, extra := range c.imports {
				source += "\t" + extra + "\n"
			}
			source += ")\n\n" + headerUses + "\n" + c.body + "\n"
		}
		file := c.file
		if file == "" {
			file = "case.go"
		}
		overlay[filepath.Join(module, "zzcases", filepath.FromSlash(dir), file)] = []byte(source)
		if c.name == "a genuine grpc-gateway forwarder" {
			trusted["tools/noproxygate/zzcases/"+dir+"/"+file] = digest([]byte(source))
		}
		dirs["tools/noproxygate/zzcases/"+dir] = c
		patterns = append(patterns, "./zzcases/"+dir)
	}
	violations, err := check(root, module, overlay, trusted, patterns...)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string][]Violation{}
	for _, v := range violations {
		found[filepath.ToSlash(filepath.Dir(v.File))] = append(found[filepath.ToSlash(filepath.Dir(v.File))], v)
	}
	var names []string
	for dir := range dirs {
		names = append(names, dir)
	}
	sort.Strings(names)
	for _, dir := range names {
		c := dirs[dir]
		got := found[dir]
		if c.reason == "" {
			if len(got) != 0 {
				t.Errorf("allowed %q was refused: %v", c.name, got)
			}
			continue
		}
		ok := false
		for _, v := range got {
			ok = ok || strings.Contains(v.Reason, c.reason)
		}
		if !ok {
			t.Errorf("refused %q: want a refusal naming %q, got %v", c.name, c.reason, got)
		}
	}
	if len(refused) < 54 {
		t.Errorf("the table holds %d refused cases; 28 from earlier rounds, 15 from r114, the FromEndpoint case and r149's 10 are 54", len(refused))
	}
}

// Coverage on disk: hidden and testdata packages are actually type-checked;
// constraints are refused even when active, and platform-excluded files fail closed.
func TestAFileTheLoadDoesNotJudgeIsRefused(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":                          "module example.com/probe\n\ngo 1.27.3\n",
		"ok.go":                           "package probe\n",
		"active.go":                       "//go:build\tgo1.1\n\npackage probe\n",
		"combined.go":                     "//go:build release && enterprise\n\npackage probe\n",
		"platform_plan9.go":               "package probe\n",
		"current_" + runtime.GOOS + ".go": "package probe\n",
		"testdata/clean/clean.go":         "package clean\n",
		"tagged.go":                       "//go:build release\n\npackage probe\n\nimport \"net/http\"\n\nfunc s() { _, _ = http.Get(\"u\") }\n",
		"_hidden/h.go":                    "package hidden\n\nimport \"net/http\"\n\nfunc s() { _, _ = http.Get(\"u\") }\n",
		".dot/d.go":                       "package dot\nimport \"net/http\"\nfunc s() { _, _ = http.Get(\"u\") }\n",
		"testdata/td/t.go":                "package td\n\nimport \"net/http\"\n\nfunc s() { _, _ = http.Get(\"u\") }\n",
		"nested/go.mod":                   "module example.com/nested\n\ngo 1.27.3\n",
		"nested/n.go":                     "package nested\n",
		"ok_test.go":                      "package probe\n",
	}
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	violations, err := Check(dir, dir, nil, "./...")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, v := range violations {
		got[v.File] += v.Reason + "\n"
	}
	for name, reason := range map[string]string{
		"tagged.go":                       "production build constraints",
		"active.go":                       "production build constraints",
		"combined.go":                     "production build constraints",
		"platform_plan9.go":               "was not judged",
		"current_" + runtime.GOOS + ".go": "platform filenames are refused",
		"_hidden/h.go":                    "http.Get uses", ".dot/d.go": "http.Get uses", "testdata/td/t.go": "http.Get uses",
	} {
		if !strings.Contains(got[name], reason) {
			t.Errorf("%s: want %q, got %q", name, reason, got[name])
		}
	}
	for _, clean := range []string{"ok.go", "nested/n.go", "ok_test.go", "testdata/clean/clean.go"} {
		if got[clean] != "" {
			t.Errorf("clean %s refused: %s", clean, got[clean])
		}
	}

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

func goModules(t *testing.T, root string) []string {
	var modules []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		if !entry.IsDir() && entry.Name() == "go.mod" {
			modules = append(modules, filepath.Dir(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return modules
}

func TestCgoIsRefusedBeforeItsRewrite(t *testing.T) {
	root := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module example.com/cgo\n\ngo 1.27.3\n",
		"cgo.go": "package cgo\nimport \"C\"\nimport \"net/http\"\nfunc f() { _, _ = http.Get(\"u\") }\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	violations, err := Check(root, root, nil, "./...")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range violations {
		if strings.Contains(v.Reason, `import "C" is refused`) {
			return
		}
	}
	t.Fatalf("cgo source not refused: %v", violations)
}

func TestGeneratedDigestBindsBothContentAndPath(t *testing.T) {
	root := repositoryRoot(t)
	for relative, want := range generatedDigests() {
		source, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		if digest(source) != want {
			t.Errorf("%s changed since reviewed generation; use codefly generate and review manifest update", relative)
		}
	}
	module, _ := os.Getwd()
	name := filepath.Join(module, "zzdigest/forged.pb.go")
	source := []byte("// Code generated by protoc-gen-go. DO NOT EDIT.\npackage probe\nimport \"unsafe\"\nvar _ = unsafe.Sizeof(0)\n")
	relative, _ := filepath.Rel(root, name)
	for _, tc := range []struct {
		name    string
		trusted map[string]string
	}{
		{"changed contents", map[string]string{filepath.ToSlash(relative): digest(append(append([]byte{}, source...), '\n'))}},
		{"copied to another path", map[string]string{"some/other.pb.go": digest(source)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			violations, err := check(root, module, map[string][]byte{name: source}, tc.trusted, "./zzdigest")
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range violations {
				if strings.Contains(v.Reason, `import "unsafe"`) {
					return
				}
			}
			t.Fatalf("forged generated code exempt: %v", violations)
		})
	}
}
