package noproxygate

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
		violations, err := Check(root, module, nil, "./...")
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range violations {
			t.Error(v)
		}
	}
}

// The self-dial allowlist only shrinks: each entry exists, still dials, and
// carries no grpc.WithNoProxy() yet; once regenerated with it, it goes.
func TestTheSelfDialAllowlistOnlyShrinks(t *testing.T) {
	root := repositoryRoot(t)
	for relative := range GeneratedSelfDials {
		source, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Errorf("%s is allowlisted but cannot be read: %v", relative, err)
			continue
		}
		if !strings.Contains(string(source), "grpc.NewClient") && !strings.Contains(string(source), "FromEndpoint(") {
			t.Errorf("%s is allowlisted but no longer dials; remove its entry", relative)
		}
		if strings.Contains(string(source), "WithNoProxy()") {
			t.Errorf("%s now dials with grpc.WithNoProxy(); remove its entry from GeneratedSelfDials", relative)
		}
	}
}

// A case is one package written to bypass the gate (or to pass it).
type gateCase struct {
	name    string
	imports []string // beyond the header's
	body    string
	source  string // a whole file, in place of header and body
	dir     string // in place of a numbered directory
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
	{name: "S3 pointer conversion from an identical struct", imports: []string{`"time"`}, body: "type fakeClient struct {\n\tTransport     http.RoundTripper\n\tCheckRedirect func(req *http.Request, via []*http.Request) error\n\tJar           http.CookieJar\n\tTimeout       time.Duration\n}\n\nfunc s() *http.Client { return (*http.Client)(&fakeClient{}) }", reason: "conversion to http.Client"},
	{name: "S4 inferred generic new", body: "func newOf[T any](_ *T) *T { return new(T) }\n\nfunc s() *http.Client { return newOf((*http.Client)(nil)) }", reason: "generic instantiated with http.Client"},
	{name: "S5 parenthesised Transport write", body: "func s() *http.Client {\n\tc := &http.Client{Transport: host.HTTPTransport()}\n\t(c.Transport) = nil\n\treturn c\n}", reason: "may only be set to host.HTTPTransport()"},
	{name: "S6 Transport write through *&", body: "func s() *http.Client {\n\tc := &http.Client{Transport: host.HTTPTransport()}\n\t*&c.Transport = nil\n\treturn c\n}", reason: "may only be set to host.HTTPTransport()"},
	{name: "S7 Transport write through a pointer to the field", body: "func s() *http.Client {\n\tc := &http.Client{Transport: host.HTTPTransport()}\n\tp := &c.Transport\n\t*p = nil\n\treturn c\n}", reason: "address of a Transport field"},
	{name: "S8 proxy pointer conversion", imports: []string{`"log"`, `"net/url"`, `"time"`}, body: "type fakeProxy struct {\n\tRewrite        func(*httputil.ProxyRequest)\n\tTransport      http.RoundTripper\n\tFlushInterval  time.Duration\n\tErrorLog       *log.Logger\n\tBufferPool     httputil.BufferPool\n\tModifyResponse func(*http.Response) error\n\tErrorHandler   func(http.ResponseWriter, *http.Request, error)\n\tDirector       func(*http.Request)\n}\n\nfunc s(target *url.URL) *httputil.ReverseProxy {\n\tf := &fakeProxy{Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(target) }}\n\treturn (*httputil.ReverseProxy)(f)\n}", reason: "conversion to httputil.ReverseProxy"},
	{name: "S9 elided proxy literal", imports: []string{`"net/url"`}, body: "func s(target *url.URL) *httputil.ReverseProxy {\n\treturn []*httputil.ReverseProxy{{Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(target) }}}[0]\n}", reason: "literal must set Transport"},
	{name: "S10 elided second transport", imports: []string{`"net/url"`, `"os"`}, body: "func s() *http.Client {\n\tts := []*http.Transport{{Proxy: func(*http.Request) (*url.URL, error) { return url.Parse(os.Getenv(\"HTTP_PROXY\")) }}}\n\treturn []*http.Client{{Transport: ts[0]}}[0]\n}", reason: "second transport"},
	{name: "S11 seam in a dead branch", imports: []string{`"google.golang.org/grpc/credentials/insecure"`}, body: "func s(target string) (*grpc.ClientConn, error) {\n\treturn grpc.NewClient(target, func() []grpc.DialOption {\n\t\tif false {\n\t\t\treturn host.DialOptions(nil)\n\t\t}\n\t\treturn []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}\n\t}()...)\n}", reason: "grpc.NewClient must be called"},
	{name: "S12 seam sliced away", imports: []string{`"google.golang.org/grpc/credentials/insecure"`}, body: "func s(target string) (*grpc.ClientConn, error) {\n\treturn grpc.NewClient(target, append(host.DialOptions(nil)[:0], grpc.WithTransportCredentials(insecure.NewCredentials()))...)\n}", reason: "grpc.NewClient must be called"},
	{name: "S13 a dial under a directory named gen", dir: "s13/gen", source: "package gen\n\nimport \"google.golang.org/grpc\"\n\nfunc FromEndpoint(endpoint string, opts []grpc.DialOption) (*grpc.ClientConn, error) {\n\treturn grpc.NewClient(endpoint, opts...)\n}\n", reason: "grpc.NewClient must be called"},
	{name: "S14 a request under a directory named gen", dir: "s14/gen", source: "package gen\n\nimport \"net/http\"\n\nfunc Fetch(u string) (*http.Response, error) { return http.Get(u) }\n", reason: "http.Get uses"},
	{name: "S15 a subprocess", imports: []string{`"context"`, `"os/exec"`}, body: "func s(ctx context.Context, u string) ([]byte, error) {\n\treturn exec.CommandContext(ctx, \"curl\", \"-s\", u).Output()\n}", reason: "exec.CommandContext starts a subprocess"},

	// The FromEndpoint rule (r114 f3).
	{name: "FromEndpoint with its own options", imports: []string{`"context"`}, body: "func RegisterThingHandlerFromEndpoint(context.Context, any, string, []grpc.DialOption) error { return nil }\n\nfunc f(ctx context.Context) { _ = RegisterThingHandlerFromEndpoint(ctx, nil, \"t\", []grpc.DialOption{}) }", reason: "must be passed host.DialOptions"},
}

var allowed = []gateCase{
	{name: "the host seam", body: "var _ = &http.Client{Transport: host.HTTPTransport()}"},
	{name: "an elided literal with the seam", body: "var _ = []*http.Client{{Transport: host.HTTPTransport()}}"},
	{name: "pointers", body: "type s struct{ c *http.Client }\n\nvar p *httputil.ReverseProxy\n\nvar t *http.Transport"},
	{name: "Transport set to the seam", body: "func f(c *http.Client) { c.Transport = host.HTTPTransport() }"},
	{name: "a gRPC dial with DialOptions", body: "func f() { _, _ = grpc.NewClient(\"t\", host.DialOptions(nil)...) }"},
	{name: "a gRPC dial appending to DialOptions", body: "func f() { _, _ = grpc.NewClient(\"t\", append(host.DialOptions(nil), grpc.WithUserAgent(\"x\"))...) }"},
	{name: "an aliased host import", source: "package %s\n\nimport (\n\t\"net/http\"\n\n\th \"github.com/codefly-dev/authority/libraries/authority-client/go/host\"\n)\n\nvar _ = &http.Client{Transport: h.HTTPTransport()}\n"},
	{name: "a plugin forwarding its gateway's endpoint and options", imports: []string{`"context"`}, body: "func RegisterThingHandlerFromEndpoint(context.Context, any, string, []grpc.DialOption) error { return nil }\n\ntype plugin struct{}\n\nfunc (plugin) RegisterREST(ctx context.Context, mux any, endpoint string, opts []grpc.DialOption) error {\n\treturn RegisterThingHandlerFromEndpoint(ctx, mux, endpoint, opts)\n}"},
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
		overlay[filepath.Join(module, "zzcases", filepath.FromSlash(dir), "case.go")] = []byte(source)
		dirs["tools/noproxygate/zzcases/"+dir] = c
		patterns = append(patterns, "./zzcases/"+dir)
	}
	violations, err := Check(root, module, overlay, patterns...)
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
	if len(refused) != 44 {
		t.Errorf("the table holds %d refused cases; 28 from earlier rounds, 15 from r114 and the FromEndpoint case are 44", len(refused))
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
		if entry.IsDir() && (entry.Name() == "node_modules" || entry.Name() == ".git") {
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
