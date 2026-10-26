package noproxygate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureMarker = "/* -----\n\n⚠️ " + agentMarker + "\n\n----- */\n"

const fixtureSeam = `package adapters

` + fixtureMarker + `
import (
	"context"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func gatewayDialOptions(extra ...grpc.DialOption) []grpc.DialOption {
	options := []grpc.DialOption{grpc.WithNoProxy()}
	options = append(options, extra...)
	return append(options, grpc.WithTransportCredentials(loopbackTransport{insecure.NewCredentials()}))
}

type loopbackTransport struct{ credentials.TransportCredentials }

func (t loopbackTransport) ClientHandshake(ctx context.Context, authority string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return t.TransportCredentials.ClientHandshake(ctx, authority, conn)
}
`

const fixtureDials = `package adapters

` + fixtureMarker + `
import (
	"context"

	"google.golang.org/grpc"
	gen "svc/pkg/gen"
)

func rest(ctx context.Context, extra []grpc.DialOption) {
	opts := gatewayDialOptions(extra...)
	_ = gen.RegisterSvcServiceHandlerFromEndpoint(ctx, nil, "127.0.0.1:1", opts)
	_, _ = grpc.NewClient("127.0.0.1:1", opts...)
	_, _ = grpc.NewClient("127.0.0.1:1", gatewayDialOptions(extra...)...)
}
`

// judge runs the gate over one adapter package written from sources.
func judge(t *testing.T, sources map[string]string) []string {
	t.Helper()
	root := repositoryRoot(t)
	module, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	overlay := map[string][]byte{filepath.Join(module, "zzselfdial/pkg/gen/api.go"): []byte(`package gen
import ("context"; "google.golang.org/grpc")
func RegisterAuthorityServiceHandlerFromEndpoint(context.Context, any, string, []grpc.DialOption) error { return nil }
`)}
	trusted := generatedDigests()
	for name, source := range sources {
		source = strings.ReplaceAll(source, `"svc/pkg/gen"`, `"github.com/codefly-dev/authority/tools/noproxygate/zzselfdial/pkg/gen"`)
		source = strings.ReplaceAll(source, "RegisterSvcServiceHandlerFromEndpoint", "RegisterAuthorityServiceHandlerFromEndpoint")
		path := filepath.Join(module, "zzselfdial/pkg/adapters", name)
		overlay[path] = []byte(source)
		rel, _ := filepath.Rel(root, path)
		trusted[filepath.ToSlash(rel)] = digest([]byte(source))
	}
	violations, err := check(root, module, overlay, trusted, "./zzselfdial/pkg/adapters")
	if err != nil {
		return []string{err.Error()}
	}
	var out []string
	for _, v := range violations {
		out = append(out, v.String())
	}
	return out
}

// The generated self-dial rule, against the template's shape and the
// regressions r157 found: options followed by name, files exempt by name,
// a WithNoProxy in dead code, and credentials that are not loopback or not last.
func TestTheGeneratedSelfDialRule(t *testing.T) {
	replace := func(source, old, new string) string {
		if !strings.Contains(source, old) {
			t.Fatalf("fixture does not contain %q", old)
		}
		return strings.Replace(source, old, new, 1)
	}
	for _, c := range []struct {
		name    string
		sources map[string]string
		refusal string // "" when the package is allowed
	}{
		{"the template's shape", map[string]string{"grpc_gen.go": fixtureSeam, "rest_gen.go": fixtureDials}, ""},
		{"a same-named variable in another function",
			map[string]string{"grpc_gen.go": fixtureSeam, "rest_gen.go": fixtureDials + `
func other(raw []grpc.DialOption) {
	opts := raw
	_, _ = grpc.NewClient("remote.example:443", opts...)
}
`}, "a generated self-dial must pass gatewayDialOptions"},
		{"the options variable written again",
			map[string]string{"grpc_gen.go": fixtureSeam, "rest_gen.go": replace(fixtureDials,
				"opts := gatewayDialOptions(extra...)\n", "opts := gatewayDialOptions(extra...)\n\topts = extra\n")},
			"a generated self-dial must pass gatewayDialOptions"},
		{"a FromEndpoint dial with other options",
			map[string]string{"grpc_gen.go": fixtureSeam, "rest_gen.go": replace(fixtureDials, `"127.0.0.1:1", opts)`, `"remote.example:443", extra)`)},
			"a generated self-dial must pass gatewayDialOptions"},
		{"a hand-written file named like a template, without the marker",
			map[string]string{"grpc_gen.go": fixtureSeam, "rest_gen.go": replace(fixtureDials, fixtureMarker, "")},
			"grpc.NewClient must be called with host.DialOptions"},
		{"a marked file that is not one of the agent's templates",
			map[string]string{"grpc_gen.go": fixtureSeam, "rest_gen.go": fixtureDials, "mine_gen.go": replace(fixtureDials, "func rest(", "func mine(")},
			"grpc.NewClient must be called with host.DialOptions"},
		{"WithNoProxy only in dead code",
			map[string]string{"rest_gen.go": fixtureDials, "grpc_gen.go": replace(fixtureSeam,
				"options := []grpc.DialOption{grpc.WithNoProxy()}\n",
				"options := []grpc.DialOption{}\n\tif false {\n\t\toptions = append(options, grpc.WithNoProxy())\n\t}\n")},
			"sets its options outside straight-line assignments"},
		{"WithNoProxy evaluated but not kept",
			map[string]string{"rest_gen.go": fixtureDials, "grpc_gen.go": replace(fixtureSeam,
				"options := []grpc.DialOption{grpc.WithNoProxy()}\n",
				"_ = grpc.WithNoProxy()\n\toptions := []grpc.DialOption{}\n")},
			"slice literal holding grpc.WithNoProxy()"},
		{"options replaced inside the seam",
			map[string]string{"rest_gen.go": fixtureDials, "grpc_gen.go": replace(fixtureSeam,
				"options = append(options, extra...)\n", "options = extra\n")},
			"replaces its options rather than appending to them"},
		{"plain insecure credentials last",
			map[string]string{"rest_gen.go": fixtureDials, "grpc_gen.go": replace(fixtureSeam,
				"grpc.WithTransportCredentials(loopbackTransport{insecure.NewCredentials()})", "grpc.WithTransportCredentials(insecure.NewCredentials())")},
			"does not append grpc.WithTransportCredentials(loopbackTransport{…}) last"},
		{"loopback credentials not last",
			map[string]string{"rest_gen.go": fixtureDials, "grpc_gen.go": replace(fixtureSeam,
				"options = append(options, extra...)\n\treturn append(options, grpc.WithTransportCredentials(loopbackTransport{insecure.NewCredentials()}))",
				"options = append(options, grpc.WithTransportCredentials(loopbackTransport{insecure.NewCredentials()}))\n\treturn append(options, extra...)")},
			"does not return append(options, grpc.WithTransportCredentials(loopbackTransport{…}))"},
		{"no gatewayDialOptions in the package",
			map[string]string{"rest_gen.go": fixtureDials}, "undefined: gatewayDialOptions"},
	} {
		t.Run(c.name, func(t *testing.T) {
			violations := judge(t, c.sources)
			if c.refusal == "" {
				if len(violations) != 0 {
					t.Fatalf("refused: %q", violations)
				}
				return
			}
			for _, violation := range violations {
				if strings.Contains(violation, c.refusal) {
					return
				}
			}
			t.Fatalf("want a refusal containing %q, got %q", c.refusal, violations)
		})
	}
}
