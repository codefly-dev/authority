# Authority Go client

Codefly generates the RPC bindings in `gen/`. The `workcontext` package
authenticates the Work Context the hop forwarded and projects its claims:

```go
import claims "github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"

md, _ := metadata.FromIncomingContext(ctx)
c, err := claims.Authenticate(md, audience, trust)
// err wraps claims.ErrUnauthenticated and names the reason.
allowed := c.Allows(resourceKind, action, exactResourceID)
```

A module does not call this directly: `hop.Verifier`
(`libraries/hop/go`) resolves `trust` from the authority's published keys and
runs it on every call. `Authenticate` is the generated-code-free check it rests
on, which the shared conformance suite also drives against both hosts.

It checks one digest-bound token with Core's Inspector: canonical decode,
issuer, signature, audience, window and attenuation. This authenticates identity
only. Method authorization and replay protection require `hop.Verifier` and the
[signed admission protocol](../../hop/README.md). A token digest alone does not
prove that the hop made a live Check.

`Scopes()` returns deep copies of the final actor's grants, or the owner's grants
when there is no actor. An empty final actor grants nothing. `Allows` evaluates
each candidate independently. An empty requested resource ID asks for the entire
kind; a restricted grant cannot satisfy it. Kind-wide grants cover named IDs.
Actions are literal. `Context()` is a deep copy of the authenticated claims.

`../testdata/vectors.json` is written by `workcontext/vectors_test.go`
(`go test ./workcontext -args -update-vectors`): tokens and Go's verdict on
each, which the Python and TypeScript readers must reach too.

From this directory, run `GOWORK=off go test -race ./...` and `go vet ./...`.
The tests re-sign the bodies of `../testdata/claims.json` with a test key of
their own (Core refuses its public fixture key outside its kit).

Handwritten code lives outside `gen/`, the directory Codefly replaces. The root
module scaffold is preserved by `codefly generate client`.

The shared `host.Dial` resolves the authority for edge and hop. Every dial
never follows a proxy from the environment (`HTTPS_PROXY`, `HTTP_PROXY`), which
would see the workload credential and could swap the published keys on a
plaintext mesh hop: `host.DialOptions(transport)` is the transport plus
`grpc.WithNoProxy()`, and a caller dialling an address `Target` or `Endpoint`
admitted uses it too (the hop does for its upstreams). `host.HTTPTransport()` is
the same for HTTP: Go's default transport with no environment proxy, the one
transport every request carrying a Work Context, a stamp or the run's proof goes
over (the hop's HTTP face and the edge's reverse proxy both use it). It is an
`http.RoundTripper` that cannot be unwrapped into the shared `*http.Transport`, so
no caller can turn proxies back on for everyone. **The no-proxy gate**
(`tools/noproxygate`, run by its `go test` and by CI on every pull request)
type-checks every production package directory in every module, including
`_`, `.`, and `testdata` directories. It refuses production build constraints
(active or inactive), platform filenames, source symlinks, and load/type errors. It checks
specific source forms by resolved object identity: banned default HTTP and
process APIs; gRPC and `Register…HandlerFromEndpoint` calls without the seam;
transport-overriding options appended after the seam; value storage and
conversions in both directions, including type parameters, for HTTP clients,
proxies and transports; and unsafe transport-field writes. Opaque appended
option slices and constructors are refused too.

Every loaded file is judged. `unsafe`, `import "C"` and `//go:linkname` are
refused in hand-written code. Limited generated exceptions require a known
marker, the corresponding output filename, and the reviewed SHA-256 digest at
that path in `tools/noproxygate/generated.json`. This includes the go-grpc
agent's own marker. A copied marker never grants an exemption. After
`codefly generate`, review its outputs and update the manifest; the manifest
is trusted review metadata, not independent proof of generator execution.

Generated adapters pass the package's generated `gatewayDialOptions` directly
or through a local variable defined once whose uses cannot alias or mutate its
backing array. The seam appends the generated loopback credentials last;
`WithNoProxy` is not a requirement of this credential check. Generated
same-package forwarders preserve the options unchanged. For generated plugin
interface dispatch, the gate checks every concrete implementation in the module,
including unregistered types and promoted methods. REST plugins forward those
options unchanged; gRPC-only plugins may have a literal no-op REST method.
Dial and endpoint-registration functions cannot be saved as function values.
There is no function-name exemption for hand-written wrappers.

Blind spots: `_test.go` files, raw sockets, reflection, unlisted process APIs,
third-party clients, behavior in callbacks passed to allowed gRPC options,
and dependency internals. The gate is not whole-program data-flow analysis:
pointer replacement, aliased slice mutation and interface-hidden values are
not tracked. Passing means the refused source forms are absent, not that all
possible proxy or credential bypasses have been proved impossible. Remote endpoints
use verified HTTPS/TLS unless the composition asserts
`internal-transport/mesh-protected=true` and the target is an in-cluster Service
DNS name. Plaintext loopback is accepted only in a local Codefly environment: the one named exactly `local` (the SDK's `IsLocal`); no name prefix is reserved for local runs.
Configured endpoints and SDK-resolved fallbacks use the same rule. Unreadable or
misspelled mesh assertions refuse before dialing; the shared host client owns
this check for edge and hop, without reviving the retired SDK verifier.
