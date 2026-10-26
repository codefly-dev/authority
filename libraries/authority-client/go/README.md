# Authority Go client

Codefly generates the RPC bindings in `gen/`. The `workcontext` package
authenticates the Work Context the hop forwarded and projects its claims:

```go
import claims "github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"

md, _ := metadata.FromIncomingContext(ctx)
c, err := claims.Authenticate(md, proof, audience, trust)
// err wraps claims.ErrUnauthenticated and names the reason.
allowed := c.Allows(resourceKind, action, exactResourceID)
```

A module does not call this directly: `hop.Verifier`
(`libraries/hop/go`) resolves `trust` from the authority's published keys and
runs it on every call. `Authenticate` is the generated-code-free check it rests
on, which the shared conformance suite also drives against both hosts.

It checks, in order: this run's hop proof, exactly one token and the stamp's
SHA-256 digest of it (`stamp.Context`); then Core's `Inspector`: canonical
decode, the issuer pin, the Ed25519 signature under the published key the token
names, the audience is this module, not-before and expiry within Core's skew,
and structure and attenuation. It consumes nothing and asks the authority
nothing: liveness is the authority's Check the hop made, bound to this call by
the digest. Proof and digest alone authenticate nothing; the signature does.

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
(`host/gate_test.go`, run by `go test ./...` here) parses every non-test Go file
in the repository and fails, naming the file and line, on `http.DefaultTransport`,
`http.DefaultClient`, `http.Get`/`Head`/`Post`/`PostForm`,
`httputil.NewSingleHostReverseProxy`, an `http.Client` or `httputil.ReverseProxy`
whose `Transport` is not `host.HTTPTransport()`, and a `grpc.NewClient`/`Dial`
without `host.DialOptions(...)`. Only the go-grpc agent's generated self-dials are
allowlisted, until its template carries `grpc.WithNoProxy()`; an entry must be
removed once its regenerated file does. Remote endpoints
use verified HTTPS/TLS unless the composition asserts
`internal-transport/mesh-protected=true` and the target is an in-cluster Service
DNS name. Plaintext loopback is accepted only in a local Codefly environment: the one named exactly `local` (the SDK's `IsLocal`); no name prefix is reserved for local runs.
Configured endpoints and SDK-resolved fallbacks use the same rule. Unreadable or
misspelled mesh assertions refuse before dialing; the shared host client owns
this check for edge and hop, without reviving the retired SDK verifier.
