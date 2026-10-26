# hop

The proxy in front of a module. It asks the authority through the generated
Check client, stamps the returned identity, and forwards the real call. Both
gRPC and HTTP/Connect use `pkg/business/decide` and `pkg/infra/proxy`.

Codefly derives `hop-routes/ROUTES` from the published API catalogs of the
principals in `hop/MODULES`. The hop declares this group; it is required and
must not be authored by a composition. Codefly resolves each exact endpoint
with the hop's visibility and native or deployed addressing. A missing, empty
or invalid carrier refuses startup. This hop revision requires the matching
CLI route projection: producer revision **eee37c1117** (`hop-routes/v1`), being
shipped through [CLI #1158](https://github.com/codefly-dev/cli/pull/1158), or a
successor containing it. There is no released-version claim yet. **Merge order:
CLI #1158 must merge with or before authority #1; do not release this hop against
an older CLI.** Missing or invalid route configuration names this requirement.
Old `UPSTREAM_*` values cannot supply a fallback.

The generated snapshot retains audience, service, endpoint, transport, package,
version, digest and served procedures or HTTP routes. One module may expose
several services. A request selects its destination, then makes one Authority Check with the
actual HTTP verb and path. The authority selects the policy from the delivered
manifest, including stricter literal routes and ambiguous-route refusals.
Connect uses a published procedure. A dotted URL alone never selects
Connect or borrows a gRPC policy. Unknown or ambiguous routes refuse. The request body, path, query and streaming protocol stay intact.

Routes are immutable for one Codefly run. Ordinary source reload retains the
accepted endpoint addresses. A changed published route set or address requires
a full run restart. A changed catalog refuses before stopping services or
admitting refreshed declarations. An address change first reported by an agent
at initialization refuses publication and preserves the accepted mapping; the
agent may already have stopped or initialized its process. This does not promise
live route-set adoption or restore that process. Failed targets
remain unavailable; a sibling service is never their fallback.

The hop always enforces the authority's method decision. Legacy
`hop/ENFORCEMENT=warn` and unknown modes refuse startup in every environment.
Advisory refusals never produce signed admissions. See the
[signed admission and replica storage contract](../../../../libraries/hop/README.md)
for Codefly key delivery, the exact procedure binding, and durable nonce consumption.

Validation: run `go vet ./...` and `go test -race ./...` in this service's
`code/`, the local authority's `code/`, and `libraries/hop/go`. The shared fixture
is also read by the Python and TypeScript regression suites.

The HTTP face always listens on its declared endpoint. A missing generated
`hop-routes/ROUTES` view is refused before starting either face. Every admitted
call names a published listener; there are no module-wide fallback routes.

All hop-to-module endpoints use the same transport gate as the authority dialer:
verified TLS, local loopback, or the composition's mesh-protected assertion plus
an in-cluster Service DNS name. HTTP origins cannot rewrite the checked path.
The mesh assertion remains a composition trust assumption; this client does not
prove mesh enrollment or Kubernetes Service type.
