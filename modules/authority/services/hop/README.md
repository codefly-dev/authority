# hop

The proxy in front of a module. It asks the authority through the generated
Check client, stamps the returned identity, and forwards the real call. Both
gRPC and HTTP/Connect use `pkg/business/decide` and `pkg/infra/proxy`.

Codefly derives `hop-routes/ROUTES` from the published API catalogs of the
principals in `hop/MODULES`. The hop declares this group; it is required and
must not be authored by a composition. Codefly resolves each exact endpoint
with the hop's visibility and native or deployed addressing. A missing, empty
or invalid carrier refuses startup. This hop revision requires the matching
CLI route projection; old `UPSTREAM_*` values cannot supply a fallback.

The generated snapshot retains audience, service, endpoint, transport, package,
version, digest and served procedures or HTTP routes. One module may expose
several services. A request selects its destination and declared policy method
together, then makes one Authority Check. HTTP templates use their declared
policy; Connect uses a published procedure. A dotted URL alone never selects
Connect or borrows a gRPC policy. Unknown or ambiguous routes refuse, including
in warn mode. The request body, path, query and streaming protocol stay intact.

Routes are immutable for one Codefly run. Ordinary source reload retains the
accepted endpoint addresses. A changed published route set or address requires
a full run restart. A changed catalog refuses before stopping services or
admitting refreshed declarations. An address change first reported by an agent
at initialization refuses publication and preserves the accepted mapping; the
agent may already have stopped or initialized its process. This does not promise
live route-set adoption or restore that process. Failed targets
remain unavailable; a sibling service is never their fallback.

The composition selects `hop/ENFORCEMENT` through SDK-delivered configuration:
`enforce` (the default) returns authority refusals; `warn` logs them and allows
permissive developer forwarding. For method-policy failures, warn mode requests
an advisory Check and uses the authority's returned context, preserving its
owner, tenant, operation binding, task and effective scopes. The refusal travels
in the stamp's advisory field and is logged once.

Missing, malformed, expired, revoked or misaddressed Work Contexts remain
refused in both modes. The hop also refuses when it cannot reach the authority.
Warning mode uses the authority's verified advisory context; it creates no
synthetic identity or developer session. The checked audience and selected
published route identify the upstream.

Warning mode relaxes method-policy admission only. Issuance and downstream
resource, visibility and ownership decisions still apply. A successful hop unit
test alone does not prove a complete solution journey or enforce-mode qualification.

Validation: run `go test -race ./...` in this service's `code/`, the local authority's
`code/`, and `libraries/hop/go`. Local authority's generated-client advisory test checks
the real issuer; proxy's routing regression checks that a Records request never
reaches Documents when its destination is unresolved.

`ENFORCEMENT=warn` is accepted only when the SDK reports a local environment.
Unknown enforcement modes and warn in other environments are refused by name.
The shared authority client dialer requires TLS for every non-loopback host.
