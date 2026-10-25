# hop

The proxy in front of a module. It asks the authority through the generated
Check client, stamps the returned identity, and forwards the real call. Both
gRPC and HTTP/Connect use `pkg/business/decide` and `pkg/infra/proxy`.

The composition selects `hop/ENFORCEMENT` through SDK-delivered configuration:
`enforce` (the default) returns authority refusals; `warn` logs them and allows
permissive developer forwarding. For method-policy failures, warn mode requests
an advisory Check and uses the authority's returned context, preserving its
owner, tenant, operation binding, task and effective scopes. The refusal travels
in the stamp's advisory field and is logged once.

Missing, malformed, expired, revoked or misaddressed Work Contexts remain
refused in both modes. The hop also refuses when it cannot reach the authority.
Warning mode uses the authority's verified advisory context; it creates no
synthetic identity or developer session. The verified audience selects the
configured upstream, and a missing route remains an error.

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
