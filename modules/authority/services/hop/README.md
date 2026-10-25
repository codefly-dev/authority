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

For other authority failures, the existing developer fallback uses the readable
token's identity, or `developer`/`local` if none is readable. A usable token
audience selects the upstream. With no audience, only a sole configured upstream
can be selected; a multi-module hop reports a routing diagnostic rather than
sending the request to an unrelated module. No module response is fabricated.

Warning mode relaxes hop admission. Issuance and downstream module checks still
run: modules that require a live Work Context, scope or resource grant can still
refuse the forwarded call. The synthetic fallback is not a complete developer
session or a replacement for an installation. Upstream connection and application
failures remain visible. Full solution unblocking needs those owner paths to be
exercised; a successful hop unit test alone does not prove it.

Validation: run `go test -race ./...` in this service's `code/`, the gateway's
`code/`, and `libraries/hop/go`. Gateway's generated-client advisory test checks
the real issuer; proxy's routing regression checks that a Records request never
reaches Documents when its destination is unresolved.
