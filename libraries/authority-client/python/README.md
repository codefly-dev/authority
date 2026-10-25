# Authority Python client

The Codefly-generated authority bindings are accompanied by a small, non-verifying
Work Context reader. The reader verifies the incoming hop stamp itself before projecting the bound
context through the generated protobuf type:

```python
from authority_client.work_context import read_claims

claims = read_claims(request.headers, proof)
# Compare claims.audience to this module's delivered audience.
allowed = claims.allows(resource_kind, action, installed_resource_id)
```

The reader preserves Core's effective scopes: the final actor's grants, or the
owner's grants when there is no actor. An empty final grant stays empty. Each
scope is evaluated independently, so an action on one resource is not combined
with an unrelated resource from another scope. An omitted resource ID asks for
whole-kind authority; a resource-limited grant cannot satisfy it. A whole-kind
grant can satisfy a named-resource request. Actions are literal, following the
existing Core containment rule and Python SDK; `admin` implies no other action,
and raw token `*` actions are not expanded here.

`read_claims` raises `UnreadableContext` for a missing/forged stamp, a substituted token, an unreadable envelope, unknown wire
fields, noncanonical payload or absent audience. It does **not** replace Core's
structural validation, authenticate a signature, check time/revocation or consume
a replay nonce. In warning mode even a stamped context may have been refused by
the authority. The advisory is diagnostic and grants nothing. Keep the module's
installed-definition, audience, expiry, ownership and visibility checks. Resolve
resource IDs from the domain object; never use a kind-wide fallback when a bound
context is missing or unreadable.

This package directly reuses its generated `WorkContextV1` binding. Its canonical
wire and exact-resource checks follow the existing Python SDK's algorithms;
they are maintained here during migration, not imported from its private helpers.
SDK changes therefore require an explicit parity review until it adopts this seam.
It does not depend on a running SaaS service or introduce another verifier.

Pin consumers by repository commit, together with the hop package:
`authority-client @ git+https://github.com/codefly-dev/authority@<commit>#subdirectory=libraries/authority-client/python`.

Run the Python tests from this directory:

```sh
uv run --no-project --with pytest --with-editable . pytest tests
```

The shared `../testdata/claims.json` contains Core-minted tokens and effective
scope/query expectations. The gateway's `TestPythonClaimProjectionFixtures`
verifies them against Core with a fixed test clock; use its
`-update-python-claims` flag to regenerate. These public conformance tokens are
test data, never credentials for a running installation.
