# Authority Python client

The Codefly-generated authority bindings, and the module-side check of the Work
Context the hop forwarded:

```python
from authority_client.work_context import Trust, authenticate

trust = Trust.from_keys(stub.Keys(KeysRequest()))  # the authority interface's published keys
claims = authenticate(request.headers, proof, audience, trust)  # raises Unauthenticated, naming why
allowed = claims.allows(resource_kind, action, installed_resource_id)
```

A module normally uses `codefly_hop.Verifier` (`libraries/hop/python`), which
resolves and refreshes the trust and derives who the call is for.

`authenticate` checks the run's hop proof, exactly one token and the stamp's
digest of it; then, in Core's order: canonical decode, the issuer pin, the
Ed25519 signature under the published key the token names, the audience is this
module, and not-before and expiry within Core's 30-second skew. Core's structural
and attenuation rules constrain what the authority signs and are not reproduced.
It consumes nothing and asks the authority nothing: liveness is the hop's Check,
bound to this call by the digest.

The SaaS Python SDK's verifier was not reused: it refuses tokens Core accepts
(several scope rows of one resource kind, and Core's own grant fixture).

Effective scopes are the final actor's grants, or the owner's when there is no
actor. Each scope is evaluated independently; an omitted resource ID asks for the
whole kind; actions are literal.

Pin consumers by repository commit:
`authority-client @ git+https://github.com/codefly-dev/authority@<commit>#subdirectory=libraries/authority-client/python`.

```sh
uv run --no-project --with pytest --with-editable . pytest tests
```

The tests re-sign the bodies of `../testdata/claims.json` with a test key.
