# Authority Python client

The Codefly-generated authority bindings, and the module-side check of the Work
Context the hop forwarded:

```python
from authority_client.work_context import Trust, authenticate

trust = Trust.from_keys(stub.Keys(KeysRequest()))  # the authority interface's published keys
claims = authenticate(request.headers, proof, audience, trust)  # raises Unauthenticated, naming why
allowed = claims.allows(resource_kind, action, installed_resource_id)
```

A module normally uses `codefly_hop.Verifier`, shipped in this same
distribution, which resolves and refreshes the trust and derives who the call is
for:

```python
from authority_client._gen.host.authority.v1.authority_pb2_grpc import AuthorityServiceStub
from codefly_hop import Unauthenticated, Verifier

verifier = Verifier(AuthorityServiceStub(channel), audience=os.environ["CODEFLY__MODULE"], proof=proof)  # once
identity = verifier.verify(request.headers)              # a sync handler
identity = await verifier.verify_async(request.headers)  # an asyncio handler: a key wait runs off the loop
identity.tenant, identity.has(kind, action), identity.claims.allows(kind, action, resource_id)
```

The verifier checks the stamp first, then reads the published keys through `Keys`
on a thread of its own with a 5 s timeout, one read at a time; it re-reads them
on an unknown key (at most every 10 s) and when older than 5 minutes; keys that
cannot be re-read are trusted for 15 minutes at most. It never fails to
construct on an authority that is not serving yet, and refuses calls with a
fixed reason until it is; `verifier.keys_error` holds the read's failure for
logs. **Readiness uses `verifier.ready()`**: true while trusted keys are held,
through failed re-reads inside the 15-minute window; false before the first read
or once they are stale. Never gate readiness on `keys_error`. `codefly_hop` reads the hop's signed fixture (`../../hop/testdata/stamped.json`)
as the Go library writes it.

`codefly_hop` and `authority_client` are one distribution so that one pinned
commit installs both, and no dependency is ever resolved by name from a public
index.

`authenticate` checks the run's hop proof, exactly one token and the stamp's
digest of it; then Core's rules in Core's order: the decode path (size, the
contract's `buf.validate` schema rules run by protovalidate against the packaged
contract descriptor, unknown fields, canonical encoding, a lifetime of at most a
day), the issuer pin, the key (never Core's public conformance key), the Ed25519
signature, the audience is this module, not-before and expiry within Core's
30-second skew, and the chain's attenuation and grant shape. Go writes
`../testdata/vectors.json` with its verdict on each case; this reader's tests
must reach the same verdict, for the same reason. It consumes nothing and asks
the authority nothing: liveness is the hop's Check, bound by the digest.

`authority_client/contract.binpb` links to the published `../contract`
descriptor because the generated Python module was emitted without the
`buf.validate` options; it is packaged with the wheel.

The SaaS Python SDK's verifier was not reused: it refuses tokens Core accepts
(several scope rows of one resource kind, and Core's own grant fixture).

Effective scopes are the final actor's grants, or the owner's when there is no
actor. Each scope is evaluated independently; an omitted resource ID asks for the
whole kind; actions are literal.

Pin consumers by repository commit (pip and uv alike):
`authority-client @ git+https://github.com/codefly-dev/authority@<commit>#subdirectory=libraries/authority-client/python`.

```sh
uv run --no-project --with pytest --with-editable . pytest tests
```

The tests re-sign the bodies of `../testdata/claims.json` with a test key.

## Dialling the host

`authority_client.host` is the Go library's `host.Target` / `host.Endpoint` rule
(`../go/host`), case for case (`tests/test_host.py` mirrors `host_test.go`):
`https://` is verified TLS; plaintext only to loopback in a local-kind run, or to an
in-cluster Service address under `internal-transport/mesh-protected=true`; anything
else (control characters, a zone id, port 0 included) is refused by name, never
echoing the value. Where its two inputs come from:

- **local**: omit it. `host.local_environment()` reads `CODEFLY__ENVIRONMENT` and
  applies Core's rule (`resources.Environment.Local`, as Go's `host.Local()` does):
  `local`, `local-authority` and every other `local-*` environment admit loopback;
  hosted environments never do. (The SDKs' `is_local` / `IsLocal` compare the name to
  `local` exactly; do not pass them.)
- **mesh**: the raw workspace value `internal-transport/mesh-protected`, from the
  Codefly Python SDK: `codefly.configuration(name="internal-transport", key="mesh-protected")`,
  or `None` when the composition sets none. Only the literal `true` asserts it.

```python
from authority_client import host

channel = host.dial(endpoint, mesh=mesh_protected_value)
stub = AuthorityServiceStub(channel)  # Keys for codefly_hop.Verifier, Issue
```

`options` may tune the channel (keepalive, message sizes) but never how the TLS
peer is verified: `grpc.ssl_target_name_override`, `grpc.default_authority` and
any other `ssl`/`tls` option are refused.
