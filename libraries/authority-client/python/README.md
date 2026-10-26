# Authority Python client

The Codefly-generated authority bindings, and the module-side check of the Work
Context the hop forwarded:

```python
from authority_client.work_context import Trust, authenticate

trust = Trust.from_keys(stub.Keys(KeysRequest()))  # the authority interface's published keys
claims = authenticate(request.headers, audience, trust)  # raises Unauthenticated, naming why
allowed = claims.allows(resource_kind, action, installed_resource_id)
```

A module normally uses `codefly_hop.Verifier`, shipped in this same
distribution, which resolves and refreshes the trust and derives who the call is
for:

```python
from authority_client._gen.host.authority.v1.authority_pb2_grpc import AuthorityServiceStub
from codefly_hop import Unauthenticated, Verifier

verifier = Verifier(AuthorityServiceStub(channel), audience=os.environ["CODEFLY__MODULE"], replay=shared_replay_store)  # once; the hop's key comes from Keys
identity = verifier.verify(request.headers, full_procedure)              # a sync handler
identity = await verifier.verify_async(request.headers, full_procedure)  # an asyncio handler: a key wait runs off the loop
with verifier.admit(request.headers, full_procedure) as identity: ...    # holds the single-use reservation while the handler runs
async with verifier.admit_async(request.headers, full_procedure) as identity: ...
identity.tenant, identity.has(kind, action), identity.claims.allows(kind, action, resource_id)
```

The verifier requires the [signed admission protocol](../../hop/README.md),
including an atomic durable replay store shared across replicas, and refuses at
construction, outside the run named exactly `local`, a store whose `shared` is
not true (`replay_store_not_shared`). It checks the stamp first and reserves its
single-use nonce, then reads the published keys through `Keys`
on a thread of its own with a 5 s timeout, one read at a time; it re-reads them
on an unknown key (at most every 10 s) and when older than 5 minutes; keys that
cannot be re-read are trusted for 15 minutes at most, and a call on keys older than
that waits for the re-read as a call on an unknown key does. It never fails to
construct on an authority that is not serving yet, and refuses calls with a
fixed reason until it is; `verifier.keys_error` holds the read's failure for
logs. **Readiness uses `verifier.ready()`**: true while trusted keys are held,
through failed re-reads inside the 15-minute window; false before the first read
or once they are stale. It also starts the same rate-limited, non-blocking re-read a
call would, so an unready replica recovers and an idle one never goes stale. Never
gate readiness on `keys_error`. `codefly_hop` reads the hop's signed fixture (`../../hop/testdata/stamped.json`)
as the Go library writes it.

`codefly_hop` and `authority_client` are one distribution so that one pinned
commit installs both, and no dependency is ever resolved by name from a public
index.

`authenticate_token` is the one identity reader, not admission. It checks one
token (a caller holding a call's headers extracts the bound token with
`bound_token` first); then Core's rules in Core's order: the decode path (size, the
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
`https://` is verified TLS; plaintext only to loopback in the `local` environment, or to an
in-cluster Service address under `internal-transport/mesh-protected=true`; anything
else (control characters, a zone id, port 0 included) is refused by name, never
echoing the value. Where its two inputs come from:

- **local**: whether the run is in the environment named exactly `local`:
  `os.environ.get("CODEFLY__ENVIRONMENT") == "local"`. This is stricter than Go's
  `codefly.IsLocal()`, which compares case-insensitively (it also accepts `LOCAL`);
  stricter is the safer side for admitting loopback.
  No name prefix is reserved for local runs; a playground's `local-authority` is a
  configuration profile of `local`. Do not use the Python SDK's `is_local`, which
  reads the wrong variable (codefly-dev/sdk-python#8).
- **mesh**: the raw workspace value `internal-transport/mesh-protected`, from the
  Codefly Python SDK: `codefly.configuration(name="internal-transport", key="mesh-protected")`,
  or `None` when the composition sets none. Only the literal `true` asserts it.

```python
from authority_client import host

channel = host.dial(endpoint, local=os.environ.get("CODEFLY__ENVIRONMENT") == "local", mesh=mesh_protected_value)
stub = AuthorityServiceStub(channel)  # Keys for codefly_hop.Verifier, Issue
```

`options` is an allowlist (`host.ALLOWED_OPTIONS`: keepalive, message sizes,
reconnect backoff, user agent). Anything else is refused: a proxy, a TLS or
authority override or a service config would route or verify the channel
otherwise. `dial` itself turns off both of grpc core's environment proxies: the
name-based one (`https_proxy` / `http_proxy` / `grpc_proxy`, with
`grpc.enable_http_proxy=0`) and the address-based one (`GRPC_ADDRESS_HTTP_PROXY`,
with an empty `grpc.address_http_proxy_enabled_addresses`), as Go's
`host.DialOptions` (`grpc.WithNoProxy()`) does. A caller can set neither.


Bare tokens returned by Issue can be authenticated without manufacturing a hop
stamp: Go `Verifier.VerifyToken(ctx, token)`, Python `verify_token(token)` /
`verify_token_async(token)`, TypeScript `verifyToken(token)`. These reuse the
stamped path's published-key cache, including waiting for stale-key refresh and
refusing failed refreshes. They check signature, issuer, audience, validity and
claim structure. They do not prove hop admission, live revocation, method policy,
or single-use consumption; retain those checks where required.

Verifier failures expose fixed caller-safe reason codes and text. Go callers use
`errors.As(err, &reason)` with `hop.Reason` (`Code()` / `Text()`); Python and
TypeScript `Unauthenticated` expose `code` and `text`, with exported `Reason`
values. These errors never retain underlying key-source errors or claim values.
`KeysError` / `keys_error` / `keysError` is a separate internal diagnostic, not a
caller response. Unknown future Core diagnostic categories remain refused.

Admission refusals carry their own codes, in the same scheme: `stamp_proof` (no
admission signed for this call), `stamp_token`, `stamp_digest`, `stamp_method`,
`stamp_audience`, `stamp_window`, `stamp_advisory`, `stamp_replayed` and
`stamp_store`. Each names no proof, token, digest, nonce or claim.

Processes that receive only Issue responses use Go `NewTokenVerifier`, or omit
`replay` when constructing the Python/TypeScript `Verifier`. They still
authenticate bare tokens against published Keys. They admit no stamped call:
without a shared replay store an admission cannot be consumed once, so `verify`
refuses with `configuration`. A process that receives hop calls supplies one;
the hop's admission keys come from the same Keys read, never from configuration.
