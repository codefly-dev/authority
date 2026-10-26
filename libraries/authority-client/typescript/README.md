# Authority TypeScript client

Codefly generates the RPC bindings exported by `@codefly-dev/authority-client`.
The handwritten module side has a separate public export. A module builds one
`Verifier` at startup from the generated client of the authority interface it
depends on:

```ts
import { Unauthenticated, Verifier } from '@codefly-dev/authority-client/work-context';

const verifier = new Verifier(createClient(AuthorityService, transport), audience, publicKey, sharedReplayStore);
const id = await verifier.verify(requestHeaders, fullProcedure);   // throws Unauthenticated, naming why
id.tenant; id.scopes; id.claims.allows(resourceKind, action, exactResourceID);
```

It is the Go library's `hop.Verifier`: the signed method, audience, token digest and admission window first, then
the keys read through `Keys` (re-read on an unknown key at most every 10 s and
when older than 5 minutes, on a read of its own bounded by 5 s; stale after 15
minutes, when a call waits for the re-read as it does on an unknown key), then
`authenticateClaims`: Core's decode path (size, the contract's `buf.validate`
rules run by protovalidate, unknown fields, canonical encoding, lifetime), the
issuer, the key (never Core's public conformance key), the Ed25519 signature,
the audience, the window, and attenuation and grant shape. Who the call is for
comes from the claims; a stamp that disagrees is refused. The shared
`../testdata/vectors.json`, written by Go, holds every rule to Go's verdict. A
read's own failure is kept in `verifier.keysError` for logs, never sent to a
caller. **Readiness uses `verifier.ready()`**: true while trusted keys are held,
through failed re-reads inside the 15-minute window; false before the first read
or once they are stale. It also starts the same rate-limited, non-blocking
re-read a call would, so an unready replica recovers and an idle one never goes
stale. Never gate readiness on `keysError`. After authenticating the identity,
it consumes the nonce through the required durable replay store shared across
replicas. See the [admission protocol](../../hop/README.md).

`claims.scopes` contains frozen copies of the final actor's grants, or the owner's
when no actor exists. Each scope is evaluated independently; an omitted resource
ID asks for the whole kind; no wildcard or admin implication occurs.

Run `npm ci --ignore-scripts` and `npm test`. Tests import the built public package
exports, including the generated schema. No running SaaS, service or provider is
needed. Test signatures and fixed-clock fixtures are not live credentials.

The generator owns `src/`, including its index. The helper lives at the package
root; preserved `package.json`/`tsconfig.json` scaffolds export and compile it
alongside generated bindings. Never edit the generated index to add this helper.


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
`public_key` and `replay` when constructing the Python/TypeScript `Verifier`.
They still authenticate bare tokens against published Keys. They admit no
stamped call: without the hop's public key and a shared replay store there is
nothing to check an admission against, so `verify` refuses with
`configuration`. A process that receives hop calls supplies both.
