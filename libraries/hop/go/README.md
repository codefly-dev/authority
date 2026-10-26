# Go hop library

## The module side: `Verifier`

Every module behind the hop authenticates each call with one `Verifier`, built
once at startup from the authority interface it already depends on:

```go
import (
	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/host"
	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/replaypg"
)

// The reservations: this module's own store. replaypg.Migration is its table.
// NewVerifier refuses a store that is not the shared one outside a local run.
pool, err := pgxpool.New(ctx, connection) // Service("store").Secret("postgres", "read-write-connection")
replay, err := replaypg.New(pool)
conn, _, err := host.Dial(ctx) // the local authority on a laptop, the host on a cell
audience, err := hop.Audience() // the module the composition started this process as (CODEFLY__MODULE)
// The hop's admission keys come with the authority's Keys: nothing is configured.
verifier, err := hop.NewVerifier(ctx, authorityv1.NewAuthorityServiceClient(conn), audience, replay)
config.GRPCServerOptions = append(config.GRPCServerOptions,
	// Judges the admission window and reserves its single-use nonce when each
	// call reaches the server, on the gRPC and the Connect listener alike, not
	// after a large request body has decoded.
	grpc.StatsHandler(verifier.StatsHandler()),
	grpc.ChainUnaryInterceptor(verifier.UnaryServerInterceptor()),
	grpc.ChainStreamInterceptor(verifier.StreamServerInterceptor()))
// in a handler: id, _ := hop.FromContext(ctx); id.Tenant, id.Has(kind, action), id.Claims.Allows(kind, action, resourceID)
// an HTTP module, once the headers arrive and before reading the body:
//	id, done, err := verifier.Admit(ctx, metadataFromHeaders, observedFullProcedure); defer done()
```

`Verify` authenticates the signed method, audience, token digest and 30-second
admission window (with a two-second clock allowance, `stamp.Skew`, judged at the
instant the call arrived), authenticates the Work Context, compares identity
metadata, and atomically reserves the call nonce in the shared replay store
before the keys are read. `Admit` does the same and holds the reservation until
the caller's work has ended, as the interceptors do for a handler. It
refuses replays across replicas without re-spending the Work Context's single
use. A process that receives no hop calls authenticates a bare Work Context with
`NewTokenVerifier` and `VerifyToken` instead, which establishes identity and no
admission.
See the [wire protocol and migration contract](../README.md).

The keys come from the interface's `Keys`, through the generated client: never
typed in, never mounted. A read runs on its own, detached from every call and
bounded by 5 s, one at a time: no caller can cancel it, fail it or delay the
next one. Keys are re-read when a token names a key the verifier does not hold
(at most every 10 s; that call waits for the read while it lasts) and when older
than 5 minutes (the held keys serve meanwhile); keys that cannot be re-read are
trusted for 15 minutes at most, and a call on keys older than that waits for the
re-read as a call on an unknown key does, refused if the read fails.
`NewVerifier` never fails on an authority that is not serving yet: calls are
refused with "the authority's published keys are unavailable" until it is, and
`KeysError()` gives the read's own failure to the module's logs, never to a
caller. **Readiness uses `Ready()`**: true while trusted keys are held, through
failed re-reads inside the 15-minute window; false before the first read or once
the keys are stale. It also starts the same rate-limited, non-blocking re-read a
call would, so an unready replica (which gets no calls) recovers once the
authority serves keys, and an idle one never goes stale. Never gate readiness on
`KeysError()`: a brief authority outage would take every replica out of rotation
while its keys are still trusted.

`hoptest` is a real authority for a module's own tests: `hoptest.New(t)` signs
with a fresh key and answers `Keys`; `Issue` mints a Work Context and
`hoptest.Forward` stamps it exactly as the hop does.

## Calling out: `Outbound`

`Outbound.ForModule(ctx, organization, binding)` names the organization of the
work item. The local authority accepts an empty organization only when exactly
one organization has an active installation of the calling module. Zero or
multiple installing organizations are refused with a reason telling the caller
to name the organization of the work item. There is no delivered tenant pin.
The helper forwards the request and preserves the authority's refusal.

`IssueForParent` and `IssueForModule` are `ForParent`'s and `ForModule`'s issue
returned rather than carried, as an `Issued`: the token, when it expires, and
the Work Context the authority says it is for. A caller that holds an issued
context across calls (renewing it before it expires) or reads whom it was issued
for uses them; `Issued.Carry` puts it on a call's outgoing metadata exactly as
the `For*` methods do. `Scopes` narrows any issue to what is asked, within the
binding's ceiling. `FileCredential(path)` reads the workload credential from a
path resolved once, on every call; `RunCredential` is it at the path the run
names. A refusal keeps the authority's gRPC status in its chain (`errors.As`)
and names the binding.

Version note (2026-10-25): `Issued`, `IssueForParent`, `IssueForModule`,
`Scopes` and `FileCredential` are additive; every existing signature is
unchanged. Consumers pin this library by commit until it is tagged.

Validate this library with `go test -race ./...` and `go vet ./...` from this
directory. Issuer unit tests in the local authority exercise
the actual installation-based tenant resolution.

The Go dependency pins the matching signed-admission authority-client;
standalone library tests need no workspace replacement.
`../testdata/stamped.json` is a genuinely signed call as the hop stamps it; the
Python verifier (`codefly_hop`, shipped in `libraries/authority-client/python`) reads it back. Regenerate with `go test -run Fixture -update-fixture`.


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
