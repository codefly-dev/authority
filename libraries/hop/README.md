# Hop admission v1

A Work Context authenticates an identity and capability. It does not prove that
this call passed method policy. Every protected listener must use `Verifier`
with the **actual full procedure**, its own audience, a trusted hop public key,
and an explicitly supplied atomic replay store. Metadata supplied by the caller
must never choose the expected method, audience, public key, or replay namespace.

This is a breaking replacement of the shared `hop/PROOF` protocol. There is no
legacy acceptance path. Go, Python and TypeScript consume the same signed fixture.
`workcontext.AuthenticateToken`, Python `authenticate_token` and TS
`authenticateToken` are the lower-level identity readers, not admission checks:
they do not authorize a method or consume a nonce. There is exactly **one** of
them per language. The header-taking variants are gone with the shared proof
(review r164 R4): a reader that took a call's metadata read as though it
admitted the call, and after the proof's removal it accepted any token plus a
self-computed digest, so a caller fixing a build break by deleting the proof
argument would have lost admission silently. A caller holding metadata now
extracts the bound token with `stamp.Context` / `bound_token` / `boundToken`
first, which is two visible calls and neither of them an admission.

## Issuance and verification

After the authority's live `Check` admits the method, the hop writes its identity
metadata and signs a UTF-8 JSON array with Ed25519:

```
["codefly-hop-v1", method, audience, token_sha256_hex, nonce_hex, issued_unix, expires_unix]
```

`x-codefly-hop-proof` is unpadded canonical base64url(payload), a dot, and
unpadded canonical base64url(signature). The signature covers the original bytes,
not a parsed and re-encoded JSON object. Nonces are 32 cryptographically random
bytes; digests and nonces are lowercase hex. Unix timestamps are integral seconds.
The maximum admission lifetime is 30 seconds, capped by the Work Context expiry.
Duplicate proof, context or digest headers fail. The signing key is distinct
from the authority's Work Context key.

A two-second clock allowance (`stamp.Skew`, Python and TypeScript `SKEW`) is
applied identically in the three languages: an admission may be issued up to
that far ahead of the verifier's clock, and stays admissible until that far past
its expiry. Being issued further ahead than the allowance has its own reason,
`stamp_issued`, so a verifier running behind is not diagnosed as an expiry. The
signed span (`expires - issued`) is still capped at 30 seconds exactly, so the
allowance cannot mint a longer-lived admission.

For gRPC and Connect, `method` is `/package.Service/Procedure`, including the
leading slash. HTTP routes use `VERB /actual/path`, not the matched route template.
The hop uses its selected generated route to distinguish Connect from ordinary
HTTP. A verifier must use the same transport's observed procedure. The audience
is the checked module principal, never an upstream address.

A REST face a module **transcodes into its gRPC or Connect listener** cannot be
admitted behind the hop. The hop signs an http route as `VERB /path`, which is
what it decided and all a published http route tells it, while the listener the
request reaches observes the full procedure; the two can never agree. A module
cannot verify at both layers either, because the second would consume the
admission nonce again and refuse as `stamp_replayed`. Signing the procedure
instead would need the published route to carry its producer's
template-to-procedure mapping, and the `hop-routes` schema has no such field.
So `routing.Validate` refuses such a composition when the hop starts
(`routing.ErrTranscodedREST`) rather than refusing every REST call at runtime.
Publish the module's HTTP face as a service of its own, or reach the procedure
through Connect, which the hop signs correctly. A module serving HTTP natively,
with no gRPC or Connect face on the same service, is unaffected.

The verifier checks the signature, method, audience, token digest and admission
window before reading authority keys. It then verifies the Work Context signature,
issuer, audience, window and attenuation, and compares identity metadata with the
claims. Advisory policy refusals cannot be signed as admission; legacy warning mode
is refused at hop startup. It atomically reserves
`codefly-hop-v1:<public-key-hex>:<nonce-hex>` as soon as the admission checks,
before the keys are read and before the request body is read, and holds the
reservation until the handler has returned. Any replay-store error refuses the
call. Invalid stamps do not reserve nonces.

The nonce is consumed for **every** stamp, including stamps on idempotent Work
Contexts. A single-use Work Context is consumed once by the hop's existing live
Check; downstream consumes the admission nonce, not that Work Context a second
time. A failed/uncertain downstream delivery burns its admission. Retry through
the hop for a fresh decision, and obtain a fresh capability if it was single-use.
A stream is admitted once before handler entry; this preserves streaming without
buffering its body. Expiry bounds starting a call, not the lifetime of its stream.
This is admission replay protection, not transactional exactly-once effects.

The window is judged exactly once, at the instant the call starts, and not again
while the admitted call runs; the reservation is taken at that instant too.
Python's and TypeScript's verifiers run before the request is read. Go's
interceptors do not: grpc-go decodes a unary request fully before it invokes
the unary interceptor, and the Connect and REST faces buffer the message too.
Judging the window there refused admissions the authority had granted to slow
uploads; consuming the nonce there let a second delivery of one admission, held
back while its body arrived, find the nonce collected after its retention and
run the handler a second time. `Verifier.StatsHandler`, installed with
`grpc.StatsHandler`, records the arrival instant when gRPC tags the call and
starts the admission check and the reservation beside it, so neither waits for
the body; the interceptor awaits them and refuses with the reason. gRPC tags
every call this way on every transport it serves: its own listener, and the
Connect listener a go-grpc module declares, which hands each call to the same
server through `grpc.Server.ServeHTTP`, where a tap handle never runs (review
r3, M1). A server that installs no handler judges and reserves when the
interceptor runs, so nothing is admitted by its absence.

A single-use admission is consumed exactly once. Its reservation is retained at
least to expiry plus the allowance, and for as long as a call holding it runs: a
store with a completion operation (Go's `hop.ReservationStore`, Python's
`ReservationStore`, TypeScript's `reserve`/`finish`) keeps it until the handler
has returned AND its retention has passed, and refuses a reservation that only
reaches it after its retention (`stamp_window`), so a delayed delivery can never
revive a collected nonce. A store with only `consume` keeps a nonce to its
retention; a consumption that completes after that retention found an evicted
nonce, not a new one, and is refused on the window. Every later delivery of the
admission is refused by name: `stamp_replayed` while the reservation is held,
`stamp_window` after. `Verify`/`verify` end the in-flight hold before returning;
a caller that runs the call's work itself holds it with `Admit` (Go) or `admit`
(Python and TypeScript) until that work has ended.

## Replicas and durable replay storage

A stateless signature or request digest cannot reject an identical replay. A
process-local set also fails on another replica or after restart. Therefore the
libraries require a replay-store dependency and have **no implicit memory cache**.
Go reuses Core's `workcontext.ReplayStore`; Python exposes `ReplayStore.consume`
and `consume_async`; TS exposes `ReplayStore.consume`. Python and TS adapters
raise the exported `Replayed` error for duplicate nonces (Go uses Core
`ErrReplayed`); other failures report store unavailability without leaking backend errors. Consumption must be atomic
across every listener accepting the same signing key and audience, fail closed on outage, and
be durable before it returns. A backend may retain entries longer than expiry.
It must not evict an entry while any verifier can still accept it: account for
clock differences and prevent clock rollback. Synchronize deployment clocks.

`replaypg.New` is the adapter to prefer: a module's own Postgres, where
`INSERT ... ON CONFLICT (nonce) DO NOTHING` over a primary key is the atomic
reservation, conditioned on the retention not having passed by the database's
clock, and the database is already shared by every replica. Its `active` column
marks a running call, for diagnosis; `Collect` removes every reservation past its
retention by the database's clock, running or not, because `Reserve` refuses any
reservation past it on that clock, so a holder that crashed before finishing
leaves no permanent row. Codefly
delivers a store, so this needs nothing the platform cannot provide.
`replaypg.Migration` is the table, `Collect` removes reservations whose
retention has passed, and the console composes exactly this
(`modules/console/services/store`).

Outside a local run, `NewVerifier` now **refuses** a store that does not declare
itself the shared one (`hop.ErrReplayStoreNotShared`), rather than leaving the
rule to documentation; Python and TypeScript refuse it the same way
(`replay_store_not_shared`), reading a store's `shared` attribute. Core's
in-memory store and `hoptest.Replay` never declare it, so a laptop and a test
keep working while a deployment cannot quietly run per-replica.
`CODEFLY__ENVIRONMENT` decides which run this is: only the name exactly `local`
is a local run. An unset or empty environment, and any other name beginning
with `local`, is not.

`hop.FileReplayStore` implements this contract for a shared durable filesystem
with atomic exclusive creation and file/directory fsync. Nothing in the library
can tell whether the directory it is given is genuinely shared: an absolute path
to per-pod storage (`/tmp`, an `emptyDir`) looks exactly the same, and a
per-replica store lets a captured admission replay once per replica inside its
window. So `NewFileReplayStore` does not declare itself shared and is refused
outside a local run; an operator who knows the mount is one durable volume every
replica shares says so with `NewSharedFileReplayStore`, which is an assertion
about the deployment, not a check. All replicas for an audience must mount the
same directory; per-pod ephemeral storage is not suitable. Reservations
survive process restart and are never automatically removed. An incomplete
reservation is retained after a crash. Operators may collect complete expired
records only once every verifier's clock has passed the recorded expiry; never
collect incomplete records while their key remains trusted. Monitor volume space;
full or unavailable storage refuses admission. Isolate each audience's volume
from other workloads: an unrelated workload must not be able to remove or edit
reservations. Remote adapters likewise expose atomic reservation, not caller-
controlled deletion. Protect the signing seed from every consumer, including
through filesystem and process isolation in local deployments. Other hosts can supply their
existing durable replay implementation through the same Core contract. The
in-memory implementation used in tests is not a replicated deployment backend.

## Codefly delivery and migration

Generate the signing seed with Codefly, scoped to the hop service:

```
codefly config generate hop-signing SEED --service authority/hop
```

The hop reads `Secret("hop-signing", "SEED")`: a 32-byte hex seed, never the old
workspace `hop/PROOF`. Do not deliver the seed to a consumer or derive it from a
previously shared proof.

### Delivering the verification key

**The authority publishes it in `Keys`** (`codefly.dev/authority@0.3.2`):
`KeysResponse.admission_keys`, each with `purpose` `hop-admission`, beside the
Work Context keys in `keys` (purpose `work-context`). A verifier (Go, Python,
TypeScript) takes them from the `Keys` read it already makes, caches and
refreshes with a fail-closed staleness policy, so no consumer is configured with
a hop key and none can drift from the seed. They are a field of their own, so a
verifier that reads `keys` alone (an earlier release, or the JSON Web Key Set)
never trusts a hop key to sign a Work Context, and each verifier uses a key for
its own purpose only. The local authority derives the public half from the hop's
`hop-signing/SEED` in code (`modules/authority/services/local/code/work.go`,
`hopAdmissionKey`); the seed never leaves it. A run with no hop publishes none,
and an authority that publishes none leaves every admission refused as
`keys_unavailable`, with `ErrNoAdmissionKeys`/`NoAdmissionKeys` in the module's
key error saying why.

Every published admission key is trusted, so a rotation overlaps: the authority
publishes the new key beside the retiring one, then the hop signs with the new
one, then the retiring key is withdrawn. A stamp signed by no published key is
refused as `stamp_proof` and starts no key read, so a caller without an
admission cannot drive the authority's keys; a verifier learns a new key on the
next read an admitted call or readiness starts, within the five-minute key age.
Publish the new key at least that long before the hop signs with it.

`accounts` adopting this (publishing its hop's key from the hop's seed) is
follow-up work in the host; until it does, a cell's modules on this verifier
refuse every admission as `keys_unavailable`.

`hop-verification/REPLAY_DIRECTORY` is gone. Reservations live in the consumer's
own store (above), because Codefly delivers a store and does not deliver a
shared volume. No address, seed, key or store connection is hard-coded. Python
and Node hosts supply their shared durable replay adapter; Python's async
adapter must not block the event loop. Readiness continues to check authority
key availability; deployment health should also check its replay store.

Upgrade the hop and consumers together and remove delivery of `hop/PROOF`.
Downstream repositories must pin this breaking version and pass their actual
procedure into `Verify`/`verify`; no method-less overload remains.

### Adoption order

The hop stops writing the shared proof the moment this lands, so every module
behind a hop is refused until it adopts. The order is therefore fixed, and
nothing in this repository can sequence it:

1. `module-document-store` and `module-record-store` adopt the signed admission
   and release. Both are pinned by the authority playground
   (`playground/workspace.codefly.yaml`, documents 0.1.13 and records 0.5.0) and
   both still verify the shared proof, so calls through the hop to them are
   refused until those releases exist and the playground repins them.
2. `accounts` publishes the hop's admission key through `Keys`
   (`admission_keys`, above). Until it does, modules on a cell refuse every
   admission as `keys_unavailable`; nothing is configured by hand.
3. This repository's hop and console upgrade together, and `hop/PROOF`
   delivery is removed.

A composition that upgrades the hop before step 1 keeps serving the console,
whose verifier is in this repository and upgrades with it, and refuses
documents and records. The regression
suite covers the read-to-delete and zero-scope fabricated-stamp probes from the
two independent reviews, cross-audience use, repeated and concurrent admission,
expiry, duplicate headers, store failure, and cross-instance durable reservations.
