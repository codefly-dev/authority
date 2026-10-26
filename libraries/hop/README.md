# Hop admission v1

A Work Context authenticates an identity and capability. It does not prove that
this call passed method policy. Every protected listener must use `Verifier`
with the **actual full procedure**, its own audience, a trusted hop public key,
and an explicitly supplied atomic replay store. Metadata supplied by the caller
must never choose the expected method, audience, public key, or replay namespace.

This is a breaking replacement of the shared `hop/PROOF` protocol. There is no
legacy acceptance path. Go, Python and TypeScript consume the same signed fixture.
`workcontext.Authenticate`, Python `authenticate`, and TS `authenticateClaims`
are lower-level identity readers, not admission checks. Their shared-proof
argument has been deleted; they do not authorize a method or consume a nonce.

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
No acceptance skew is added. Duplicate proof, context or digest headers fail.
The signing key is distinct from the authority's Work Context key.

For gRPC and Connect, `method` is `/package.Service/Procedure`, including the
leading slash. HTTP routes use `VERB /actual/path`, not the matched route template.
The hop uses its selected generated route to distinguish Connect from ordinary
HTTP. A verifier must use the same transport's observed procedure. A translated
REST gateway uses the full procedure observed by its gRPC listener. The audience
is the checked module principal, never an upstream address.

The verifier checks the signature, method, audience, token digest and admission
window before reading authority keys. It then verifies the Work Context signature,
issuer, audience, window and attenuation, and compares identity metadata with the
claims. Advisory policy refusals cannot be signed as admission; legacy warning mode
is refused at hop startup. Finally it atomically
consumes `codefly-hop-v1:<public-key-hex>:<nonce-hex>` before entering the handler.
Any replay-store error refuses the call. Invalid stamps do not reserve nonces.

The nonce is consumed for **every** stamp, including stamps on idempotent Work
Contexts. A single-use Work Context is consumed once by the hop's existing live
Check; downstream consumes the admission nonce, not that Work Context a second
time. A failed/uncertain downstream delivery burns its admission. Retry through
the hop for a fresh decision, and obtain a fresh capability if it was single-use.
A stream is admitted once before handler entry; this preserves streaming without
buffering its body. Expiry bounds starting a call, not the lifetime of its stream.
This is admission replay protection, not transactional exactly-once effects.

## Replicas and durable replay storage

A stateless signature or request digest cannot reject an identical replay. A
process-local set also fails on another replica or after restart. Therefore the
libraries require a replay-store dependency and have **no implicit memory cache**.
Go reuses Core's `workcontext.ReplayStore`; Python exposes `ReplayStore.consume`
and `consume_async`; TS exposes `ReplayStore.consume`. Python and TS adapters
raise the exported `Replayed` error for duplicate nonces (Go uses Core
`ErrReplayed`); other failures report store unavailability without leaking backend errors. Consumption must be atomic
across every process accepting the same signing key, fail closed on outage, and
be durable before it returns. A backend may retain entries longer than expiry.
It must not evict an entry while any verifier can still accept it: account for
clock differences and prevent clock rollback. Synchronize deployment clocks.

`hop.FileReplayStore` implements this contract for a shared durable filesystem
with atomic exclusive creation and file/directory fsync. All replicas must mount
the same directory; per-pod ephemeral storage is not suitable. Reservations
survive process restart and are never automatically removed. An incomplete
reservation is retained after a crash. Operators may collect complete expired
records only once every verifier's clock has passed the recorded expiry; never
collect incomplete records while their key remains trusted. Monitor volume space;
full or unavailable storage refuses admission. Other hosts can supply their
existing durable replay implementation through the same Core contract. The
in-memory implementation used in tests is not a replicated deployment backend.

## Codefly delivery and migration

Generate the signing seed with Codefly, scoped to the hop service:

```
codefly config generate hop-signing SEED --service authority/hop
```

The hop reads `Secret("hop-signing", "SEED")`: a 32-byte hex seed, never the old
workspace `hop/PROOF`. Delivery derives its public half with
`stamp.NewSigner(seed).PublicKey()` and supplies that non-secret value as
`hop-verification/PUBLIC_KEY` to consumers. Do not deliver the seed or derive it
from a previously shared proof. The key must come from trusted composition,
never from a request or an unauthenticated key advertisement. Key rotation changes
the trusted public key and immediately refuses stamps from the retired key.

The console example also resolves `hop-verification/REPLAY_DIRECTORY` from
Codefly's mounted shared volume and uses `FileReplayStore`. Configure the volume
and public key before upgrading consumers. No address, seed, key or volume path
is hard-coded. Python and Node hosts supply their shared durable replay adapter;
Python's async adapter must not block the event loop. Readiness continues to check
authority key availability; deployment health should also check its replay store.

Upgrade the hop and consumers together and remove delivery of `hop/PROOF`.
Downstream repositories must pin this breaking version and pass their actual
procedure into `Verify`/`verify`; no method-less overload remains. The regression
suite covers the read-to-delete and zero-scope fabricated-stamp probes from the
two independent reviews, cross-audience use, repeated and concurrent admission,
expiry, duplicate headers, store failure, and cross-instance durable reservations.
