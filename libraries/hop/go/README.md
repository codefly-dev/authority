# Go hop library

## The module side: `Verifier`

Every module behind the hop authenticates each call with one `Verifier`, built
once at startup from the authority interface it already depends on:

```go
import (
	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/host"
	hop "github.com/codefly-dev/authority/libraries/hop/go"
)

proof, _ := codefly.For(ctx).WorkspaceSecret("hop", "PROOF")
conn, _, err := host.Dial(ctx) // the local authority on a laptop, the host on a cell
audience, err := hop.Audience() // the module the composition started this process as (CODEFLY__MODULE)
verifier, err := hop.NewVerifier(ctx, authorityv1.NewAuthorityServiceClient(conn), audience, proof)
config.GRPCServerOptions = append(config.GRPCServerOptions,
	grpc.ChainUnaryInterceptor(verifier.UnaryServerInterceptor()),
	grpc.ChainStreamInterceptor(verifier.StreamServerInterceptor()))
// in a handler: id, _ := hop.FromContext(ctx); id.Tenant, id.Has(kind, action), id.Claims.Allows(kind, action, resourceID)
// an HTTP module: id, err := verifier.Verify(ctx, metadataFromHeaders)
```

`Verify` checks this run's proof and that the stamp's digest binds the one
forwarded token first (a call without them never reaches the keys), and then the token itself (Core's `Inspector`): the issuer pin,
the Ed25519 signature under the authority's published key, the audience is this
module, not-before and expiry, structure and attenuation. Who the call is for is
read from the authenticated claims (`IdentityOf`); a stamp that says otherwise
is refused, naming the field. It re-checks no permission the hop decided and
consumes nothing: liveness (revision, seal, single use) is the authority's Check
the hop made, bound to this call by the digest.

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

The proof is shared by every hop-fronted module: it keeps out a caller that is
not a composed workload, and it does not show that a composed workload came
through the hop (codefly-dev/authority#5).

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

The Go dependency pins authority-client at the commit that introduced
`workcontext.Authenticate`; standalone library tests need no workspace replacement.
`../testdata/stamped.json` is a genuinely signed call as the hop stamps it; the
Python verifier (`codefly_hop`, shipped in `libraries/authority-client/python`) reads it back. Regenerate with `go test -run Fixture -update-fixture`.
