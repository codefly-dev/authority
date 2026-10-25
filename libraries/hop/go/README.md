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
verifier, err := hop.NewVerifier(ctx, authorityv1.NewAuthorityServiceClient(conn), "<this module's audience>", proof)
config.GRPCServerOptions = append(config.GRPCServerOptions,
	grpc.ChainUnaryInterceptor(verifier.UnaryServerInterceptor()),
	grpc.ChainStreamInterceptor(verifier.StreamServerInterceptor()))
// in a handler: id, _ := hop.FromContext(ctx); id.Tenant, id.Has(kind, action), id.Claims.Allows(kind, action, resourceID)
// an HTTP module: id, err := verifier.Verify(ctx, metadataFromHeaders)
```

`Verify` checks this run's proof, that the stamp's digest binds the one
forwarded token, and then the token itself (Core's `Inspector`): the issuer pin,
the Ed25519 signature under the authority's published key, the audience is this
module, not-before and expiry, structure and attenuation. Who the call is for is
read from the authenticated claims (`IdentityOf`); a stamp that says otherwise
is refused, naming the field. It re-checks no permission the hop decided and
consumes nothing: liveness (revision, seal, single use) is the authority's Check
the hop made, bound to this call by the digest.

The keys come from the interface's `Keys`, through the generated client: never
typed in, never mounted. They are re-read when a token names a key the verifier
does not hold (at most every 10 s) and when older than 5 minutes; keys that
cannot be re-read are trusted for 15 minutes at most, then every call is
refused naming the outage.

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
Python verifier reads it back. Regenerate with `go test -run Fixture -update-fixture`.
