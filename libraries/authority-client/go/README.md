# Authority Go client

Codefly generates the RPC bindings in `gen/`. The `workcontext` package adds a
non-verifying projection using Core's maintained decoder and scope containment:

```go
import claims "github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"

// The reader requires incoming metadata and the run-delivered hop proof.
md, _ := metadata.FromIncomingContext(ctx)
c, err := claims.ReadClaims(md, proof)
// Handle err, compare c.Audience() to this module's delivered audience, then:
allowed := c.Allows(resourceKind, action, exactResourceID)
```

`Scopes()` returns deep copies of the final actor's grants, or the owner's grants
when there is no actor. An empty final actor grants nothing. `Allows` evaluates
each candidate independently. An empty requested resource ID asks for the entire
kind; a restricted grant cannot satisfy it. Kind-wide grants cover named IDs.
Actions are literal: no admin implication, wildcard expansion, prefix matching
or union of one grant's actions with another's resources.

The reader checks a bounded canonical envelope and 64-byte signature shape, then
uses Core Decode. Go deliberately retains Core's stronger structural/schema and
attenuation checks; the Python and TypeScript readers only project readable
claims. All three agree on the shared Core-produced fixtures. None verifies a
signature, current time, live revisions or replay. Even a digest-bound context
may have been refused in warning mode. These claims alone never prove authority.
Keep audience, installed-definition, ownership, resource and live-visibility
checks at their existing owners. The exposed protobuf scopes are Core's current
public types during the authority migration; do not mutate returned copies and
expect to change the claims snapshot.

From this directory, run `GOWORK=off go test -race ./...` and `go vet ./...`.
The tests consume `../testdata/claims.json`, whose gateway-side oracle verifies
Core-minted tokens at a fixed fixture clock. Synthetic mutated tokens in unit
tests exercise parsing only and are not valid credentials.

Handwritten code lives outside `gen/`, the directory Codefly replaces. The root
module scaffold is preserved by `codefly generate client`.

The shared `host.Dial` resolves the authority for edge and hop. Remote endpoints
use verified HTTPS/TLS unless the composition asserts
`internal-transport/mesh-protected=true` and the target is an in-cluster Service
DNS name. Plaintext loopback is accepted only in a local Codefly environment.
Configured endpoints and SDK-resolved fallbacks use the same rule. Unreadable or
misspelled mesh assertions refuse before dialing; the shared host client owns
this check for edge and hop, without reviving the retired SDK verifier.
