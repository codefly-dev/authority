# MCP acquisition: implementation boundary and remaining decisions

Tracking: [authority #52](https://github.com/codefly-dev/authority/issues/52).
Acquisition is **not enabled**: an ordinary MCP client still cannot complete the
flow against the local edge. The `oauthwire` package prepares stateless protocol
checks; it has no production caller yet. It is not an authorization server,
client registry, code store or token issuer. No public endpoints, issuer URLs,
resource identifiers or client identities have been provisioned by this change.

## What can be reused

[Authority #50](https://github.com/codefly-dev/authority/pull/50), merged at
`39369d67`, supplies expiring delegations in interface 0.3.5.
`libraries/authority-core/go/authority/delegation.go` already does the grant
intersection, current holdings/binding checks and pre/post-signing expiry checks.
The local issuer's `IssueRequest_Delegation` arm attests the actor's workload
credential before calling `IssueForDelegation`. Acquisition must use those paths,
not introduce another grant type or resolve permissions in HTTP handlers.

That reuse has a concrete boundary: `Delegate` requires an installed composed
module; `IssueForDelegation` requires that same module and a declared binding
addressing the target audience. An arbitrary OAuth `client_id` satisfies neither.
Registration of an OAuth redirect URI does not attest a module or grant a binding.
Even borrowing a composed identity requires an owner decision about which
workload holds its credential and exercises the binding for the external client.

Accounts already has OAuth discovery, public-client PKCE, resource binding and
rotating refresh in
[`oauth_authorization_server.go`](https://github.com/codefly-dev/module-saas-starter/blob/55563cda2450dc293beaaaa0392763701eb54be3/module/services/accounts/code/pkg/business/oauth_authorization_server.go).
Its redemption path calls `ConsumeClientAuthorizationCode` and
`minter.MintForClient` in one transaction, issuing an Accounts client session.
Its code lives in module `accounts`, importing `accounts/pkg/auth` and the
business service; it is not an independently consumable delegation adapter.
Copying its store or minter here would violate this repository's reuse boundary.
The host owner still needs to reconcile a shared implementation with Accounts;
local tests do not establish host adoption or SaaS parity.

## Decisions required from the authority owner

1. **The grantee and client discovery mechanism.** Does an external MCP client
   become a first-class grantee, or use a specifically named composed actor?
   If the latter, which actor, and who declares its solution bindings?
   Should RFC 7591 dynamic registration be served for clients that attempt it?
   #52 asks this; Accounts' source above explicitly omits DCR in favor of
   operator-registered clients and Client ID Metadata Documents. Supporting DCR
   and mapping registered clients into authority are separate decisions.
2. **Consent.** Must an external/background client's grant show a consent screen
   naming the client, solution, access and expiry? The
   [#50 handbook proposal](https://github.com/obin-ai/handbook/blob/main/proposals/2026-10-28-a-person-delegates-a-run-from-the-page.md)
   says, “There is no consent screen: the person is already acting in that page,
   the scopes are what they hold, and the delegation ends with the run.”
   That rationale does not decide the background-client case.
3. **The route declaration.** Who supplies the complete public MCP URL for each
   solution and the authority's public issuer URL, and through which SDK-resolved
   projection? Runtime
   [issue #50](https://github.com/codefly-dev/solution-runtime-go/issues/50)
   records a missing public origin and a workspace-wide value that cannot name
   two solutions. Historical
   [PR #54](https://github.com/codefly-dev/solution-runtime-go/pull/54)
   records the internal/public route confusion. Neither route spelling is an
   answer for the new edge. The resource must equal the URL the client dials.

These questions were presented to the owner in the #52 workspace. No answers
are assumed. Changes to `interfaces/` require a handbook proposal first.

A composed agent acting **for a person** can use a delegation to its workload if
the binding exists. An agent acting **as itself** has no human grantor: the existing
`Issue(as=workload)` or installation arm is the relevant owner shape. A public
client's authorization-code flow must not manufacture a person for that case
or turn a client registration into workload attestation.

## Protocol work prepared independently

`libraries/authority-core/go/oauthwire` constructs RFC 9728 and RFC 8414 JSON
documents from supplied public URLs. The initial missing-token response is
HTTP 401 with `WWW-Authenticate: Bearer resource_metadata="<metadata URL>"`.
Metadata must be reachable without sign-in. The protected-resource document
names exactly one solution URL and the authority issuer; Bearer transport is
the Authorization header. URL strings are preserved, never derived from Host,
Forwarded headers, internal service addresses or guessed frontend routes.

The authorization-server document describes code + refresh, public-client
authentication (`none`) and S256. It may only be published when those handlers
actually exist. Registration and metadata-client support are advertised only
when explicitly configured and implemented. No OAuth scope vocabulary has been
invented: callers must declare only scopes their flow enforces.

The PKCE checks use the RFC 7636 vector, strict unpadded SHA-256 challenges and
43–128 character verifiers. The eventual host adapter must additionally bind
each short-lived, single-use authorization code to the client, exact approved
redirect URI, resource, person, delegation and S256 challenge. Code consumption
and token issuance need the host's atomic redemption path. Duplicate parameters,
unapproved redirects, missing resource, `plain`, and reused codes must refuse.
PKCE by itself is not code storage or replay protection.

Every authorization records one exact resource URL and its trusted solution
audience mapping. Code exchange, refresh and edge admission preserve it; another
solution must refuse before forwarding anything. `CheckResource` compares the
whole string without normalization. An omitted resource on token/refresh requests
inherits the stored value; it never makes the token unbound. Repeated resource
parameters refuse. The edge must distinguish acquired tokens from person sessions
before the existing session issuance path, so a resource-bound credential cannot
fall through into issuance for any module.

OAuth scope strings are not WorkScopes. Grant derivation remains `Delegate`'s
intersection with the person's holdings, then `IssueForDelegation`'s intersection
with the current holdings and binding. Refresh preserves or narrows the original
scope ceiling; it cannot exchange the resource or add authority the person later
acquired outside that delegation. The scope mapping and storage adapter remain
to be connected after the grantee decision.

## Lifetime and refresh

The local authority defaults `MaxTTL` to 15 minutes. New delegated capabilities
now also cap their signed expiry at the delegation's end. Refresh must issue anew
using `Issue(as=delegation)`, preserving that delegation and its fixed expiry.
It cannot keep the person's browser session as a substitute for the delegation.
The core rechecks membership, holdings, binding, revocation and expiry each time.

`oauthwire.ExpiresIn` reports whole seconds down to the earlier of the actual
capability expiry and delegation expiry. A zero/expired delegation refuses in
this acquisition flow even though server-side `Delegate(ttl_seconds=0)` remains
valid elsewhere. Refresh credentials must rotate atomically with replay detection
in the shared host storage path. Rotation never extends the delegation; expiry
or revocation requires fresh authorization by the person.

Core verification retains its documented 30-second clock tolerance; clamping a
signed expiry is not an instantaneous cancellation guarantee. Previously minted
capabilities keep their signed expiry. The OAuth edge must enforce the recorded
access/delegation end before admitting a new request. An already admitted tool
call is allowed to finish under its existing request context; expiry does not
cancel it. Each later tool request or downstream authority issuance is checked
again. Runtime authority-call timeouts bound individual authority calls, not the
duration of the tool. Refresh never retries or resumes a tool call automatically.

## Verification and the remaining acceptance run

From the repository root, run:

```sh
(cd libraries/authority-core/go && GOWORK=off go test -race -count=1 ./...)
(cd libraries/authority-core/go && GOWORK=off go vet ./...)
(cd modules/authority/services/local/code && GOWORK=off go test -race -count=1 ./pkg/business/issuer ./plugins/authority ./plugins/registry_test)
```

These cover wire shapes, S256, exact resource refusal and lifetime arithmetic,
the signed delegation-expiry bound, core's Work Context conformance kit, and the
shared authority suite through the local adapter. They do not exercise a live
OAuth server or prove the client acquisition definition of done.

The acceptance recipe is pending the owner decisions and shared host adapter:
run the existing playground composition with `codefly run`, obtain the public
solution MCP URL from the route owner's SDK-resolved declaration, and configure
an MCP client with only that URL. Follow the 401 challenge to both documents;
sign in through the existing fixture session service; complete S256 authorization
and any required consent without copying credentials by hand. Verify initialize,
the five tools listed in #52 and their answers for that person. Present the same
access token to a second solution and require refusal. Exercise refresh after
capability expiry, and refusal after delegation expiry/revocation, without
extending the delegation. Record the client version and resolved route identities
with the run. No such run is claimed by this change.
