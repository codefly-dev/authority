# MCP acquisition: settled decisions and remaining integration

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
credential before calling `IssueForDelegation`. The new client arm reuses the
same stored delegation and shared decisions; HTTP handlers must not resolve
permissions or introduce another grant type.

The module arm remains unchanged: `Delegate` requires an installed composed
module and `IssueForDelegation` its attested workload and declared binding.
The core now also supports a client grantee on the **same stored delegation**:
`RegisterClient`, `ClientScopes`, `DelegateToClient` and
`IssueForClientDelegation`. Registration creates identity only. The owner stays
the person, and the actor chain carries `principal_kind=client` and the client's
own ID through later solution/module hops. A client borrows no installation,
workload credential or binding. The solution's installation seals the capability.

Both grantee arms call the extracted `delegableScopes` calculation; the client
path reuses the existing holdings, scope decisions, fencing and core minter.
Its resource, solution audience, grantor, scopes and expiry are fixed by the
person's delegation and rechecked on issue. The caller of the internal core API
must authenticate client custody through code/refresh redemption: knowing the
public client ID or delegation ID is not proof. These core methods are not yet
exposed by RPC or HTTP. The existing in-memory authority adapter supports the new
identity record for tests; that is not a new OAuth code or refresh store and
is not evidence that Accounts has adopted the new grantee.

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

## Owner decisions, settled 2026-10-28

These are the owner's explicit decisions in the #52 working session:

1. **An external client has its own identity; RFC 7591 is required.** It holds no
   scopes of its own and receives all authority from the person's delegation.
   Borrowing a composed module identity is rejected. Dynamic registration is
   part of acceptance because clients such as `claude mcp add` attempt it;
   hand-registration is not the URL-only flow.
2. **An explicit consent page at the edge names the solution, scopes and expiry.**
   Consent supplements the expiring delegation. The
   [#50 proposal](https://github.com/obin-ai/handbook/blob/main/proposals/2026-10-28-a-person-delegates-a-run-from-the-page.md)
   decided against consent because the person was acting in that page. A
   background client acts when the person is not watching; the premise differs,
   so this adds consent for a different act without contradicting #50.
3. **The solution declares its resource once; the SDK resolves it.** Never
   derive it from `PUBLIC_URL`. It must be exactly the MCP URL the client dials,
   shared by discovery, authorization, refresh and admission. The authority
   issuer is the edge's own origin. Historical
   [runtime issue #50](https://github.com/codefly-dev/solution-runtime-go/issues/50)
   and [PR #54](https://github.com/codefly-dev/solution-runtime-go/pull/54) explain
   why the former derivations were wrong.

The contract implications are recorded in the handbook proposal branch
[`authority-52-client-acquisition`](https://github.com/obin-ai/handbook/blob/authority-52-client-acquisition/proposals/2026-10-28-mcp-clients-use-their-own-delegated-identity.md).
No `interfaces/` or generated client has changed yet. The product choices are
settled; public API implementation and provider qualification are not.

A composed agent acting **for a person** can still use a module delegation.
An agent acting **as itself** has no human grantor: it uses the existing workload
or installation arm. Public-client registration gives no headless authority.

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
actually exist. RFC 7591 registration is required by the owner; its endpoint must be advertised
when implemented. Metadata-client support remains optional and may be advertised
only when implemented. No OAuth scope vocabulary has been
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
to be connected to the host redemption path.

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

The acceptance recipe is pending the shared host adapter and HTTP/SDK wiring:
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

## Exact continuation point

The flow still stops at the first unauthenticated MCP request: the running edge
returns its existing session 401 without OAuth discovery. Core client identity
and client delegation are implemented and tested; they are not an HTTP DCR
endpoint. There are no issued OAuth codes, access handles or rotating refresh
credentials yet. The consent page and solution-owned SDK projection are not wired.

The remaining reuse boundary is concrete. At Accounts commit `55563cda`:

- `pkg/business/client_authorization.go` defines the authorization-code record
  and `ClientAuthorizationCodeStore` callback transaction.
- `pkg/business/oauth_authorization_server.go:698` consumes that code and invokes
  `minter.MintForClient` in the same transaction, bound to an Accounts session.
- `pkg/infra/postgres_client_authorization.go` implements that transaction.
- `pkg/auth/pg/client_session_store.go` holds client sessions and refresh rotation.

These operations are not an independently importable delegation adapter. The
next implementation step is to extract/reconcile their common code redemption
and refresh logic with the host owner and supply an adapter calling the client
arm of the shared authority core. Accounts must consume the same extracted
implementation. A parallel local code/refresh store would violate AGENTS.md's
host-reuse rule, even if an OAuth smoke test passed. No such substitute has been
added. This work crosses into `module-saas-starter`; it cannot be delivered
solely by changing this authority PR. No issue or ticket has been opened for it.

After that shared path exists: propose/generate the client arm of the public
interface, wire bounded RFC 7591 registration and explicit consent, resolve each
solution's declared resource and the edge origin via the SDK, wire discovery,
code/refresh exchange and exact-resource edge admission, then execute and record
the composed five-tool and second-solution refusal run. PR #53 remains draft.
