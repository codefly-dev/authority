# edge

The auth gateway's role in a run that composes the authority: the one origin a
browser talks to. A person signs in here and the browser holds only a session
cookie. Every call to a module is routed by its path to the module's own HTTP
face, with a Work Context the edge issues for that person at that module. The
hop in front of the module checks and stamps it, so the edge decides nothing
about what a call may do. Its routes and its refusals are in
[the repository README](../../../../README.md#the-edge-the-browsers-origin-2026-10-23).

The sign-in page at `/auth/sign-in` is built from the platform's UI kit
(`@codefly-dev/ui`) in [`web/`](web/) and embedded from `code/signin/out`, a
committed build. After changing `web/`, rebuild it and commit the output:
`cd web && NODE_AUTH_TOKEN=<read:packages token> npm ci && npm run build`.

Session discovery asks routed modules concurrently. A failed module is listed in
`refused` with its authority reason; other modules and the session still answer.
Cached Work Contexts are removed on expiry and sign-out, which also fences
in-flight cache writes. Authority endpoints use the shared host client's transport rule: verified TLS,
or an in-cluster Service address under `internal-transport/mesh-protected=true`;
plaintext loopback is local-only.

Run `npm ci` then `npm run check:bundle` in `web/` to rebuild the embedded sign-in
bundle and fail on changed, removed or newly generated assets. Supply the package
read credential through `NODE_AUTH_TOKEN` as configured in `.npmrc`.

A Current outage returns 503 with the authority's reason and preserves cached
contexts. Only Unauthenticated evicts the session's cached contexts and returns
401. Other Current failures also remain service failures, not evidence of sign-out.

Known interface gap: `host.session.v1` has no SignOut RPC. Browser sign-out clears
the local cookie and edge cache; it does not revoke a copied bearer at the host.
Host-wide termination requires a proposed Session.SignOut interface addition,
its host implementations, and the edge call before browser sign-out can promise
revocation. This change does not invent a second session revocation mechanism.

## Composition-owned sign-in choices

A composing workspace can choose which fixture people its sign-in page shows,
order them, describe each in plain language, and mark one **Start here**. Set the
optional `SIGN_IN_CHOICES` key in the existing workspace `edge` configuration
through Codefly, from the composing workspace:

```sh
codefly config set edge --plaintext \
  'SIGN_IN_CHOICES=[{"personId":"dev","description":"Dev — developer: explore the installed tools","startHere":true},{"personId":"maya","description":"Maya — viewer: explore a refusal"}]'
```

The JSON array's order is the page's order. Each entry names a fixture `personId`
and a nonblank one-line `description`; `startHere` is optional and at most one
entry may set it to true. Descriptions render as text, never HTML. Use `--force`
to replace an existing value. Omit the key (or set it to an empty value) to retain
the default: all people in the authority's order with their email, organisation
and roles. A configured array must be nonempty. Malformed entries, unknown
fields, duplicate IDs and multiple starting choices refuse startup with a reason;
a person absent from the host's list refuses the page with a reason.

This controls presentation only. It does not remove fixture people, change grants,
filter `ListFixturePeople`, or restrict sign-in for unlisted people. Other
compositions and conformance suites continue to use the full fixture. The edge
still obtains identity details and fixture tokens through its generated session
client; the configuration supplies neither credentials nor permissions.

## The setup page

`/auth/setup` installs the run's solutions and grants their roles. It is
mounted only where the host serves `OfferService`, which the local authority
does and a hosted authority does not: the edge asks the host once, without a
credential, and a host answering `Unimplemented` gets a 404 for the path (no
install, grant or revoke is ever sent to it); an unreachable host is a 503 and
is asked again. It needs a session, and without one it redirects to sign-in.
Neither it nor the sign-in page may be framed (`X-Frame-Options: DENY`,
`Content-Security-Policy: frame-ancestors 'none'`), so another page, a
same-site one on another local port included, cannot overlay a click on it. The page is the same embedded
build as sign-in (`web/src/setup.tsx`). The edge writes into its data island
what the authority answers to the person's own session:

- `OfferService.ListOffers`: the solutions offered.
- `InstallationService.List`: their installations.
- For the reviewed one, `OfferService.ReviewOffer` (its roles, the operations
  each covers, the tools composed for those operations, the permission ceiling
  and the consent tuple) and `ListRoleGrants`.
- The organisation's fixture people, by id and email (never a sign-in token),
  and their teams.

Each change is a form posted back to `/auth/setup`: `install` (the consent
tuple, a fresh UUID `operationId`, the agent role, and the consent checkbox,
without which nothing is sent), `grant` and `revoke` (one role to `person:<id>`
or `team:<id>`). A post must carry this origin. The edge sends it through the
generated client with the person's bearer; the authority decides it. A refusal
is shown with the authority's reason. An install the authority did not confirm
is shown again with its exact request, so the retry is the same operation.

## The Setup tab's Connect face

A solution's Setup tab reads and changes its roles through the host's own
installation interface, so it is the same page locally and on a hosted
authority. The edge serves these procedures of `host.installation.v1` to the
signed-in person, over Connect, on this origin, at the paths the proto names:

| Path | Who the authority answers |
|---|---|
| `/host.installation.v1.InstallationService/List` | an administrator of the organization |
| `/host.installation.v1.InstallationService/ListHeld` | any member, for themselves: the installations they hold a role on (none is an empty list) |
| `/host.installation.v1.InstallationService/Review` | an administrator (the consent tuple) |
| `/host.installation.v1.InstallationService/ListRoleGrants` | an administrator, or the installation's installer-role holder |
| `/host.installation.v1.InstallationService/GrantRole` | the same |
| `/host.installation.v1.InstallationService/RevokeRole` | the same |
| `/host.installation.v1.OfferService/ListOffers` | an administrator |
| `/host.installation.v1.OfferService/ReviewOffer` | an administrator, with the consent tuple; a member holding a role on the solution's active installation, without it |

Each call is sent to the host through the generated client with the person's
own session and decided there; a refusal keeps the host's code and reason
(Connect's `permission_denied`, `unauthenticated`, …). Nothing else of the
package is served to a browser: `Install` and `Current` answer `unimplemented`,
and install stays on `/auth/setup`, behind its consent form.

A call is admitted only as Connect: a `POST` carrying `Connect-Protocol-Version: 1`
and `application/json` or `application/proto`. A form, a `text/plain` simple
request, gRPC-Web and a `GET` are refused before the host is asked, and no CORS
header is ever set, so another site's page is stopped at its preflight. A call
made with the session cookie must also carry this origin in `Origin`; a caller
presenting its bearer itself needs none. The page reads the organization to name
in each request from `/auth/session`.

### A page delegates a run (2026-10-28)

The face also serves two procedures of the authority's own interface, so a
person's page can delegate work that outlives their session to a module and read
that delegation back ([handbook proposal](https://github.com/obin-ai/handbook/blob/main/proposals/2026-10-28-a-person-delegates-a-run-from-the-page.md)):

| Path | What the edge requires before asking the authority |
|---|---|
| `/host.authority.v1.AuthorityService/Delegate` | a positive `ttl_seconds`: a delegation made from a page ends after the work it was made for |
| `/host.authority.v1.AuthorityService/GetDelegation` | no `actor`: a page reads as the grantor; a module's credential is the module's own read |

They are admitted, forwarded and refused exactly as above. The edge requires
`codefly.dev/authority@>=0.3.5`: an older host drops `ttl_seconds` as an unknown
field and would record a page's delegation as one that never ends. Every other procedure
of `AuthorityService` (`Issue`, `RevokeDelegation`, …) is served to no browser:
the edge routes these two paths by name, never the package.

Calls the edge routes to a module are refused in Connect's words when the caller
says it speaks Connect (a `Connect-Protocol-Version` header, or `?connect=v1` on a
GET) or gRPC, so a generated client keeps the reason (the hop does the same).
Every other caller, a REST or form caller included, keeps `{"error": reason}`.
