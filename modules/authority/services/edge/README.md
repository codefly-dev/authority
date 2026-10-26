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

`/auth/setup` installs the run's solutions and grants their roles. It needs a
session, and without one it redirects to sign-in. The page is the same embedded
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

Calls the edge routes to a module are refused in Connect's words when the caller
speaks Connect, so a generated client keeps the reason (the hop does the same).
