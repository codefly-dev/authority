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
