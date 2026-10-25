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
