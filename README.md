# authority

**What we are doing.** Making the interface the mapping between local development
and deployment. The local authority a developer runs on a laptop and the host's
accounts service implement the same declared contract, checked by the render and
proven by one suite, so what passes on the laptop is what runs on the cell and
what refuses on the laptop is what refuses on the cell. Without the interface
that mapping is a hope; with it, it is a test.

This repository holds two things, and only these two:

1. **The host authority interface** (`interfaces/authority/interface.codefly.yaml`):
   a Codefly interface declaring what a module or solution calls on the host that
   runs it. Issue a Work Context for a person, an installation or a module's own
   binding; re-address, derive a child, renew; check a revision live; the current
   installation. The host's `accounts` service implements the same interface;
   provider qualification gaps are recorded below. A module
   depends on the interface, never on a service.
2. **The local authority** (`modules/authority/services/local`): the development
   implementation. One process that signs in fixture people with their roles,
   issues and verifies Work Contexts, knows the composition from the rendered
   manifests, and holds the installations its composition declares in memory. No accounts
   service, no stores, no platform frontend. Running a solution locally is the
   solution, the modules it consumes, and this.

**What is reused today.** The local implementation uses Core's Work Context
authority/verifier, workload attestation and signed composition machinery.
Its local issuer delegates issuance and grant derivation to this repository's
shared authority core; the state adapter supplies fixture roles and delivery data.
It does not currently link Accounts' sign-in or grant-derivation packages, and
this adapter migration does not establish Accounts adoption of that core.
The original host-package reuse requirement
remains an unresolved design obligation with the host owner, not a guarantee
established by this checkout. The shared conformance suite must run against both
implementations; a local pass or a skipped provider scenario does not prove parity.

**What this repo is, in one line.** The interfaces the host's saas component
MUST satisfy, with the suite that proves it, and the development implementation
that satisfies them on a laptop, fixture included.

**Order of work.**

1. Declare the interfaces and give them their protos, reduced to the six duties
   (done; `interfaces/`, `modules/authority/services/local/proto/host/*/v1`).
2. Build the local authority against them with the suite every implementation must
   pass (done; `pkg/conformance`, run over gRPC in `plugins/registry_test`).
3. Point the host and the SDKs at these packages; run `pkg/conformance` against
   accounts; delete the copies in `codefly-dev/core` and the host, fixtures proving
   identical bytes at each step.
4. Then the major clean-up of `codefly-dev/core` and the CLI the owner named on
   2026-10-21: nothing of authority left in core, nothing of the host's model
   left in the CLI's launcher.

**Tests (47, `go test ./...` under the service's `code/`).** They use the
primer's cast and its cases, nothing invented: Acme; Maya on Finance, a viewer;
Rémi the engineer, an editor; Alex the administrator; the wiki; documents, model,
runtime, records and the org-directory page.

- `pkg/business/issuer/scenario_test.go`: the primer's section 4, one hop at a
  time. 1 Maya signs in. 2 The wiki is her navigation and not Rémi's. 3 The wiki
  reads documents for her: owner = actor = Maya, scopes = roles ∩ ceiling, sealed
  to documents at Acme, write refused by name. 4 documents embeds through model
  for itself under its binding; `modelservice` is refused as not composed; the
  second binding the envelope forgot this week is simply there. 5 A 60-second
  child for Runtime is refused for Maya, who has no Runtime grant; the entitled
  developer succeeds with actor documents and only the Runtime binding's scopes.
  6 The wiki reconciles
  overnight as its installation; uninstalled at 10:00, its 09:58 token is refused.
  7 Maya opens the directory page and is issued records read; Rémi gets write; the
  UI follows the token. 8 All of it ran with no accounts service, no store, no
  envelope, no anchor.

- `pkg/business/issuer`: every core conformance fixture round-trips through our
  `WorkContextV1` byte for byte and every descriptor names the same fields and
  numbers; core's conformance kit passes through the verifier `Check` is built
  on; a person is issued what her roles hold and no more; an uncomposed audience
  is refused by name (this week's `modelservice` typo); a check refuses another
  audience and a tampered token; an uninstall refuses an outstanding token on the
  next check; an installation acts for itself within its role; a pending
  installation is issued nothing; a workload is issued its binding's headless
  scopes and refused an undeclared binding, a binding addressed elsewhere, a
  widened scope, a forged credential; a child hop attenuates and names its actor;
  `Keys` lets an independent core verifier check what was issued; TTL clamps.
- `pkg/business/state`: the fixture installs through the real path; entitlement
  is the navigation; module installations exist per organisation without a click;
  a manifest moves only forward; a manifest with some bindings is NOT all or
  nothing; headless may not exceed invoke; one principal per module; the seal
  answers only for an active installation and a known principal; the revision
  moves on every grant change; the install step runs and stays pending until it
  converges; workload credentials are the launcher's word and nothing else.
- `pkg/conformance`: the interface-level suite, driven only through the generated
  clients, asserting gRPC codes and that every refusal names its reason. The host
  runs the same suite against accounts in step 3.

**CLI and agent gaps (2026-10-21), to file.** The go-grpc agent (0.1.58)
generates adapters for `proto/api.proto`'s service only, and its plugin registry
template always returns nil, so `plugins/plugins.yaml` is declared but not
rendered; the four plugins implement the agent's own `framework.Plugin` and are
wired in the tests, and serving them from the agent's server is the agent's work,
not a hand edit of `registry_gen.go`. `codefly generate client --from
authority/local/grpc --language go,python` writes two Go packages (`api` from
the scaffold's proto, `authority` from ours) into one facade directory and fails
its own build; the Go and Python clients that would replace the solution SDK wait
on that fix.

After changing a proto, regenerate its bindings and clients with `codefly
generate` and review the output. For changed files already recorded in
`tools/noproxygate/generated.json`, refresh their SHA-256 digests from that
reviewed output; do not add exclusions or change the gate to accept a mismatch.
Run `GOWORK=off go test -race -count=1 ./...` and `GOWORK=off go vet ./...`
in `tools/noproxygate` before committing the generated change.

**Where the thinking is.** The Platform Authority Primer (decisions 6 and 7) and the
handbook proposal that will carry them. Run it with `codefly run` from the module.

## What the local authority must serve, read from the callers (2026-10-21)

Inventory taken from the code that calls the host today: the module SDK
(`saas-sdk-go/moduleauthority`), the solution runtime (`solution-runtime-go`), the
CLI's delivery (`cli/pkg/gitops`), the host frontend and the gateway's own routes.
Paths are the host's spellings; the interface grows from this list, not from a
design.

**Phase 1, a module alone**

| Need | Host surface today |
|---|---|
| A fixture person signs in | `POST /v1/auth/authenticate` with `fixture_token` (accounts `auth/dev` validator); `/v1/auth/refresh` |
| Verify what the host issued | `GET /v1/auth/.well-known/jwks.json` (also `/jwks`, `/.well-known/openid-configuration`) |
| The composition reaches the host | `POST /platform/_delivery/manifest` (one signed manifest per module instance) |
| What a module may hold | derived from the manifest; today `GET`/`PUT /v1/platform/module-envelope`, which the local authority does not serve |
| The module's workload becomes a principal and gets Work Contexts | gateway workload endpoint: `POST /modules/_work-context` (for a person), `/modules/_operation-context` (the module's own binding), `/modules/_source-operation-context` (a source delegation) |
| The module calls the host as itself | Connect proxy at `/modules/_authority` → `ModuleCapabilitiesService`: `ExchangeDelegatedOperationAudience`, `EmitAuditEvent`, `DeclareAuditEventTypes`, `AuthorizeExecutableArtifact` / `ApproveExecutableArtifact`, `NotifyUser` / `NotifyOrgAdmins` |
| Person-owned authority | `WorkContextService`: `StartTask`, `ExchangeAudience`, `StartChildSession`, `RenewWorkContext`, `CheckAuthorizationRevision`, `StartInstallationTask`, `AuthorizeEvidenceRead`, `ConsumeSingleUse` |
| A module route carries a viewer | `/v1/<alias>/*` through ext_authz, stamped `x-user-id`, `x-org-id`, `x-org-role`, `x-platform-role`, `x-scoped-roles`; the viewer Work Context per module call is decision 4 of the primer |

**Phase 2, a solution**

| Need | Host surface today |
|---|---|
| The solution registers its backend and page | `/modules/_register`, `/modules/_registration-token` (gateway `gateway_module_routes.go`); `/.well-known/solution.json` and `/.well-known/capabilities` served by the runtime and proxied |
| Routes to the solution | `/solutions/<id>/*` (gateway), `/api/solutions/<id>/proxy/*` (frontend), module-federation assets, the registry snapshot, the 120 s lease |
| Who may use it | `ListSolutionEntitlements` (gateway `handleSolutionEntitlements`); `InstallationService`: `InstallSolution`, `GrantInstallationToTeam`, `ListInstallations`; installations come from the composition's fixture-composition document |
| The solution is installed | host → solution `POST /_codefly/installations` with a Work Context, retried until acknowledged |
| The solution acts for a viewer against a module | `StartTask` under resource and installation confinement (`x-codefly-resource`, installation header) |

**Phase 3, when wanted**

| Need | Host surface today |
|---|---|
| An MCP client or another solution's robin calls the solution's tools | OAuth authorize and token endpoints with RFC 8707 resource, `/.well-known/oauth-protected-resource`, registered clients |
| Sources, notifications, approvals | `DatasourceService` (`PruneSourceOperationReceipts` and friends), the notification and approval RPCs above |

Not served, ever: the module envelope endpoints (the ceiling is the manifest), the
pod and container review, the trust-anchor files, any identity provider but the
fixture one.

## Which of these are real (2026-10-21)

A host must do six things for a unit, no more: know who the person is; issue a
Work Context for an owner shape, an audience and scopes, and let the callee
verify and re-check it; know the composition; know what is installed and who may
use it; call the solution's install step once; be the one entrance a browser
talks to. Against that:

- **Accidental, host:** the twelve issue-shaped operations (one `Issue` with a
  request shape; renew, child and exchange are "issue from parent"); the envelope
  endpoints (ceiling = manifest; narrowing is an admin operation, never a delivered
  file); solution self-registration and registration secrets (a solution identifies
  like any module instance, with its workload credential); two route families per
  solution; the registry snapshot and the lease (replication plumbing); the five
  identity headers and the confinement headers (one Work Context per module call
  makes them vanish); three key-set paths.
- **Misfiled:** audit, notifications, approvals and sources on the capabilities
  service. Host services a module uses, each a small interface of its own, a log
  locally. Not authority.
- **Accidental, elsewhere:** the CLI's anchors, policies and envelope writing; the
  solution runtime's build seal and gateway-header reading; eleven audience
  spellings in compositions.
- **Never:** pod and container review, trust-anchor files, a non-fixture identity
  provider locally.
- **Needed:** fixture sign-in, the key set, manifest delivery (a file on a laptop,
  an endpoint on a cell), installations with the install step, module routes.

**What remains is the interface.** Authority: `Issue`, `Check`, `Keys`.
Composition: `ApplyManifest`. Installation: `Install`, `GrantRole`, `RevokeRole`,
`ListRoleGrants`, `List`, and the install step callback (installation 0.2.0: an
installed solution is a principal, and a role grant to a person or a team is
the access; `GrantToTeam` is gone). Sign-in at the browser edge only. Routing is the data
plane, not a contract. 0.1.0 mirrors today's spellings so the local authority serves
the SDKs as they are; the reduced shape is 0.2.0, a host contract change through a
handbook proposal, after which the SDKs move once.

## Audit: is solution-runtime-go still needed? (2026-10-21, v0.0.15)

8,342 non-test lines; the six solutions in core-solutions use: `Consumes`,
`ConsumedModule`, `ConsumedMethod`, `Transcoded` (passthrough of module operations
to the page with the viewer's Work Context, because a module route refuses the
browser's bearer); `Contract` and the contract artifacts; `FieldMask`/`Apply`;
`Handle`/`Serve`; `OrgID`; `ClientError`; `ForModule` twice.

| Runtime part | Lines (approx.) | Where it belongs |
|---|---|---|
| execution credential, broker, scoped credential, mint errors | 2,400 | the `codefly.dev/authority` interface, generated client |
| passthrough, transcode, stream, protowire | 5,000 with tests | nowhere: when a module route carries the viewer's Work Context (primer decision 4) the page calls the module through the gateway and nothing passes through |
| contract, operations, interface artifacts | 1,200 | the CLI (`codefly generate contracts`, cli#1094) |
| listener, health, CORS, assets, config | in `solution.go` | the service agent, as for every service |
| install step | 300 | the generated `installable` server |
| MCP server + protected-resource metadata | 1,500 | the MCP library plus one middleware: stamped viewer → `Issue` |
| field masks, viewer-from-request, client errors | a few hundred | a small library, or the generated client's facade |

**Verdict: not as a runtime.** A solution becomes an agent-scaffolded service that
depends on the authority and installation interfaces through generated Go or
Python clients. Order: `pkg/conformance` passes on accounts; decision 4 lands on
the gateway; `codefly generate client` works for Go and Python (gap above); the
six solutions move; solution-runtime-go is deleted, not fenced. Until then, pinned
at v0.0.15.

## Validation ladder (proposed 2026-10-21)

Each rung proves one claim; nothing is deleted before the rung above it is green.

| Rung | Claim | How | Pass | Owner |
|---|---|---|---|---|
| 0 | the local authority holds | 47 tests here: byte identity, core's kit, scenario, `pkg/conformance` over gRPC | green (done) | this repo |
| 1 | one contract, two implementations | accounts implements the four interfaces as adapters over what it does; saas CI runs `pkg/conformance` against it with the saas fixture | same codes, same reasons on both | module-saas-starter |
| 2 | a module cannot tell which answered | documents takes the generated authority client and requires the interface, not a service; runs against the local authority and against accounts | identical tests, playground and refusals; the render picks the implementation | module-document-store, saas-sdk-go |
| 3 | a solution needs no runtime | the wiki as an agent-scaffolded service on the generated clients; wiki + documents + local authority, then the full host locally, then obin-staging; the eight steps through the UI | the scenario passes end to end; no envelope, anchor or audience key anywhere | core-solutions |
| 4 | the laptop refuses where the cell refuses | recorded request vectors replayed against both, compared field by field; property tests on the four ways a token widens; replay, expiry, revocation, forgery; one independent security review | zero divergence, zero widening, findings closed | this repo + reviewer |
| 5 | it is fast | clean clone → Maya sees the wiki, one command, timed; a grep gate against envelope files and audience keys | the owner's number; gate green fleet-wide | cli, handbook |

Exit for the deletions (core's authority packages, the CLI's cluster path and host
knowledge, solution-runtime-go, the audience spellings): rungs 1–5 green and
staging validated.

**Rung 1 first; it is the one that matters (owner, 2026-10-21).** The loop:

1. Cut a branch in module-saas-starter. accounts declares in its module
   interface that it implements `codefly.dev/authority@0.3.2`, `codefly.dev/composition@0.2.0`,
   `codefly.dev/installation@0.1.0` and `codefly.dev/session@0.2.0`, takes this repo's
   protos (bindings via `codefly generate proto`), and serves the four services as
   adapters over what it already has: `Issue` → StartTask / StartInstallationTask /
   the module broker's mint / StartChildSession-ExchangeAudience-Renew by owner
   shape; `Check` → its verifier plus the live revision; `Keys` → its key set;
   `ApplyManifest` → manifest delivery with the ceiling read from the manifest
   (the envelope path is not consulted); the installation operations → its
   installation service and team grants; `SignIn` → its fixture validator. No
   behaviour is rewritten on that branch; the adapters are the contract's spelling
   of what accounts does.
2. saas CI on that branch runs `pkg/conformance` against accounts with the saas
   fixture (the same Acme people). Red is the gap list; green is the claim.
3. Run a solution against the branch: platform-core overridden to the saas branch
   checkout, `codefly run workspace`, the wiki, Maya signs in, the eight steps
   through the UI. The gaps that surface are filed against the branch.
4. Only then: documents takes the generated client (rung 2), the wiki drops the
   runtime (rung 3), and the deletions.

## Rung 1 status (2026-10-22)

Branch `authority-interface` in the host repository, draft PR
codefly-dev/module-saas-starter#1217. accounts declares `implements` for the four
interfaces, carries the protos, states its own method policies for them in a
sidecar (`business.InterfaceMethodPolicies`, read when a descriptor carries no
host option), and serves Keys, Check, Issue by owner shape, List and SignIn as
adapters over existing paths; workload Issue, ApplyManifest, Install and
GrantToTeam refuse by name. `go build` and the policy tests pass. The suite has
not run yet, because of what the branch found:

| # | Gap in the host | Where |
|---|---|---|
| 1 | ~~the service catalog assumes one proto package~~ **closed 2026-10-22**: the catalog carries the implemented `interface_packages` beside its `api_package`; frontend catalog, route aliases and mesh gates read the API package only | `business/service_catalog.go`, `catalog.proto` field 9 |
| 2 | ~~Connect bindings are keyed by short service name~~ **closed 2026-10-22**: bindings resolve by full service name first; the generator imports each implemented package under derived aliases | `cataloggen/connect_registration.go`, `connect_bindings.yaml` |
| 3 | workload-owned Issue is minted on the gateway's workload endpoint, not an accounts RPC | `/modules/_operation-context` |
| 4 | ApplyManifest is signed delivery, not an RPC | `/platform/_delivery/manifest` |
| 5 | Install/GrantToTeam need resolvers: target name → target id + agent identifier; role name → role id | installation service |
| 6 | no exposure audit event is registered | `business/audit_registry.go` |
| 7 | ~~the host's naming gate refused the publisher name in 733 places~~ **closed 2026-10-22**: the interfaces carry the host's names (publisher `codefly.dev`, packages `host.*.v1`); the gate is at its main baseline on the branch | `tools/naming-gate.mjs check` |

Gap 7 was a decision, taken on 2026-10-22: the interface carries the host's names, see "The namespace, settled" below. Gaps 1 and 2 closed the same day on the host branch; a ninth surfaced and closed with them: the generated service catalog crossed the host's naming-gate scan cap (512 KiB) at 40 services, and the gate now skips that generated file for the reason it skips descriptors.

**What the second implementation taught the interface.** `GrantToTeamRequest` gained `organization_id`: the host checks an administrator against the organisation before it reads the installation, so the request must name it; the local authority now refuses a grant naming another organisation than the installation's, and the suite asserts it. That is what a second implementation is for.

## The namespace, settled (2026-10-22)

The interfaces are the host's contract, so they carry the host's names: publisher
`codefly.dev` (ids `codefly.dev/authority@0.3.2`, `composition`, `installation`,
`installable`, `session`) and protobuf packages `host.authority.v1`,
`host.composition.v1`, `host.installation.v1`, `host.session.v1` under `proto/host/`.
Not `codefly.*`: the host's buf configuration excludes a `codefly/` proto directory
for its vendored core files, and ours would vanish into it. Message bytes are
unchanged (field numbers are); only RPC paths and import paths moved, and nobody
called them yet. The repository may stay in the consumer's organisation: a gate
scans files, not URLs. This closes gap 7 of rung 1.

## The transition, mapped (2026-10-22)

**Invariant:** one declared interface and one suite on both sides from phase 0 on,
so local development to deployment is correct by construction. Phases: 0 now
(interfaces, local authority, host adapters on a branch; protos and policy exist
twice, knowingly); 1 rung 1 done (suite green against accounts, refusing adapters
made real, suite and credential and person shape corrected, digest check on the
copied protos); 2 the wiki against the branch; 3 rungs 2 and 3 (agent and CLI
gaps closed, documents on the generated client, the wiki without the runtime);
4 one source (CLI generates from the published interface; one policy source; the
copies, the envelope, the audience keys and the CLI's cluster path deleted); 5 the
clean-up (core loses its authority packages, solution-runtime-go deleted).
Deletions only in 4 and 5, each behind a green suite and staging. The full table
is the handbook's `design/host-authority-interface.md`.

**Corrections of 2026-10-22 (`0403966`).** The suite accepts pending or active from
Install. The local authority attests core's native launcher credential against the
launcher's anchor; nothing of its own. The person shape is the caller's bearer;
`PersonSession` is empty. See the handbook's audit sidecar for the reasoning.

## Moved to codefly-dev (2026-10-22)

The repository is `codefly-dev/authority`: the interface is the host's, published as
`codefly.dev`, and the host may import from here (its naming gate refuses a
consumer's organisation in an import path). GitHub redirects the old location.
`libraries/authority-client/go` is the generated Go bindings library
(`codefly generate client --no-facade`), importable as
`github.com/codefly-dev/authority/libraries/authority-client/go`. The Python
library publishes generated bindings under `libraries/authority-client/python`.
The [Python bound-context reader](libraries/authority-client/python/README.md) projects
effective resource scopes without another verification call. Consumers read the
hop stamp first and retain their domain resource and installation checks.
The [Go reader](libraries/authority-client/go/README.md) reuses Core Decode and
scope containment; the [TypeScript reader](libraries/authority-client/typescript/README.md)
uses Codefly-generated protobuf bindings. Shared Core-produced fixtures cover
their scope decisions. These projections do not authenticate a context or replace
live checks; TypeScript hop-binding integration remains separate work. Go also
retains Core's stronger structural validation.

After changing local Go library dependencies, validate all four services as
standalone modules: local, hop, edge and console API. The latter three consume
the local authority client; local has other local library replacements. Run
`GOWORK=off go mod tidy -diff`, `GOWORK=off go test -race ./...` and
`GOWORK=off go vet ./...` from each service's `code/` directory. Workspace-only
library tests can hide stale service module graphs and leave `codefly run`
unable to build.

## Rules of change (owner, 2026-10-22)

- **Additive until phase 4.** A field, a message, a service, a test or a check is
  added beside what exists; nothing is cut, renamed in place or moved. Field
  numbers never change. Deletions belong to phases 4 and 5 of the transition,
  behind a green suite and staging.
- **A suite change is a contract change.** Reviewed as one; never loosened so an
  implementation passes. A red line is fixed in the implementation or argued in
  the contract, in the open.
- **Phase 1 now also carries:** the agent and CLI gaps (#192, #193, #1107), core's
  full manifest as a proto message beside `ModuleManifestV1`, the digest check on
  the host's copied protos, the differential corpus, the decision-4 gateway design,
  and an independent security review before rung 1 is called green.

## Roles and the permission matrix

A solution declares its roles in its canonical `module.contract.codefly.yaml`,
each within what the solution serves or explicitly consumes through its invoke
and lookup bindings. Headless-only permissions cannot supply a role grant.
One role is `installer`: whoever installs the solution holds it on
that installation, which is the install-and-configure surface. A module declares
no roles; a person's access to a module is the organisation's roles intersected
with what the module serves. A person's access to a solution is the role its
installation grants her, the installer role as its owner or the installation's
role through a granted team, and nothing from the organisation's roles. Another
organisation's installation grants nothing. The values of real roles belong to
each solution's manifest and arrive through the carrier: core's manifest carries
no roles, so they travel in the authority's own document delivered with it
(`AuthorityManifestV1.roles`), bounded
by the solution's own scope ceilings and the invoke/lookup scopes in the paired
Core manifest. Consumed kinds do not become kinds the solution serves. This repository holds
the contract and its evaluation, never a product's roles.

An installation acting for itself resolves its selected role in that installed
solution's manifest, using the same role source as installation validation.
An organisation role with the same label supplies no authority to it. The
requested audience still intersects that role with what it serves; a binding
alone does not grant downstream module access. A role may explicitly grant a
consumed permission within those bindings, allowing the installation's agent to
issue at that module or carry it on a child call. Resource restrictions survive
that intersection.

For person-owned work through a solution, the person's effective installation
roles are the permission source, including explicitly declared consumed grants.
No additional organisation grant is required. Installer-only owners hold only the
installer role; members of granted teams hold the selected role; a person in both
positions holds their union. A binding is a ceiling, never an independent grant.
The authority applies this source to person issuance naming a solution binding,
children, delegation admission and use, and resource reads. Every solution in the
verified actor chain continues to bound later module calls; a later module cannot
recover a permission that the solution role withheld. A target solution also
requires the person's entitlement there. Independent person-to-module work still
uses organisation roles; child derivation follows the target rule below.

Solution roles preserve exact resource IDs and whole-kind grants through issuance
and resource listing. Restricted grants still do not satisfy a method policy
requiring a whole kind. Solutions must declare their intended consumed permissions
in their own roles; missing declarations cause refusal, not an organisation-role
fallback. Tests cover both denied organisation rights and permitted solution rights,
signed role delivery, multiple solution actors, and role/installation/delegation
revocation. SaaS parity and composed browser qualification remain separate work.
Installation-owned calls to another solution still need the target-consent contract
tracked by the pending tool-matrix row 11; this person rule does not supply it.

Delivering a narrower or removed selected role, or narrowing the installer's
role, advances active installation seals and the affected organisations'
authorization revisions. Existing roots and descendants are then refused by
Core's ordinary live verification. Role expansion alone leaves existing narrow
installation roots valid; module actors still obey their generation checks.
New issuance resolves the current declaration.

Issuance binds those role reads to the authorization revision Core signs. If
delivery changes it between resolution and minting, issuance refuses with
`permissions changed during issuance`; it does not retry with the old scopes.
Workload, delegated and child binding resolution likewise must match the signed
binding's module generation. Narrowing, removing or retargeting a binding also
advances the active installations' seals and organization revisions: person
roots can carry its scopes for a later hop without carrying the module's epoch.
Organization revision invalidation is coarse: unrelated existing capabilities in
each affected organization also need fresh issuance. Current grants remain usable.
A change after version capture leaves an older capability that ordinary
verification refuses. Deterministic issuer tests cover
role narrowing/removal and binding narrowing/removal before resolution, during
minting and after issuance. These checks do not choose a child-scope policy or
qualify the separate accounts implementation.

Installation administration (`List`, `Install`) requires an open session whose
current person is an administrator or owner of the requested organization; role
grants (`GrantRole`, `RevokeRole`, `ListRoleGrants`) also admit the holder of the
installer role on that installation. Anonymous and invalid sessions are
`Unauthenticated`; anyone else receives `PermissionDenied`, and a caller of
another organization is answered as if the installation did not exist. Every
decision is the generic authority core's (`libraries/authority-core/go`); the
local authority is a host over it. This is
not the navigation API: a member probes each target with an empty-scope `Issue`.
That call returns `FailedPrecondition` when the audience has no active
installation in the person's organization, and `PermissionDenied` when installed
but the person holds no grant. Shared conformance exercises both distinctions;
its optional `UnentitledToken` must name a fixture person with no roles or teams.
The local fixture includes `no-roles` in Acme for that case.

The suite proves it as a matrix: the fixture states, for each person at each
audience, which kind and action is allowed and which refused, and the suite asks
for exactly that scope and expects the answer. The local authority's fixture carries
two organisations, a person with no roles or teams and an automatically generated
developer role; the test kit's composition document installs a solution under
different roles in each. The host supplies its own matrix from its
own fixture. The suite requires a signed carrier and authenticated delivery
workload, with the paired authority document carrying the solution's roles.

The fixture names only the authority's own vocabulary. Each module states what
the fixture's roles may do at its kinds in a fragment next to its code, a
composition states only what is its own, and the run merges the fragments into
the versioned `fixture-composition` document
([what a composition adds to the fixture](modules/authority/services/local/README.md#what-a-composition-adds-to-the-fixture)).
The local authority also logs a delivery-time role × method report and
generates its local developer role from concrete delivered permissions. See
[local permission diagnostics](modules/authority/services/local/README.md#permission-diagnostics-during-local-development)
for the distinction between static coverage and runtime authorization.

## Delegate chains: a module inherits who it acts for

Owner's rule A of 2026-10-25, generic to every module that acts for someone (robin
and runtime first): a module holds no standing authority over anyone's data. Its
hop on a person's or an installation's token is owned by that principal, adds
the module to the actor chain, and derives its scopes for each target from the
owner's current grants intersected with the selected binding, capped by the
parent's per-kind limits. Dropped actions and restricted resource IDs stay
restricted even after an intermediate call to another audience. An explicit ask
that drops an entire current-target kind leaves a zero-action cap; disjoint
resource sets also leave that cap, never an unrestricted empty resource list.
A kind never visited can still be derived from the owner's current grants.

Authority scopes and replayed prior actors carry those limits across audiences;
the final actor receives only the current target's effective scopes. Carried
limits are not usable authority at that target. A service-owned context has no
person role to recover and retains only its existing authority through the
binding. A stored `Delegate` grant remains a complete ceiling: absent kinds,
dropped actions and named resource IDs cannot return. Every matching stored
delegation must still authorize the owner and actor. The target projection does
not replace that durable grant.
The child never outlives its parent. A module hops only on a
token addressed to it and names the binding it exercises. Revoking the person's
access, or changing the solution's role, revokes every delegate on the next call.
The suite proves it with a chain of three modules where the last hop gets a read
the person's first token never carried.

The shared `conformance.Fixture.ChildScopes` case proves exact effective target
scopes, exclusion of unrelated carried caps, a two-target stored delegation,
resource discovery, refusal to restore actions/IDs, and descendant revocation.
Each host must populate this fixture: an omitted case fails conformance.
`Fixture.ParentLimits` additionally proves action, resource and entirely dropped
kind restrictions across repeated audience round trips. Local issuer tests cover
disjoint target actions/IDs, service-owned attenuation, and revocation
interleavings. A missing, undeclared or misaddressed binding is refused before
verification can spend a single-use parent; binding seals use
`<organization>/<module>/<binding>`. SaaS must run this same
suite against its own real adapters before cross-host qualification is claimed.

## The hop: one door in front of a module (2026-10-23)

The hop is the authority module's second service. It stands in front of a module
and lets through only a call the authority checked. For each call it reads the
caller's Work Context, asks the interface's `Check` with the module's principal
as the audience, removes any stamp the caller sent, writes its own stamp, and
forwards the call as opaque frames. Its generated catalog snapshot identifies
each method's service and endpoint; it does not interpret permission requirements.
See [hop routing and upgrade requirements](modules/authority/services/hop/README.md).

The hop always listens on its declared HTTP endpoint, including in a
gRPC-only composition. An empty HTTP routing table does not remove that
endpoint from Codefly's readiness checks. Requests still pass through the
authority decision and are refused when no corresponding HTTP upstream exists.

The module behind it carries the interceptor from `libraries/hop/go`. It
verifies a short-lived Ed25519 admission bound to the exact method, audience and
token digest, authenticates the identity, and atomically consumes the call nonce
in a durable store shared by replicas. The hop alone receives the Codefly-generated
signing seed; modules receive its public key. See the breaking
[admission protocol and delivery migration](libraries/hop/README.md).

The hop and the edge ask the host the composition names in the `authority`
group's `endpoint`, the key every module reads for the same host, so pointing
that key at saas accounts' Connect listener moves them with the modules:
`host:port` and `http://` are the run's plaintext transport (h2c), `https://` is
TLS. A composition that names none reaches the authority module's local service.
Signed admissions require enforced method policy in every environment.
Legacy `hop/ENFORCEMENT=warn` configuration is refused with a reason.

This run's hop fronts the console, whose one operation answers who the call is
for. Run it from the playground workspace, `playground/`, which composes this
repository's modules with the platform's stores and the directory's page:

```bash
cd playground
codefly config generate hop-signing SEED --service authority/hop
codefly config generate internal-auth CODEFLY_INTERNAL_TOKEN
codefly run service console/api authority/hop --local-agents
```

The repository root is the authority module's own workspace and carries no run
configuration. A module's checkout root provides its configuration groups to
every workspace that composes it, so a root holding this run's groups forced
them on every composer: a workspace composing the authority could not name its
own edge routes or the modules its hop fronts. Each composer owns those groups
whole, as `playground/configurations/` does here.

Then sign a fixture person in, issue a Work Context for the console, and call
the console's `WhoAmI` through the hop's gRPC endpoint with it in
`x-codefly-work-context`. Proven live on 2026-10-23 with the CLI of
codefly-dev/cli#1128:

| Call | Answer |
|---|---|
| Maya's Work Context, through the hop | `maya`, `human`, `acme`, `console.identity:read` |
| No Work Context, through the hop | refused: carries no Work Context |
| Maya's Work Context, straight to the console | refused: did not come through the hop |
| A forged stamp, straight to the console | refused: did not come through the hop |
| Maya's Work Context with a forged stamp, through the hop | Maya, as the authority answered; the forged stamp is gone |
| A Work Context for another module, through the hop | refused by the authority: minted for another audience |
| Omar, who holds no role, asks for the console | refused at issue: holds nothing at this audience |

Every refusal through the hop is also in the hop's log, naming the module, the
method and the reason.

### Each method declares what a call must hold, and Check decides

The declaration is the authority's, not core's and not a host SDK's: the method
option `authority.hop.v1.policy` in `libraries/hop/proto`, generated by
`codefly generate proto`. A method either lists what the call must hold
(`requires`: actions on resource kinds) or says it requires nothing beyond a
checked Work Context (`any_checked_caller`). The console marks `WhoAmI`
(`console.identity` read) and `Version` (any checked caller), and its published
contract carries the marks.

The marks reach the authority in the delivery, and the authority decides:

1. **Delivery.** With the core manifest, the CLI delivers the authority's own
   document, `AuthorityManifestV1`: every method the module's published
   contracts serve, with what each declares. It is signed in the same envelope
   format by the same release key as the core manifest (`libraries/delivery/go`),
   and names that manifest's digest, module and generation. The authority
   refuses a document signed by another key or naming another manifest, and a
   delivery without one leaves the module with no method policy.
2. **Check.** `Check` takes the method. With it, the authority applies what the
   audience module's delivery declares and refuses by name: an action the call
   does not hold (saying what it holds), a method that declares nothing or both,
   a method the module does not serve. Without it, `Check` answers as before.
3. **The hop** asks `Check` with the method and passes the answer on. It holds
   no permission requirements and polls nothing. Codefly supplies its published
   route inventory; the selected destination and declared policy method travel
   together into the single Check decision.

A method requirement names a whole resource kind. Delivery rejects a method
requirement containing resource IDs instead of silently dropping its restriction.
A capability restricted to
resource IDs does not satisfy that requirement, even with a wildcard action;
several restricted scopes do not become a whole-kind grant. A whole-kind grant
alongside restricted scopes still satisfies its declared action. Refusals mark
resource-limited holdings in the diagnostic. `Advise` reports the same refusal
without widening or discarding the checked capability. An advisory result is
not sufficient to issue a hop admission.
Checking a capability without a method and reading its resource scope remain
supported. Modules still own resource visibility, ownership and installation
checks; method admission does not replace them.

Proven live on 2026-10-23 with the CLI of codefly-dev/cli#1128 at 13f7a3e3: the
console's delivery carries its signed document; Maya's `WhoAmI` and `Version`
pass through the hop on the delivered policy; `Check` answers an unserved
console method `NotFound`; and a check naming a method at a module whose
delivery carried no document is refused, while the same token with no method
named is checked as before.

The local authority passes the suite line that proves it ("a check naming a
method applies what the module's delivery declares"), which fails when `Check`
ignores the method. Each host must supply a signed authority document and prove the method cases;
an omitted signer fails conformance. Local results do not establish Accounts parity.

The console imports the option by copying `policy.proto` into its proto tree,
as every module in the fleet copies the option protos it uses. That copy is a
stopgap, codefly-dev/cli#1130: no Codefly library exports a proto, so the CLI
cannot import one module's option into another. A test fails when the copy
drifts.

Not yet:
- **A hop in front of every module.** One hop stands in front of the modules
  the composition lists in the `hop` group: `MODULES` (their principals) and,
  for each, `UPSTREAM_<MODULE>` (a `${endpoint:…}` reference the CLI resolves).
  A call goes to the module its Work Context is addressed to; a context for a
  module the hop does not front is refused before the authority is asked, and
  the authority refuses a method that module does not serve. This repository's
  `playground/configurations/local/hop.env` lists the console. Composing hops is the
  composition's job.
- **The interface, not the provider.** The SDK resolves an endpoint by its
  provider, so the hop names the local authority. An accessor by interface is
  an SDK change.
- **The cell face.** The same decision, called by the mesh's authorization step.

## The artifact interface: a person's consent to what a module runs (2026-10-24)

Robin runs an authored agent (a folder compiled to a configuration, a source's
imported bundle version) only after its host approved the exact artifact for
the installation, in person, and re-authorized it at each run; it asked the saas
host through accounts' module capabilities, and on the authority it refused to
start with either of its two artifact policies named. The authority now
implements that consent as a fifth interface, `host.artifact.v1.ArtifactService`
(proposal: handbook `proposals/2026-10-24-the-authority-approves-authored-artifacts.md`):

- `Approve(installation, policy, identity)` records the person's consent;
  `Authorize` answers the standing approval for a run; `Revoke` withdraws it for
  good. An identity is the module compiler's canonical export (schema, source,
  subject bytes, contracts, expected revision); the approval's digest is
  `sha256:` of its deterministic encoding, its name `host/approved-artifacts/<uuid>`.
- **A policy is a resource kind at the module**, nothing more: approving and
  revoking need its `activate` action, held by a person present (a human owner
  with no module acting between, in a context addressed to the asking module);
  a run needs its `run` action, which a delegated context may carry. What a
  person may approve is what their roles grant at the module, which the
  authority already decides, so there is no policy document and no second
  permission table. Robin's two policies both name `robin.intents`.
- **An installation names its namespace** (`Installation.namespace`, from the
  installation interface's `List`): `<organization>.<target>` for a module
  installed by composition, so a bound conversation's intent is
  `acme.robin/field-naturalist` and no module chooses which source an
  installation may run.

Approvals persist in the module's own store (`modules/authority/services/store`,
the `approvals` table), as accounts keeps its own in its store when it implements
the interface: consent is runtime state a person created, not fixture, and a
restart that forgot it refused every run of the approved artifact while the
consuming module kept its installation. A run that composes no store keeps
them in memory, and the local authority says which at boot
([the module page](modules/authority/README.md)). The fixture grants an Acme
admin `robin.intents:activate` and an editor `robin.intents:run`.

**Published as `codefly.dev/artifact@0.1.0`** (`interfaces/artifact`, 2026-10-27):
`host.artifact.v1.ArtifactService` with `Approve`, `Authorize` and `Revoke`,
the proto above unchanged. The local authority's grpc endpoint declares it
beside the other host interfaces; a host serving the same service declares it
the same way.

**One decision, in the shared core.** Who may decide is
`authority.DecideArtifact` over `decide.Artifact` (`libraries/authority-core/go`),
which every host calls before it reads or writes its own approvals; the
approval's digest is `decide.ArtifactDigest`. The definition, as the proposal
states it: the policy is a resource kind the module serves; approving and
revoking need the person present holding its `activate` action at the module,
a run its `run` action, held on the whole kind (a scope limited to some ids is
refused, since an identity names no resource of the policy), administrator or
not; the installation is the asking module's own, active, at the parent's
organization, and any other is refused alike (`decide.ForeignInstallation` for
another organization's or a missing one, so nothing of another organization is
learned); the source is the installation's namespace; the digest is `sha256:`
of the identity's deterministic protobuf encoding, so the revision is part of
what was approved; every answer carries the revision the approval was given
at. A request missing its policy or identity is `InvalidArgument`; every other
refusal is `PermissionDenied` with its reason.

`conformance.RunArtifacts` (`libraries/conformance/go/artifact.go`) is the
shared case both hosts run, over the published interfaces only, and the local
authority runs it in `plugins/registry_test/artifact_test.go`. Its fixture is a
module installed at one organization under one policy, an administrator and a
non-administrator approver holding the policy's `activate` and `run`, a member
holding `run` alone, another module's credential, and another organization's
administrator. Before this change the local authority answered `NotFound` for
another organization's installation and let a module name another module's
installation at its own organization; both are refused now.

## The edge: the browser's origin (2026-10-23)

The edge is the authority module's third service. It is the auth gateway's
role in a run without saas: the one origin a browser talks to, so a page or a
playground works the way a frontend does in a cell. A frontend sends a browser
with no session to `/auth/sign-in?return=<path>`, the host's sign-in page. It
lists the people the authority's fixture defines (the session interface's
`ListFixturePeople`; a host with a real identity provider lists none), and the
chosen one is signed in and returned to the path. The edge keeps the bearer in
an `HttpOnly`, `SameSite=Lax` cookie, so the page holds no token. Signing in
and signing out are writes: each must come from this origin, a return to
another site lands on the root, and a non-browser caller signs in with a JSON
`fixtureToken`.

`/auth/session` answers who is signed in (`personId`, `organizationId`,
`roles`), the `installations` the person may use, each `{id, target}`, which a
frontend binds its calls to (a robin conversation names its installation), and
`refused`, the reason for each other target. Both come from `Issue`, once per
module the edge routes, as a call to that module would: a target is usable when
the authority issues the person a Work Context there, and its id is the
installation the context is sealed to. A member reads this as well as an
administrator, so the installation interface's `List`, an administrator's read
a host refuses a member, decides nothing here. A person who holds nothing at a
target and an organisation that never installed it are each refused with the
authority's own words. `List` is asked only for each installation's
`namespace`, which no member's read carries yet, so the namespace is named for
whoever the host lets list. An installation id is a canonical UUID, as the host
issues, named by organisation and target so it is the same on every start: a
module's stored rows keep naming it.

Each call is routed by its path: `/v1/<module>/…` to the module's REST face,
`/<package.Service>/…` to its Connect face, and every other path to the
frontend. For a module call the edge issues a Work Context for the person at the
module (`Issue` with the module as the audience and no scopes, so the token
carries what the person's roles grant there). It caches the context until
shortly before it expires. It strips `Authorization`, `Cookie` and every
`x-codefly-*` header the browser sent, then sets `x-codefly-work-context`. The
module's faces dial the hop, which checks the method. A write authenticated by
the cookie must carry this origin in `Origin`. Each refusal names its reason.

The routes come from the composition (`playground/configurations/local/edge.env`) until
the authority's registry of composed modules serves them. The edge declares no
dependency on the modules it routes, so the run delivers their addresses as
`${endpoint:…}` references, never through an SDK query.

Proven live on 2026-10-23 with the records and document stores behind the hop:

| Call through the edge | Answer |
|---|---|
| No session | 401: sign in at `/auth/sign-in` |
| Remi signs in, lists record types over REST | 200 |
| Remi lists record types over Connect | 200 |
| The same Connect call with a foreign `Origin` | 403: a write must come from this origin |
| Omar, who holds no role, asks for records | 403: the authority refused this person at records |
| Maya (viewer) defines a record type | 403 from the hop: requires `records.types:define` |
| Maya sends a forged `x-codefly-hop-person: remi` | stripped; answered as Maya |

The document store's Connect face still transcodes in process at go-grpc agent
0.1.58, so a Connect call to it reaches the store without the hop's stamp and
is refused as unauthenticated: it fails closed, and works once the store is
synced to the agent whose Connect face dials the hop, as the record store is.

## The setup page: install a solution and grant its roles (2026-10-26)

`/auth/setup` on the edge is the run's installation screen, with the words of
the host's install dialog. An administrator sees the solutions the run delivered
(**Modules & solutions**). They review one, choose its **Agent role**, consent to
that exact version and install it. Under **Who may reach it?** they grant and
remove its roles for the organisation's people and teams. A person who is not an
administrator sees the authority's refusal and its reason.

The review is the mapping from a role to tools. For each role the solution
declares, it shows the role's scopes, confined to what the installation owns (or
to the resources attached to it). It lists every composed module operation those
scopes cover, from the delivered authority documents. For each operation it names
the Robin tools composed for it: the tool-exposed Connect bindings
`codefly generate runnable-bindings` prepared for that operation. Installing a
solution and granting a role is what makes those tools available to the people
granted it. An agent's intent declares which of them it uses. The authority still
decides every call from the person's current grants and the binding. No table is
maintained by hand: the page joins the authority's own records to the composed
bindings when the person reviews.

The read is `host.installation.v1.OfferService` (`ListOffers`, `ReviewOffer`),
served by the local authority beside `InstallationService`. It is not part of
`codefly.dev/installation`: a host answers its own product's reads, and
conformance is unchanged. `ReviewOffer` returns the consent tuple from the same
read as the roles it shows. The page posts that tuple to `Install` with a fresh
`operation_id`; a changed offer is refused and reviewed again. An install the
authority did not confirm keeps its exact request, so a retry is the same
operation. Changes are plain forms posted to the edge, from this origin only,
and sent through the generated clients with the person's own session.
[The edge page](modules/authority/services/edge/README.md#the-setup-page) has
the details.

### The Setup tab's Connect face (2026-10-27)

The edge serves the host's installation reads and changes (`InstallationService`
List, Review, ListRoleGrants, GrantRole, RevokeRole; `OfferService` ListOffers,
ReviewOffer) to the signed-in person over Connect, at
`/host.installation.v1.<Service>/<Method>`, the paths a hosted gateway serves, so
one Setup component calls either with the generated client. The edge sends each
with the person's session and decides nothing; a cookie call must carry this
origin and speak Connect, and no CORS header is set
([services/edge](modules/authority/services/edge/README.md#the-setup-tabs-connect-face)).

A member reads what the solution they use grants: the core's `ReviewOffer` answers
an administrator with the consent tuple, and a member holding a role on the
solution's active installation in their organization (granted to them or to a
team of theirs) with the same roles, operations, tools, ceiling and installation
and no tuple. Anyone else is refused by one reason, before the target is looked
up. `Review` (the tuple alone), `List`, `ListOffers` and the role grants stay as
they were.

## Which resources a context covers (2026-10-23)

`Check` answers for one call. Which resources of a kind a caller may touch,
such as the document collections a person reads, is the authority's other
question: `ListResources(token, audience, kind, action)`. It is decided at the
time of the call, from the owner's live grants, rather than carried in the
token, so tokens stay small and a new grant takes effect at once.

The answer is a list of grants. Each one covers every resource of the kind, one
id, an id prefix, or a whole-id RE2 pattern of at most 256 bytes. A resource is
covered when any grant matches its id. `libraries/resources/go` is the one
evaluation of grants, used by the local authority to validate its roles, by
the suite, and by any module deciding which of its own resources a caller sees.
The authority knows resources by id only; each module maps ids onto its own.

On the local authority a role's scope may carry `resources`. A scope with
none covers the whole kind. A scope with resources is never issued as the
whole kind (2026-10-26): its ids are the capability's resource ids, so an ask
naming none is issued on exactly those ids, and an ask naming any other id, or
the whole kind, is refused, at the root and at every hop. A token cannot carry
a prefix or a pattern, so one holds only the ids an ask (or the capability a
hop derives from) names that it matches, and an ask naming none carries none
of it. A person's answer is what her roles grant, cut to the ids her
capability names. A module's or an installation's own work is bounded by its
capability alone. A capability that does not hold the action is refused.

The suite line "the authority answers which resources a context covers, by
grant" holds an implementation to a fixture's covered and uncovered ids, an
unheld action, an empty ask that never carries the whole kind, and the refusal
of an ask naming an uncovered id or the whole kind. It fails on an
implementation that answers every resource or issues a resource-scoped role as
the whole kind.

Building it exposed an attenuation bug: the local authority's scope operations dropped
resource ids, so a capability asked for two named resources was issued for the
whole kind. They now keep ids, and an intersection keeps the narrower side
(`pkg/business/state`, with unit tests). The fixture's record kinds are now the
record store's own, `records.records` and `records.types`.

## The document store on the local authority, no saas (2026-10-23)

Proven live, with the document store from obin-ai/module-document-store's
`authority/behind-the-hop` branch (4e295b1) and the record store from its
branch (d506000), composed in this workspace with the local authority as host,
the hop in front of both, and no saas module:

| Call | Answer |
|---|---|
| Rémi (editor) creates `directory/people.csv` through the hop | created |
| Rémi lists the collection through the hop | his document: the store asked the authority which collections he covers |
| Maya (viewer) creates a document | refused at the hop: `CreateDocument` requires `documents:write`, she holds `documents:read, documents.collection:read` |
| Maya lists | nothing: the authority answers `directory/` and `shared-*`, and the store's namespace for this collection matches neither |
| Rémi lists over REST, at the store's REST face | HTTP 200: the face sends the call through the hop |
| The same REST call with no token | HTTP 401 from the hop, naming the gRPC method |
| Rémi's token straight to the store's gRPC port | refused: no stamp |

Every manifest reached the local authority through the composition interface.
The store's host services (jobs, notifications, approvals, record placement,
file fetch) report themselves unwired and idle, and ingest is off because no
runtime is composed. The fixture's collection grants do not yet use the store's
real namespace spelling.

## Delegated resource restrictions

A delegation preserves the exact resource IDs supplied in its WorkScopes.
Omitted IDs grant the whole kind, while named IDs remain a ceiling even when
the grantor and operation binding hold broader authority. Delegate,
GetDelegation, Issue, downstream children and RevokeDelegation preserve that
stored ceiling; requesting an ID outside it is refused. The child reconstructs
the target projection from the stored grant, not from the narrower previous
audience's projection.

Development fixtures use `resource_ids` on delegation scopes. The
`resources` matchers used by roles (IDs, prefixes and patterns) are a separate
contract and are rejected on delegation scopes rather than silently ignored.
The generated gRPC client regression covers the complete delegation lifecycle;
the fixture regression checks exact IDs and matcher-syntax refusal. These are
hermetic local authority checks, not full consumer or SaaS-provider qualification.

Revoking a delegation advances the organization's authorization revision in the
same state update. Previously issued capabilities, including descendants, then
fail the ordinary core verifier. This is deliberately conservative: outstanding
capabilities throughout that organization are invalidated, while other
organizations are unaffected. Ordinary authorized callers recover by requesting
fresh authority; the revoked delegation cannot issue again. Repeated, unknown
or unauthorized revocations do not advance the revision.

Issuance rereads the delegation after signing, and parent exchanges recheck the
original parent after signing, to prevent concurrent revocation from being
refreshed into new authority. Regressions cover existing-token checks, resource
discovery, descendants, tenant isolation and deterministic issuance interleavings.
This does not qualify the separate cross-audience attenuation or durable custody
contracts.

## Every saas module-authority feature, and where it lives now (2026-10-23)

A module's saas client (`saas-sdk-go/moduleauthority`) is replaced by this
interface and the hop. Nothing is dropped silently: each feature is either on
the interface, with a suite line, or named as belonging elsewhere.

| Saas feature | Where it lives now | Proven by |
|---|---|---|
| The module's own Work Context (`MintModuleWorkContext`) | `Issue` as the workload, through a binding | suite: a workload is issued its own binding |
| The module's operation context for one binding (`MintModuleOperationContext`) | the same `Issue` | the same line; the document store's embedder and trace export use it |
| A child of a caller's token (`ExchangeOperation` with a parent) | `Issue` with the parent token and the module as actor (`hop.Outbound.ForParent`) | suite: a child hop; a delegate chain |
| A lookup child (`ExchangeOperation` with `Lookup`) | `Issue` with `operation: lookup`: the binding's lookup scopes alone (`hop.Lookup()`) | suite: a lookup through a binding carries only its lookup scopes |
| A source's operation context (`MintSourceOperationContext`) and a child by delegation id (`ExchangeOperation` with `DelegationID`) | `Delegate` and `RevokeDelegation`, and `Issue` from a delegation (`hop.Outbound.ForDelegation`): owned by the grantor, the module as actor, re-checked on every issue, renewed by issuing again | suite: a delegation issues as its grantor through its module, until revoked |
| The live revision check that keeps delegation-backed work honest after its token expires (`CheckAuthorizationRevision` with the delegation's binding) | `GetDelegation`, read by the delegation's module (workload credential) or its grantor; anyone else is told it does not exist | suite: the same delegation line reads it standing, then revoked |
| Live seal and revision answers for a module verifying a token (`WorkContextSources`) | the hop asks `Check`; modules verify nothing | suite: a callee refuses what does not verify; the hop's tests |
| Which collections or resources a caller reads (saas `ListReadableSourceCollections`) | `ListResources`, by id, prefix or pattern | suite: the authority answers which resources a context covers |
| Executable artifact approvals (`Approve`, `Authorize`, `RevokeExecutableArtifact`) | not authority: the signed release (handbook#146) | open |
| Audit (`EmitAuditEvent`, `DeclareAuditEventTypes`) | not authority: an optional audit interface; with none injected, the module logs each event | the record store |
| Notifications (`NotifyUser`, `NotifyOrgAdmins`) | host services, optional interfaces | open |
| Current installation identity and authored namespace | `InstallationService.Current`, confined to the authenticated module in the parent organization | shared core and public RPC tests; host adoption pending |

The local authority supplies these cases. Each host must run the current suite
against its own provider; missing required fixtures fail. Earlier Accounts
results do not qualify later suite additions.

## Open decisions

- **Decided 2026-10-23, the hop rule.** A module hops only on a verified token
  addressed to it, and the hop names the binding it exercises. Current child
  derivation supports person and installation owners through their target grants;
  service-owned work remains bounded by its existing effective scopes. The
  target-projection and stored-delegation rules above state these distinctions.
  Core main `e501458995d05b641ed10e456fcb2837ff8b9f86` supplies action-specific
  scope containment; these dependency graphs require Go 1.27.3. The local authority
  and the suite state it; the host's `childHop` and its person issue follow
  (saas #1219 is the person half there). History:
  The host's `module_actor` mode (saas #1215) requires the person's parent to be
  sealed to the acting module's installation: the parent is addressed to the
  module acting for the person, and the module's hop names its binding to the
  audience it calls. That satisfies core as it stands. Recommended: adopt it as
  the hop rule here; the suite's hop then takes the parent at the acting module
  and names the binding, `issuer.child` checks the parent's audience is the
  actor's module, and the host's `childHop` does the same. Original note: Core keeps the owner's
  seal installation on a hop and requires a binding named on that hop to be
  granted within the same installation; a module's binding is granted within the
  module's own installation. So a module taking a hop on a person's context
  cannot name the binding it exercises, and the suite does not ask it to. The
  host today carries the hop's binding out of band, in the revision check's
  request. Either core lets a hop name a binding held in the exercising
  principal's installation, or bindings are recorded within the audience's
  installation; the suite states the hop's binding once one of these is taken.
- **What ApplyManifest carries (decided 2026-10-22).** The signed carrier:
  core's module manifest and the DSSE envelope over it, plus the delivering
  workload's credential (`SignedManifestV1`, `ApplyManifestRequest.carrier` and
  `.credential`). Each implementation verifies the envelope against the release
  keys it pins and reads the manifest from the verified document. The mini
  local authority pins the kit's release key and attests the carrier by the launcher's
  anchor; the host pins its release keys and attests the delivery service
  account. Public requests without a signed carrier and authenticated delivery
  credential are refused before composition or pending installation work. The
  old `manifest` wire field grants no authority. Trusted fixture seeding is a
  host-only state API. Not yet done: the host adapter behind it.

## Local service name (2026-10-25)

The development implementation is `authority/local`, with `grpc` and `rest`
endpoints. Module and solution playgrounds compose this local authority; the
platform composition uses SaaS locally as its authority interface implementation.
The edge and hop resolve `authority/local/grpc` when no `authority/endpoint`
configuration is supplied. Consumers must update service pins and endpoint
references together. The existing Go module import and protobuf wire identities
remain stable; they do not select the implementation in a composition.

The local issuer is `codefly.dev/authority/local`; compositions pinning an
expected issuer (including Runtime) must update that configuration alongside the
endpoint selectors. SaaS compositions keep their own issuer and host selection.

## Tool-call authority tests (2026-10-25)

An installation-owned `Issue` requires `actor.credential` from that installed
solution's workload. The host verifies it through the same workload verifier used
for ordinary module issuance, then checks that the authenticated module is the
installation's target solution. An installation ID or a signed-in person's
session alone grants nothing. Existing callers must supply the credential; the
shared conformance fixture now requires `InstalledCredential` as well.

The issuer tests and shared gRPC conformance suite exercise a module's binding to
an installed solution: the entitled person's root carries the binding scope,
the child preserves the person as owner and the module as actor, and a real
method-policy check succeeds. A person without the target entitlement cannot
obtain that permission, including when the child asks for its default scopes.
A solution target bounds the whole child by its person role and binding; ordinary
module-to-module derivation is unchanged. Hosts supply `SolutionTools` to run this
additional shared scenario; a missing scenario fails conformance.

An installation owner can cross successive module actors in its organisation.
The local seal source associates an active solution installation's agent with
active module installations in that same organisation. The acting module's
binding remains sealed to its own installation, and Core's binding/seal
verification is unchanged. The issuer still derives each target from the
original installation's current role and the binding; the seal association adds
no actions or resource rights. It does not associate an agent with another
solution installation or another organisation.

Issuer tests cover exact owner/actor provenance, resource restrictions, wrong
actors, source and actor uninstall, role/binding narrowing, and source uninstall
during issuance. Shared conformance hosts supply `InstallationChain` to prove
successive module hops; the local fixture crosses three actors. A missing
fixture fails conformance and is not evidence of provider parity. These are offline
authority tests, not a live solution or SaaS qualification.

Target-solution consent for installation-owned tool calls is **not implemented**.
The executable regression is deliberately behind the `pending` build tag:
`go test -tags pending ./pkg/business/issuer -run
TestInstallationToolRequiresTargetSolutionConsent` from the local service's
`code/` directory. It currently fails for direct issuance based on the source
solution's role alone; the two-hop case now also issues without target consent.
Neither result proves target consent. The
positive consent relationship and its revocation remain an authority contract
and implementation gap. No target-consent grant was invented, and Core's
binding verification was not bypassed to hide it.

## Interface evolution, 2026-10-25

`codefly.dev/authority@0.2.0` is the breaking successor to 0.1.0. Core's
interface evolution rules require a minor bump below 1.0. Installation Issue
requires its installed caller's workload credential; an installation ID alone
is never authority. Workloads name the work item's organization; the local
sole-installation convenience is not required of other hosts. Advisory Check
is a local diagnostic extension; the hop requires enforcing Check in every environment.

`codefly.dev/session@0.2.0` adds person and organization display names to Current
and SignIn (fields 7 and 8). Missing fields fail conformance. These implement the
[host interface use cases](https://github.com/obin-ai/handbook/blob/main/design/host-authority-interface/use-cases.md)
under the existing
[host interface proposal](https://github.com/obin-ai/handbook/blob/main/proposals/2026-10-22-the-host-authority-interface-and-the-local-authority.md).
All consumers and implementations must select the updated interface versions;
this repository updates its module, edge, hop and console declarations. SaaS
must adopt the version and fields before claiming this contract.

`codefly.dev/authority@0.3.1` adds `AttachResource` and `DetachResource`, and
`codefly.dev/composition@0.2.0` adds `RoleV1.installation_owned_scopes`: a role
scope held only on the resources its installation owns. The kind's one serving
module attaches a resource from a capability holding `create` on the whole kind
for a newly created resource. Existing resources change owner through
`AuthorizeTransfer`: the serving module attests the current owner and presents
a person's capability through the target installation. The existing policy
requires that person's live organization admin grant on the resource and write
through their target role, and refuses foreign owners, solution-principal
owners, agents, missing grants and wrong provenance by name. Only after those
checks succeed does the same transaction record the owned id. Admin-only
`AttachResource` is refused with `AuthorizeTransfer` named; ordinary solution
roles always retain their resource-owner selector. A resource has one owner per organisation,
an installation owns at most 32 of a kind at a time, and the serving module
detaches what it deletes and rolls back a create whose attach is refused. Both
are additive. The local authority implements authority 0.3.1 and composition 0.2.0; the edge, hop and
console call nothing new, so they require `>=0.2.0 <0.4.0` and resolve against
a host still at 0.2.0. Shared conformance requires `InstallationResources`, so
a host must implement both before it passes.

The local authority keeps installation ownership in memory, for development
only: a restart (a hot reload included) re-derives installations from the
fixture but not what they own, so viewers lose owned resources until the store
reconciles them through the authorized creation or transfer path. A host keeps ownership durably.

The installation-owned resolver and ownership transactions live in
`libraries/authority-core/go`, alongside the ordinary role resolver. Hosts
persist `domain.Module.OwnedRoles` and `domain.Installation.Owned` through the
shared Store contract. Ordinary roles retain main's resource-owner selection;
installation-owned rows contain only attached ids, and an empty owned set emits
no grant. The local host is an adapter to that core. Accounts adoption and
its durable adapter are not qualified by a local authority test.

`codefly.dev/authority@0.3.2` adds `KeysResponse.admission_keys` and
`PublicKey.purpose`: `Keys` publishes the hop's admission verification keys
(purpose `hop-admission`) beside the Work Context keys (purpose
`work-context`), and every verifier takes the admission keys from the `Keys`
read it already caches and refreshes, so no consumer is configured with a hop
public key. The admission keys are a field of their own, never entries of
`keys`, so a verifier that reads `keys` alone (an earlier release, or the JSON
Web Key Set) can never trust a hop key to sign a Work Context. More than one is
published while a hop key rotates. It is additive, so `>=0.2.0 <0.4.0`
consumers admit it; a host that publishes no admission key leaves every hop
admission refused (`keys_unavailable`), so `accounts` must publish its hop's key
before a cell's modules adopt this verifier.

`codefly.dev/authority@0.3.3` adds `RegisterAdmissionKey`: the hop presents its
public key under its own workload credential (it declares `module-identity`),
the authority refuses any other workload by name, and `Keys` publishes the key
until its registration lapses (`AdmissionLease`, two minutes) unless the hop
renews it, which it does while it runs. A restarted authority therefore learns
the key again at the next renewal, a restarted hop re-registers the same entry,
and a key no running hop signs with is withdrawn without being named. The seed
never leaves the hop; nothing about the hop is configured on the authority. It
is additive too. The local authority implements it; `accounts` implementing the
same registration is follow-up work in the host. The hop calls it, so the hop
requires `>=0.3.3 <0.4.0`: a host below 0.3.3 is refused at render instead of
leaving every module's verifier to refuse every call.

`codefly.dev/authority@0.3.4` hardens the registration. The authority pins one
admission key per hop instance (the instance the hop's workload credential
names): the first registration for an instance binds its key until the lease
lapses, the same key renews, and any other key for that instance is refused by
name. So a captured hop credential cannot replace or add a key for an instance
that has registered. It is not a key binding: a holder of a captured credential
who registers before that instance's first registration (the hop registers at
boot), or after an authority restart (pins are in memory) and before the hop's
next renewal, pins its own key, and the hop's registration is then refused by
name in its log. Closing that window needs the launcher to bind the key in the
credential at issuance. Each registration also carries
`RegisterAdmissionKeyRequest.proof`, an Ed25519 signature by the key it
registers over the authority's audience, the SHA-256 of the presented
credential, the key and a fresh nonce and second (`stamp.ProveRegistration`,
`stamp.CheckRegistration`): it proves possession of that key and stops a
replayed, retargeted, stale (over 30 seconds) or credential-swapped
registration, but since the registrant chooses the key it does not by itself
prove the registrant is the hop. A hop attested in any trust domain but the
host's (the one the run's anchor declares its workloads under) is refused. The
field is additive on the wire; an authority at 0.3.4 refuses a 0.3.3 hop's
unproved registration, so the hop and the authority move together. A key
rotation is a new hop instance with the new seed, overlapping the retiring one
until its lease lapses; a new seed under the same instance (a hop restarted
within one run keeps its instance) registers once the previous key's lease
lapses, within two minutes of the hop's retries.

The 0.3.1 authority version is an additive pre-stable revision selected for
this refresh so existing `>=0.2.0 <0.4.0` consumers admit it. It retains 0.3.0's
`AuthorizeTransfer` and adds attachment operations. Composition remains 0.2.0.

## Current installation metadata for a module

The installation interface advances to `0.3.0` for this additive capability.
The in-repository edge accepts it; external compositions constrained below
`0.3.0` need explicit consumer adoption before selecting this provider.

`InstallationService.Current` accepts the caller's parent Work Context and the
module's independently authenticated workload credential. Shared core verifies
the parent for that module and returns only its active installation in the parent
organization. A delegated child is sealed to its source actor; that seal is
verified, never mistaken for the destination module installation.
The projection contains id, organization, target, revision and authored namespace;
it exposes no roles, grants or other installations. There are no tenant or
installation selectors. It is a current metadata read, not content access,
artifact consent or a lease; artifact approval and authorization remain separate.
`List` remains administrator-only. Invalid credentials, foreign audiences and
revoked authority refuse instead of returning an empty namespace.

The scoped contract is carried by the handbook
[installation and intent-selection decision](https://github.com/obin-ai/handbook/blob/main/decisions/authored-installation-and-intent-selection.md)
(handbook#403).
Shared-core tests exercise tenant/audience isolation and revocation; the shared
conformance suite exercises the generated public RPC. Accounts must adopt this
method and pass that suite before its consumer deployment is qualified.
