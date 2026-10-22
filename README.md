# authority

**What we are doing.** Making the interface the mapping between local development
and deployment. The small gateway a developer runs on a laptop and the host's
accounts service implement the same declared contract, checked by the render and
proven by one suite, so what passes on the laptop is what runs on the cell and
what refuses on the laptop is what refuses on the cell. Without the interface
that mapping is a hope; with it, it is a test.

This repository holds two things, and only these two:

1. **The host authority interface** (`interfaces/authority/interface.codefly.yaml`):
   a Codefly interface declaring what a module or solution calls on the host that
   runs it. Issue a Work Context for a person, an installation or a module's own
   binding; re-address, derive a child, renew; check a revision live; the current
   installation. The host's `accounts` service implements it in full. A module
   depends on the interface, never on a service.
2. **The mini gateway** (`modules/authority/services/gateway`): the development
   implementation. One process that signs in fixture people with their roles,
   issues and verifies Work Contexts, knows the composition from the rendered
   manifests, and holds the fixture installations in memory. No accounts
   service, no stores, no platform frontend. Running a solution locally is the
   solution, the modules it consumes, and this.

**What keeps the mini gateway from being a second authority.** It links the same
packages `accounts` uses to sign in, mint and derive a module's grant from its
manifest, and the conformance kit runs against both implementations in one test.
It is a profile of the host, not a reimplementation. If a package of `accounts`
cannot be linked without its store, the package is split in the host; nothing is
copied here.

**What this repo is, in one line.** The interfaces the host's saas component
MUST satisfy, with the suite that proves it, and the development implementation
that satisfies them on a laptop, fixture included.

**Order of work.**

1. Declare the interfaces and give them their protos, reduced to the six duties
   (done; `interfaces/`, `modules/authority/services/gateway/proto/host/*/v1`).
2. Build the mini gateway against them with the suite every implementation must
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
  child for the runtime, actor documents, nothing widened. 6 The wiki reconciles
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
authority/gateway/grpc --language go,python` writes two Go packages (`api` from
the scaffold's proto, `authority` from ours) into one facade directory and fails
its own build; the Go and Python clients that would replace the solution SDK wait
on that fix.

**Where the thinking is.** The Platform Authority Primer (decisions 6 and 7) and the
handbook proposal that will carry them. Run it with `codefly run` from the module.

## What the mini gateway must serve, read from the callers (2026-10-21)

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
| What a module may hold | derived from the manifest; today `GET`/`PUT /v1/platform/module-envelope`, which the mini gateway does not serve |
| The module's workload becomes a principal and gets Work Contexts | gateway workload endpoint: `POST /modules/_work-context` (for a person), `/modules/_operation-context` (the module's own binding), `/modules/_source-operation-context` (a source delegation) |
| The module calls the host as itself | Connect proxy at `/modules/_authority` → `ModuleCapabilitiesService`: `ExchangeDelegatedOperationAudience`, `EmitAuditEvent`, `DeclareAuditEventTypes`, `AuthorizeExecutableArtifact` / `ApproveExecutableArtifact`, `NotifyUser` / `NotifyOrgAdmins` |
| Person-owned authority | `WorkContextService`: `StartTask`, `ExchangeAudience`, `StartChildSession`, `RenewWorkContext`, `CheckAuthorizationRevision`, `StartInstallationTask`, `AuthorizeEvidenceRead`, `ConsumeSingleUse` |
| A module route carries a viewer | `/v1/<alias>/*` through ext_authz, stamped `x-user-id`, `x-org-id`, `x-org-role`, `x-platform-role`, `x-scoped-roles`; the viewer Work Context per module call is decision 4 of the primer |

**Phase 2, a solution**

| Need | Host surface today |
|---|---|
| The solution registers its backend and page | `/modules/_register`, `/modules/_registration-token` (gateway `gateway_module_routes.go`); `/.well-known/solution.json` and `/.well-known/capabilities` served by the runtime and proxied |
| Routes to the solution | `/solutions/<id>/*` (gateway), `/api/solutions/<id>/proxy/*` (frontend), module-federation assets, the registry snapshot, the 120 s lease |
| Who may use it | `ListSolutionEntitlements` (gateway `handleSolutionEntitlements`); `InstallationService`: `InstallSolution`, `GrantInstallationToTeam`, `ListInstallations`; installations come from the fixture file |
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
Composition: `ApplyManifest`. Installation: `Install`, `GrantToTeam`, `List`, and
the install step callback. Sign-in at the browser edge only. Routing is the data
plane, not a contract. 0.1.0 mirrors today's spellings so the mini gateway serves
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
| 0 | the mini gateway holds | 47 tests here: byte identity, core's kit, scenario, `pkg/conformance` over gRPC | green (done) | this repo |
| 1 | one contract, two implementations | accounts implements the four interfaces as adapters over what it does; saas CI runs `pkg/conformance` against it with the saas fixture | same codes, same reasons on both | module-saas-starter |
| 2 | a module cannot tell which answered | documents takes the generated authority client and requires the interface, not a service; runs against the mini gateway and against accounts | identical tests, playground and refusals; the render picks the implementation | module-document-store, saas-sdk-go |
| 3 | a solution needs no runtime | the wiki as an agent-scaffolded service on the generated clients; wiki + documents + mini gateway, then the full host locally, then obin-staging; the eight steps through the UI | the scenario passes end to end; no envelope, anchor or audience key anywhere | core-solutions |
| 4 | the laptop refuses where the cell refuses | recorded request vectors replayed against both, compared field by field; property tests on the four ways a token widens; replay, expiry, revocation, forgery; one independent security review | zero divergence, zero widening, findings closed | this repo + reviewer |
| 5 | it is fast | clean clone → Maya sees the wiki, one command, timed; a grep gate against envelope files and audience keys | the owner's number; gate green fleet-wide | cli, handbook |

Exit for the deletions (core's authority packages, the CLI's cluster path and host
knowledge, solution-runtime-go, the audience spellings): rungs 1–5 green and
staging validated.

**Rung 1 first; it is the one that matters (owner, 2026-10-21).** The loop:

1. Cut a branch in module-saas-starter. accounts declares in its module
   interface that it implements `codefly.dev/authority@0.1.0`, `codefly.dev/composition@0.1.0`,
   `codefly.dev/installation@0.1.0` and `codefly.dev/session@0.1.0`, takes this repo's
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

**What the second implementation taught the interface.** `GrantToTeamRequest` gained `organization_id`: the host checks an administrator against the organisation before it reads the installation, so the request must name it; the mini gateway now refuses a grant naming another organisation than the installation's, and the suite asserts it. That is what a second implementation is for.

## The namespace, settled (2026-10-22)

The interfaces are the host's contract, so they carry the host's names: publisher
`codefly.dev` (ids `codefly.dev/authority@0.1.0`, `composition`, `installation`,
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
(interfaces, mini gateway, host adapters on a branch; protos and policy exist
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
Install. The mini gateway attests core's native launcher credential against the
launcher's anchor; nothing of its own. The person shape is the caller's bearer;
`PersonSession` is empty. See the handbook's audit sidecar for the reasoning.

## Moved to codefly-dev (2026-10-22)

The repository is `codefly-dev/authority`: the interface is the host's, published as
`codefly.dev`, and the host may import from here (its naming gate refuses a
consumer's organisation in an import path). GitHub redirects the old location.
`libraries/authority-client/go` is the generated Go bindings library
(`codefly generate client --no-facade`), importable as
`github.com/codefly-dev/authority/libraries/authority-client/go`. The Python
library did not generate: the client generator lacks the protovalidate dependency
the Work Context messages import (reported on codefly-dev/cli#1107).

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

## Open decisions

- **A cross-module hop and its binding (2026-10-22).** Core keeps the owner's
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
  gateway pins the kit's release key and attests the carrier by the launcher's
  anchor; the host pins its release keys and attests the delivery service
  account. The sketch (`manifest`) stays through the transition and is ignored
  when a carrier is present. Not yet done: the host adapter behind it.
