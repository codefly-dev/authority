# authority

**What we are doing.** Making it certain that the small gateway a developer runs
on a laptop and the real gateway in the host implement the same authority
contract, so a laptop refuses exactly where a cell refuses.

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
   (done; `interfaces/`, `modules/authority/services/gateway/proto/obin/*/v1`).
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
