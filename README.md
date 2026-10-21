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

**Order of work.**

1. Declare the interface and give it its proto, taken from core (the Work Context
   types) and from the host (the two services), with every message, field and
   field number unchanged; only the package is `obin.authority.v1`. Done; `buf
   build` passes under `interfaces/authority/proto`.
2. Build the mini gateway against it, with the conformance kit as a required test.
3. Point the host and the SDKs at this package and delete the copies in
   `codefly-dev/core` and the host, in that order, the fixtures proving identical
   bytes at each step. Nine Go modules import core's authority packages today;
   none moves before the mini gateway proves the interface.

**Agent gap (2026-10-21).** The go-grpc agent (0.1.58) generates its adapters for
the single service in `proto/api.proto`; the interface's services in
`proto/obin/authority/v1` get bindings from `codefly generate proto` but no adapter,
so the gateway does not yet serve them. Wiring them by hand in `pkg/adapters` would
be the local pipeline the development contract forbids. The fix is in the agent:
generate adapters for every service under `proto/`, or for what the module's
`interface.implements` names. Filed against the agent when the owner says so.

Known lint debt: the four module-authority messages carry no doc comments, as they
did not in the host; `buf lint` says so and the next change writes them here.

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
