# local authority

The development implementation of the host interfaces, one process: it signs
fixture people in with their roles, issues and verifies Work Contexts, knows the
composition from the manifests the run delivers, and answers the installation
and artifact interfaces. The repository's [README](../../../../README.md) is the
story and the rules; this page is what the process keeps and where.

**A host over the core.** Every decision and every signature is the generic
authority core's (`libraries/authority-core/go`), over its in-memory store
(`memstore`): modules, installations, role grants, delegations, revisions and
issuance. This service keeps what a host owns: the fixture and its sign-in
tokens (`pkg/business/state` seeds the core's store from them), sessions,
workload attestation against the launcher's anchor, signed delivery
admission, method admission on `Check`, and approvals. The plugins translate
the wire to the core's calls (`pkg/business/issuer`, `plugins/installation`).

Request-facing installation methods require a person value and current stored
authority. Trusted fixture setup and teardown use the separate `InstallAsHost`
and `UninstallAsHost` methods; a missing or unauthenticated person never selects
host power. Module installations remain composition-owned after withdrawal.
Role calls answer as foreign when the caller is neither administrator nor
installer, including for an installation in their own organization.

Child issuance preserves the verified parent's workspace/project identifiers
and each prior actor's agent/organization identifiers while deriving the new
target's grants. These fields remain absent when the parent omitted them;
replaying an actor does not substitute the task's organization for that actor's.
The shared core's `TestChildPreservesVerifiedTaskAndActorProvenance` exercises
populated parents through its production minter, child issuance and Check over
two exchanges, including action/resource limits. The ordinary Issue request
does not originate these optional fields. This test does not establish a live
populated-parent fixture or cross-host conformance coverage.

| State | Where | Across a restart |
|---|---|---|
| who exists, what they hold, what is installed by fixture | `code/fixtures/<name>.yaml`, selected by the run | re-read: fixture, not state |
| the composition: each module's manifest, generation and bindings | memory, re-delivered by the run | re-delivered |
| sessions, delegations, installations and role grants made at runtime | memory (the core's `memstore`) | forgotten |
| **approvals**: a person's consent to one exact artifact for one installation | **the module's [store](../store/README.md)**, `approvals` table, when the run composes it; memory otherwise | **kept**: a run of the approved artifact is answered after a restart, and a revoked one stays refused |

**How it chooses.** `code/work.go` (`approvalsFor`) reads the store's
`postgres/read-write-connection` secret through the SDK. Delivered: approvals
are `pkg/infra/postgres`, as the runtime role `app_authority` (read, insert,
update, never delete), and the boot log says `approvals persist in the
authority's store`. Not delivered — `go test` through `pkg/business/testkit`, or
a run that selects the local authority without the store — approvals are
`state.MemoryApprovals`, and the boot log says so. A delivered connection that
does not answer refuses to boot: the store was composed, so a local authority that
forgot consent would be the wrong local authority. Both implementations pass
`pkg/business/approvalstest.Contract`.

**Tests.** `go test ./...` runs everything in memory. The Postgres suite
(`pkg/infra/postgres`) runs when `AUTHORITY_STORE_TEST_DATABASE_URL` names a
Postgres whose login may create databases: it creates one per test, applies the
store's migration and acts as `app_authority`; unset, it skips and says why.

```bash
AUTHORITY_STORE_TEST_DATABASE_URL='postgres://postgres:…@127.0.0.1:5432/postgres?sslmode=disable' go test ./...
```

Generated code (`pkg/gen`, `*_gen.go`, `main.go`) comes from `codefly generate`
and the agent; `work.go` and everything under `pkg/business`, `pkg/infra` and
`plugins` is written here.

## The setup read

Beside the installation interface the local authority serves
`host.installation.v1.OfferService` for the edge's setup page. It is an
administrator's read and grants nothing:

- `ListOffers`: the delivered solutions. Modules are installed by composition
  and are never offered.
- `ReviewOffer`: one solution's roles, the composed operations each role's scopes
  cover (from the delivered authority documents), and the tools composed for
  those operations, read with its consent tuple in one transaction.

The tools come from the workspace group `runnable-bindings`, read through the
SDK as a tool caller reads it. Only Connect-callable bindings with a tool
exposure whose invoke and lookup scopes the role covers are listed, one per tool
name, Connect endpoint first. A run that composes no bindings says so
(`tools_composed: false`) rather than listing none. The local authority does not
declare the group: declaring it would give it authority bindings of its own.

## What a composition adds to the fixture

The embedded fixture (`code/fixtures/local.yaml`) says who exists and which
organisation roles they hold, in the authority's own vocabulary only
(`console.identity`). It names no module's kinds, no solution and no stand-in
module. What the fixture's roles may do at a module is that module's to say,
once, next to its code; what is truly a composition's own (a collection its
seed writes, an installation of its solution) is the composition's. Both are
**fragments** of the workspace configuration document `fixture-composition`:

- a module ships `configurations/<profile>/fixture-composition.yaml` in its own
  directory: the grants of the fixture's standard roles (viewer, editor, admin,
  …) at that module's kinds, and nothing about any other module;
- a composition ships the same file in its own module's directory, for what
  only it knows: the seeded collection a viewer reads, by id.

```yaml
schema: codefly.dev/authority/fixture-composition/v1
roles:          # grants added to roles the fixture defines
  - organization: acme
    name: editor
    scopes:
      - {kind: ledger.entry, actions: [read, write]}
installations:  # installations of a solution the run composes, the fixture's own path
  # role: the installation's own (its agent's) role; owner: who installed it,
  # granted the installer role; teams: each granted role on the installation.
  - {organization: acme, target: atlas, role: viewer, owner: alex, teams: [finance]}
modules:        # a module the run supervises itself, until its own delivery
  - module: oracle
    kinds: [{kind: oracle.answers, actions: [read]}]
```

**The run merges them.** Before the local authority boots, `codefly run`
merges the fragment of every module the workspace composes into the
workspace's own `configurations/<profile>/fixture-composition.yaml`, which the
local authority reads (`codefly generate fixture-composition --env local` does
the same on its own). That file is generated: it says so in its first line and
is never committed. A hand-written one is never overwritten: `codefly generate`
refuses, and `codefly run` reads it as it stands and says that no module's
fragment is applied until it is deleted. The merge
rules are this repository's, in [`libraries/fixture-composition`](../../../../libraries/fixture-composition/go/README.md),
the one parser of the document:

- every statement has exactly one source: a role's grant on one kind, one
  installation, one stand-in module. Two fragments stating the same one are
  refused naming both, even when they agree, so a composition narrowing a
  module's grant to its seeded collection is never silently widened by the
  module's, and a module's grant copied into a playground is refused rather
  than left to drift. One **fragment** stating the same one twice is refused
  too, and for the same reason: the grants of a kind are a union, so a file
  granting `{id: seeded}` and again `{all: true}` widens exactly as two files
  would;
- the result does not depend on the order fragments are found in.

**What the merge does not enforce: ownership.** A statement is keyed by
organisation, role and kind alone, never by which module ships the fragment, so
a module's fragment *can* grant at another module's kinds — and a composition's
fragment does, by design: the robin playground grants its viewer
`documents.collection` on the collection its own seed writes, a kind the
document store owns. "One definition per module" is therefore a convention
about where a grant is written, enforced only in that two fragments cannot
state the same grant; it is not a check that a module grants on its own kinds.
Nothing is lost by that: these fragments reach the development fixture alone,
never a host, and a grant at a kind no composed module serves resolves to
nothing (the authority intersects every capability with the delivered
manifests), so the failure mode is a refusal, not a widening. A composition
that wanted ownership enforced would have to name each kind's owning module in
the document, which v1 does not.

The authority module's own fragment
(`modules/authority/configurations/local/fixture-composition.yaml`) is the
schema line alone, so a composition of the authority and nothing else boots
on the fixture alone.

**The contract.** The `schema` line versions the document. Its sections, and
the fixture's organisation, role and person ids it names (`acme`, `globex`,
`viewer`, `editor`, `admin`, `alex`, …), are a contract with every composing
repository. A breaking change is a new schema version, never an edit to v1.

**What is refused.** Each of these refuses the merge or the boot by name and
changes no role:
- an empty or null document, a section spelled `null`, an unknown field, or a
  schema other than v1;
- an entry naming a role the fixture does not define, or the generated
  `developer` role (it is derived from the delivered catalog);
- no scope, or a scope with no action;
- a wildcard kind or action (`*`): a composition grants the concrete
  permissions its modules serve, so viewer, editor and administrator stay
  distinct;
- a kind or action outside the grammar, surrounding whitespace included;
- a malformed resource matcher;
- an installation whose organisation or owner the fixture does not define;
- two fragments stating the same grant, installation or stand-in module.

The boot log names each effect, for example `the composition grants
acme/editor: ledger.entry:[read write]`, or says that the composition adds
nothing. The local authority refuses to start in a pod.

## Permission diagnostics during local development

The local fixture's `developer` role uses `generated: true` and declares no
scopes. The local authority replaces its scopes after each delivery with the explicit
union of currently delivered module kinds/actions. Method requirements contribute
to that catalog; explicitly declared non-method ceilings remain supported during
migration. A new delivery can remove an action as well as add one. The generated
role does not assign itself to anyone and does not change business roles or
solution installation roles. This is fixture behavior in the development local authority.

Every successful composition delivery logs a sorted role × module-generation ×
method report. It names uncovered requirements, unrecognized fixture actions and
kinds unresolved in the currently delivered composition. These are diagnostics,
not a demand that every role may call every method. Static coverage still needs
valid identity, active installation, consent where required and resource checks.
An absent method policy remains a named local refusal; contradictory or malformed
policy is rejected when delivered. Offline deployment validation uses the same
policy validator in the delivery library, requiring explicit method declarations.

`go test -race ./...` in `code/` includes replacement/removal and fixture coverage
regressions. This does not qualify the production host or live browser journeys.

Person issuance sorts and deduplicates a copy of the session's team attribution
before signing. Fixture order therefore does not affect a module's ability to
consume the context; the original session remains unchanged. A role name implies no
grants: the test kit's composition
(`code/pkg/business/testkit/testdata/composition.yaml`) gives the Globex
administrator its collection read explicitly. Issuer regressions and the shared
fixture matrix cover that grant and a person who lacks it.

## Signed delivery lifecycle

The signed-carrier path retains Core's verified manifest and its paired authority
policy. Core decides host coordinate, domain continuity, generation replay and
terminal withdrawal; the local authority applies that decision and its permission
projection together. The host declares the `federation` workspace configuration
and reads `SOLUTION_HOST_COORDINATE` through the SDK. A carrier cannot select the
coordinate against which it is checked.

An identical replay returns the original receipt without advancing revisions or
reapplying grants. Changing, adding or removing the authority policy at the same
generation is refused. Every public composition call requires a signed carrier
and the authenticated delivery workload; unsigned manifests are refused before
any host operation, including pending fixture installations. Trusted fixture
setup uses the host-only state API and cannot overwrite a signed alias.

A workload must still be declared by the current signed manifest to obtain new
authority. Withdrawal removes the module and its principal, revokes its
installations and alias-scoped delegations, and retains a terminal binding record.
Repeating withdrawal has no additional effects. Pending fixture installation
work remains attached to its admitted delivery: replay resumes the same convergent
installation step after failure or cancellation. Completion is serialized per
binding, outside the state lock; a superseded or withdrawn attempt cannot
acknowledge an installation or expose it to teams. Cancellation does not undo
already-applied declarations or external installation effects.

**Compatibility limits.** Existing installation UUIDs remain stable. This process
explicitly refuses a new binding reusing an already-admitted alias, even after
withdrawal, and refuses renaming the alias of a binding. Supporting those
transitions requires an installation-identity migration that preserves existing
stored rows without transferring them to a replacement. Signed records and
tombstones currently live in memory: restart forgets them. This does not prove
anti-resurrection or persistent consumer-data isolation across changed bindings
and restarts. Full alias replacement, durable history and production accounts
parity remain unfinished; local lifecycle tests do not qualify those behaviors.

Installation-owned Issue verifies an explicitly supplied `organization_id`
against the installation's organization, as well as authenticating the installed
solution workload. Omitting the organization uses the installation's own tenant.
A pending installation cannot be granted to a team: its install step must first
acknowledge it. Shared conformance observes the pending state while that step is
blocked, then verifies exposure after acknowledgement and refusal after revocation.
See `libraries/conformance/go/README.md` for the complete host comparison contract.

Workloads name the organization of the work item. The local convenience of
omitting it works only for a sole active installing organization; it is not a
shared host requirement. Method admission checks kind/action while preserving
resource limits for the module's resource check. The hop refuses `ENFORCEMENT=warn`
unless the SDK identifies the environment as local; advisory conformance is
explicitly enabled only by the local runner.

HTTP Check uses the concrete verb and canonical path, with literal precedence
and ambiguity refusal over the delivered manifest. Published Connect calls use
the protobuf procedure spelling; a dotted HTTP URL cannot borrow gRPC policy.

## Artifact consent admission

Approve, Authorize and Revoke check effective scope coverage against the target
installation's stored principal before accessing approvals. An owner-selected
capability cannot access another installation's consent. Module installations
without a solution principal require owner-unrestricted coverage. Artifact identities
must name that installation's host-defined namespace as their source.

The policy resource id is not established by the opaque identity subject or an
approval id. Resource-limited scopes are therefore refused with that reason;
consent requires the policy action over the installation owner's whole kind.
The shared scope algebra enforces both owner and resource restrictions.
