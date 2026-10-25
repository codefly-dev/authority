# gateway

The development implementation of the host interfaces, one process: it signs
fixture people in with their roles, issues and verifies Work Contexts, knows the
composition from the manifests the run delivers, and answers the installation
and artifact interfaces. The repository's [README](../../../../README.md) is the
story and the rules; this page is what the process keeps and where.

| State | Where | Across a restart |
|---|---|---|
| who exists, what they hold, what is installed by fixture | `code/fixtures/<name>.yaml`, selected by the run | re-read: fixture, not state |
| the composition: each module's manifest, generation and bindings | memory, re-delivered by the run | re-delivered |
| sessions, delegations, installations made at runtime | memory | forgotten |
| **approvals**: a person's consent to one exact artifact for one installation | **the module's [store](../store/README.md)**, `approvals` table, when the run composes it; memory otherwise | **kept**: a run of the approved artifact is answered after a restart, and a revoked one stays refused |

**How it chooses.** `code/work.go` (`approvalsFor`) reads the store's
`postgres/read-write-connection` secret through the SDK. Delivered: approvals
are `pkg/infra/postgres`, as the runtime role `app_authority` (read, insert,
update, never delete), and the boot log says `approvals persist in the
authority's store`. Not delivered — `go test` through `pkg/business/testkit`, or
a run that selects the gateway without the store — approvals are
`state.MemoryApprovals`, and the boot log says so. A delivered connection that
does not answer refuses to boot: the store was composed, so a gateway that
forgot consent would be the wrong gateway. Both implementations pass
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

## Permission diagnostics during local development

The local fixture's `developer` role uses `generated: true` and declares no
scopes. The gateway replaces its scopes after each delivery with the explicit
union of currently delivered module kinds/actions. Method requirements contribute
to that catalog; explicitly declared non-method ceilings remain supported during
migration. A new delivery can remove an action as well as add one. The generated
role does not assign itself to anyone and does not change business roles or
solution installation roles. This is fixture behavior in the development gateway.

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
consume the context; the original session remains unchanged. The local Globex
administrator explicitly holds `documents.collection:read` alongside document
read/write; the role name itself implies no additional grants. Issuer regressions
and the shared fixture matrix cover this grant and a person who lacks it.

## Signed delivery lifecycle

The signed-carrier path retains Core's verified manifest and its paired authority
policy. Core decides host coordinate, domain continuity, generation replay and
terminal withdrawal; the gateway applies that decision and its permission
projection together. The host declares the `federation` workspace configuration
and reads `SOLUTION_HOST_COORDINATE` through the SDK. A carrier cannot select the
coordinate against which it is checked.

An identical replay returns the original receipt without advancing revisions or
reapplying grants. Changing, adding or removing the authority policy at the same
generation is refused. Once an alias is delivered as a signed carrier, the
transitional unsigned sketch cannot overwrite or resurrect it. Sketch-only
composition retains its existing strictly newer generation rule.

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
