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
