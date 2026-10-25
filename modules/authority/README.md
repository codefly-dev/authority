# authority — the module

The host authority on a laptop: four services, one module, composed by any
workspace that runs modules with no saas. The repository's [README](../../README.md)
is the story; this page is what each service is and what each keeps.

| Service | What it is | What it keeps, and where |
|---|---|---|
| [local](services/local/README.md) | the development implementation of the host interfaces (authority, composition, installation, session, artifact): signs fixture people in, issues and checks Work Contexts, knows the composition from delivered manifests | the fixture (who exists, what they hold) read at boot; sessions, installations and delegations in memory; **approvals in the store** when one is composed |
| [hop](services/hop/README.md) | stands in front of a module and lets through only a call the authority checked, stamped with who it is for | nothing |
| [edge](services/edge/README.md) | the browser's origin: signs a person in and routes each call to a module's HTTP face behind the hop | the session cookie, in the browser |
| [store](services/store/README.md) | the module's own Postgres (the `postgres` agent) | what a person created at runtime and a restart must not forget: today the `approvals` table, one row per consent to one artifact for one installation, revoked in place |

**Why a store.** An approval is a person's consent to one exact authored
artifact for one installation (the artifact interface's `Approve`, read back by
`Authorize`, withdrawn by `Revoke`). It is runtime state a person created, not
fixture, and the consuming module keeps its installation across the local authority's
restarts, so a local authority that forgot it refused every run of the approved
artifact afterwards. The local authority declares the store as its dependency; a run
that composes the module starts the store first and delivers its read-write
connection, and the local authority says at boot whether approvals persist there or
live in memory (a test, or a run that composes no store).

**What stays in memory, deliberately.** Sessions, installations and
delegations. Each moves into the store when a restart losing it is the bug
being fixed; the store absorbs nothing ahead of that.
