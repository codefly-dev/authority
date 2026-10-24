# store

The authority's own Postgres, the `postgres` agent, composed for the gateway.

**What persists here.** Approvals: a person's consent to one exact authored
artifact for one installation, under one policy, as the artifact interface
records it (`Approve`, read back by `Authorize`, withdrawn by `Revoke`). One
row per (installation, policy, digest) in `approvals`; a revoked row stays, marked,
so the artifact is refused for good and cannot be approved again. Nothing here
is deleted by the gateway.

**What does not.** Who exists and what they hold is the gateway's fixture.
Sessions, installations and delegations are still the gateway's memory; each
earns a table here when a restart losing it is the bug being fixed, as it was
for approvals.

**How the gateway reaches it.** The gateway declares this service as a
dependency, so a run starts the store first, and reads
`codefly.For(ctx).Service("store").Secret("postgres", "read-write-connection")`:
the runtime read-write principal's connection, acting as `app_authority`
(migration 1), which may read, insert and update `approvals` and nothing else.
With no store composed the gateway keeps approvals in memory and says so at
boot.

- [migrations](migrations/README.md): the schema, one paired file per change.
- [configurations/local](configurations/local/README.md): the committed local
  credentials and why.
