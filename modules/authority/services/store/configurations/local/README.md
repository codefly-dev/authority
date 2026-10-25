# store — local configuration

`postgres.secret.env` here is **committed on purpose**. It holds the throwaway
credentials the `local` profile boots the `store` Postgres service with: an
owner login and two role passwords that protect nothing and must never be
reused anywhere.

It is committed because a composing workspace cannot supply it: Codefly reads a
service's configuration from the service's own directory, and a workspace that
composes this module by tag resolves it into a read-only module cache that is
the published tree byte for byte. The repository root ignores every
`*.secret.env` under a configurations directory; this service's `.gitignore`
lets exactly this file back through.

The file also carries the **key names** a render needs: `codefly deploy gitops
render` promotes each key into a typed Kubernetes Secret reference, and the
postgres agent refuses to render without one for each. Only the names reach a
rendered manifest; the values never do. **No hosted profile ever ships one**:
every other profile's credentials live in the provider's secret store,
generated there.

The keys the postgres agent reads:

- `POSTGRES_USER` — the owner / migrator role
- `POSTGRES_PASSWORD` — owner password
- `POSTGRES_READ_ONLY_PASSWORD` — read-only principal password
- `POSTGRES_READ_WRITE_PASSWORD` — read-write principal password; the agent
  exports its connection as the `postgres/read-write-connection` secret the
  local authority reads
