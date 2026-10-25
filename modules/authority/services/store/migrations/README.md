# store — migrations

Paired `N_<name>.up.sql` / `N_<name>.down.sql` files, applied in order by the
postgres agent (golang-migrate) when the store boots. Each migration owns the
tables it creates and grants `app_authority`, the local authority's runtime role,
exactly the writes the local authority makes on them; nothing grants `DELETE`.

| # | What it adds |
|---|---|
| 1 | the `app_authority` role and `approvals`: a person's consent to one artifact for one installation, unique on (installation, policy, digest), revoked in place |
