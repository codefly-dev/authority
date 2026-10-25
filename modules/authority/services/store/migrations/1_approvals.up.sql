-- Approvals: a person's consent to one exact authored artifact for one
-- installation, under one policy (the artifact interface: Approve, Authorize,
-- Revoke). The local authority used to keep these in memory, so a restart forgot every
-- consent while the consuming module kept its installation, and every run of
-- the approved artifact was refused afterwards. A row here outlives the process.
--
-- The runtime read-write role first: service.codefly.yaml declares
-- `runtime-read-write-roles: [app_authority]`, the postgres agent reconciles its
-- managed read-write principal into it on every boot and refuses to boot while
-- the role is absent. Idempotent: created only when absent.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_authority') THEN
        CREATE ROLE app_authority NOINHERIT;
    END IF;
END $$;

GRANT USAGE ON SCHEMA public TO app_authority;

-- The migration owner may SET ROLE app_authority, so a test runs under exactly
-- the privileges the local authority has.
DO $$
BEGIN
    EXECUTE format('GRANT app_authority TO %I', current_user);
END $$;

-- One row per (installation, policy, digest): approving the same artifact again
-- answers the standing row, and a revoked one is refused by the local authority, never
-- deleted and never re-approved. `digest` is "sha256:<hex>" of the identity's
-- deterministic encoding, as the local authority computes it.
CREATE TABLE approvals (
    id           text        PRIMARY KEY,
    installation text        NOT NULL CHECK (installation <> ''),
    policy       text        NOT NULL CHECK (policy <> ''),
    digest       text        NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    revision     bigint      NOT NULL,
    revoked      boolean     NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz,
    CHECK (revoked = (revoked_at IS NOT NULL)),
    UNIQUE (installation, policy, digest)
);

-- Exactly what the local authority does: read, record, revoke. Nothing deletes consent.
GRANT SELECT, INSERT, UPDATE ON approvals TO app_authority;
