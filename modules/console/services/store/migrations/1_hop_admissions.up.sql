-- Hop admission reservations: one row per admitted call, keyed by the nonce the
-- hop signed into its admission. The verifier consumes a nonce before it enters
-- a handler, so a captured admission is refused the second time it is
-- presented. This has to hold across every replica of the console and across a
-- restart, which is why it is a table and not a set in the process.
--
-- The runtime read-write role first: service.codefly.yaml declares
-- `runtime-read-write-roles: [app_console]`, the postgres agent reconciles its
-- managed read-write principal into it on every boot and refuses to boot while
-- the role is absent. Idempotent: created only when absent.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_console') THEN
        CREATE ROLE app_console NOINHERIT;
    END IF;
END $$;

GRANT USAGE ON SCHEMA public TO app_console;

-- The migration owner may SET ROLE app_console, so a test runs under exactly
-- the privileges the console has.
DO $$
BEGIN
    EXECUTE format('GRANT app_console TO %I', current_user);
END $$;

-- The table is exactly libraries/hop/go/replaypg.Migration; the console's test
-- asserts this file still carries it, so the two cannot drift. The primary key
-- is the reservation: Postgres decides one winner among concurrent inserts.
CREATE TABLE IF NOT EXISTS hop_admissions (
	nonce TEXT PRIMARY KEY,
	retain_until TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS hop_admissions_retain_until ON hop_admissions (retain_until);

-- Exactly what the verifier does: reserve, read back, and collect what has
-- aged out. No UPDATE: a reservation is never refreshed.
GRANT SELECT, INSERT, DELETE ON hop_admissions TO app_console;
