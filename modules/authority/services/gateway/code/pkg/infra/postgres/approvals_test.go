package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"gateway/pkg/business/approvalstest"
	"gateway/pkg/business/state"
	"gateway/pkg/infra/postgres"
)

// The store's schema, as the agent applies it: the migration file itself, so
// the test and the run share one source.
const migration = "../../../../../store/migrations/1_approvals.up.sql"

// database gives the suite a fresh database on the Postgres named by
// AUTHORITY_STORE_TEST_DATABASE_URL (an owner login that may create databases),
// migrated with the store's migration, and skips when none is named. owner is
// the migration owner; runtime acts as app_authority, the role the gateway runs
// as, so the suite is held to the gateway's privileges.
func database(t *testing.T) (owner, runtime *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("AUTHORITY_STORE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHORITY_STORE_TEST_DATABASE_URL unset: no Postgres to run the store's migration against")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connecting to the test Postgres: %v", err)
	}
	name := fmt.Sprintf("authority_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("creating %s: %v", name, err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)")
		_ = admin.Close(ctx)
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	if owner, err = pgxpool.NewWithConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	sql, err := os.ReadFile(filepath.FromSlash(migration))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, string(sql)); err != nil {
		t.Fatalf("the store's migration: %v", err)
	}
	cfg = cfg.Copy()
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE app_authority")
		return err
	}
	if runtime, err = pgxpool.NewWithConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	return owner, runtime
}

func TestApprovalsContract(t *testing.T) {
	_, runtime := database(t)
	approvalstest.Contract(t, func(*testing.T) state.Approvals { return postgres.NewApprovals(runtime) })
}

// The reason the store exists: consent given before a restart still answers a
// run after it.
func TestConsentOutlivesTheProcess(t *testing.T) {
	owner, runtime := database(t)
	ctx := context.Background()
	before := postgres.NewApprovals(runtime)
	approved, err := before.Approve(ctx, "acme/robin", "robin.intents", approvalstest.Digest("field-naturalist"), 3)
	if err != nil {
		t.Fatal(err)
	}
	// A new process: a new pool over the same database, nothing carried over.
	cfg := runtime.Config().Copy()
	restarted, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	after := postgres.NewApprovals(restarted)
	standing, err := after.Standing(ctx, "acme/robin", "robin.intents", approvalstest.Digest("field-naturalist"))
	if err != nil || standing != approved {
		t.Fatalf("after a restart: %+v %v", standing, err)
	}
	if _, err := after.Revoke(ctx, "acme/robin", "robin.intents", approved.ID); err != nil {
		t.Fatal(err)
	}
	var revokedAt *time.Time
	if err := owner.QueryRow(ctx, `SELECT revoked_at FROM approvals WHERE id = $1`, approved.ID).Scan(&revokedAt); err != nil || revokedAt == nil {
		t.Fatalf("revoked_at = %v %v", revokedAt, err)
	}
}

// The gateway's role may read, record and revoke, never delete or reshape.
func TestTheRuntimeRoleCannotDelete(t *testing.T) {
	_, runtime := database(t)
	ctx := context.Background()
	for _, stmt := range []string{`DELETE FROM approvals`, `DROP TABLE approvals`, `TRUNCATE approvals`} {
		_, err := runtime.Exec(ctx, stmt)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" { // insufficient_privilege
			t.Fatalf("%s as app_authority: %v", stmt, err)
		}
	}
	// And the schema's own guards hold whatever the caller sends.
	if _, err := runtime.Exec(ctx, `INSERT INTO approvals (id, installation, policy, digest, revision) VALUES ('x', 'acme/robin', 'robin.intents', 'md5:nope', 1)`); err == nil || !strings.Contains(err.Error(), "approvals_digest_check") {
		t.Fatalf("a malformed digest was stored: %v", err)
	}
}
