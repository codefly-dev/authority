// Package replaypg is the hop admission replay store on Postgres: the durable,
// atomic, shared reservation the admission contract requires, over a store
// Codefly already delivers to a module.
//
// It exists because the contract's requirement had no deployable backend. A
// process-local set fails on a second replica and after a restart, and
// hop.FileReplayStore needs a shared mount the platform does not deliver, so a
// hand-written path to per-pod storage would silently become a per-replica
// store and let a captured stamp replay once per replica. A module with a store
// has somewhere atomic to put a nonce, and INSERT ... ON CONFLICT DO NOTHING
// over a primary key is that atomic reservation, shared by every replica
// reaching the same database.
//
// Create the table with Migration, as the module's own migration, and keep
// Collect on a schedule: reservations are retained past their admission's
// expiry (hop passes expiry plus the clock allowance) and nothing removes them
// otherwise.
package replaypg

import (
	"context"
	"errors"
	"time"

	core "github.com/codefly-dev/core/workcontext"
	"github.com/jackc/pgx/v5/pgconn"
)

// Migration creates the table, as the module's own migration. The primary key
// is the reservation: Postgres decides one winner among concurrent inserts.
const Migration = `CREATE TABLE IF NOT EXISTS hop_admissions (
	nonce TEXT PRIMARY KEY,
	retain_until TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS hop_admissions_retain_until ON hop_admissions (retain_until);`

// Pool is the part of *pgxpool.Pool this store uses, so a caller may wrap it
// and a test may stand in for it.
type Pool interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// Store reserves admission nonces in a module's own Postgres.
type Store struct{ pool Pool }

// New wraps a pool connected as the role that may insert into hop_admissions.
func New(pool Pool) (*Store, error) {
	if pool == nil {
		return nil, errors.New("hop replay: a Postgres replay store needs a connection pool")
	}
	return &Store{pool: pool}, nil
}

var _ core.ReplayStore = (*Store)(nil)

// Shared marks this store as the durable shared reservation the contract
// requires, so hop.NewVerifier admits it outside local.
func (s *Store) Shared() bool { return true }

// Consume reserves nonce until retainUntil, atomically across every replica
// reaching this database. It reports core.ErrReplayed when the nonce is already
// held, and any other error as unavailability, which the verifier refuses: a
// store that cannot answer must never admit a call.
//
// A reservation is never updated. Letting a second insert refresh retain_until
// would let a replay extend the window it is being refused for.
func (s *Store) Consume(ctx context.Context, nonce string, retainUntil time.Time) error {
	if nonce == "" {
		return errors.New("hop replay: a reservation needs a nonce")
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO hop_admissions (nonce, retain_until)
		VALUES ($1, $2) ON CONFLICT (nonce) DO NOTHING`, nonce, retainUntil.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.ErrReplayed
	}
	return nil
}

// Collect removes reservations whose retention has passed, by the database's
// own clock, and answers how many it removed. Run it on a schedule: without it
// the table grows by one row per admitted call.
//
// Removing a reservation at its retention is safe because the verifier judges
// the admission window when a call arrives: a call carrying a nonce this
// removes would already be refused on its window, whatever the store answers.
func (s *Store) Collect(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM hop_admissions WHERE retain_until < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
