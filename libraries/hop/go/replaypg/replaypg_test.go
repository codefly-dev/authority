package replaypg

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	core "github.com/codefly-dev/core/workcontext"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pool is a Postgres that holds one nonce per primary key, as the real table's
// ON CONFLICT DO NOTHING does: the first insert affects a row, a repeat none.
type pool struct {
	held   map[string]time.Time
	active map[string]bool
	fail   error
	sql    []string
	args   [][]any
	// ahead is how far the database's clock runs ahead of this process's.
	ahead time.Duration
}

func (p *pool) now() time.Time { return time.Now().Add(p.ahead) }

func (p *pool) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	p.sql, p.args = append(p.sql, sql), append(p.args, args)
	if p.fail != nil {
		return pgconn.CommandTag{}, p.fail
	}
	if p.held == nil {
		p.held = map[string]time.Time{}
	}
	switch strings.Fields(sql)[0] {
	case "UPDATE":
		// Finish: the call has returned.
		delete(p.active, args[0].(string))
		return pgconn.NewCommandTag("UPDATE 1"), nil
	case "DELETE":
		// The collection statement; remove what is a margin past its
		// retention, running or not.
		margin := time.Duration(args[0].(float64) * float64(time.Second))
		removed := 0
		for nonce, until := range p.held {
			if until.Before(p.now().Add(-margin)) {
				delete(p.held, nonce)
				removed++
			}
		}
		return pgconn.NewCommandTag("DELETE 0 " + itoa(removed)), nil
	}
	nonce, until := args[0].(string), args[1].(time.Time)
	if _, replayed := p.held[nonce]; replayed {
		return pgconn.NewCommandTag("INSERT 0 0"), nil
	}
	p.held[nonce] = until
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

// QueryRow is the reservation statement: the insert happens only while the
// retention has not passed, and the answer says which way it went.
func (p *pool) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	p.sql, p.args = append(p.sql, sql), append(p.args, args)
	if p.fail != nil {
		return row{err: p.fail}
	}
	if p.held == nil {
		p.held, p.active = map[string]time.Time{}, map[string]bool{}
	}
	nonce, until := args[0].(string), args[1].(time.Time)
	_, taken := p.held[nonce]
	switch {
	case !until.After(p.now()):
		return row{outcome: "expired"}
	case taken:
		return row{outcome: "replayed"}
	}
	p.held[nonce], p.active[nonce] = until, true
	return row{outcome: "reserved"}
}

type row struct {
	outcome string
	err     error
}

func (r row) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*string) = r.outcome
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var out []byte
	for ; n > 0; n /= 10 {
		out = append([]byte{byte('0' + n%10)}, out...)
	}
	return string(out)
}

func TestAReservationIsHeldOnceAndAReplayIsRefused(t *testing.T) {
	p := &pool{}
	store, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	if !store.Shared() {
		t.Fatal("a Postgres store is the shared reservation the contract requires")
	}
	until := time.Now().Add(32 * time.Second)
	if err := store.Consume(context.Background(), "nonce", until); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(context.Background(), "nonce", until); !errors.Is(err, core.ErrReplayed) {
		t.Fatalf("a replay was not refused: %v", err)
	}
	// A different nonce is unaffected, and retention is stored in UTC.
	if err := store.Consume(context.Background(), "other", until); err != nil {
		t.Fatal(err)
	}
	if stored := p.args[0][1].(time.Time); stored.Location() != time.UTC || !stored.Equal(until) {
		t.Fatalf("retention stored as %v", stored)
	}
	// A reservation is never refreshed: a replay cannot extend its own window.
	if err := store.Consume(context.Background(), "nonce", until.Add(time.Hour)); !errors.Is(err, core.ErrReplayed) {
		t.Fatalf("a replay was not refused: %v", err)
	}
	if held := p.held["nonce"]; !held.Equal(until) {
		t.Fatalf("a refused replay moved the retention to %v", held)
	}
}

// A store that cannot answer must never admit a call: the error is neither
// swallowed nor reported as a replay, so hop.Verify refuses it as stamp_store.
func TestAnUnavailableStoreIsNeitherAdmissionNorReplay(t *testing.T) {
	outage := errors.New("connection refused")
	store, err := New(&pool{fail: outage})
	if err != nil {
		t.Fatal(err)
	}
	err = store.Consume(context.Background(), "nonce", time.Now().Add(time.Minute))
	if !errors.Is(err, outage) || errors.Is(err, core.ErrReplayed) {
		t.Fatalf("an outage must not read as a replay: %v", err)
	}
	if _, err := New(nil); err == nil {
		t.Fatal("a store with no pool was accepted")
	}
	if err := store.Consume(context.Background(), "", time.Now()); err == nil {
		t.Fatal("a reservation with no nonce was accepted")
	}
}

func TestCollectRemovesOnlyReservationsPastTheirRetention(t *testing.T) {
	p := &pool{}
	store, _ := New(p)
	if err := store.Consume(context.Background(), "aged", time.Now().Add(-CollectMargin-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(context.Background(), "inside-the-margin", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(context.Background(), "current", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	removed, err := store.Collect(context.Background())
	if err != nil || removed != 1 {
		t.Fatalf("collected %d: %v", removed, err)
	}
	for _, kept := range []string{"current", "inside-the-margin"} {
		if _, held := p.held[kept]; !held {
			t.Fatalf("collection removed %s", kept)
		}
	}
}

// A reservation is refused to anyone else while it is retained; collection
// removes it once its retention has passed, its call finished or not, and a
// reservation whose retention has already passed is refused as the window,
// never inserted, so it cannot revive a collected nonce.
func TestAReservationIsHeldToItsRetentionWhetherOrNotItsCallFinished(t *testing.T) {
	p := &pool{}
	store, _ := New(p)
	ctx := context.Background()
	if err := store.Reserve(ctx, "running", time.Now().Add(50*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := store.Reserve(ctx, "running", time.Now().Add(time.Minute)); !errors.Is(err, core.ErrReplayed) {
		t.Fatalf("a second reservation was not refused: %v", err)
	}
	if removed, err := store.Collect(ctx); err != nil || removed != 0 {
		t.Fatalf("collection removed %d reservations still retained: %v", removed, err)
	}
	time.Sleep(60 * time.Millisecond)
	// Past its retention but inside the margin: still held.
	if removed, err := store.Collect(ctx); err != nil || removed != 0 {
		t.Fatalf("collection removed %d reservations inside the margin: %v", removed, err)
	}
	p.ahead = CollectMargin + time.Second
	// Never finished: its holder stopped between Reserve and Finish.
	if removed, err := store.Collect(ctx); err != nil || removed != 1 {
		t.Fatalf("collected %d reservations past their retention: %v", removed, err)
	}
	if err := store.Reserve(ctx, "running", time.Now().Add(-time.Second)); !errors.Is(err, refusal.StampWindow) {
		t.Fatalf("a reservation past its retention was not refused as the window: %v", err)
	}
	if _, held := p.held["running"]; held {
		t.Fatal("a reservation past its retention revived a collected nonce")
	}
	outage := errors.New("connection refused")
	if err := (&Store{pool: &pool{fail: outage}}).Reserve(ctx, "n", time.Now().Add(time.Minute)); !errors.Is(err, outage) {
		t.Fatalf("an outage must not read as a replay: %v", err)
	}
	if err := store.Reserve(ctx, "", time.Now().Add(time.Minute)); err == nil {
		t.Fatal("a reservation with no nonce was accepted")
	}
}

// The migration is the module's own, and the primary key is what makes the
// reservation atomic across replicas.
func TestTheMigrationReservesTheNonceAsAPrimaryKey(t *testing.T) {
	for _, want := range []string{"hop_admissions", "nonce TEXT PRIMARY KEY", "retain_until", "active BOOLEAN NOT NULL DEFAULT FALSE"} {
		if !contains(Migration, want) {
			t.Fatalf("the migration does not declare %q: %s", want, Migration)
		}
	}
}

func contains(haystack, needle string) bool {
	for n := 0; n+len(needle) <= len(haystack); n++ {
		if haystack[n:n+len(needle)] == needle {
			return true
		}
	}
	return false
}

// Review r3 M2, on a real Postgres (HOP_TEST_POSTGRES): a holder that stops
// between Reserve and Finish leaves its row active for good, and collection
// still removes it once it is a margin past its retention by the database's
// clock; the nonce is not revived, since a reservation past its retention is
// refused. A row past its retention but inside the margin is kept.
func TestACrashedHoldersReservationIsCollectedOnTheDatabaseClock(t *testing.T) {
	pg := postgres(t)
	ctx := context.Background()
	store, _ := New(pg)
	crashed := fmt.Sprintf("crashed-holder-%d", time.Now().UnixNano())
	recent := crashed + "-recent"
	// Rows as a crashed holder leaves them, aged by the database's own clock.
	for nonce, age := range map[string]string{crashed: "61 seconds", recent: "30 seconds"} {
		if _, err := pg.Exec(ctx, `INSERT INTO hop_admissions (nonce, retain_until, active) VALUES ($1, now() - $2::interval, TRUE)`, nonce, age); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Collect(ctx); err != nil {
		t.Fatal(err)
	}
	if held(t, pg, crashed) {
		t.Fatal("a crashed holder's reservation outlived its retention and the margin")
	}
	if !held(t, pg, recent) {
		t.Fatal("collection removed a reservation inside the margin past its retention")
	}
	if err := store.Reserve(ctx, crashed, time.Now().Add(-time.Second)); !errors.Is(err, refusal.StampWindow) {
		t.Fatalf("the collected nonce was reserved again: %v", err)
	}
}

// Review r4 N1, on a real Postgres: Reserve checks the retention and inserts
// in one statement but not one instant, so a Collect that removed a row the
// moment its retention passed could commit between the two and let the insert
// revive the nonce. With the margin, concurrent collection and reservation of
// a nonce near its expiry never admit it a second time.
func TestConcurrentCollectionNeverRevivesANonceNearItsExpiry(t *testing.T) {
	pg := postgres(t)
	ctx := context.Background()
	store, _ := New(pg)
	for round := range 20 {
		nonce := fmt.Sprintf("near-expiry-%d-%d", time.Now().UnixNano(), round)
		until := time.Now().Add(150 * time.Millisecond)
		if err := store.Reserve(ctx, nonce, until); err != nil {
			t.Fatal(err)
		}
		stop := time.Now().Add(400 * time.Millisecond)
		done := make(chan error, 1)
		go func() {
			for time.Now().Before(stop) {
				if _, err := store.Collect(ctx); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}()
		for time.Now().Before(stop) {
			switch err := store.Reserve(ctx, nonce, until); {
			case err == nil:
				t.Fatalf("round %d: a replay of a nonce near its expiry was admitted", round)
			case errors.Is(err, core.ErrReplayed), errors.Is(err, refusal.StampWindow):
			default:
				t.Fatal(err)
			}
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if !held(t, pg, nonce) {
			t.Fatalf("round %d: the reservation was collected inside the margin", round)
		}
	}
}

func postgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("HOP_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("HOP_TEST_POSTGRES names no Postgres")
	}
	pg, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pg.Close)
	if _, err := pg.Exec(context.Background(), Migration); err != nil {
		t.Fatal(err)
	}
	return pg
}

func held(t *testing.T, pg *pgxpool.Pool, nonce string) bool {
	t.Helper()
	var n int
	if err := pg.QueryRow(context.Background(), `SELECT count(*) FROM hop_admissions WHERE nonce = $1`, nonce).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}
