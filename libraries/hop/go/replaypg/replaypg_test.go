package replaypg

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	core "github.com/codefly-dev/core/workcontext"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// pool is a Postgres that holds one nonce per primary key, as the real table's
// ON CONFLICT DO NOTHING does: the first insert affects a row, a repeat none.
type pool struct {
	held   map[string]time.Time
	active map[string]bool
	fail   error
	sql    []string
	args   [][]any
}

func (p *pool) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	p.sql, p.args = append(p.sql, sql), append(p.args, args)
	if p.fail != nil {
		return pgconn.CommandTag{}, p.fail
	}
	if p.held == nil {
		p.held = map[string]time.Time{}
	}
	if len(args) == 1 {
		// Finish: the call has returned.
		delete(p.active, args[0].(string))
		return pgconn.NewCommandTag("UPDATE 1"), nil
	}
	if len(args) != 2 {
		// The collection statement; remove what has aged out and is not running.
		removed := 0
		for nonce, until := range p.held {
			if until.Before(time.Now()) && !p.active[nonce] {
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
	case !until.After(time.Now()):
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
	if err := store.Consume(context.Background(), "aged", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(context.Background(), "current", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	removed, err := store.Collect(context.Background())
	if err != nil || removed != 1 {
		t.Fatalf("collected %d: %v", removed, err)
	}
	if _, held := p.held["current"]; !held {
		t.Fatal("collection removed a reservation still retained")
	}
}

// A reservation is held while its call runs, past its retention, and refused
// to anyone else; once the call finishes, collection removes it after its
// retention. A reservation whose retention has already passed is refused as
// the window, never inserted, so it cannot revive a collected nonce.
func TestAReservationIsHeldWhileItsCallRuns(t *testing.T) {
	p := &pool{}
	store, _ := New(p)
	ctx := context.Background()
	if err := store.Reserve(ctx, "running", time.Now().Add(50*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := store.Reserve(ctx, "running", time.Now().Add(time.Minute)); !errors.Is(err, core.ErrReplayed) {
		t.Fatalf("a second reservation was not refused: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	if removed, err := store.Collect(ctx); err != nil || removed != 0 {
		t.Fatalf("collection removed %d running reservations: %v", removed, err)
	}
	if err := store.Finish(ctx, "running"); err != nil {
		t.Fatal(err)
	}
	if removed, err := store.Collect(ctx); err != nil || removed != 1 {
		t.Fatalf("collected %d finished reservations: %v", removed, err)
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
