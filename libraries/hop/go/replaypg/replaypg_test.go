package replaypg

import (
	"context"
	"errors"
	"testing"
	"time"

	core "github.com/codefly-dev/core/workcontext"
	"github.com/jackc/pgx/v5/pgconn"
)

// pool is a Postgres that holds one nonce per primary key, as the real table's
// ON CONFLICT DO NOTHING does: the first insert affects a row, a repeat none.
type pool struct {
	held map[string]time.Time
	fail error
	sql  []string
	args [][]any
}

func (p *pool) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	p.sql, p.args = append(p.sql, sql), append(p.args, args)
	if p.fail != nil {
		return pgconn.CommandTag{}, p.fail
	}
	if p.held == nil {
		p.held = map[string]time.Time{}
	}
	if len(args) != 2 {
		// The collection statement; remove what has aged out.
		removed := 0
		for nonce, until := range p.held {
			if until.Before(time.Now()) {
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

// The migration is the module's own, and the primary key is what makes the
// reservation atomic across replicas.
func TestTheMigrationReservesTheNonceAsAPrimaryKey(t *testing.T) {
	for _, want := range []string{"hop_admissions", "nonce TEXT PRIMARY KEY", "retain_until"} {
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
