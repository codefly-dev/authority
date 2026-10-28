package hop

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	core "github.com/codefly-dev/core/workcontext"
)

// Use the real constructors and cache, with a clock safe for detached reads.
func readinessVerifier(t *testing.T, source *keys, tokenOnly bool) (*Verifier, *atomic.Int64) {
	t.Helper()
	var v *Verifier
	var err error
	if tokenOnly {
		v, err = NewTokenVerifier(t.Context(), source, "documents")
	} else {
		v, err = NewVerifier(t.Context(), source, "documents", core.NewMemoryReplayStore())
	}
	if err != nil {
		t.Fatal(err)
	}
	clock := new(atomic.Int64)
	clock.Store(time.Now().UnixNano())
	v.mu.Lock()
	v.now = func() time.Time { return time.Unix(0, clock.Load()) }
	v.tried = v.now()
	if !v.fetched.IsZero() {
		v.fetched = v.now()
	}
	v.mu.Unlock()
	t.Cleanup(func() { settled(v) })
	return v, clock
}

func readinessPublication(s signer, admission ...*authorityv1.PublicKey) *authorityv1.KeysResponse {
	return &authorityv1.KeysResponse{Issuer: s.issuer, Keys: []*authorityv1.PublicKey{s.published()}, AdmissionKeys: admission}
}

func requireReadinessReason(t *testing.T, err error, want refusal.Reason) {
	t.Helper()
	var reason refusal.Reason
	if !errors.As(err, &reason) || reason != want {
		t.Fatalf("want %s, got %v", want, err)
	}
}

func TestReadyRequiresAdmissionKeys(t *testing.T) {
	authority := newSigner("readiness-absent")
	for _, tc := range []struct {
		name      string
		admission []*authorityv1.PublicKey
	}{
		{"literal-empty", nil},
		{"explicit-empty", []*authorityv1.PublicKey{}},
		{"filtered-purpose", []*authorityv1.PublicKey{{Algorithm: core.Algorithm, Purpose: "work-context", PublicKey: make([]byte, 32)}}},
		{"filtered-algorithm", []*authorityv1.PublicKey{{Algorithm: "unsupported", Purpose: "hop-admission", PublicKey: make([]byte, 32)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &keys{literalResponse: true, response: readinessPublication(authority, tc.admission...)}
			v, clock := readinessVerifier(t, source, false)
			if v.Ready() {
				t.Error("admitting verifier is ready without any usable admission key")
			}
			if !errors.Is(v.KeysError(), ErrNoAdmissionKeys) {
				t.Fatalf("missing diagnostic: %v", v.KeysError())
			}
			_, err := v.Verify(t.Context(), forwarded(t, authority.issue(t, v.now(), "documents"), "proof", ""), "/test.Service/Read")
			requireReadinessReason(t, err, refusal.KeysUnavailable)
			source.set(readinessPublication(authority, publishedHop("proof")), nil, nil)
			clock.Add(int64(keyRetry - time.Nanosecond))
			if v.Ready() {
				t.Error("missing-key cache became ready before a successful refresh")
			}
			if source.count() != 1 {
				t.Fatal("read retried before keyRetry")
			}
			clock.Add(1)
			if v.Ready() {
				t.Error("poll initiating refresh must observe its old empty snapshot")
			}
			settled(v)
			if !v.Ready() || v.KeysError() != nil || source.count() != 2 {
				t.Fatalf("poll-only recovery: ready=%v error=%v reads=%d", v.Ready(), v.KeysError(), source.count())
			}
		})
	}
}

func TestReadyObservesLastKeyWithdrawalAndPollOnlyRepublication(t *testing.T) {
	authority := newSigner("readiness-withdrawal")
	publication := readinessPublication(authority, publishedHop("proof"))
	source := &keys{literalResponse: true, response: publication}
	v, clock := readinessVerifier(t, source, false)
	if !v.Ready() {
		t.Fatal("initial published key not ready")
	}
	source.set(readinessPublication(authority), nil, nil)
	clock.Add(int64(keyMaxAge + time.Nanosecond))
	if !v.Ready() {
		t.Fatal("refresh-starting poll should still observe cached usable keys")
	}
	settled(v)
	if v.Ready() || !errors.Is(v.KeysError(), ErrNoAdmissionKeys) {
		t.Fatal("observed last-key withdrawal did not remove readiness")
	}
	// A newly minted token/stamp has neither expired nor spent a nonce before:
	// the refusal must be missing keys, not a replay/window false positive.
	_, err := v.Verify(t.Context(), forwarded(t, authority.issue(t, v.now(), "documents"), "proof", ""), "/test.Service/Read")
	requireReadinessReason(t, err, refusal.KeysUnavailable)
	source.set(nil, errors.New("authority unavailable"), nil)
	clock.Add(int64(keyRetry))
	if v.Ready() {
		t.Fatal("withdrawn key restored before failed refresh")
	}
	settled(v)
	if v.Ready() || v.KeysError() == nil {
		t.Fatal("failed refresh restored withdrawn key readiness")
	}
	source.set(publication, nil, nil)
	clock.Add(int64(keyRetry))
	if v.Ready() {
		t.Fatal("unobserved republication became ready")
	}
	settled(v)
	if !v.Ready() || v.KeysError() != nil {
		t.Fatal("readiness polling did not learn republication")
	}
	if _, err := v.Verify(t.Context(), forwarded(t, authority.issue(t, v.now(), "documents"), "proof", ""), "/test.Service/Read"); err != nil {
		t.Fatalf("republished key refused: %v", err)
	}
}

func TestReadyPreservesFreshnessBoundariesOnReadFailures(t *testing.T) {
	authority := newSigner("readiness-freshness")
	for _, tokenOnly := range []bool{false, true} {
		mode := "admitting"
		if tokenOnly {
			mode = "token-only"
		}
		for _, malformed := range []bool{false, true} {
			failure := "transport"
			if malformed {
				failure = "invalid-publication"
			}
			t.Run(mode+"/"+failure, func(t *testing.T) {
				publication := readinessPublication(authority)
				if !tokenOnly {
					publication.AdmissionKeys = []*authorityv1.PublicKey{publishedHop("proof")}
				}
				source := &keys{literalResponse: true, response: publication}
				v, clock := readinessVerifier(t, source, tokenOnly)
				start := clock.Load()
				if malformed {
					source.set(readinessPublication(authority, &authorityv1.PublicKey{Algorithm: core.Algorithm, Purpose: "hop-admission", PublicKey: []byte("bad-length")}), nil, nil)
				} else {
					source.set(nil, errors.New("authority down"), nil)
				}
				clock.Store(start + int64(keyMaxAge))
				if !v.Ready() || source.count() != 1 {
					t.Fatal("refresh at exact keyMaxAge changed")
				}
				clock.Add(1)
				if !v.Ready() {
					t.Fatal("fresh keys lost during a refresh")
				}
				settled(v)
				if source.count() != 2 || v.KeysError() == nil || !v.Ready() {
					t.Fatal("failed refresh lost trusted cache")
				}
				if malformed && !errors.Is(v.KeysError(), refusal.InvalidKey) {
					t.Fatalf("invalid publication diagnostic: %v", v.KeysError())
				}
				clock.Store(start + int64(keyStale))
				if !v.Ready() {
					t.Fatal("trust must remain ready at exact keyStale")
				}
				settled(v)
				clock.Add(1)
				if v.Ready() {
					t.Fatal("trust remained ready beyond keyStale")
				}
				source.set(publication, nil, nil)
				clock.Store(start + int64(keyStale+keyRetry))
				if v.Ready() {
					t.Fatal("stale snapshot became ready before refresh completed")
				}
				settled(v)
				if !v.Ready() || v.KeysError() != nil {
					t.Fatal("poll-only recovery from stale trust failed")
				}
			})
		}
	}
}

func TestTokenOnlyReadyNeedsNoAdmissionKeys(t *testing.T) {
	authority := newSigner("readiness-token-only")
	source := &keys{literalResponse: true, response: readinessPublication(authority)}
	v, _ := readinessVerifier(t, source, true)
	if !v.Ready() || v.KeysError() != nil {
		t.Fatal("token-only trust incorrectly requires admission keys")
	}
	token := authority.issue(t, v.now(), "documents")
	if id, err := v.VerifyToken(t.Context(), token); err != nil || id.Owner != core.FixturePrincipal {
		t.Fatalf("valid token: %+v %v", id, err)
	}
	md := forwarded(t, token, "proof", "")
	_, err := v.Verify(t.Context(), md, "/test.Service/Read")
	requireReadinessReason(t, err, refusal.Configuration)
	_, _, err = v.Admit(t.Context(), md, "/test.Service/Read")
	requireReadinessReason(t, err, refusal.Configuration)
	if source.count() != 1 {
		t.Fatal("token-only admission refusal fetched keys")
	}
}

func TestReadinessPollingIsNonblockingSingleFlightAndRecoversFromInitialOutage(t *testing.T) {
	authority := newSigner("readiness-polling")
	source := &keys{literalResponse: true, err: errors.New("not serving yet")}
	v, clock := readinessVerifier(t, source, false)
	if v.Ready() {
		t.Fatal("never-fetched verifier is ready")
	}
	hold := make(chan struct{})
	// Close before verifier cleanup waits, including on an assertion failure.
	release := sync.OnceFunc(func() { close(hold) })
	t.Cleanup(release)
	source.set(readinessPublication(authority, publishedHop("proof")), nil, hold)
	clock.Add(int64(keyRetry))
	result := make(chan bool, 1)
	go func() {
		ready := false
		for range 20 {
			ready = v.Ready() || ready
		}
		result <- ready
	}()
	select {
	case ready := <-result:
		if ready {
			t.Fatal("held first successful fetch cannot make readiness true")
		}
	case <-time.After(time.Second):
		t.Fatal("readiness polls blocked on a held key fetch")
	}
	release()
	settled(v)
	if !v.Ready() || source.count() != 2 {
		t.Fatalf("polls did not share one recovery read: ready=%v reads=%d", v.Ready(), source.count())
	}
}
