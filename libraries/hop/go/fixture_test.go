package hop

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var updateFixture = flag.Bool("update-fixture", false, "rewrite ../testdata/stamped.json")

// signer is a test authority: a key derived from a seed in this file, so it is
// public and signs fixtures only. It is not Core's fixture key, which Core refuses.
type signer struct {
	id     string
	key    ed25519.PrivateKey
	issuer string
}

func newSigner(seed string) signer {
	sum := sha256.Sum256([]byte(seed))
	return signer{id: "hop-" + seed, key: ed25519.NewKeyFromSeed(sum[:]), issuer: "https://authority.hop.test"}
}

func (s signer) published() *authorityv1.PublicKey {
	return &authorityv1.PublicKey{KeyId: s.id, Algorithm: core.Algorithm, PublicKey: s.key.Public().(ed25519.PublicKey), Purpose: workContextPurpose}
}

func (s signer) issue(t *testing.T, at time.Time, audience string, scopes ...*basev0.WorkScopeV1) string {
	t.Helper()
	a := &core.Authority{Issuer: s.issuer, KeyID: s.id, Key: s.key, Revisions: core.FixtureRevisions(), Seals: core.FixtureSeals(), Now: func() time.Time { return at }}
	token, _, err := a.Start(context.Background(), core.StartInput{
		TenantID: core.FixtureTenant, OwnerPrincipalID: core.FixturePrincipal, OwnerPrincipalKind: "human",
		OrganizationID: core.FixtureOrganization, TaskID: core.FixtureTask, Audience: audience,
		ReplayPolicy: core.ReplaySingleUse, AuthorityScopes: scopes, InstallationID: core.FixtureInstallation, TTL: 10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func forwarded(t *testing.T, token, proof, advisory string) metadata.MD {
	t.Helper()
	decoded, err := core.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	id := IdentityOf(decoded.Context())
	id.Advisory = advisory
	md := metadata.Pairs(WorkContextKey, token)
	if err := Stamp(md, id, testSigner(proof), "/test.Service/Read", decoded.Context().GetAudience(), time.Unix(decoded.Context().GetNotBeforeUnix(), 0)); err != nil {
		t.Fatal(err)
	}
	return md
}

// keys is a switchable Keys answer that counts the reads; with hold set, a
// read waits for it to be closed (or for its own context to end). A response
// that publishes no hop admission key publishes the test hop's
// (testSigner("proof")), as an authority publishes its hop's key.
type keys struct {
	mu       sync.Mutex
	response *authorityv1.KeysResponse
	err      error
	reads    int
	hold     chan struct{}
}

func (k *keys) Keys(ctx context.Context, _ *authorityv1.KeysRequest, _ ...grpc.CallOption) (*authorityv1.KeysResponse, error) {
	k.mu.Lock()
	k.reads++
	hold, response, err := k.hold, k.response, k.err
	k.mu.Unlock()
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if response != nil && len(response.GetAdmissionKeys()) == 0 {
		response = proto.Clone(response).(*authorityv1.KeysResponse)
		response.AdmissionKeys = []*authorityv1.PublicKey{publishedHop("proof")}
	}
	return response, err
}

func (k *keys) set(response *authorityv1.KeysResponse, err error, hold chan struct{}) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.response, k.err, k.hold = response, err, hold
}

func (k *keys) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.reads
}

// settled waits for the verifier's running read, if any, to end.
func settled(v *Verifier) {
	v.mu.Lock()
	wait := v.inflight
	v.mu.Unlock()
	if wait != nil {
		<-wait
	}
}

type stampFixture struct {
	Audience string            `json:"audience"`
	Now      int64             `json:"now"`
	Keys     json.RawMessage   `json:"keys"`
	Headers  map[string]string `json:"headers"`
	Identity map[string]any    `json:"identity"`
}

// The stamp's one contract, for every language a module is written in: the
// headers this hop writes for one call carrying a genuinely signed Work
// Context, the published keys that authenticate it at a fixed clock (the Work
// Context's and the hop's admission key), and the identity read from it. The Python verifier (codefly_hop, in libraries/authority-client/python) reads it back.
func TestTheStampFixtureAuthenticatesAsTheHopWroteIt(t *testing.T) {
	path := filepath.Join("..", "testdata", "stamped.json")
	s := newSigner("fixture")
	if *updateFixture {
		at := time.Unix(1792818000, 0)
		token := s.issue(t, at, "documents", &basev0.WorkScopeV1{ResourceKind: "documents.collection", Actions: []string{"read"}}, &basev0.WorkScopeV1{ResourceKind: "documents.collection", Actions: []string{"write"}, ResourceIds: []string{"c-1"}})
		md := forwarded(t, token, "fixture-proof", "")
		published, _ := protojson.Marshal(&authorityv1.KeysResponse{Issuer: s.issuer, Keys: []*authorityv1.PublicKey{s.published()}, AdmissionKeys: []*authorityv1.PublicKey{publishedHop("fixture-proof")}})
		f := stampFixture{Audience: "documents", Now: at.Unix(), Keys: published, Headers: map[string]string{}}
		for key, values := range md {
			f.Headers[key] = values[0]
		}
		id := IdentityOf(mustDecode(t, token))
		f.Identity = map[string]any{"owner": id.Owner, "owner_kind": id.OwnerKind, "tenant": id.Tenant, "actors": id.Actors, "scopes": id.Scopes, "binding": id.Binding, "task": id.Task, "expires": id.Expires, "advisory": ""}
		out, _ := json.MarshalIndent(f, "", "  ")
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f stampFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	published := &authorityv1.KeysResponse{}
	if err := protojson.Unmarshal(f.Keys, published); err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(context.Background(), &keys{response: published}, f.Audience, core.NewMemoryReplayStore())
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return time.Unix(f.Now, 0) }
	md := metadata.MD{}
	for key, value := range f.Headers {
		md.Set(key, value)
	}
	id, err := v.Verify(context.Background(), md, "/test.Service/Read")
	if err != nil {
		t.Fatalf("%s no longer authenticates; regenerate with -update-fixture: %v", path, err)
	}

	if id.Owner != f.Identity["owner"] || id.Tenant != f.Identity["tenant"] || strings.Join(id.Scopes, ",") != "documents.collection:read" || id.Advisory != f.Identity["advisory"] || !id.Claims.Allows("documents.collection", "write", "c-1") {
		t.Fatalf("identity: %+v", id)
	}
}

func mustDecode(t *testing.T, token string) *basev0.WorkContextV1 {
	t.Helper()
	d, err := core.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	return d.Context()
}

// A rotated key is fetched when a token first names it, at most once per
// keyRetry; a removed key stops verifying within keyMaxAge; keys that cannot
// be re-read are trusted no longer than keyStale.
func TestPublishedKeysAreRereadOnRotationAndExpireWhenUnreadable(t *testing.T) {
	first, second := newSigner("first"), newSigner("second")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: first.issuer, Keys: []*authorityv1.PublicKey{first.published()}}}
	start := time.Unix(1792818000, 0)
	clock := start
	v, err := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return clock }
	v.tried, v.fetched = start, start
	verify := func(token string) error {
		_, err := v.Verify(context.Background(), forwarded(t, token, "proof", ""), "/test.Service/Read")
		settled(v)
		return err
	}
	if err := verify(first.issue(t, clock, "documents")); err != nil {
		t.Fatal(err)
	}
	source.set(&authorityv1.KeysResponse{Issuer: first.issuer, Keys: []*authorityv1.PublicKey{second.published()}}, nil, nil)
	clock = start.Add(time.Second)
	if err := verify(second.issue(t, clock, "documents")); err == nil || !strings.Contains(err.Error(), "no verification key") || source.count() != 1 {
		t.Fatalf("within keyRetry the keys are not re-read: %v (reads %d)", err, source.count())
	}
	clock = start.Add(keyRetry + time.Second)
	if err := verify(second.issue(t, clock, "documents")); err != nil || source.count() != 2 {
		t.Fatalf("a rotated key is fetched: %v (reads %d)", err, source.count())
	}
	if err := verify(first.issue(t, clock, "documents")); err == nil {
		t.Fatal("a key the authority no longer publishes still verifies")
	}
	source.set(nil, errors.New("dial authority.internal:4000: connection refused"), nil)
	clock = clock.Add(keyMaxAge + time.Second)
	if err := verify(second.issue(t, clock, "documents")); err != nil {
		t.Fatalf("a failed re-read keeps the last keys until keyStale: %v", err)
	}
	clock = clock.Add(keyStale)
	err = verify(second.issue(t, clock, "documents"))
	if !errors.Is(err, workcontext.ErrUnauthenticated) || !strings.Contains(err.Error(), "unavailable") || strings.Contains(err.Error(), "4000") {
		t.Fatalf("stale keys are refused with a fixed reason that names no address: %v", err)
	}
	if v.KeysError() == nil || !strings.Contains(v.KeysError().Error(), "4000") {
		t.Fatalf("the read's own failure is kept for the module's logs: %v", v.KeysError())
	}
}

// Review r44 B1, first probe: after a rotation, a caller without the proof,
// with a cancelled context, every keyRetry, must neither read the keys nor
// stop the genuine call carrying the new key.
func TestAnUnauthenticatedCallerNeitherReadsNorStarvesTheKeys(t *testing.T) {
	first, second := newSigner("first"), newSigner("second")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: first.issuer, Keys: []*authorityv1.PublicKey{first.published()}}}
	clock := time.Unix(1792818000, 0)
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	v.now = func() time.Time { return clock }
	v.fetched, v.tried = clock, clock
	source.set(&authorityv1.KeysResponse{Issuer: first.issuer, Keys: []*authorityv1.PublicKey{second.published()}}, nil, nil)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	genuine, unauthenticatedReads := 0, 0
	for i := 0; i < 100; i++ {
		clock = clock.Add(keyRetry)
		before := source.count()
		for _, md := range []metadata.MD{metadata.Pairs(WorkContextKey, "garbage"), forwarded(t, second.issue(t, clock, "documents"), "another-run", "")} {
			if _, err := v.Verify(cancelled, md, "/test.Service/Read"); err == nil {
				t.Fatal("a call without this run's proof was admitted")
			}
		}
		settled(v)
		unauthenticatedReads += source.count() - before
		if _, err := v.Verify(context.Background(), forwarded(t, second.issue(t, clock, "documents"), "proof", ""), "/test.Service/Read"); err == nil {
			genuine++
		}
		settled(v)
	}
	if genuine != 100 || unauthenticatedReads != 0 {
		t.Fatalf("admitted %d/100 genuine calls; %d key reads caused by calls without the proof", genuine, unauthenticatedReads)
	}
}

// Review r44 B1, second probe: a hung read stalls no call whose key is held,
// and a caller that gives up waiting delays nobody's next read.
func TestAHungReadStallsNoHeldKeyAndACallerGivingUpDelaysNoOne(t *testing.T) {
	first, second := newSigner("first"), newSigner("second")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: first.issuer, Keys: []*authorityv1.PublicKey{first.published(), second.published()}}}
	start := time.Unix(1792818000, 0)
	clock := start
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	v.now = func() time.Time { return clock }
	v.fetched, v.tried = start, start
	hold := make(chan struct{})
	source.set(&authorityv1.KeysResponse{Issuer: first.issuer, Keys: []*authorityv1.PublicKey{first.published(), second.published()}}, nil, hold)
	clock = start.Add(keyMaxAge + time.Second) // old keys: a background read starts, and hangs
	done := make(chan error, 1)
	go func() {
		_, err := v.Verify(context.Background(), forwarded(t, first.issue(t, clock, "documents"), "proof", ""), "/test.Service/Read")
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a held key: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a call with a held key stalled behind a hung read")
	}
	// A key not held waits for the read; a caller who gives up is refused alone.
	third := newSigner("third")
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := v.Verify(short, forwarded(t, third.issue(t, clock, "documents"), "proof", ""), "/test.Service/Read"); err == nil || !strings.Contains(err.Error(), "ended while") {
		t.Fatalf("a caller giving up: %v", err)
	}
	source.set(&authorityv1.KeysResponse{Issuer: first.issuer, Keys: []*authorityv1.PublicKey{third.published()}}, nil, nil)
	close(hold)
	settled(v)
	clock = clock.Add(keyRetry)
	if _, err := v.Verify(context.Background(), forwarded(t, third.issue(t, clock, "documents"), "proof", ""), "/test.Service/Read"); err != nil {
		t.Fatalf("the next read is not delayed by the caller who gave up: %v", err)
	}
}

// The robin playground's model gateway, live: its first call after 39 idle
// minutes, with no readiness poll between, was refused while the re-read it
// started succeeded in the background. Held keys past keyStale cannot judge a
// call, so the call waits for the read, as it does for a key not held.
func TestACallOnKeysPastKeyStaleWaitsForTheReread(t *testing.T) {
	first := newSigner("first")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: first.issuer, Keys: []*authorityv1.PublicKey{first.published()}}}
	start := time.Unix(1792818000, 0)
	clock := start
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	v.now = func() time.Time { return clock }
	v.fetched, v.tried = start, start
	clock = start.Add(39 * time.Minute)
	if _, err := v.Verify(context.Background(), forwarded(t, first.issue(t, clock, "documents"), "proof", ""), "/test.Service/Read"); err != nil {
		t.Fatalf("the first call after an idle stretch is refused while its keys are re-read: %v", err)
	}
	if source.count() != 2 {
		t.Fatalf("reads %d, want the startup read and the one re-read", source.count())
	}
}

// The wait on keys past keyStale fails closed: a re-read that fails, or that
// outlives keyTimeout, refuses the call with the fixed reason, and only once
// the read has ended.
func TestACallOnKeysPastKeyStaleIsRefusedWhenTheRereadFails(t *testing.T) {
	first := newSigner("first")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: first.issuer, Keys: []*authorityv1.PublicKey{first.published()}}}
	start := time.Unix(1792818000, 0)
	clock := start
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	v.now = func() time.Time { return clock }
	v.timeout = 100 * time.Millisecond
	v.fetched, v.tried = start, start
	refused := func(err error) bool {
		return errors.Is(err, workcontext.ErrUnauthenticated) && strings.Contains(err.Error(), "unavailable") && !strings.Contains(err.Error(), "4000")
	}

	hold := make(chan struct{})
	source.set(nil, errors.New("dial authority.internal:4000: connection refused"), hold)
	clock = start.Add(keyStale + time.Minute)
	md := forwarded(t, first.issue(t, clock, "documents"), "proof", "")
	done := make(chan error, 1)
	go func() {
		_, err := v.Verify(context.Background(), md, "/test.Service/Read")
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the call was judged before its re-read ended: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(hold)
	if err := <-done; !refused(err) {
		t.Fatalf("a failed re-read refuses with the fixed reason: %v", err)
	}
	if v.KeysError() == nil || !strings.Contains(v.KeysError().Error(), "4000") {
		t.Fatalf("the read's own failure is kept for the module's logs: %v", v.KeysError())
	}

	source.set(nil, nil, make(chan struct{})) // a read that never answers
	clock = clock.Add(keyRetry)
	began := time.Now()
	_, err := v.Verify(context.Background(), forwarded(t, first.issue(t, clock, "documents"), "proof", ""), "/test.Service/Read")
	if !refused(err) || time.Since(began) < v.timeout {
		t.Fatalf("a hung re-read refuses with the fixed reason after keyTimeout: %v after %v", err, time.Since(began))
	}
	if !errors.Is(v.KeysError(), context.DeadlineExceeded) {
		t.Fatalf("the timeout is recorded: %v", v.KeysError())
	}
}

// A read that never answers is bounded by the verifier's own timeout.
func TestAReadIsBoundedByItsOwnTimeout(t *testing.T) {
	source := &keys{hold: make(chan struct{})}
	v := &Verifier{source: source, audience: "documents", replay: core.NewMemoryReplayStore(), now: time.Now, timeout: 20 * time.Millisecond}
	v.mu.Lock()
	done := v.refresh()
	v.mu.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a hung read was not bounded")
	}
	if !errors.Is(v.KeysError(), context.DeadlineExceeded) {
		t.Fatalf("the timeout is recorded: %v", v.KeysError())
	}
}

// An actor granted nothing narrows the identity to nothing, as Core's
// EffectiveScopes does (review r44 m1).
func TestAnActorGrantedNothingNarrowsToNothing(t *testing.T) {
	id := IdentityOf(&basev0.WorkContextV1{
		AuthorityScopes: []*basev0.WorkScopeV1{{ResourceKind: "documents", Actions: []string{"read"}}},
		ActorChain:      []*basev0.WorkActorV1{{PrincipalId: "robin"}},
	})
	if len(id.Scopes) != 0 || id.Has("documents", "read") {
		t.Fatalf("identity: %+v", id)
	}
}

// Readiness follows trust, not the last read: a failed re-read keeps a replica
// ready while its keys are inside keyStale; then it is not ready.
func TestReadyHoldsWhileKeysAreTrusted(t *testing.T) {
	first := newSigner("first")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: first.issuer, Keys: []*authorityv1.PublicKey{first.published()}}}
	clock := time.Unix(1792818000, 0)
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	v.now = func() time.Time { return clock }
	v.fetched, v.tried = clock, clock
	if !v.Ready() {
		t.Fatal("not ready after a successful read")
	}
	source.set(nil, errors.New("authority down"), nil)
	clock = clock.Add(keyMaxAge + time.Second)
	v.Ready() // starts the re-read, which fails
	settled(v)
	if v.KeysError() == nil || !v.Ready() {
		t.Fatalf("a failed re-read inside keyStale keeps the replica ready: ready=%v err=%v", v.Ready(), v.KeysError())
	}
	clock = clock.Add(keyStale)
	if v.Ready() {
		t.Fatal("ready with stale keys")
	}
}

// Review r74 B1, first case: a replica that starts during an authority outage
// gets no calls while unready; polling Ready alone must read again and turn it
// ready once the authority serves its keys.
func TestAnUnreadyReplicaBecomesReadyByPollingAlone(t *testing.T) {
	first := newSigner("first")
	source := &keys{err: errors.New("authority not serving yet")}
	clock := time.Unix(1792818000, 0)
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	v.now = func() time.Time { return clock }
	v.tried = clock
	ready := false
	for poll := 0; poll < 30 && !ready; poll++ {
		if poll == 3 {
			source.set(&authorityv1.KeysResponse{Issuer: first.issuer, Keys: []*authorityv1.PublicKey{first.published()}}, nil, nil)
		}
		clock = clock.Add(time.Second)
		v.Ready()
		settled(v)
		ready = v.Ready()
	}
	if !ready || source.count() > 3 {
		t.Fatalf("polling Ready after the authority recovered: ready=%v reads=%d", ready, source.count())
	}
}

// Review r74 B1, second case: an idle replica (no calls) polled for readiness
// past keyStale re-reads as its keys age and stays ready.
func TestAnIdleReplicaPolledForReadinessStaysReady(t *testing.T) {
	first := newSigner("first")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: first.issuer, Keys: []*authorityv1.PublicKey{first.published()}}}
	clock := time.Unix(1792818000, 0)
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	v.now = func() time.Time { return clock }
	v.fetched, v.tried = clock, clock
	for minute := 1; minute <= 60; minute++ {
		clock = clock.Add(time.Minute)
		v.Ready()
		settled(v)
		if !v.Ready() {
			t.Fatalf("an idle replica went unready at minute %d (reads %d)", minute, source.count())
		}
	}
	if reads := source.count(); reads < 10 || reads > 13 {
		t.Fatalf("an hour of readiness polls re-read the keys %d times; keyMaxAge says about 12", reads)
	}
}

// publishedHop is the admission key of the test hop that signs as label, as
// an authority's Keys carries it in admission_keys.
func publishedHop(label string) *authorityv1.PublicKey {
	id, public := testSigner(label).Admission()
	return &authorityv1.PublicKey{KeyId: id, Algorithm: core.Algorithm, PublicKey: public, Purpose: stamp.Purpose}
}

func testSigner(label string) *stamp.Signer {
	sum := sha256.Sum256([]byte(label))
	signer, _ := stamp.NewSigner(hex.EncodeToString(sum[:]))
	return signer
}
