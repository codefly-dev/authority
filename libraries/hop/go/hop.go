// Package hop is the stamp's contract: what the hop in front of a module writes
// onto a call it let through, and how the module authenticates it.
//
// The hop asked the authority's Check, which verified the caller's Work Context
// live (revision, seal, single use) and applied the method's policy, then wrote
// who the call is for and a signed admission for this call.
// The module re-checks no permission the hop decided, but believes nothing it
// has not authenticated: Verifier checks the token's signature under the
// authority's published keys, its issuer, that it is addressed to this module,
// its window and structure, and that it is the token the stamp's digest binds;
// who the call is for is read from the authenticated claims, never a header.
//
// The hop signs each admission with a service-only key. The authority publishes
// its public half in Keys (admission_keys, purpose hop-admission), so verifiers
// take it from the keys they already read, cache and refresh, never from their
// own configuration, and trust every published one while a key rotates. They
// atomically consume the signed nonce in a shared ReplayStore. Method, audience
// and token digest are authenticated; a captured stamp is single-use.
//
// Every refusal a caller is given is a refusal.Reason (Reason here): a stable
// code with fixed text that names no token, claim, key or transport failure.
// Read it with errors.As. A process that receives no hop calls but must still
// authenticate a Work Context it was handed — an Issue response, say — builds a
// NewTokenVerifier and calls VerifyToken: that authenticates identity on the
// same published keys, and establishes no admission.
package hop

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

// WorkContextKey carries the caller's Work Context to the hop, as everywhere.
// The hop forwards it, so a module acting onward can ask for a child.
const WorkContextKey = "x-codefly-work-context"

// The stamp. Every key the hop writes starts with StampPrefix, and the hop
// removes every such key a caller sent before writing its own.
const (
	StampPrefix  = "x-codefly-hop-"
	ProofKey     = StampPrefix + "proof"
	OwnerKey     = StampPrefix + "owner"
	OwnerKindKey = StampPrefix + "owner-kind"
	TenantKey    = StampPrefix + "tenant"
	ActorsKey    = StampPrefix + "actors"
	ScopesKey    = StampPrefix + "scopes"
	BindingKey   = StampPrefix + "binding"
	// TaskKey and ExpiresKey are the checked context's task and the instant it
	// expires (unix seconds): what a module keeps state under, and what it must
	// not hold a session past.
	TaskKey    = StampPrefix + "task"
	ExpiresKey = StampPrefix + "expires"
	// ContextKey binds the stamp to the one Work Context the authority checked:
	// the digest of the forwarded token. A module reading that token's claims
	// reads exactly what was checked, and nothing a caller swapped in after.
	ContextKey = StampPrefix + "context"
	// AdvisoryKey is always refused at admission. Diagnostic identity is never authority.
	AdvisoryKey = StampPrefix + "advisory"
)

// Identity is who a call is for, as the hop established it.
type Identity struct {
	Owner     string
	OwnerKind string
	Tenant    string
	// Actors are the modules acting for the owner, in order.
	Actors []string
	// Scopes are what the call may do, each "<resource kind>:<action>".
	Scopes []string
	// Binding is the operation binding the last actor exercises, when it names one.
	Binding string
	// Task is the checked context's task, and Expires the instant it expires
	// (unix seconds), when the hop stamped them.
	Task    string
	Expires int64
	// Context is the authenticated Work Context, as forwarded: the parent a
	// module asks a child of when it acts onward.
	Context string
	// Claims are the authenticated claims, for resource-exact questions
	// (Claims.Allows) the flat Scopes cannot answer.
	Claims *workcontext.Claims
	// Advisory is diagnostic only. Stamp refuses an identity carrying a refusal.
	Advisory string
}

// Has reports whether the identity may do action on kind.
func (i Identity) Has(kind, action string) bool {
	for _, s := range i.Scopes {
		if s == kind+":"+action {
			return true
		}
	}
	return false
}

// Strip removes every stamp key a caller may have sent: a stamp is the hop's to
// write and no one else's.
func Strip(md metadata.MD) {
	for key := range md {
		if strings.HasPrefix(strings.ToLower(key), StampPrefix) {
			delete(md, key)
		}
	}
}

// Stamp writes identity and a signed call admission, stripping caller stamps.
func Stamp(md metadata.MD, id Identity, signer *stamp.Signer, method, audience string, now time.Time) error {
	if id.Advisory != "" {
		return errors.New("hop: an advisory policy refusal cannot be signed as admission")
	}
	proof, err := signer.Sign(first(md, WorkContextKey), method, audience, now, id.Expires)
	if err != nil {
		return err
	}
	Strip(md)
	md.Set(ProofKey, proof)
	md.Set(OwnerKey, id.Owner)
	md.Set(OwnerKindKey, id.OwnerKind)
	md.Set(TenantKey, id.Tenant)
	md.Set(ActorsKey, strings.Join(id.Actors, ","))
	md.Set(ScopesKey, strings.Join(id.Scopes, ","))
	if id.Binding != "" {
		md.Set(BindingKey, id.Binding)
	}
	if id.Task != "" {
		md.Set(TaskKey, id.Task)
	}
	if id.Expires > 0 {
		md.Set(ExpiresKey, strconv.FormatInt(id.Expires, 10))
	}
	if id.Advisory != "" {
		md.Set(AdvisoryKey, id.Advisory)
	}
	if token := first(md, WorkContextKey); token != "" {
		md.Set(ContextKey, digest(token))
	}
	return nil
}

// IdentityOf reads who an authenticated Work Context is for. Its scopes are the
// effective ones: the owner's authority narrowed by every actor's grant. A
// scope limited to named resources is left out rather than widened to its whole
// kind; Claims.Allows answers those. It is the one derivation: the hop stamps
// it from the authority's checked context and the module derives it from the
// token it authenticated, so the two agree or the call is refused.
func IdentityOf(wc *basev0.WorkContextV1) Identity {
	id := Identity{
		Owner:     wc.GetOwnerPrincipalId(),
		OwnerKind: wc.GetOwnerPrincipalKind(),
		Tenant:    wc.GetTenantId(),
		Binding:   wc.GetOperationBinding().GetBindingId(),
		Task:      wc.GetTaskId(),
		Expires:   wc.GetExpiresAtUnix(),
	}
	scopes := flatten(wc.GetAuthorityScopes())
	for _, actor := range wc.GetActorChain() {
		id.Actors = append(id.Actors, actor.GetPrincipalId())
		held := flatten(actor.GetGrantedScopes()) // an actor granted nothing narrows to nothing, as Core's EffectiveScopes
		scopes = slices.DeleteFunc(scopes, func(s string) bool { return !slices.Contains(held, s) })
	}
	id.Scopes = scopes
	return id
}

// flatten stamps only kind-wide scopes. A resource-limited or owner-selected
// scope is never a kind-wide one; the module reads it from the claims
// (AllowsOwned), which keep its ids and owner.
func flatten(scopes []*basev0.WorkScopeV1) []string {
	var out []string
	for _, s := range scopes {
		if len(s.GetResourceIds()) > 0 || s.GetResourceOwnerId() != "" {
			continue
		}
		for _, action := range s.GetActions() {
			if scope := s.GetResourceKind() + ":" + action; !slices.Contains(out, scope) {
				out = append(out, scope)
			}
		}
	}
	return out
}

// Audience is this module's audience: the module the composition started this
// process as (CODEFLY__MODULE, the identity a manifest names), which is the
// name a Work Context is addressed to and the hop routes by. Read it rather
// than typing the module's name.
func Audience() (string, error) {
	module := strings.TrimSpace(os.Getenv(resources.ModulePrefix))
	if module == "" {
		return "", fmt.Errorf("hop: %s is not set: the composition names no module for this process", resources.ModulePrefix)
	}
	return module, nil
}

// KeySource is the authority interface's Keys, as its generated client serves
// it: the issuer, the public keys every Work Context is signed with, and the
// hop's admission keys.
type KeySource interface {
	Keys(ctx context.Context, in *authorityv1.KeysRequest, opts ...grpc.CallOption) (*authorityv1.KeysResponse, error)
}

// How the published keys are kept: re-read when a token names a key the
// verifier does not hold (at most once per keyRetry), and when they are older
// than keyMaxAge, so a removed key stops verifying. A read runs on its own,
// detached from any call, bounded by keyTimeout, one at a time; no caller can
// cancel it or fail it. A call waits for it only when it cannot be judged
// without it: its key is not held, or the held keys are keyStale old. A failed
// read keeps the last keys until they are keyStale old; then every call is
// refused, as the hop refuses a call it cannot check.
const (
	keyRetry   = 10 * time.Second
	keyMaxAge  = 5 * time.Minute
	keyStale   = 15 * time.Minute
	keyTimeout = 5 * time.Second
)

// errKeysUnavailable is the one reason a caller is given when keys are
// missing or stale: the read's own failure may name the authority's address,
// so it goes to KeysError, for the module's logs, never to a caller.
var errKeysUnavailable = fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, refusal.KeysUnavailable)

// ErrNoAdmissionKeys is what KeysError reports, for the module's logs, while
// the authority's keys read but publish no hop admission key: every call is
// refused as keys_unavailable until the authority publishes its hop's key.
var ErrNoAdmissionKeys = errors.New("hop: the authority's Keys publish no hop admission key (admission_keys), so no call can be admitted: the authority must publish its hop's key")

// Verifier is the one module-side entry point: it authenticates every call the
// hop forwards before anything reads it. Build it once, at startup.
type Verifier struct {
	source   KeySource
	audience string
	replay   core.ReplayStore
	now      func() time.Time
	timeout  time.Duration

	mu        sync.Mutex
	trust     workcontext.Trust
	admission []string      // the published hop admission keys, hex, read with trust
	fetched   time.Time     // when trust was read
	tried     time.Time     // when the last read started
	inflight  chan struct{} // closed when the running read ends; nil when none runs
	failure   error         // the last read's failure, for KeysError
}

// NewVerifier pins this module's audience. Keys is the generated authority
// client: the Work Context keys and the hop's admission keys are both read
// through it, so nothing about the hop is configured here and no signing seed
// is delivered. replay must atomically reserve nonces across all replicas and
// survive restart.
//
// It waits for that first read while ctx allows, and never fails on it: a
// module starts before its authority serves keys, and refuses calls, with the
// reason, until they are read.
func NewVerifier(ctx context.Context, keys KeySource, audience string, replay core.ReplayStore) (*Verifier, error) {
	if replay == nil {
		return nil, refusal.Configuration
	}
	if err := durableOutsideLocal(replay); err != nil {
		return nil, err
	}
	return newVerifier(ctx, keys, audience, replay)
}

// SharedReplayStore is a replay store that reports whether it is the durable
// reservation shared by every replica that the admission contract requires.
// replaypg.Store and a FileReplayStore opened with NewSharedFileReplayStore
// report true; Core's in-memory store does not implement this at all.
type SharedReplayStore interface {
	core.ReplayStore
	Shared() bool
}

// ErrReplayStoreNotShared is the named refusal for a replay store that cannot
// be the one every replica shares. A process-local set answers only for its own
// process, so a captured stamp replays once per replica inside its window, and
// a restart forgets every reservation. The contract has always forbidden that
// outside local; this refuses it at startup instead of documenting it.
//
// It is judged by CODEFLY__ENVIRONMENT, the environment the composition started
// this process in. A local run may use any store, so a laptop and a test keep
// working with Core's in-memory store and hoptest.Replay.
var ErrReplayStoreNotShared = errors.New("hop: this replay store is not the durable store every replica shares, which admission requires outside a local run: a captured admission would replay once per replica, and a restart would forget every reservation. Use replaypg.New over the module's own store, or NewSharedFileReplayStore for a genuinely shared mount")

// durableOutsideLocal refuses a store that does not declare itself shared,
// unless this process runs in a local environment.
func durableOutsideLocal(replay core.ReplayStore) error {
	environment := os.Getenv(resources.EnvironmentPrefix)
	if environment == "local" {
		return nil
	}
	if shared, ok := replay.(SharedReplayStore); ok && shared.Shared() {
		return nil
	}
	return fmt.Errorf("%w (environment %s)", ErrReplayStoreNotShared, environment)
}

// NewTokenVerifier builds a verifier for Issue responses in a process that does
// not receive hop calls. It needs no replay store. Verify always refuses stamps,
// because admission cannot be checked without one; VerifyToken uses the same
// key cache and validation as NewVerifier.
func NewTokenVerifier(ctx context.Context, keys KeySource, audience string) (*Verifier, error) {
	return newVerifier(ctx, keys, audience, nil)
}

func newVerifier(ctx context.Context, keys KeySource, audience string, replay core.ReplayStore) (*Verifier, error) {
	if keys == nil || audience == "" {
		return nil, refusal.Configuration
	}
	v := &Verifier{source: keys, audience: audience, replay: replay, now: time.Now, timeout: keyTimeout}
	v.mu.Lock()
	done := v.refresh()
	v.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
	}
	return v, nil
}

// KeysError is the last failure to read the published keys, nil after a
// successful read: for the module's logs and readiness, never for a caller.
// A verifier that admits calls also reports ErrNoAdmissionKeys when the keys
// read but publish no hop admission key.
func (v *Verifier) KeysError() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.failure
}

// Ready reports whether the verifier holds trusted keys: true from the first
// successful read, and through failed re-reads while the last keys are inside
// keyStale; false before any read succeeded or once they are stale. A module's
// readiness uses it, never KeysError: a brief authority outage must not take a
// replica out of rotation while its keys are still trusted.
//
// It also starts the read a call would (keys missing or older than keyMaxAge,
// or no admission key published, at most once per keyRetry, never waiting for
// it): an unready replica gets no calls, so without this it would never read
// again and never become ready, and an idle one would go stale.
func (v *Verifier) Ready() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	unadmitting := v.replay != nil && len(v.admission) == 0
	if (v.fetched.IsZero() || now.Sub(v.fetched) > keyMaxAge || unadmitting) && v.inflight == nil && now.Sub(v.tried) >= keyRetry {
		v.refresh()
	}
	return !v.fetched.IsZero() && now.Sub(v.fetched) <= keyStale
}

// Verify authenticates the call md carries and returns who it is for, from the
// authenticated claims. The error wraps workcontext.ErrUnauthenticated and
// carries a caller-safe refusal.Reason. The admission is checked first: a call
// that does not carry a hop admission signed for this exact procedure and
// audience, binding this token, never reaches the keys.
//
// Verify consumes the admission and ends its in-flight hold before returning,
// so the reservation lasts to the admission's expiry plus the clock allowance.
// A caller that runs work for the call afterwards uses Admit, which holds the
// reservation until that work has finished.
func (v *Verifier) Verify(ctx context.Context, md metadata.MD, method string) (Identity, error) {
	id, done, err := v.Admit(ctx, md, method)
	if err != nil {
		return Identity{}, err
	}
	done()
	return id, nil
}

// Admit is Verify for a caller that runs the call's work itself, such as an
// HTTP module: it reserves the single-use admission before any key read, and
// holds the reservation, past its retention if need be, until done is called.
// Call done once the work has returned, whatever its outcome:
//
//	id, done, err := verifier.Admit(ctx, md, procedure)
//	if err != nil { return err }
//	defer done()
//
// The window is judged now. Call Admit as soon as the request's headers have
// arrived, before its body is read, so a slow body neither fails the window
// nor delays the reservation.
func (v *Verifier) Admit(ctx context.Context, md metadata.MD, method string) (Identity, func(), error) {
	release, err := v.reserve(ctx, md, method, v.instant())
	if err != nil {
		return Identity{}, nil, err
	}
	id, err := v.establish(ctx, md, release)
	if err != nil {
		return Identity{}, nil, err
	}
	return id, release, nil
}

// VerifyToken authenticates a bare Work Context using the same published keys
// and fail-closed refresh policy as Verify. It does not establish hop admission,
// consume a single-use nonce, or check live revocation or method permissions.
func (v *Verifier) VerifyToken(ctx context.Context, token string) (Identity, error) {
	trust, err := v.trustFor(ctx, keyIDOf(token))
	if err != nil {
		return Identity{}, err
	}
	claims, err := workcontext.AuthenticateToken(token, v.audience, trust)
	if err != nil {
		return Identity{}, err
	}
	id := IdentityOf(claims.Context())
	id.Context, id.Claims = token, claims
	return id, nil
}

// trustFor returns the keys to judge a token naming keyID by. A key not held,
// or held keys past keyStale, start a read (at most once per keyRetry) and the
// call waits for it, as long as the caller does and no longer than the read's
// own keyTimeout: an idle replica's first call is judged on fresh keys, not
// refused while they arrive. Keys older than keyMaxAge but inside keyStale
// start a read and are used meanwhile.
func (v *Verifier) trustFor(ctx context.Context, keyID string) (workcontext.Trust, error) {
	v.mu.Lock()
	now := v.now()
	_, held := v.trust.Keys[keyID]
	if (!held || now.Sub(v.fetched) > keyMaxAge) && v.inflight == nil && now.Sub(v.tried) >= keyRetry {
		v.refresh()
	}
	wait, judgeable := v.inflight, held && now.Sub(v.fetched) <= keyStale
	v.mu.Unlock()
	if !judgeable {
		if err := v.await(ctx, wait); err != nil {
			return workcontext.Trust{}, err
		}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.trusted(); err != nil {
		return workcontext.Trust{}, err
	}
	return workcontext.Trust{Issuer: v.trust.Issuer, Keys: v.trust.Keys, Now: v.now}, nil
}

// admissionKey is the published hop admission key the admission md carries is
// signed by. It is judged on the keys held: the admission is what a call has
// not yet proven, so neither a stamp signed by no published key nor keys past
// keyMaxAge start a read here, and a caller without an admission can neither
// drive the authority's keys nor delay the read a genuine call needs. Only
// when no trusted keys are held at all (never read, or past keyStale, as on an
// idle replica's first call), or the last read published no admission key (the
// hop had not registered yet), does it start a read, at most once per keyRetry
// as readiness does, and wait for it. A hop's new key is therefore learnt on
// the next read an admitted call or readiness starts, within keyMaxAge, so an
// authority publishes it that long before its hop signs with it, beside the
// retiring key.
func (v *Verifier) admissionKey(ctx context.Context, md metadata.MD) (string, error) {
	v.mu.Lock()
	// Holding no published admission key is holding no key to judge by: the
	// authority publishes the hop's once the hop registers it, which may be
	// after this verifier first read Keys.
	untrusted := v.trusted() != nil || len(v.admission) == 0
	if untrusted && v.inflight == nil && v.now().Sub(v.tried) >= keyRetry {
		v.refresh()
	}
	wait := v.inflight
	v.mu.Unlock()
	if untrusted {
		if err := v.await(ctx, wait); err != nil {
			return "", err
		}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.trusted(); err != nil {
		return "", err
	}
	if len(v.admission) == 0 {
		return "", errKeysUnavailable
	}
	key := stamp.SignedBy(md, v.admission)
	if key == "" {
		return "", fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, refusal.StampProof)
	}
	return key, nil
}

// await waits for the running read, if any, as long as the caller does.
func (v *Verifier) await(ctx context.Context, read chan struct{}) error {
	if read == nil {
		return nil
	}
	select {
	case <-read:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, refusal.Cancelled)
	}
}

// trusted refuses, with the reason, keys that were never read or are past
// keyStale; v.mu is held.
func (v *Verifier) trusted() error {
	if v.fetched.IsZero() || v.now().Sub(v.fetched) > keyStale {
		if errors.Is(v.failure, refusal.InvalidKey) {
			return fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, refusal.InvalidKey)
		}
		return errKeysUnavailable
	}
	return nil
}

// refresh starts the one read, detached from every call; v.mu is held. It
// returns the channel closed when the read ends.
func (v *Verifier) refresh() chan struct{} {
	if v.inflight != nil {
		return v.inflight
	}
	done := make(chan struct{})
	v.inflight, v.tried = done, v.now()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), v.timeout)
		defer cancel()
		trust, admission, err := v.read(ctx)
		v.mu.Lock()
		defer v.mu.Unlock()
		if err == nil {
			v.trust, v.admission, v.fetched = trust, admission, v.now()
			if v.replay != nil && len(admission) == 0 {
				err = ErrNoAdmissionKeys
			}
		}
		v.failure, v.inflight = err, nil
		close(done)
	}()
	return done
}

// read asks the authority for its published keys: the Work Context keys from
// keys, each used only if its purpose is a Work Context's, and the hop's
// admission keys from admission_keys, each used only if its purpose is
// stamp.Purpose. A key in the wrong field is never used for the other.
func (v *Verifier) read(ctx context.Context) (workcontext.Trust, []string, error) {
	response, err := v.source.Keys(ctx, &authorityv1.KeysRequest{})
	if err != nil {
		return workcontext.Trust{}, nil, fmt.Errorf("hop: the authority's published keys cannot be read: %w", err)
	}
	trust := workcontext.Trust{Issuer: response.GetIssuer(), Keys: map[string]ed25519.PublicKey{}}
	for _, key := range response.GetKeys() {
		if key.GetAlgorithm() != core.Algorithm || (key.GetPurpose() != "" && key.GetPurpose() != workContextPurpose) {
			continue
		}
		if key.GetKeyId() == "" || len(key.GetPublicKey()) != ed25519.PublicKeySize || trust.Keys[key.GetKeyId()] != nil {
			return workcontext.Trust{}, nil, refusal.InvalidKey
		}
		trust.Keys[key.GetKeyId()] = ed25519.PublicKey(slices.Clone(key.GetPublicKey()))
	}
	if trust.Issuer == "" || len(trust.Keys) == 0 {
		return workcontext.Trust{}, nil, refusal.InvalidKey
	}
	var admission []string
	for _, key := range response.GetAdmissionKeys() {
		if key.GetAlgorithm() != core.Algorithm || key.GetPurpose() != stamp.Purpose {
			continue
		}
		if len(key.GetPublicKey()) != ed25519.PublicKeySize {
			return workcontext.Trust{}, nil, refusal.InvalidKey
		}
		if public := hex.EncodeToString(key.GetPublicKey()); !slices.Contains(admission, public) {
			admission = append(admission, public)
		}
	}
	return trust, admission, nil
}

// workContextPurpose is a Work Context key's purpose in Keys. A key published
// with no purpose, by a host older than admission_keys, is one too.
const workContextPurpose = "work-context"

// keyIDOf is the key a token names, read only to choose the keys it is judged
// by; "" when it does not decode, which Authenticate then refuses.
func keyIDOf(token string) string {
	decoded, err := core.Decode(token)
	if err != nil {
		return ""
	}
	return decoded.Context().GetKeyId()
}

// sameAsStamped refuses a stamp that says anything the authenticated claims do
// not: the identity is the token's, and a disagreeing header is a forgery or a
// broken hop, either way not a call to serve.
func sameAsStamped(md metadata.MD, id Identity) error {
	expires := ""
	if id.Expires > 0 {
		expires = strconv.FormatInt(id.Expires, 10)
	}
	for _, field := range []struct{ key, want string }{
		{OwnerKey, id.Owner}, {OwnerKindKey, id.OwnerKind}, {TenantKey, id.Tenant},
		{ActorsKey, strings.Join(id.Actors, ",")}, {ScopesKey, strings.Join(id.Scopes, ",")},
		{BindingKey, id.Binding}, {TaskKey, id.Task}, {ExpiresKey, expires},
	} {
		if got := md.Get(field.key); len(got) > 1 || first(md, field.key) != field.want {
			return fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, refusal.StampIdentity)
		}
	}
	return nil
}

func digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

type identityKey struct{}

// FromContext returns the identity the module's interceptor authenticated.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

// UnaryServerInterceptor gives each call the identity Verify authenticated,
// and refuses, naming the reason, a call it does not. Health checks pass
// unstamped: the run probes the module directly, and they read no data.
func (v *Verifier) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, err := v.admit(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		defer finishAdmission(ctx)
		return handler(ctx, req)
	}
}

// StreamServerInterceptor is UnaryServerInterceptor for streams.
func (v *Verifier) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := v.admit(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		defer finishAdmission(ctx)
		return handler(srv, &stamped{ServerStream: ss, ctx: ctx})
	}
}

func (v *Verifier) admit(ctx context.Context, method string) (context.Context, error) {
	if strings.HasPrefix(method, "/grpc.health.v1.Health/") {
		return ctx, nil
	}
	held, ok := ctx.Value(admissionKey{}).(*admission)
	if !ok || held.verifier != v || held.method != method {
		// No stats handler reserved this call: it is reserved now, judged at now.
		md, _ := metadata.FromIncomingContext(ctx)
		release, err := v.reserve(ctx, md, method, v.instant())
		held = &admission{verifier: v, method: method, md: md, reserved: make(chan struct{}), release: release, err: err}
		close(held.reserved)
	}
	select {
	case <-held.reserved:
	case <-ctx.Done():
		return nil, status.Error(codes.Unauthenticated, fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, refusal.Cancelled).Error())
	}
	if held.err != nil {
		return nil, status.Error(codes.Unauthenticated, held.err.Error())
	}
	if !held.start() {
		return nil, status.Error(codes.Unauthenticated, fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, refusal.Cancelled).Error())
	}
	id, err := v.establish(ctx, held.md, held.release)
	if err != nil {
		held.finish()
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	return context.WithValue(context.WithValue(ctx, admissionKey{}, held), identityKey{}, id), nil
}

type stamped struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *stamped) Context() context.Context { return s.ctx }

func first(md metadata.MD, key string) string {
	if v := md.Get(key); len(v) > 0 {
		return v[0]
	}
	return ""
}

// StatsHandler reserves each call's single-use admission when the call
// arrives, before its body is read, and the interceptors hold that reservation
// until the handler returns.
//
// grpc-go decodes a unary request fully before it invokes the unary
// interceptor, and the Connect and REST faces buffer the message too. Judging
// the admission there would refuse a genuinely admitted upload that took
// longer than stamp.Lifetime to arrive; consuming its nonce there would let a
// second delivery of the same admission, held back while its body arrived,
// consume a nonce that had since been released, and run the handler twice.
// Installing this handler judges the window at the instant the call reached
// the server and reserves the nonce then, so every delivery that arrives
// inside the window meets the reservation and is refused as stamp_replayed.
// Python's and TypeScript's verifiers run at the same point, before the body
// is read.
//
// It is a stats handler rather than a tap handle because gRPC tags every call
// with it, on every transport the server serves: its own listener, and the
// Connect listener that hands each call to the same server through
// grpc.Server.ServeHTTP, where a tap handle never runs. Install it beside the
// interceptors:
//
//	grpc.NewServer(grpc.StatsHandler(verifier.StatsHandler()),
//		grpc.ChainUnaryInterceptor(verifier.UnaryServerInterceptor()),
//		grpc.ChainStreamInterceptor(verifier.StreamServerInterceptor()))
//
// It does no work on the call's path: it records the arrival instant and
// starts the check and the reservation beside the call, which the interceptor
// awaits and which refuses with the reason. A call that ends before its
// handler starts releases its hold; one whose handler started is released
// when the handler returns.
func (v *Verifier) StatsHandler() stats.Handler { return arrivals{v} }

// arrivals is the Verifier's stats handler: it tags each call with its
// admission, and observes nothing else.
type arrivals struct{ v *Verifier }

func (a arrivals) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	method := info.FullMethodName
	if strings.HasPrefix(method, "/grpc.health.v1.Health/") {
		return ctx
	}
	md, _ := metadata.FromIncomingContext(ctx)
	arrival := a.v.instant()
	held := &admission{verifier: a.v, method: method, md: md, reserved: make(chan struct{})}
	go func() {
		defer close(held.reserved)
		held.release, held.err = a.v.reserve(ctx, md, method, arrival)
	}()
	context.AfterFunc(ctx, held.abandon)
	return context.WithValue(ctx, admissionKey{}, held)
}

func (arrivals) HandleRPC(context.Context, stats.RPCStats) {}

func (arrivals) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context { return ctx }

func (arrivals) HandleConn(context.Context, stats.ConnStats) {}
