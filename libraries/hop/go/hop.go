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
// The hop signs each admission with a service-only key. Verifiers pin its public
// key and atomically consume the signed nonce in a shared ReplayStore. Method,
// audience and token digest are authenticated; a captured stamp is single-use.
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
// it: the issuer and the public keys every Work Context is signed with.
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

// Verifier is the one module-side entry point: it authenticates every call the
// hop forwards before anything reads it. Build it once, at startup.
type Verifier struct {
	source    KeySource
	audience  string
	publicKey string
	replay    core.ReplayStore
	now       func() time.Time
	timeout   time.Duration

	mu       sync.Mutex
	trust    workcontext.Trust
	fetched  time.Time     // when trust was read
	tried    time.Time     // when the last read started
	inflight chan struct{} // closed when the running read ends; nil when none runs
	failure  error         // the last read's failure, for KeysError
}

// NewVerifier pins this module's audience and the delivered hop public key.
// replay must atomically reserve nonces across all replicas and survive restart.
// Keys is the generated authority client; no signing seed is delivered here.
//
// It waits for that first read while ctx allows, and never fails on it: a
// module starts before its authority serves keys, and refuses calls, with the
// reason, until they are read.
func NewVerifier(ctx context.Context, keys KeySource, audience, publicKey string, replay core.ReplayStore) (*Verifier, error) {
	raw, keyErr := hex.DecodeString(publicKey)
	if replay == nil || keyErr != nil || len(raw) != ed25519.PublicKeySize || hex.EncodeToString(raw) != publicKey {
		return nil, refusal.Configuration
	}
	return newVerifier(ctx, keys, audience, publicKey, replay)
}

// NewTokenVerifier builds a verifier for Issue responses in a process that does
// not receive hop calls. It needs neither the hop's public key nor a replay
// store. Verify always refuses stamps, because admission cannot be checked
// without them; VerifyToken uses the same key cache and validation as NewVerifier.
func NewTokenVerifier(ctx context.Context, keys KeySource, audience string) (*Verifier, error) {
	return newVerifier(ctx, keys, audience, "", nil)
}

func newVerifier(ctx context.Context, keys KeySource, audience, publicKey string, replay core.ReplayStore) (*Verifier, error) {
	if keys == nil || audience == "" {
		return nil, refusal.Configuration
	}
	v := &Verifier{source: keys, audience: audience, publicKey: publicKey, replay: replay, now: time.Now, timeout: keyTimeout}
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
// at most once per keyRetry, never waiting for it): an unready replica gets no
// calls, so without this it would never read again and never become ready, and
// an idle one would go stale.
func (v *Verifier) Ready() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	if (v.fetched.IsZero() || now.Sub(v.fetched) > keyMaxAge) && v.inflight == nil && now.Sub(v.tried) >= keyRetry {
		v.refresh()
	}
	return !v.fetched.IsZero() && now.Sub(v.fetched) <= keyStale
}

// Verify authenticates the call md carries and returns who it is for, from the
// authenticated claims. The error wraps workcontext.ErrUnauthenticated and
// carries a caller-safe refusal.Reason. The admission is checked first: a call
// that does not carry a hop admission signed for this exact procedure and
// audience, binding this token, never reaches the keys.
func (v *Verifier) Verify(ctx context.Context, md metadata.MD, method string) (Identity, error) {
	if v.publicKey == "" || v.replay == nil {
		// A token-only verifier (NewTokenVerifier) holds neither the hop's
		// public key nor a replay store, so it can establish no admission.
		return Identity{}, fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, refusal.Configuration)
	}
	call, err := stamp.Check(md, v.publicKey, method, v.audience, v.now())
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, err)
	}
	id, err := v.VerifyToken(ctx, first(md, WorkContextKey))
	if err != nil {
		return Identity{}, err
	}
	if err := sameAsStamped(md, id); err != nil {
		return Identity{}, err
	}
	if call.Expires <= v.now().Unix() {
		return Identity{}, fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, refusal.StampWindow)
	}
	if err := v.replay.Consume(ctx, call.ReplayKey(v.publicKey), time.Unix(call.Expires, 0)); err != nil {
		if errors.Is(err, core.ErrReplayed) {
			return Identity{}, fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, refusal.StampReplayed)
		}
		return Identity{}, fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, refusal.StampStore)
	}
	if call.Expires <= v.now().Unix() {
		return Identity{}, fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, refusal.StampWindow)
	}
	// An admission carrying an advisory refusal is refused by stamp.Check, so
	// an admitted call never has one: diagnostic identity is never authority.
	return id, nil
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
	if !judgeable && wait != nil {
		select {
		case <-wait:
		case <-ctx.Done():
			return workcontext.Trust{}, fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, refusal.Cancelled)
		}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.fetched.IsZero() || v.now().Sub(v.fetched) > keyStale {
		if errors.Is(v.failure, refusal.InvalidKey) {
			return workcontext.Trust{}, fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, refusal.InvalidKey)
		}
		return workcontext.Trust{}, errKeysUnavailable
	}
	return workcontext.Trust{Issuer: v.trust.Issuer, Keys: v.trust.Keys, Now: v.now}, nil
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
		trust, err := v.read(ctx)
		v.mu.Lock()
		defer v.mu.Unlock()
		if err == nil {
			v.trust, v.fetched = trust, v.now()
		}
		v.failure, v.inflight = err, nil
		close(done)
	}()
	return done
}

// read asks the authority for its published keys.
func (v *Verifier) read(ctx context.Context) (workcontext.Trust, error) {
	response, err := v.source.Keys(ctx, &authorityv1.KeysRequest{})
	if err != nil {
		return workcontext.Trust{}, fmt.Errorf("hop: the authority's published keys cannot be read: %w", err)
	}
	trust := workcontext.Trust{Issuer: response.GetIssuer(), Keys: map[string]ed25519.PublicKey{}}
	for _, key := range response.GetKeys() {
		if key.GetAlgorithm() != core.Algorithm {
			continue
		}
		if key.GetKeyId() == "" || len(key.GetPublicKey()) != ed25519.PublicKeySize || trust.Keys[key.GetKeyId()] != nil {
			return workcontext.Trust{}, refusal.InvalidKey
		}
		trust.Keys[key.GetKeyId()] = ed25519.PublicKey(slices.Clone(key.GetPublicKey()))
	}
	if trust.Issuer == "" || len(trust.Keys) == 0 {
		return workcontext.Trust{}, refusal.InvalidKey
	}
	return trust, nil
}

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
		return handler(srv, &stamped{ServerStream: ss, ctx: ctx})
	}
}

func (v *Verifier) admit(ctx context.Context, method string) (context.Context, error) {
	if strings.HasPrefix(method, "/grpc.health.v1.Health/") {
		return ctx, nil
	}
	md, _ := metadata.FromIncomingContext(ctx)
	id, err := v.Verify(ctx, md, method)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	return context.WithValue(ctx, identityKey{}, id), nil
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
