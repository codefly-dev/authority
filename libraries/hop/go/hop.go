// Package hop is the stamp's contract: what the hop in front of a module writes
// onto a call it let through, and how the module authenticates it.
//
// The hop asked the authority's Check, which verified the caller's Work Context
// live (revision, seal, single use) and applied the method's policy, then wrote
// who the call is for, this run's proof and the digest of the checked token.
// The module re-checks no permission the hop decided, but believes nothing it
// has not authenticated: Verifier checks the token's signature under the
// authority's published keys, its issuer, that it is addressed to this module,
// its window, and that it is the token the stamp's digest binds; who the call
// is for is read from the authenticated claims, never from a header. The proof
// says the call came through the hop, so the method policy and the live check
// were applied; it authenticates no identity, because every hop-fronted module
// holds it.
package hop

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
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
	// AdvisoryKey carries what the authority would have refused when the hop
	// runs permissive (hop/ENFORCEMENT=warn): the call went through, this says
	// why it would not have. Empty, or absent, when nothing was refused.
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
	// Advisory is what the authority would have refused, when the hop let the
	// call through anyway (permissive mode); "" when the call was admitted.
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

// Stamp writes identity and the run's proof onto md, after stripping whatever
// stamp a caller sent.
func Stamp(md metadata.MD, id Identity, proof string) {
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
		if granted := actor.GetGrantedScopes(); len(granted) > 0 {
			held := flatten(granted)
			scopes = slices.DeleteFunc(scopes, func(s string) bool { return !slices.Contains(held, s) })
		}
	}
	id.Scopes = scopes
	return id
}

func flatten(scopes []*basev0.WorkScopeV1) []string {
	var out []string
	for _, s := range scopes {
		if len(s.GetResourceIds()) > 0 {
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

// KeySource is the authority interface's Keys, as its generated client serves
// it: the issuer and the public keys every Work Context is signed with.
type KeySource interface {
	Keys(ctx context.Context, in *authorityv1.KeysRequest, opts ...grpc.CallOption) (*authorityv1.KeysResponse, error)
}

// How the published keys are kept: re-read when a token names a key the
// verifier does not hold (at most once per keyRetry), and when they are older
// than keyMaxAge, so a removed key stops verifying. A failed re-read keeps the
// last keys until they are keyStale old; then every call is refused, naming
// the outage, as the hop refuses a call it cannot check.
const (
	keyRetry  = 10 * time.Second
	keyMaxAge = 5 * time.Minute
	keyStale  = 15 * time.Minute
)

// Verifier is the one module-side entry point: it authenticates every call the
// hop forwards before anything reads it. Build it once, at startup.
type Verifier struct {
	source   KeySource
	audience string
	proof    string
	now      func() time.Time

	mu      sync.Mutex
	trust   workcontext.Trust
	fetched time.Time // when trust was read
	tried   time.Time // the last read attempt
}

// NewVerifier pins this module's audience and the run's hop proof, and reads
// the authority's published keys through the interface's Keys. keys is the
// generated client of the authority the module already depends on
// (authorityv1.NewAuthorityServiceClient over host.Dial): the local authority
// on a laptop, the host on a cell. A key is never typed in or mounted.
func NewVerifier(ctx context.Context, keys KeySource, audience, proof string) (*Verifier, error) {
	switch {
	case keys == nil:
		return nil, errors.New("hop: a verifier needs the authority's Keys")
	case audience == "":
		return nil, errors.New("hop: a verifier needs this module's audience")
	case proof == "":
		return nil, errors.New("hop: a verifier needs the run's hop proof (codefly config generate hop PROOF)")
	}
	v := &Verifier{source: keys, audience: audience, proof: proof, now: time.Now}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.fetch(ctx); err != nil {
		return nil, err
	}
	return v, nil
}

// Verify authenticates the call md carries and returns who it is for, from the
// authenticated claims. The error wraps workcontext.ErrUnauthenticated and
// names the reason.
func (v *Verifier) Verify(ctx context.Context, md metadata.MD) (Identity, error) {
	trust, err := v.trustFor(ctx, first(md, WorkContextKey))
	if err != nil {
		return Identity{}, err
	}
	claims, err := workcontext.Authenticate(md, v.proof, v.audience, trust)
	if err != nil {
		return Identity{}, err
	}
	id := IdentityOf(claims.Context())
	if err := sameAsStamped(md, id); err != nil {
		return Identity{}, err
	}
	id.Context, id.Claims, id.Advisory = first(md, WorkContextKey), claims, first(md, AdvisoryKey)
	return id, nil
}

// trustFor returns the keys to judge token by, re-reading them when the token
// names a key not held or the keys are old.
func (v *Verifier) trustFor(ctx context.Context, token string) (workcontext.Trust, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	_, held := v.trust.Keys[keyIDOf(token)]
	if (!held || now.Sub(v.fetched) > keyMaxAge) && now.Sub(v.tried) >= keyRetry {
		if err := v.fetch(ctx); err != nil && now.Sub(v.fetched) > keyStale {
			return workcontext.Trust{}, err
		}
	}
	if now.Sub(v.fetched) > keyStale {
		return workcontext.Trust{}, fmt.Errorf("%w: the authority's keys were last read %s ago", workcontext.ErrUnauthenticated, now.Sub(v.fetched).Round(time.Second))
	}
	return workcontext.Trust{Issuer: v.trust.Issuer, Keys: v.trust.Keys, Now: v.now}, nil
}

// fetch reads the published keys; v.mu is held.
func (v *Verifier) fetch(ctx context.Context) error {
	v.tried = v.now()
	response, err := v.source.Keys(ctx, &authorityv1.KeysRequest{})
	if err != nil {
		return fmt.Errorf("%w: the authority's published keys cannot be read: %w", workcontext.ErrUnauthenticated, err)
	}
	trust := workcontext.Trust{Issuer: response.GetIssuer(), Keys: map[string]ed25519.PublicKey{}}
	for _, key := range response.GetKeys() {
		if key.GetAlgorithm() != core.Algorithm {
			continue
		}
		if key.GetKeyId() == "" || len(key.GetPublicKey()) != ed25519.PublicKeySize || trust.Keys[key.GetKeyId()] != nil {
			return fmt.Errorf("%w: the authority publishes an unnamed, repeated or malformed key", workcontext.ErrUnauthenticated)
		}
		trust.Keys[key.GetKeyId()] = ed25519.PublicKey(slices.Clone(key.GetPublicKey()))
	}
	if trust.Issuer == "" || len(trust.Keys) == 0 {
		return fmt.Errorf("%w: the authority publishes no issuer or no Ed25519 key", workcontext.ErrUnauthenticated)
	}
	v.trust, v.fetched = trust, v.tried
	return nil
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
			return fmt.Errorf("%w: the stamp's %s does not match the authenticated Work Context", workcontext.ErrUnauthenticated, strings.TrimPrefix(field.key, StampPrefix))
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
	id, err := v.Verify(ctx, md)
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
