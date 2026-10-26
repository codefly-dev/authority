// Package workcontext authenticates the Work Context the hop forwarded to a
// module, and projects its claims. AuthenticateToken is the one check a
// module's reading rests on: nothing here decodes a token it has not
// authenticated. It establishes identity, never hop admission, which is
// hop.Verifier's.
package workcontext

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	"strings"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/protobuf/proto"
)

// ErrUnauthenticated is a forwarded Work Context the module must not believe.
// The error chain names the reason: Core's refusal (signature, issuer,
// audience, window, structure) or the stamp's (proof, digest).
var ErrUnauthenticated = errors.New("authority: the forwarded Work Context is not authenticated")

// Trust is the authority a module believes: the issuer every capability must
// name and that issuer's published verification keys by key id, exactly as
// the authority interface's Keys answers them. It is resolved from the host,
// never typed in.
type Trust struct {
	Issuer string
	Keys   map[string]ed25519.PublicKey
	// Now is the clock the window is judged at; nil means time.Now.
	Now func() time.Time
}

// Claims owns a snapshot of an authenticated context. It can be read
// concurrently. Its zero value grants nothing.
type Claims struct {
	audience string
	scopes   []*basev0.WorkScopeV1
	context  *basev0.WorkContextV1
}

// AuthenticateToken authenticates one Work Context with Core's Inspector:
// canonical decode, the issuer pin, the Ed25519 signature under the published
// key the token names, the audience is this module, not-before and expiry
// within Core's skew, and the chain's structure and attenuation. It returns the
// claims, or a caller-safe refusal.Reason naming why they must not be believed.
//
// This is the one identity-only reader here, and identity is all it
// establishes. It proves no hop admission: it does not check that a call was
// admitted for the procedure it arrived on, consumes no single-use nonce, and
// asks the authority nothing, so it checks no live revocation either. A service
// admits a call through hop.Verifier, which checks the hop's signed admission
// and reserves its nonce in a store every replica shares, and reaches here for
// the identity.
//
// A caller holding a call's metadata rather than a token extracts the token the
// stamp's digest binds with stamp.Context first. That is deliberately two
// calls (review r164 R4): a reader taking metadata reads as though it admitted
// the call, and it does not — a digest binding authorizes nothing, because
// whoever forwards a call can write both the token and its digest.
func AuthenticateToken(token, audience string, trust Trust) (*Claims, error) {
	if audience == "" {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, refusal.Configuration)
	}
	if trust.Issuer == "" || len(trust.Keys) == 0 {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, refusal.InvalidKey)
	}
	inspector := core.Inspector{Issuer: trust.Issuer, Keys: trust.Keys, Now: trust.Now}
	if _, err := inspector.Inspect(token, audience); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, safeReason(err))
	}
	decoded, err := core.Decode(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, safeReason(err))
	}
	context := decoded.Context()
	scopes := context.GetAuthorityScopes()
	if chain := context.GetActorChain(); len(chain) > 0 {
		scopes = chain[len(chain)-1].GetGrantedScopes()
	}
	return &Claims{audience: context.GetAudience(), scopes: scopes, context: context}, nil
}

// Audience is the module the context is addressed to: the one Authenticate
// was asked for.
func (c *Claims) Audience() string {
	if c == nil {
		return ""
	}
	return c.audience
}

// Context returns a deep copy of the authenticated claims.
func (c *Claims) Context() *basev0.WorkContextV1 {
	if c == nil || c.context == nil {
		return nil
	}
	return proto.Clone(c.context).(*basev0.WorkContextV1)
}

// Scopes returns deep copies; changing them cannot change later Allows results.
func (c *Claims) Scopes() []*basev0.WorkScopeV1 {
	if c == nil {
		return nil
	}
	out := make([]*basev0.WorkScopeV1, len(c.scopes))
	for n, scope := range c.scopes {
		out[n] = proto.Clone(scope).(*basev0.WorkScopeV1)
	}
	return out
}

// Allows asks for one literal action on one exact resource. An empty resourceID
// asks for the whole kind; a resource-limited grant cannot satisfy that request.
// No wildcard expansion, action implication or cross-grant merging occurs. It
// names no resource owner, so an owner-selected grant never satisfies it: a
// module whose resources have owners asks AllowsOwned.
func (c *Claims) Allows(kind, action, resourceID string) bool {
	return c.AllowsOwned(kind, action, resourceID, "")
}

// AllowsOwned is Allows for a resource owned by ownerID (the owner the
// module's own record names): an owner-selected grant covers it only when it
// names that owner, and, with ids, the id too. A grant naming no owner covers
// it whatever its owner. An empty resourceID with an owner asks for every
// resource that owner holds, the list path.
func (c *Claims) AllowsOwned(kind, action, resourceID, ownerID string) bool {
	if c == nil || kind == "" || action == "" {
		return false
	}
	ask := &basev0.WorkScopeV1{ResourceKind: kind, Actions: []string{action}, ResourceOwnerId: ownerID}
	if resourceID != "" {
		ask.ResourceIds = []string{resourceID}
	}
	for _, scope := range c.scopes {
		if core.ScopeContained(ask, []*basev0.WorkScopeV1{scope}) {
			return true
		}
	}
	return false
}

// Core's pinned Inspector exposes ErrInvalid with diagnostic text. Translate
// only its fixed leading categories; never expose or retain the diagnostic.
// Unknown future failures stay refused as Malformed. Verification remains Core's.
func safeReason(err error) refusal.Reason {
	var reason refusal.Reason
	if errors.As(err, &reason) {
		return reason
	}
	message := strings.TrimPrefix(err.Error(), core.ErrInvalid.Error()+": ")
	for _, entry := range []struct {
		prefix string
		reason refusal.Reason
	}{
		{"issued by ", refusal.Issuer}, {"no verification key ", refusal.UnknownKey},
		{"verification key ", refusal.InvalidKey}, {"key ", refusal.FixtureKey},
		{"signature does not verify ", refusal.Signature}, {"minted for audience ", refusal.Audience},
		{"not valid before ", refusal.NotYetValid}, {"expired at ", refusal.Expired},
		{"actor hop ", refusal.Attenuation}, {"grant ", refusal.Grant},
		{"the capability's lifetime ", refusal.Lifetime},
	} {
		if strings.HasPrefix(message, entry.prefix) {
			return entry.reason
		}
	}
	return refusal.Malformed
}
