// Package workcontext authenticates the Work Context the hop forwarded to a
// module, and projects its claims. Authenticate is the one check a module's
// reading rests on: nothing here decodes a token it has not authenticated.
package workcontext

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	"strings"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"google.golang.org/grpc/metadata"

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

// Authenticate returns the claims of the Work Context the hop forwarded with
// md to this module (audience), after two checks, in order:
//
//  1. the stamp: md carries this run's hop proof, exactly one token, and the
//     stamp's digest of that token, so the token is the one the authority's
//     Check admitted for this call (stamp.Context);
//  2. the token itself, with Core's Inspector: canonical decode, the issuer
//     pin, the Ed25519 signature under the published key the token names, the
//     audience is this module, not-before and expiry within Core's skew, and
//     the chain's structure and attenuation.
//
// It consumes nothing and asks the authority nothing: liveness (revision,
// seal, single-use) is the authority's Check the hop made, which the digest
// binds to this call. A proof alone, or a digest alone, authenticates nothing:
// whoever holds the proof can write both, but cannot sign.
func Authenticate(md metadata.MD, proof, audience string, trust Trust) (*Claims, error) {
	token, err := stamp.Context(md, proof)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, safeReason(err))
	}
	return AuthenticateToken(token, audience, trust)
}

// AuthenticateToken authenticates an unstamped token without consuming it or
// checking live revocation. Callers still enforce their operation's policy.
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
