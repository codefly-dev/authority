// Package workcontext projects an already hop-bound Work Context. It is not a
// verifier: readable claims prove neither authentication nor live authority.
package workcontext

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/protobuf/proto"
)

// ErrUnreadableContext names a token that cannot be projected. Core's structural
// refusals are also retained in the error chain; no signature is verified.
var ErrUnreadableContext = errors.New("authority: unreadable context")

// Claims owns a snapshot of the audience and Core's effective scopes.
// It can be read concurrently. Its zero value grants nothing.
type Claims struct {
	audience string
	scopes   []*basev0.WorkScopeV1
}

// ReadClaims reads the token bound by the hop, using Core's maintained decoder.
// In addition to canonical envelope checks, Go retains Core's structural checks;
// the Python/TypeScript projections do not implement that structural validator.
// None of these readers verifies signatures, time, live revisions or replay.
func ReadClaims(token string) (*Claims, error) {
	if len(token) == 0 || len(token) > core.MaxTokenSize {
		return nil, fmt.Errorf("%w: expected a bounded context", ErrUnreadableContext)
	}
	payload, signature, ok := strings.Cut(token, ".")
	if !ok || strings.Contains(signature, ".") {
		return nil, fmt.Errorf("%w: expected payload.signature", ErrUnreadableContext)
	}
	for n, segment := range []string{payload, signature} {
		decoded, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != segment || (n == 1 && len(decoded) != 64) {
			return nil, fmt.Errorf("%w: noncanonical envelope or invalid signature length", ErrUnreadableContext)
		}
	}
	decoded, err := core.Decode(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreadableContext, err)
	}
	context := decoded.Context()
	scopes := context.GetAuthorityScopes()
	if chain := context.GetActorChain(); len(chain) > 0 {
		scopes = chain[len(chain)-1].GetGrantedScopes()
	}
	return &Claims{audience: context.GetAudience(), scopes: scopes}, nil
}

// Audience is data to compare with this module's delivered audience.
func (c *Claims) Audience() string {
	if c == nil {
		return ""
	}
	return c.audience
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
// No wildcard expansion, action implication or cross-grant merging occurs.
func (c *Claims) Allows(kind, action, resourceID string) bool {
	if c == nil || kind == "" || action == "" {
		return false
	}
	ask := &basev0.WorkScopeV1{ResourceKind: kind, Actions: []string{action}}
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
