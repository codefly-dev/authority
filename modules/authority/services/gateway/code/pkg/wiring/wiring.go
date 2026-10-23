// Package wiring holds what the service's Configure builds and the plugins read
// when the registry instantiates them: the state and the issuer. It is set once,
// before any listener starts, and read by every plugin's New.
package wiring

import (
	"context"
	"crypto"

	"github.com/codefly-dev/core/solutionhost"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
)

var (
	configuredState  *state.State
	configuredIssuer *issuer.Issuer
)

// Set records the configured state and issuer.
func Set(st *state.State, is *issuer.Issuer) { configuredState, configuredIssuer = st, is }

// State is the configured state; nil before Configure ran, which a plugin's New
// reports by refusing to serve.
func State() *state.State { return configuredState }

// Issuer is the configured issuer.
func Issuer() *issuer.Issuer { return configuredIssuer }

var (
	configuredVerifier *solutionhost.Verifier
	configuredCarrier  func(ctx context.Context, credential, module string) error
)

// SetDelivery records how a delivered manifest is verified and who may carry it.
func SetDelivery(verifier *solutionhost.Verifier, keys map[string]crypto.PublicKey, carrier func(ctx context.Context, credential, module string) error) {
	configuredVerifier, configuredKeys, configuredCarrier = verifier, keys, carrier
}

var configuredKeys map[string]crypto.PublicKey

// Keys are the pinned release keys by id, for the authority's own document.
func Keys() map[string]crypto.PublicKey { return configuredKeys }

// Verifier pins the release keys a run admits; nil verifies nothing.
func Verifier() *solutionhost.Verifier { return configuredVerifier }

// Carrier admits a delivery credential as the module's delivery workload.
func Carrier() func(ctx context.Context, credential, module string) error { return configuredCarrier }
