// Package wiring holds what the service's Configure builds and the plugins read
// when the registry instantiates them: the state and the issuer. It is set once,
// before any listener starts, and read by every plugin's New.
package wiring

import (
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
