package solutionhost

import (
	"errors"
	"fmt"

	"github.com/codefly-dev/core/composition"
)

var (
	// ErrStaleGeneration means a manifest declares a generation lower than the
	// one applied for its binding. It is refused, never merged.
	ErrStaleGeneration = errors.New("module manifest generation is older than the applied generation")

	// ErrRewrittenGeneration means the applied generation came back with
	// different content. A generation is immutable; a change is a new one.
	ErrRewrittenGeneration = errors.New("module manifest generation was rewritten")

	// ErrWrongHost means a manifest targets a coordinate other than the
	// host's, or other than the one its binding was applied on.
	ErrWrongHost = errors.New("module manifest names a different host")

	// ErrWrongDomain means a manifest speaks for an ownership domain its
	// signer is not pinned for, or other than the one its binding was applied
	// under. The domain is what says who may change a binding.
	ErrWrongDomain = errors.New("module manifest reaches outside its ownership domain")

	// ErrWithdrawn means a binding was withdrawn and a later generation tries
	// to bring it back. A withdrawal is terminal: everything keyed on the
	// binding (installations, grants) would otherwise re-attach to a new
	// instance that merely reused the id. A replacement needs a new binding.
	ErrWithdrawn = errors.New("module manifest binding was withdrawn; a withdrawal is terminal and a replacement needs a new binding")

	// ErrAppliedUnusable means the manifest a host supplied as its applied
	// record cannot be held a candidate against. It accuses the host's own
	// stored state, not the delivery.
	ErrAppliedUnusable = errors.New("module manifest applied record is unusable; the host's own stored state must be repaired")
)

// Decision is what a host does with a manifest Admit accepted.
type Decision string

const (
	// DecisionAccept means apply the candidate: the binding is new to the
	// host, or the candidate is a higher generation.
	DecisionAccept Decision = "accept"

	// DecisionReplay means the candidate is the applied manifest, byte for
	// byte in its canonical encoding: nothing to apply, nothing wrong.
	DecisionReplay Decision = "replay"
)

// Admit decides whether candidate may be applied by the host at coordinate,
// given the manifest previously applied for the same binding (nil when there
// is none). It answers DecisionAccept or DecisionReplay, or refuses with:
//
//   - ErrWrongHost: the candidate targets another coordinate, or not the one
//     its binding was applied on;
//   - ErrWrongDomain: the candidate speaks for another ownership domain than
//     its binding was applied under;
//   - ErrWithdrawn: the binding was withdrawn and the candidate is a later
//     generation;
//   - ErrStaleGeneration: a lower generation;
//   - ErrRewrittenGeneration: the applied generation with different content;
//   - ErrInvalid: the candidate is not a valid manifest;
//   - ErrAppliedUnusable: previous is not a valid manifest for this binding.
//
// Admit decides the generation only. Whether the signer may speak for the
// domain is VerifyDelivered's; whether the alias is free is CheckAlias'.
func Admit(coordinate string, previous, candidate *ModuleManifest) (Decision, error) {
	if !namePattern.MatchString(coordinate) {
		return "", fmt.Errorf("%w: a host admits under its own coordinate, and %q is not one", ErrInvalid, coordinate)
	}
	if err := candidate.Validate(); err != nil {
		return "", err
	}
	if candidate.Host.Coordinate != coordinate {
		return "", fmt.Errorf("%w: binding %q targets %q, this host is %q", ErrWrongHost, candidate.Binding, candidate.Host.Coordinate, coordinate)
	}
	if previous == nil {
		return DecisionAccept, nil
	}
	if err := previous.Validate(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrAppliedUnusable, err)
	}
	if previous.Binding != candidate.Binding {
		return "", fmt.Errorf("%w: the applied manifest is for binding %q and the candidate for %q", ErrAppliedUnusable, previous.Binding, candidate.Binding)
	}
	if previous.Host.Coordinate != candidate.Host.Coordinate {
		return "", fmt.Errorf("%w: binding %q was applied on %q and the candidate targets %q", ErrWrongHost, candidate.Binding, previous.Host.Coordinate, candidate.Host.Coordinate)
	}
	if previous.Host.Domain != candidate.Host.Domain {
		// Refused whatever the generation, a withdrawal included: otherwise any
		// accepted signer could withdraw any binding by declaring a higher
		// generation under its own domain.
		return "", fmt.Errorf("%w: binding %q was applied under domain %q and the candidate declares %q", ErrWrongDomain, candidate.Binding, previous.Host.Domain, candidate.Host.Domain)
	}
	switch {
	case candidate.Generation < previous.Generation:
		return "", fmt.Errorf("%w: binding %q declares generation %d, applied is %d", ErrStaleGeneration, candidate.Binding, candidate.Generation, previous.Generation)
	case candidate.Generation > previous.Generation:
		if previous.Removed {
			return "", fmt.Errorf("%w: binding %q was withdrawn at generation %d and the candidate is generation %d", ErrWithdrawn, candidate.Binding, previous.Generation, candidate.Generation)
		}
		return DecisionAccept, nil
	}
	applied, err := previous.Digest()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrAppliedUnusable, err)
	}
	digest, err := candidate.Digest()
	if err != nil {
		return "", err
	}
	if digest != applied {
		return "", fmt.Errorf("%w: binding %q generation %d was applied as %s and now reads %s", ErrRewrittenGeneration, candidate.Binding, candidate.Generation, applied, digest)
	}
	return DecisionReplay, nil
}

// CheckAlias holds candidate's route alias to the host's route rules, against
// the manifests the host has applied: the alias lies in no reserved namespace
// ("codefly" reserves "codefly", "codefly/…" and "codefly.…"), and no other
// live binding on the same coordinate claims it. The applied manifest of the
// candidate's own binding is the one it replaces, so its alias is free; a
// withdrawn manifest claims none.
//
// Only the candidate is judged against the reserved namespaces. Re-judging an
// alias a binding already holds would let a newly reserved namespace refuse
// every unrelated delivery until an operator withdrew the incumbent.
//
// It answers composition.ErrCollision, the error every route collision in
// core answers; ErrInvalid for an invalid candidate; ErrAppliedUnusable for an
// invalid applied manifest.
func CheckAlias(reserved []string, applied []*ModuleManifest, candidate *ModuleManifest) error {
	if err := candidate.Validate(); err != nil {
		return err
	}
	if candidate.Removed {
		return nil
	}
	claim := composition.Claim{Kind: composition.CollisionRoute, Key: candidate.Alias, Owner: candidate.Binding}
	if err := composition.ValidateCollisions([]composition.Claim{claim}, reserved); err != nil {
		return err
	}
	claims := []composition.Claim{claim}
	for _, held := range applied {
		if err := held.Validate(); err != nil {
			return fmt.Errorf("%w: %v", ErrAppliedUnusable, err)
		}
		if held.Removed || held.Binding == candidate.Binding || held.Host.Coordinate != candidate.Host.Coordinate {
			continue
		}
		claims = append(claims, composition.Claim{Kind: composition.CollisionRoute, Key: held.Alias, Owner: held.Binding})
	}
	// Uniqueness only: the reserved namespaces were applied to the candidate.
	return composition.ValidateCollisions(claims, nil)
}
