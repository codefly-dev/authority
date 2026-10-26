package state

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"github.com/codefly-dev/core/solutionhost"
)

// appliedDelivery retains Core's verified bytes, the paired policy identity and
// the original receipt. Pending fixture work is separate from admission: a
// callback failure must neither forget an admitted generation nor report success.
type appliedDelivery struct {
	carrier    *solutionhost.Delivered
	sidecar    []byte
	ids        []string
	pending    []*pendingInstallation
	completion chan struct{}
}

// pendingInstallation is one fixture installation waiting on a delivery; done
// prevents its replay once performed. Guarded by State.mu.
type pendingInstallation struct {
	FixtureInstallation
	done bool
}

// ApplyDelivered atomically admits and projects a verified carrier. Coordinate
// belongs to the host's configuration, never to the candidate. The plugin has
// verified the sidecar and derived m from these two documents before calling.
func (s *State) ApplyDelivered(ctx context.Context, coordinate string, carrier *solutionhost.Delivered, sidecar []byte, m Manifest) ([]string, error) {
	candidate, err := carrier.Manifest()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	record, err := s.admitDeliveryLocked(coordinate, carrier, sidecar, candidate, m)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !candidate.Removed {
		if err := s.finishDelivery(ctx, candidate, record); err != nil {
			return nil, err
		}
	}
	return slices.Clone(record.ids), nil
}

func (s *State) admitDeliveryLocked(coordinate string, carrier *solutionhost.Delivered, sidecar []byte, candidate *solutionhost.ModuleManifest, m Manifest) (*appliedDelivery, error) {
	var previous *solutionhost.ModuleManifest
	held := s.deliveries[candidate.Binding]
	if held != nil {
		previous, _ = held.carrier.Manifest()
	}
	decision, err := solutionhost.Admit(coordinate, previous, candidate)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStale, err)
	}
	var applied []*solutionhost.ModuleManifest
	for _, record := range s.deliveries {
		manifest, err := record.carrier.Manifest()
		if err != nil {
			return nil, err
		}
		applied = append(applied, manifest)
		if manifest.Alias == candidate.Alias && manifest.Binding != candidate.Binding {
			return nil, fmt.Errorf("%w: alias %q belongs to historical binding %q; replacement requires an installation identity migration", ErrForbidden, candidate.Alias, manifest.Binding)
		}
	}
	if previous != nil && previous.Alias != candidate.Alias {
		return nil, fmt.Errorf("%w: binding %q cannot rename alias %q without an installation identity migration", ErrForbidden, candidate.Binding, previous.Alias)
	}
	if err := solutionhost.CheckAlias([]string{"codefly"}, applied, candidate); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrForbidden, err)
	}
	if decision == solutionhost.DecisionReplay {
		if (held.sidecar == nil) != (sidecar == nil) || !bytes.Equal(held.sidecar, sidecar) {
			return nil, fmt.Errorf("%w: binding %s rewrote its authority document at generation %d", ErrStale, candidate.Binding, candidate.Generation)
		}
		return held, nil
	}
	record := &appliedDelivery{carrier: carrier, sidecar: bytes.Clone(sidecar), completion: make(chan struct{}, 1)}
	if held != nil {
		record.completion = held.completion
	}
	if candidate.Removed {
		// An unknown tombstone must not erase an unrelated transitional sketch.
		if previous == nil {
			if _, exists := s.Module(candidate.Alias); exists {
				return nil, fmt.Errorf("%w: withdrawal has no admitted binding for %s", ErrForbidden, candidate.Alias)
			}
		}
		if err := s.withdrawLocked(candidate.Alias); err != nil {
			return nil, err
		}
	} else {
		ids, pending, err := s.applyManifestLocked(m)
		if err != nil {
			return nil, err
		}
		record.ids = slices.Clone(ids)
		for _, intent := range pending {
			record.pending = append(record.pending, &pendingInstallation{FixtureInstallation: intent})
		}
		if held != nil {
			record.pending = append(record.pending, held.pending...)
		}
	}
	s.deliveries[candidate.Binding] = record
	return record, nil
}

// finishDelivery serializes only completion for this admitted record. It never
// holds the state lock across an install callback, and a replay resumes the same
// convergent Pending installation after failure or cancellation.
func (s *State) finishDelivery(ctx context.Context, manifest *solutionhost.ModuleManifest, record *appliedDelivery) error {
	select {
	case record.completion <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-record.completion }()
	s.mu.Lock()
	if s.deliveries[manifest.Binding] != record {
		s.mu.Unlock()
		return fmt.Errorf("%w: delivery completion was superseded", ErrStale)
	}
	pending := slices.Clone(record.pending)
	s.mu.Unlock()
	if err := s.finishFixtureInstalls(ctx, manifest, pending); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deliveries[manifest.Binding] != record {
		return fmt.Errorf("%w: delivery completion was superseded", ErrStale)
	}
	record.pending = nil
	return nil
}

func (s *State) finishFixtureInstalls(ctx context.Context, _ *solutionhost.ModuleManifest, pending []*pendingInstallation) error {
	for _, i := range pending {
		if err := ctx.Err(); err != nil {
			return err
		}
		s.mu.RLock()
		done := i.done
		s.mu.RUnlock()
		if done {
			continue
		}
		if err := s.performInstall(ctx, i.FixtureInstallation); err != nil {
			return err
		}
		s.mu.Lock()
		i.done = true
		s.mu.Unlock()
	}
	return nil
}

// withdrawLocked removes a module through the core: its installations are
// revoked and the delegations granted to it end. Caller holds mu.
func (s *State) withdrawLocked(alias string) error {
	s.takePendingInstalls(alias)
	if _, ok := s.Module(alias); ok {
		if err := s.svc.WithdrawModule(context.Background(), alias); err != nil {
			return err
		}
	}
	s.refreshRolesLocked()
	return nil
}
