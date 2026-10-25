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

// pendingInstallation follows one fixture intent across failed callbacks and
// superseding deliveries. Its fields are guarded by State.mu; revision fences
// an explicit uninstall/reinstall and done prevents replay of completed grants.
type pendingInstallation struct {
	FixtureInstallation
	revision uint64
	done     bool
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
			if _, exists := s.modules[candidate.Alias]; exists {
				return nil, fmt.Errorf("%w: withdrawal has no admitted binding for %s", ErrForbidden, candidate.Alias)
			}
		}
		s.withdrawLocked(candidate.Alias)
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

func (s *State) finishFixtureInstalls(ctx context.Context, manifest *solutionhost.ModuleManifest, pending []*pendingInstallation) error {
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
		inst, err := s.install(ctx, i.Organization, i.Target, i.Role, i.Owner, manifest.Generation, i)
		if err != nil {
			return fmt.Errorf("fixture installation of %s: %w", i.Target, err)
		}
		s.mu.Lock()
		current, live := s.modules[i.Target]
		held := s.installations[inst.ID]
		if !live || current.Generation != manifest.Generation || held.Status != Active || held.Revision != inst.Revision {
			s.mu.Unlock()
			return fmt.Errorf("%w: fixture installation changed before team grants", ErrStale)
		}
		for _, team := range i.Teams {
			if !slices.Contains(held.Teams, team) {
				held.Teams = append(held.Teams, team)
				held.Revision++
				s.revisions[i.Organization]++
			}
		}
		s.installations[inst.ID] = held
		i.done = true
		s.mu.Unlock()
	}
	return nil
}

func (s *State) withdrawLocked(alias string) {
	if previous, ok := s.modules[alias]; ok {
		delete(s.principals, previous.Principal)
	}
	delete(s.modules, alias)
	s.takePendingInstalls(alias)
	for id, installation := range s.installations {
		if installation.Target != alias || installation.Status == Revoked {
			continue
		}
		installation.Status = Revoked
		installation.Revision++
		s.installations[id] = installation
		s.revisions[installation.Organization]++
	}
	for id, delegation := range s.delegations {
		if delegation.Module != alias || delegation.Revoked {
			continue
		}
		delegation.Revoked = true
		s.delegations[id] = delegation
		s.revisions[delegation.Organization]++
	}
	s.refreshDeveloperRoles()
}
