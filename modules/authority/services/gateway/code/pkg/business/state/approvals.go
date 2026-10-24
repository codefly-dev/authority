package state

import (
	"fmt"
	"sync"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/google/uuid"
)

// An Approval is a person's consent to one exact authored artifact for one
// installation, under one policy. It is read back at every run and withdrawn
// for good when revoked: approving the same artifact again is refused.
type Approval struct {
	ID           string
	Installation string
	Policy       string
	// Digest is "sha256:<hex>" of the artifact's canonical identity.
	Digest   string
	Revision int64
	Revoked  bool
}

// QualifiedName is the approval's name as a module cites it.
func (a Approval) QualifiedName() string { return "host/approved-artifacts/" + a.ID }

// Approvals keeps the gateway's approvals, in memory like its sessions.
type Approvals struct {
	mu   sync.Mutex
	byID map[string]Approval
}

func approvalKey(installation, policy, digest string) string {
	return installation + "\x00" + policy + "\x00" + digest
}

// Approve records consent, or answers the approval already standing; a revoked
// one is refused.
func (s *Approvals) Approve(installation, policy, digest string, revision int64) (Approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byID == nil {
		s.byID = map[string]Approval{}
	}
	if a, ok := s.find(installation, policy, digest); ok {
		if a.Revoked {
			return Approval{}, fmt.Errorf("%w: this artifact's approval was revoked for %s", ErrForbidden, installation)
		}
		return a, nil
	}
	a := Approval{ID: uuid.NewString(), Installation: installation, Policy: policy, Digest: digest, Revision: revision}
	s.byID[a.ID] = a
	return a, nil
}

// Standing answers the approval of the artifact for a run, or refuses.
func (s *Approvals) Standing(installation, policy, digest string) (Approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.find(installation, policy, digest)
	if !ok || a.Revoked {
		return Approval{}, fmt.Errorf("%w: no approval stands for this artifact at %s", ErrForbidden, installation)
	}
	return a, nil
}

// Revoke withdraws an approval, permanently.
func (s *Approvals) Revoke(installation, policy, id string) (Approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[id]
	if !ok || a.Installation != installation || a.Policy != policy {
		return Approval{}, fmt.Errorf("%w: approval %q is not one of %s's under %s", ErrUnknown, id, installation, policy)
	}
	a.Revoked = true
	s.byID[id] = a
	return a, nil
}

func (s *Approvals) find(installation, policy, digest string) (Approval, bool) {
	for _, a := range s.byID {
		if approvalKey(a.Installation, a.Policy, a.Digest) == approvalKey(installation, policy, digest) {
			return a, true
		}
	}
	return Approval{}, false
}

// HoldsAction is whether held carries action on kind.
func HoldsAction(held []*basev0.WorkScopeV1, kind, action string) bool {
	return holdsAction(held, kind, action)
}
