package issuer

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sort"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/core/workcontext"

	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

// AdmissionLease is how long a registered admission key stays published
// without being registered again. The hop renews well inside it, so a
// restarted authority learns the key again within one renewal, and a key no
// running hop signs with any more is withdrawn once it lapses.
const AdmissionLease = 2 * time.Minute

// maxAdmissionKeys bounds the keys published at once: a rotation needs two,
// and a few more absorb rotations closer together than one lease.
const maxAdmissionKeys = 8

// HopModule and HopService name the one workload whose admission keys this
// authority publishes: the hop service of the authority module.
const (
	HopModule  = "authority"
	HopService = "hop"
)

type admission struct {
	key   *authorityv1.PublicKey
	until time.Time
}

// RegisterAdmissionKey records the public key the hop signs call admissions
// with, attesting that the caller is the hop, and publishes it in Keys until
// the answered time; registering it again renews it. Any other workload is
// refused by name, and only the public half is ever presented.
func (i *Issuer) RegisterAdmissionKey(ctx context.Context, credential string, public []byte) (*authorityv1.PublicKey, time.Time, error) {
	workload, err := i.state.AttestWorkload(ctx, credential)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("an admission key is registered by the hop: %w", err)
	}
	if workload.Module != HopModule || workload.Service != HopService {
		return nil, time.Time{}, domain.Refuse("the caller is %s/%s, not the hop (%s/%s): only the hop registers an admission key",
			workload.Module, workload.Service, HopModule, HopService)
	}
	if len(public) != ed25519.PublicKeySize {
		return nil, time.Time{}, domain.Malformed("an admission key is a %d-byte Ed25519 public key, not %d bytes", ed25519.PublicKeySize, len(public))
	}
	key := &authorityv1.PublicKey{KeyId: stamp.KeyID(public), Algorithm: workcontext.Algorithm, PublicKey: append([]byte(nil), public...), Purpose: stamp.Purpose}
	now := i.now()
	until := now.Add(AdmissionLease)
	i.mu.Lock()
	defer i.mu.Unlock()
	i.lapse(now)
	if _, renewed := i.admission[key.KeyId]; !renewed && len(i.admission) >= maxAdmissionKeys {
		return nil, time.Time{}, domain.NotNow("%d admission keys are already published; one must lapse before %s is registered", maxAdmissionKeys, key.KeyId)
	}
	i.admission[key.KeyId] = admission{key: key, until: until}
	return key, until, nil
}

// admissionKeys are the registered keys still within their lease, by key id.
func (i *Issuer) admissionKeys() []*authorityv1.PublicKey {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.lapse(i.now())
	out := make([]*authorityv1.PublicKey, 0, len(i.admission))
	for _, a := range i.admission {
		out = append(out, a.key)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].GetKeyId() < out[b].GetKeyId() })
	return out
}

// lapse withdraws every registration past its lease. Called with mu held.
func (i *Issuer) lapse(now time.Time) {
	for id, a := range i.admission {
		if !now.Before(a.until) {
			delete(i.admission, id)
		}
	}
}
