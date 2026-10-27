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

// maxRegistrationNonces bounds the registration proofs remembered at once.
// Only the attested hop reaches the reservation, and it registers a few times
// a minute; past the bound a registration waits for a proof to age out.
const maxRegistrationNonces = 1024

// maxHopInstances bounds the hop instances pinned at once: one per running hop
// replica, each lapsing with its key's lease.
const maxHopInstances = 64

// nonceRetention is how long an accepted registration proof's nonce is
// remembered: as long as the proof could still be judged fresh.
const nonceRetention = stamp.RegistrationWindow + stamp.Skew

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

// pin is the one admission key a hop instance registered, and until when
// that instance's registration holds it.
type pin struct {
	keyID string
	until time.Time
}

// RegisterAdmissionKey records the public key the hop signs call admissions
// with and publishes it in Keys until the answered time; registering it again
// renews it. The caller must be the hop of this host's trust domain (any
// other workload is refused by name) and must present a fresh, unused proof
// signed by the key it registers (stamp.CheckRegistration).
//
// One key is pinned per hop instance, the instance the credential names: the
// first registration for an instance binds its key until that registration's
// lease lapses, the same key renews it, and another key for that instance is
// refused by name until then. The proof proves possession of a key the
// registrant chose, so it is the pin that keeps a captured hop credential
// from replacing or adding a key for an instance that has registered. It
// does not keep one from registering first: before that instance's own first
// registration (the hop registers at boot), or after a restart of this
// authority (pins are in memory) and before the hop's next renewal.
func (i *Issuer) RegisterAdmissionKey(ctx context.Context, credential string, public []byte, proof string) (*authorityv1.PublicKey, time.Time, error) {
	workload, err := i.state.AttestWorkload(ctx, credential)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("an admission key is registered by the hop: %w", err)
	}
	if workload.Module != HopModule || workload.Service != HopService {
		return nil, time.Time{}, domain.Refuse("the caller is %s/%s, not the hop (%s/%s): only the hop registers an admission key",
			workload.Module, workload.Service, HopModule, HopService)
	}
	if workload.Instance == "" {
		return nil, time.Time{}, domain.Refuse("the hop's credential names no instance, so no admission key can be pinned to it")
	}
	if host := i.trustDomain; host == "" || workload.TrustDomain != host {
		return nil, time.Time{}, domain.Refuse("the caller is the hop of trust domain %q, not of this host's (%q): only this host's hop registers an admission key",
			workload.TrustDomain, host)
	}
	if len(public) != ed25519.PublicKeySize {
		return nil, time.Time{}, domain.Malformed("an admission key is a %d-byte Ed25519 public key, not %d bytes", ed25519.PublicKeySize, len(public))
	}
	now := i.now()
	proved, err := stamp.CheckRegistration(proof, public, credential, i.state.Audience(), now)
	if err != nil {
		return nil, time.Time{}, domain.Refuse("%v", err)
	}
	key := &authorityv1.PublicKey{KeyId: stamp.KeyID(public), Algorithm: workcontext.Algorithm, PublicKey: append([]byte(nil), public...), Purpose: stamp.Purpose}
	until := now.Add(AdmissionLease)
	i.mu.Lock()
	defer i.mu.Unlock()
	i.lapse(now)
	if p, pinned := i.pins[workload.Instance]; pinned && p.keyID != key.KeyId {
		return nil, time.Time{}, domain.Refuse("hop instance %q registered admission key %s, held until %s: another key (%s) is refused for that instance until then; a new key is registered by a new hop instance",
			workload.Instance, p.keyID, p.until.UTC().Format(time.RFC3339), key.KeyId)
	}
	if _, replayed := i.nonces[proved.Nonce]; replayed {
		return nil, time.Time{}, domain.Refuse("the registration proof was already used: sign a fresh one for each registration")
	}
	if len(i.nonces) >= maxRegistrationNonces {
		return nil, time.Time{}, domain.NotNow("%d registration proofs are remembered; one must age out before another is accepted", maxRegistrationNonces)
	}
	if _, renewed := i.admission[key.KeyId]; !renewed && len(i.admission) >= maxAdmissionKeys {
		return nil, time.Time{}, domain.NotNow("%d admission keys are already published; one must lapse before %s is registered", maxAdmissionKeys, key.KeyId)
	}
	if _, pinned := i.pins[workload.Instance]; !pinned && len(i.pins) >= maxHopInstances {
		return nil, time.Time{}, domain.NotNow("%d hop instances hold admission keys; one must lapse before instance %q registers", maxHopInstances, workload.Instance)
	}
	i.nonces[proved.Nonce] = now.Add(nonceRetention)
	i.pins[workload.Instance] = pin{keyID: key.KeyId, until: until}
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

// lapse withdraws every registration past its lease, releases every hop
// instance's pin past it, and forgets every registration proof too old to be
// judged fresh again. Called with mu held.
func (i *Issuer) lapse(now time.Time) {
	for id, a := range i.admission {
		if !now.Before(a.until) {
			delete(i.admission, id)
		}
	}
	for instance, p := range i.pins {
		if !now.Before(p.until) {
			delete(i.pins, instance)
		}
	}
	for nonce, until := range i.nonces {
		if !now.Before(until) {
			delete(i.nonces, nonce)
		}
	}
}
