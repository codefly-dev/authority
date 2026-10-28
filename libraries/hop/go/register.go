package hop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc"
)

// Registrar is the authority interface's RegisterAdmissionKey, as its
// generated client serves it.
type Registrar interface {
	RegisterAdmissionKey(ctx context.Context, in *authorityv1.RegisterAdmissionKeyRequest, opts ...grpc.CallOption) (*authorityv1.RegisterAdmissionKeyResponse, error)
}

// registerRetry is how soon a registration that failed is tried again.
const registerRetry = 5 * time.Second

// Registration keeps the hop's admission key registered with the authority,
// which publishes it in Keys for every module behind the hop: the hop presents
// the public half with its workload credential, never its seed, and a fresh
// proof signed by the admission key over that credential, the key and the
// authority's audience (stamp.ProveRegistration). The authority pins one key
// per hop instance: this hop's first registration binds its key to its
// instance, and a captured credential cannot replace or add a key for it
// while that registration holds. Keep registers at boot, before any request
// is served, because a first registration by another key would win; the
// refusal is reported by name. A registration
// lapses unless renewed, so the hop renews it while it runs, and a restarted
// authority learns the key again at the next renewal.
type Registration struct {
	Authority Registrar
	Signer    *stamp.Signer
	// Credential returns the hop's workload credential, read fresh on every
	// registration so a rotation takes effect (RunCredential).
	Credential func() (string, error)
	// Report is told each time the outcome changes: the published key and
	// when it lapses, or why the authority did not publish it.
	Report func(key *authorityv1.PublicKey, expires time.Time, err error)
}

// Register registers the key once and answers the published entry and when
// it lapses unless registered again.
func (r Registration) Register(ctx context.Context) (*authorityv1.PublicKey, time.Time, error) {
	credential, err := r.Credential()
	if err != nil {
		return nil, time.Time{}, err
	}
	audience, err := CredentialAudience(credential)
	if err != nil {
		return nil, time.Time{}, err
	}
	proof, err := r.Signer.ProveRegistration(credential, audience, time.Now())
	if err != nil {
		return nil, time.Time{}, err
	}
	_, public := r.Signer.Admission()
	out, err := r.Authority.RegisterAdmissionKey(ctx, &authorityv1.RegisterAdmissionKeyRequest{
		Actor: &authorityv1.WorkloadCredential{Credential: credential}, PublicKey: public, Proof: proof,
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	key, expires := out.GetKey(), time.Unix(out.GetExpiresAtUnix(), 0)
	id, _ := r.Signer.Admission()
	if key.GetKeyId() != id || !bytes.Equal(key.GetPublicKey(), public) ||
		key.GetAlgorithm() != core.Algorithm || key.GetPurpose() != stamp.Purpose || !time.Now().Before(expires) {
		return nil, time.Time{}, errors.New("hop: registration did not acknowledge this admission key with a valid publication lease")
	}
	return key, expires, nil
}

// CredentialAudience is the audience the launcher issued this workload's
// credential for: the authority the credential is presented to, which a
// registration proof names. It reads the hop's own credential and verifies
// nothing; the authority attests the credential and refuses a proof naming
// any audience but its own.
func CredentialAudience(credential string) (string, error) {
	parts := strings.Split(credential, ".")
	if len(parts) != 3 {
		return "", errors.New("hop: this workload's credential is not a compact JWS, so it names no audience to prove a registration to")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("hop: this workload's credential has an unreadable payload")
	}
	var claims struct {
		Audience json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", errors.New("hop: this workload's credential has unreadable claims")
	}
	var one string
	var many []string
	switch {
	case json.Unmarshal(claims.Audience, &one) == nil && one != "":
		return one, nil
	case json.Unmarshal(claims.Audience, &many) == nil && len(many) == 1 && many[0] != "":
		return many[0], nil
	}
	return "", errors.New("hop: this workload's credential names no single audience to prove a registration to")
}

// Keep registers the key now, then renews it at a quarter of each lease's
// remaining time, or every registerRetry after a failure, until stop is
// called. The first outcome is reported before Keep returns, so the hop's
// boot says whether its key is published; a failure does not stop renewal,
// since the authority may answer later.
func (r Registration) Keep(ctx context.Context) (stop func()) {
	return r.Start(ctx).Close
}

// RegistrationLease tracks this signer's acknowledged publication, not whether
// downstream verifiers have learned its key. It is updated on every renewal,
// independently of Report's log deduplication. The zero value is unready.
type RegistrationLease struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	expires time.Time
	closed  bool
}

// Ready is true strictly before the last acknowledged lease expires, unless
// cancelled or closed. A failed renewal does not extend that deadline. This is
// only a publication condition: a new key still needs prepublication overlap.
func (l *RegistrationLease) Ready() bool {
	return l.ready(time.Now())
}

func (l *RegistrationLease) ready(now time.Time) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ctx != nil && l.ctx.Err() == nil && !l.closed && now.Before(l.expires)
}

func (l *RegistrationLease) acknowledge(expires time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed && l.ctx.Err() == nil {
		l.expires = expires
	}
}

// Close immediately makes the lease unready, cancels renewal and joins it.
// It is idempotent; it does not withdraw the authority's published key.
func (l *RegistrationLease) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.closed = true
	cancel, done := l.cancel, l.done
	l.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// Start attempts registration before returning, then retries or renews in the
// existing loop until ctx is cancelled or Close is called. An initial failure
// returns an unready lease that can recover. Report remains log-only.
func (r Registration) Start(ctx context.Context) *RegistrationLease {
	ctx, cancel := context.WithCancel(ctx)
	l := &RegistrationLease{ctx: ctx, cancel: cancel, done: make(chan struct{})}
	var last string
	attempt := func() time.Duration {
		call, done := context.WithTimeout(ctx, registerRetry)
		defer done()
		key, expires, err := r.Register(call)
		if err == nil {
			l.acknowledge(expires)
		}
		outcome := "ok " + key.GetKeyId()
		if err != nil {
			outcome = err.Error()
		}
		if outcome != last && ctx.Err() == nil {
			last = outcome
			if r.Report != nil {
				r.Report(key, expires, err)
			}
		}
		if err != nil {
			return registerRetry
		}
		return max(time.Until(expires)/4, time.Second)
	}
	next := attempt()
	go func() {
		defer close(l.done)
		timer := time.NewTimer(next)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				timer.Reset(attempt())
			}
		}
	}()
	return l
}
