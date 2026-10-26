package hop

import (
	"context"
	"sync"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
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
// the public half with its workload credential, never its seed. A registration
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
	_, public := r.Signer.Admission()
	out, err := r.Authority.RegisterAdmissionKey(ctx, &authorityv1.RegisterAdmissionKeyRequest{
		Actor: &authorityv1.WorkloadCredential{Credential: credential}, PublicKey: public,
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	return out.GetKey(), time.Unix(out.GetExpiresAtUnix(), 0), nil
}

// Keep registers the key now, then renews it at a quarter of each lease's
// remaining time, or every registerRetry after a failure, until stop is
// called. The first outcome is reported before Keep returns, so the hop's
// boot says whether its key is published; a failure does not stop renewal,
// since the authority may answer later.
func (r Registration) Keep(ctx context.Context) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	var last string
	attempt := func() time.Duration {
		call, done := context.WithTimeout(ctx, registerRetry)
		defer done()
		key, expires, err := r.Register(call)
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
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
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
	return func() {
		cancel()
		wg.Wait()
	}
}
