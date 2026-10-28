package hop

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc"
)

type leaseRegistrar func(context.Context, *authorityv1.RegisterAdmissionKeyRequest) (*authorityv1.RegisterAdmissionKeyResponse, error)

func (f leaseRegistrar) RegisterAdmissionKey(ctx context.Context, in *authorityv1.RegisterAdmissionKeyRequest, _ ...grpc.CallOption) (*authorityv1.RegisterAdmissionKeyResponse, error) {
	return f(ctx, in)
}
func leaseResponse(in *authorityv1.RegisterAdmissionKeyRequest) *authorityv1.RegisterAdmissionKeyResponse {
	return &authorityv1.RegisterAdmissionKeyResponse{Key: &authorityv1.PublicKey{KeyId: stamp.KeyID(in.PublicKey), PublicKey: in.PublicKey, Algorithm: core.Algorithm, Purpose: stamp.Purpose}, ExpiresAtUnix: time.Now().Add(time.Minute).Unix()}
}
func leaseRegistration(r Registrar) Registration {
	return Registration{Authority: r, Signer: testSigner("lease"), Credential: func() (string, error) { return testCredential(testAudience, "lease"), nil }}
}
func leaseDeadline(l *RegistrationLease) time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.expires
}

func TestRegistrationRejectsUnusableAcknowledgements(t *testing.T) {
	for name, change := range map[string]func(*authorityv1.RegisterAdmissionKeyResponse){
		"missing key":       func(r *authorityv1.RegisterAdmissionKeyResponse) { r.Key = nil },
		"wrong identity":    func(r *authorityv1.RegisterAdmissionKeyResponse) { r.Key.KeyId = "other" },
		"wrong bytes":       func(r *authorityv1.RegisterAdmissionKeyResponse) { r.Key.PublicKey = []byte("other") },
		"missing algorithm": func(r *authorityv1.RegisterAdmissionKeyResponse) { r.Key.Algorithm = "" },
		"wrong algorithm":   func(r *authorityv1.RegisterAdmissionKeyResponse) { r.Key.Algorithm = "RSA" },
		"missing purpose":   func(r *authorityv1.RegisterAdmissionKeyResponse) { r.Key.Purpose = "" },
		"wrong purpose":     func(r *authorityv1.RegisterAdmissionKeyResponse) { r.Key.Purpose = "work-context" },
		"missing expiry":    func(r *authorityv1.RegisterAdmissionKeyResponse) { r.ExpiresAtUnix = 0 },
		"past expiry": func(r *authorityv1.RegisterAdmissionKeyResponse) {
			r.ExpiresAtUnix = time.Now().Add(-time.Second).Unix()
		},
		"exact expiry": func(r *authorityv1.RegisterAdmissionKeyResponse) { r.ExpiresAtUnix = time.Now().Unix() },
	} {
		t.Run(name, func(t *testing.T) {
			r := leaseRegistration(leaseRegistrar(func(_ context.Context, in *authorityv1.RegisterAdmissionKeyRequest) (*authorityv1.RegisterAdmissionKeyResponse, error) {
				out := leaseResponse(in)
				change(out)
				return out, nil
			}))
			l := r.Start(t.Context())
			defer l.Close()
			if l.Ready() || !leaseDeadline(l).IsZero() {
				t.Fatal("invalid acknowledgement established a lease")
			}
		})
	}
	t.Run("nil response", func(t *testing.T) {
		l := leaseRegistration(leaseRegistrar(func(context.Context, *authorityv1.RegisterAdmissionKeyRequest) (*authorityv1.RegisterAdmissionKeyResponse, error) {
			return nil, nil
		})).Start(t.Context())
		defer l.Close()
		if l.Ready() {
			t.Fatal("nil acknowledgement ready")
		}
	})
}

func TestPublicationLeaseDeadlineFailureRecoveryAndClose(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	l := &RegistrationLease{ctx: ctx}
	now := time.Now()
	first := now.Add(time.Minute)
	if l.ready(now) {
		t.Fatal("never acknowledged")
	}
	l.acknowledge(first)
	if !l.ready(first.Add(-time.Nanosecond)) || l.ready(first) {
		t.Fatal("expiry boundary")
	}
	// A failed attempt has no acknowledgement and therefore does not extend the lease.
	if !l.ready(now) || l.ready(first.Add(time.Second)) {
		t.Fatal("failure changed the acknowledged deadline")
	}
	second := first.Add(time.Minute)
	l.acknowledge(second)
	if !l.ready(first) {
		t.Fatal("recovery did not extend")
	}
	l.acknowledge(first)
	if l.ready(first) {
		t.Fatal("shorter authoritative lease was ignored")
	}
	l.Close()
	l.Close()
	l.acknowledge(second)
	if l.ready(now) {
		t.Fatal("close revived")
	}
	var zero RegistrationLease
	if zero.Ready() || (*RegistrationLease)(nil).Ready() {
		t.Fatal("zero lease ready")
	}
	zero.Close()
	(*RegistrationLease)(nil).Close()
}

func TestPublicationInitialFailureRecoversInTheExistingLoop(t *testing.T) {
	first := make(chan struct{})
	var mu sync.Mutex
	fail := true
	r := leaseRegistration(leaseRegistrar(func(_ context.Context, in *authorityv1.RegisterAdmissionKeyRequest) (*authorityv1.RegisterAdmissionKeyResponse, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			select {
			case <-first:
			default:
				close(first)
			}
			return nil, errors.New("unavailable")
		}
		return leaseResponse(in), nil
	}))
	l := r.Start(t.Context())
	defer l.Close()
	if l.Ready() {
		t.Fatal("initial failure ready")
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	deadline := time.Now().Add(registerRetry + 2*time.Second)
	for !l.Ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !l.Ready() {
		t.Fatal("existing retry loop did not recover")
	}
}

func TestPublicationCancellationWinsOverLateSuccess(t *testing.T) {
	for _, phase := range []string{"initial", "renewal"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			calls := 0
			r := leaseRegistration(leaseRegistrar(func(_ context.Context, in *authorityv1.RegisterAdmissionKeyRequest) (*authorityv1.RegisterAdmissionKeyResponse, error) {
				calls++
				if phase == "initial" || calls > 1 {
					close(entered)
					<-release
				}
				out := leaseResponse(in)
				if calls == 1 && phase == "renewal" {
					out.ExpiresAtUnix = time.Now().Add(2 * time.Second).Unix()
				}
				return out, nil // deliberately ignore cancellation to exercise late result handling
			}))
			result := make(chan *RegistrationLease, 1)
			go func() { result <- r.Start(ctx) }()
			var l *RegistrationLease
			if phase == "renewal" {
				l = <-result
			}
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("attempt not entered")
			}
			cancel()
			if l != nil && l.Ready() {
				t.Fatal("cancellation did not invalidate before RPC returned")
			}
			close(release)
			if l == nil {
				l = <-result
			}
			l.Close()
			l.Close()
			if l.Ready() {
				t.Fatal("late acknowledgement revived cancelled lease")
			}
		})
	}
}

func TestPublicationReadyRenewCloseConcurrent(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	l := &RegistrationLease{ctx: ctx}
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				l.acknowledge(time.Now().Add(time.Minute))
				l.Ready()
			}
		}()
	}
	l.Close()
	wg.Wait()
	if l.Ready() {
		t.Fatal("concurrent renewal revived closed lease")
	}
}

func TestFailedRenewalDoesNotExtendAcknowledgedLease(t *testing.T) {
	for _, mode := range []string{"rpc-error", "invalid-receipt"} {
		t.Run(mode, func(t *testing.T) {
			failed := make(chan struct{}, 1)
			calls := 0
			r := leaseRegistration(leaseRegistrar(func(_ context.Context, in *authorityv1.RegisterAdmissionKeyRequest) (*authorityv1.RegisterAdmissionKeyResponse, error) {
				calls++
				if calls > 1 {
					if mode == "rpc-error" {
						return nil, errors.New("renewal refused")
					}
					bad := leaseResponse(in)
					bad.Key.Purpose = "work-context"
					return bad, nil
				}
				out := leaseResponse(in)
				out.ExpiresAtUnix = time.Now().Add(3 * time.Second).Unix()
				return out, nil
			}))
			r.Report = func(_ *authorityv1.PublicKey, _ time.Time, err error) {
				if err != nil {
					failed <- struct{}{}
				}
			}
			l := r.Start(t.Context())
			defer l.Close()
			first := leaseDeadline(l)
			select {
			case <-failed:
			case <-time.After(2 * time.Second):
				t.Fatal("no renewal")
			}
			if !leaseDeadline(l).Equal(first) || !l.Ready() || l.ready(first) {
				t.Fatal("failed renewal altered lease")
			}
		})
	}
}

func TestPublicationInitialDeadlineIsUnready(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	r := leaseRegistration(leaseRegistrar(func(ctx context.Context, _ *authorityv1.RegisterAdmissionKeyRequest) (*authorityv1.RegisterAdmissionKeyResponse, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}))
	l := r.Start(ctx)
	defer l.Close()
	if l.Ready() || !leaseDeadline(l).IsZero() {
		t.Fatal("timed-out registration acknowledged")
	}
}
