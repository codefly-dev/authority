package hop

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"google.golang.org/grpc"
)

// registrar is an authority answering RegisterAdmissionKey with a lease, or
// refusing while refuse is set; it records what it was presented.
type registrar struct {
	mu          sync.Mutex
	lease       time.Duration
	refuse      error
	credentials []string
	keys        [][]byte
}

func (r *registrar) RegisterAdmissionKey(_ context.Context, in *authorityv1.RegisterAdmissionKeyRequest, _ ...grpc.CallOption) (*authorityv1.RegisterAdmissionKeyResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.credentials = append(r.credentials, in.GetActor().GetCredential())
	r.keys = append(r.keys, in.GetPublicKey())
	if r.refuse != nil {
		return nil, r.refuse
	}
	return &authorityv1.RegisterAdmissionKeyResponse{
		Key:           &authorityv1.PublicKey{KeyId: stamp.KeyID(in.GetPublicKey()), PublicKey: in.GetPublicKey(), Purpose: stamp.Purpose},
		ExpiresAtUnix: time.Now().Add(r.lease).Unix(),
	}, nil
}

func (r *registrar) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.keys)
}

// The hop presents its public key and its workload credential, read fresh on
// every registration, never its seed; the first outcome is reported before
// Keep returns, and the registration is renewed while the hop runs.
func TestTheHopKeepsItsPublicKeyRegisteredUnderItsCredential(t *testing.T) {
	authority := &registrar{lease: 4 * time.Second}
	signer := testSigner("the-hop")
	rotation := 0
	var reports []string
	var mu sync.Mutex
	stop := Registration{Authority: authority, Signer: signer,
		Credential: func() (string, error) { rotation++; return "credential-" + string(rune('0'+rotation)), nil },
		Report: func(key *authorityv1.PublicKey, _ time.Time, err error) {
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				reports = append(reports, err.Error())
				return
			}
			reports = append(reports, key.GetKeyId())
		}}.Keep(context.Background())
	mu.Lock()
	id, public := signer.Admission()
	if len(reports) != 1 || reports[0] != id {
		t.Fatalf("Keep returned before reporting the first registration: %v", reports)
	}
	mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for authority.calls() < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	stop()
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if len(authority.keys) < 2 {
		t.Fatalf("the registration was not renewed inside its lease: %d registrations", len(authority.keys))
	}
	for n, key := range authority.keys {
		if string(key) != string(public) {
			t.Fatalf("registration %d presented %x, not the hop's public key", n, key)
		}
	}
	if authority.credentials[0] == authority.credentials[1] {
		t.Fatal("the credential was not read fresh for the renewal")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 1 {
		t.Fatalf("an unchanged outcome was reported again: %v", reports)
	}
}

// An authority that refuses (or is not up yet) is reported once and retried;
// a hop with no credential presents nothing.
func TestARefusedRegistrationIsReportedAndRetried(t *testing.T) {
	refused := errors.New("rpc error: code = PermissionDenied desc = the caller is console/api, not the hop")
	authority := &registrar{lease: time.Minute, refuse: refused}
	var got error
	stop := Registration{Authority: authority, Signer: testSigner("the-hop"),
		Credential: func() (string, error) { return "credential", nil },
		Report:     func(_ *authorityv1.PublicKey, _ time.Time, err error) { got = err }}.Keep(context.Background())
	stop()
	if !errors.Is(got, refused) {
		t.Fatalf("the refusal was not reported: %v", got)
	}
	none := &registrar{lease: time.Minute}
	_, _, err := Registration{Authority: none, Signer: testSigner("the-hop"),
		Credential: func() (string, error) { return "", errors.New("CODEFLY__WORKLOAD_TOKEN_FILE is not set") }}.Register(context.Background())
	if err == nil || none.calls() != 0 {
		t.Fatalf("a hop with no credential registered: %v (%d calls)", err, none.calls())
	}
}
