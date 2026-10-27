package hop

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"google.golang.org/grpc"
)

// registrar is an authority answering RegisterAdmissionKey with a lease, or
// refusing while refuse is set; it records what it was presented, and checks
// each registration's proof as the authority at testAudience does.
type registrar struct {
	mu          sync.Mutex
	lease       time.Duration
	refuse      error
	credentials []string
	keys        [][]byte
	nonces      []string
}

const testAudience = "https://authority.hop.test"

// testCredential is a launcher-shaped credential for audience; only its
// claims are read here, the authority attests it.
func testCredential(audience, id string) string {
	encode := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return encode(`{"alg":"EdDSA"}`) + "." + encode(`{"aud":["`+audience+`"],"jti":"`+id+`"}`) + "." + encode("signature")
}

func (r *registrar) RegisterAdmissionKey(_ context.Context, in *authorityv1.RegisterAdmissionKeyRequest, _ ...grpc.CallOption) (*authorityv1.RegisterAdmissionKeyResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.credentials = append(r.credentials, in.GetActor().GetCredential())
	r.keys = append(r.keys, in.GetPublicKey())
	if r.refuse != nil {
		return nil, r.refuse
	}
	proved, err := stamp.CheckRegistration(in.GetProof(), ed25519.PublicKey(in.GetPublicKey()), in.GetActor().GetCredential(), testAudience, time.Now())
	if err != nil {
		return nil, err
	}
	r.nonces = append(r.nonces, proved.Nonce)
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
		Credential: func() (string, error) {
			rotation++
			return testCredential(testAudience, "credential-"+string(rune('0'+rotation))), nil
		},
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
	// Review #28 F1: each registration proves possession of the key, over
	// that registration's credential, with a nonce of its own.
	if len(authority.nonces) != len(authority.keys) || authority.nonces[0] == authority.nonces[1] {
		t.Fatalf("registrations without a fresh proof each: %v", authority.nonces)
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
		Credential: func() (string, error) { return testCredential(testAudience, "credential"), nil },
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

// The proof names the audience the credential was issued for, so it is good
// at that authority alone; a credential naming none presents nothing.
func TestARegistrationProofNamesTheCredentialsAudience(t *testing.T) {
	signer := testSigner("the-hop")
	_, public := signer.Admission()
	var seen *authorityv1.RegisterAdmissionKeyRequest
	authority := registrarFunc(func(in *authorityv1.RegisterAdmissionKeyRequest) { seen = in })
	credential := testCredential("https://elsewhere.test", "c1")
	if _, _, err := (Registration{Authority: authority, Signer: signer, Credential: func() (string, error) { return credential, nil }}).Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := stamp.CheckRegistration(seen.GetProof(), public, credential, "https://elsewhere.test", time.Now()); err != nil {
		t.Fatalf("the proof is not for the credential's audience: %v", err)
	}
	if _, err := stamp.CheckRegistration(seen.GetProof(), public, credential, testAudience, time.Now()); err == nil || !strings.Contains(err.Error(), "another authority") {
		t.Fatalf("a proof for one authority was good at another: %v", err)
	}
	seen = nil
	for _, bad := range []string{"opaque-bearer", testCredential("", "c2")} {
		if _, _, err := (Registration{Authority: authority, Signer: signer, Credential: func() (string, error) { return bad, nil }}).Register(context.Background()); err == nil || seen != nil {
			t.Fatalf("%q registered with no audience to prove to: %v", bad, err)
		}
	}
}

type registrarFunc func(*authorityv1.RegisterAdmissionKeyRequest)

func (f registrarFunc) RegisterAdmissionKey(_ context.Context, in *authorityv1.RegisterAdmissionKeyRequest, _ ...grpc.CallOption) (*authorityv1.RegisterAdmissionKeyResponse, error) {
	f(in)
	return &authorityv1.RegisterAdmissionKeyResponse{Key: &authorityv1.PublicKey{KeyId: stamp.KeyID(in.GetPublicKey())}, ExpiresAtUnix: time.Now().Add(time.Minute).Unix()}, nil
}
