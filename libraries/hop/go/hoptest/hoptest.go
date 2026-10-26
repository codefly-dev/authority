// Package hoptest is a real authority for a module's tests: it signs Work
// Contexts with a key of its own, answers Keys for them and for the hops it
// publishes, and forwards a call exactly as the hop stamps it. A module's interceptor tests then exercise the
// same Verifier production runs, with no hand-built header standing in.
package hoptest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	hop "github.com/codefly-dev/authority/libraries/hop/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

// Issuer is the issuer every Work Context this authority signs names.
const Issuer = "https://authority.hoptest"

// Authority signs with a fresh key; Rotate replaces it. Keys publishes that
// key and the admission key of every hop PublishHop names.
type Authority struct {
	signer *core.Authority
	// Now is the signing clock; nil means time.Now.
	Now func() time.Time

	mu   sync.Mutex
	keys *authorityv1.KeysResponse
}

// New returns an authority with a fresh signing key.
func New(t testing.TB) *Authority {
	a := &Authority{}
	a.Rotate(t)
	return a
}

// Rotate signs from now on with a fresh key, and publishes only that key.
func (a *Authority) Rotate(t testing.TB) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("hoptest-%x", public[:4])
	a.signer = &core.Authority{Issuer: Issuer, KeyID: id, Key: private, Revisions: core.FixtureRevisions(), Seals: core.FixtureSeals(),
		Now: func() time.Time {
			if a.Now != nil {
				return a.Now()
			}
			return time.Now()
		}}
	a.mu.Lock()
	defer a.mu.Unlock()
	var hops []*authorityv1.PublicKey
	if a.keys != nil {
		hops = a.keys.AdmissionKeys
	}
	a.keys = &authorityv1.KeysResponse{Issuer: Issuer, Keys: []*authorityv1.PublicKey{{KeyId: id, Algorithm: core.Algorithm, PublicKey: public, Purpose: "work-context"}}, AdmissionKeys: hops}
}

// PublishHop publishes, beside those already published, the admission key of
// each hop that signs as label (Signer(label)), as an authority publishes its
// hop's key: a Verifier reading this authority's Keys then admits what they
// sign. Publishing two is a rotation's overlap.
func (a *Authority) PublishHop(labels ...string) *Authority {
	a.mu.Lock()
	defer a.mu.Unlock()
	keys := proto.Clone(a.keys).(*authorityv1.KeysResponse)
	for _, label := range labels {
		keys.AdmissionKeys = append(keys.AdmissionKeys, Published(label))
	}
	a.keys = keys
	return a
}

// WithdrawHop stops publishing the admission key of each hop that signs as
// label, as an authority does once a rotation's overlap ends.
func (a *Authority) WithdrawHop(labels ...string) *Authority {
	a.mu.Lock()
	defer a.mu.Unlock()
	keys := proto.Clone(a.keys).(*authorityv1.KeysResponse)
	keys.AdmissionKeys = nil
	for _, key := range a.keys.AdmissionKeys {
		withdrawn := false
		for _, label := range labels {
			withdrawn = withdrawn || proto.Equal(key, Published(label))
		}
		if !withdrawn {
			keys.AdmissionKeys = append(keys.AdmissionKeys, key)
		}
	}
	a.keys = keys
	return a
}

// Keys is the authority interface's Keys, as a Verifier reads it.
func (a *Authority) Keys(context.Context, *authorityv1.KeysRequest, ...grpc.CallOption) (*authorityv1.KeysResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.keys, nil
}

// Issue signs a ten-minute Work Context for Core's fixture owner, addressed to
// audience, carrying scopes.
func (a *Authority) Issue(t testing.TB, audience string, scopes ...*basev0.WorkScopeV1) string {
	return a.issue(t, audience, core.ReplayIdempotent, scopes...)
}

// IssueSingleUse reproduces admission probes with a genuine single-use capability.
func (a *Authority) IssueSingleUse(t testing.TB, audience string, scopes ...*basev0.WorkScopeV1) string {
	return a.issue(t, audience, core.ReplaySingleUse, scopes...)
}

func (a *Authority) issue(t testing.TB, audience, replay string, scopes ...*basev0.WorkScopeV1) string {
	t.Helper()
	token, _, err := a.signer.Start(context.Background(), core.StartInput{
		TenantID: core.FixtureTenant, OwnerPrincipalID: core.FixturePrincipal, OwnerPrincipalKind: "human",
		OrganizationID: core.FixtureOrganization, TaskID: core.FixtureTask, Audience: audience,
		ReplayPolicy: replay, AuthorityScopes: scopes, InstallationID: core.FixtureInstallation, TTL: 10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// Forward is the incoming metadata of a call the hop let through carrying
// token: the token, and the stamp the hop writes for it under proof.
func Forward(t testing.TB, token, proof, method string) metadata.MD {
	t.Helper()
	decoded, err := core.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	md := metadata.Pairs(hop.WorkContextKey, token)
	if err := hop.Stamp(md, hop.IdentityOf(decoded.Context()), Signer(proof), method, decoded.Context().GetAudience(), time.Now()); err != nil {
		t.Fatal(err)
	}
	return md
}

// Signer derives a public test key. Production seeds come only from Codefly.
// An Authority publishes its admission key once PublishHop names label.
func Signer(label string) *stamp.Signer {
	sum := sha256.Sum256([]byte(label))
	signer, _ := stamp.NewSigner(hex.EncodeToString(sum[:]))
	return signer
}
func PublicKey(label string) string { return Signer(label).PublicKey() }

// Published is the admission key of the hop that signs as label, as an
// authority's Keys carries it in admission_keys.
func Published(label string) *authorityv1.PublicKey {
	id, public := Signer(label).Admission()
	return &authorityv1.PublicKey{KeyId: id, Algorithm: core.Algorithm, PublicKey: public, Purpose: stamp.Purpose}
}

// Replay is for single-process tests only; deployments supply a shared store.
// It declares no Shared(), so hop.NewVerifier refuses it outside a local run
// rather than leaving that to this comment.
func Replay() core.ReplayStore { return core.NewMemoryReplayStore() }
