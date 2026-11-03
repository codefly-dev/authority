// Package hopconformance is the suite every verifier of the hop's admission
// must pass: the hop side of the rule the authority suite states, one
// contract, N implementations, one suite. A verifier is proved by passing it,
// not by whoever wrote it.
//
// The target has two halves. Run drives the cases that need a live authority
// and more than one verifier (rotation, a store two replicas share, a handler
// holding its reservation, keys that cannot be read) against a Go verifier,
// built on hoptest: a real authority that signs Work Contexts with a key of
// its own, answers Keys for them and for the hops it publishes, and forwards a
// call exactly as the hop stamps it. The wire-level half is
// libraries/authority-client/testdata/stamps.json: signed admissions on the
// wire with the verdict every verifier must reach at a fixed clock, written by
// the Go hop library's test and replayed by Go, Python and TypeScript.
//
// Run drives the verifier under test through its public entry points alone,
// on the verifier's own clock. What the suite moves is the hop's signing
// clock, the authority's, and the stamps it signs itself under the hop's test
// key, so a case that needs a window the hop would never sign still has one.
// A verifier passes by answering every case as the contract states, with the
// refusal.Reason the contract names; no case may be loosened so that an
// implementation passes.
package hopconformance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"
	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

// Verifier is the module-side check under test: what hop.Verifier is in Go.
// A second Go implementation runs the same cases behind this interface.
type Verifier interface {
	// Verify authenticates the call md carries for method and answers who it
	// is for, read from the authenticated Work Context. A refusal wraps
	// workcontext.ErrUnauthenticated and carries a refusal.Reason, read with
	// errors.As, that names no token, proof, digest, nonce or transport
	// failure. Verify consumes the admission and ends its in-flight hold
	// before returning.
	Verify(ctx context.Context, md metadata.MD, method string) (hop.Identity, error)
	// Admit is Verify for a caller that runs the call's work itself: it holds
	// the single-use reservation until done is called.
	Admit(ctx context.Context, md metadata.MD, method string) (hop.Identity, func(), error)
}

// Target is one implementation of the verifier.
type Target struct {
	// New builds the verifier for audience. It reads the authority's Keys
	// through keys, the Work Context keys and the hop's admission keys alike,
	// and reserves single-use nonces in replay. It refuses, with an error, a
	// nil keys, an empty audience, a nil replay, and, outside the run named
	// exactly "local", a replay store that does not declare itself the one
	// every replica shares (hop.SharedReplayStore). It never fails on an
	// authority that is not serving keys yet: calls are refused, with the
	// reason, until they are read.
	New func(ctx context.Context, keys hop.KeySource, audience string, replay core.ReplayStore) (Verifier, error)
}

// The module every case stands behind, the procedure its calls arrive on, and
// the hop in front of it. A hop is named by the label hoptest derives its
// signing key from, so hoptest.PublicKey(Hop) is the admission key the
// authority publishes for it.
const (
	Audience = "documents"
	Method   = "/documents.v1.Service/Get"
	Hop      = "the-hop"
)

// read is the scope every issued Work Context carries, unless a case says
// otherwise.
var read = &basev0.WorkScopeV1{ResourceKind: "documents", Actions: []string{"read"}}

// Run drives every case against the target.
//
// The suite's replay stores are process-local, shared by the verifiers of one
// case, which only the run named exactly "local" admits: Run sets that
// environment for its duration (t.Setenv, so the calling test cannot be
// parallel), and the case proving the refusal outside it sets its own.
func Run(t *testing.T, target Target) {
	t.Helper()
	if target.New == nil {
		t.Fatal("hopconformance: the target builds no verifier")
	}
	t.Setenv(resources.EnvironmentPrefix, "local")
	// The suite signs some stamps itself under the key hoptest derives for a
	// hop's label; the two derivations must agree or every such case misreads.
	if hex.EncodeToString(hopKey(Hop).Public().(ed25519.PublicKey)) != hoptest.PublicKey(Hop) {
		t.Fatal("hopconformance: the suite's hop key is not the one hoptest publishes")
	}
	s := suite{target: target}
	s.keys(t)
	s.binding(t)
	s.window(t)
	s.replay(t)
	s.identity(t)
	s.hop(t)
	s.startup(t)
}

type suite struct{ target Target }

// verifier builds the target's verifier, failing the case when it cannot.
func (s suite) verifier(t *testing.T, keys hop.KeySource, audience string, replay core.ReplayStore) Verifier {
	t.Helper()
	v, err := s.target.New(context.Background(), keys, audience, replay)
	if err != nil {
		t.Fatalf("the target builds no verifier: %v", err)
	}
	return v
}

// authority is a hoptest authority that publishes Hop's admission key.
func authority(t *testing.T) *hoptest.Authority { return hoptest.New(t).PublishHop(Hop) }

// forward is the call the hop that signs as label let through carrying
// token: the token, and the stamp the hop writes for method and the token's
// audience, now.
func forward(t *testing.T, token, label, method string) metadata.MD {
	t.Helper()
	return hoptest.Forward(t, token, label, method)
}

// hopKey is the signing key hoptest derives for the hop that signs as label.
// Production seeds come only from Codefly; this one signs fixtures.
func hopKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

// proof is the signed admission the hop that signs as label writes for a call
// carrying token, with the fields the suite chooses: the payload the contract
// fixes, under the hop's key. The suite signs these itself because a hop never
// issues a window outside the contract, and the cases need one.
func proof(t *testing.T, label, method, audience, token string, issued, expires int64) string {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(token))
	payload, err := json.Marshal([]any{"codefly-hop-v1", method, audience, hex.EncodeToString(sum[:]), hex.EncodeToString(nonce), issued, expires})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(hopKey(label), payload))
}

// stampedAt is forward with the admission's window chosen by the suite:
// the identity headers the hop writes, and a proof issued at issued, expiring
// at expires, for method and audience.
func stampedAt(t *testing.T, token, label, method, audience string, issued, expires int64) metadata.MD {
	t.Helper()
	decoded, err := core.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	md := metadata.Pairs(hop.WorkContextKey, token)
	// The hop's stamp, signed at the token's own start so an expired token can
	// still carry its identity headers; the proof is then the suite's.
	if err := hop.Stamp(md, hop.IdentityOf(decoded.Context()), hoptest.Signer(label), method, audience, time.Unix(decoded.Context().GetNotBeforeUnix(), 0)); err != nil {
		t.Fatal(err)
	}
	md.Set(hop.ProofKey, proof(t, label, method, audience, token, issued, expires))
	return md
}

// replayKey is the reservation the admission md carries takes in a store, as
// the verifier derives it: namespaced by the hop's published key and the nonce.
func replayKey(t *testing.T, md metadata.MD, label string) string {
	t.Helper()
	call, err := stamp.Check(md, hoptest.PublicKey(label), Method, Audience, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return call.ReplayKey(hoptest.PublicKey(label))
}

// refused asserts err is the refusal the contract names, wrapping
// workcontext.ErrUnauthenticated, and that its text keeps every secret the
// case names out of the caller's sight.
func refused(t *testing.T, err error, want refusal.Reason, secrets ...string) {
	t.Helper()
	var reason refusal.Reason
	if !errors.Is(err, workcontext.ErrUnauthenticated) || !errors.As(err, &reason) || reason != want {
		t.Fatalf("want a refusal naming %s, got %v", want, err)
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(err.Error(), secret) {
			t.Fatalf("the refusal %s names what it must not", want)
		}
	}
}

// admitted asserts a Verify admitted the call and answers who it is for:
// admitted(t)(v.Verify(ctx, md, method)).
func admitted(t *testing.T) func(hop.Identity, error) hop.Identity {
	return func(id hop.Identity, err error) hop.Identity {
		t.Helper()
		if err != nil {
			t.Fatalf("a genuine call was refused: %v", err)
		}
		return id
	}
}

// digest is the hex SHA-256 of token, as the stamp binds it.
func digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// counting counts the reads of the authority's Keys.
type counting struct {
	hop.KeySource
	reads atomic.Int64
}

func (c *counting) Keys(ctx context.Context, in *authorityv1.KeysRequest, opts ...grpc.CallOption) (*authorityv1.KeysResponse, error) {
	c.reads.Add(1)
	return c.KeySource.Keys(ctx, in, opts...)
}

// editing answers the authority's Keys as edit rewrites them.
type editing struct {
	hop.KeySource
	edit func(*authorityv1.KeysResponse)
}

func (e editing) Keys(ctx context.Context, in *authorityv1.KeysRequest, opts ...grpc.CallOption) (*authorityv1.KeysResponse, error) {
	response, err := e.KeySource.Keys(ctx, in, opts...)
	if err != nil {
		return nil, err
	}
	response = proto.Clone(response).(*authorityv1.KeysResponse)
	e.edit(response)
	return response, nil
}

// unreachable is an authority whose Keys cannot be read; its failure names
// an address a caller must never see.
type unreachable struct{}

const unreachableAddress = "authority.internal:4000"

func (unreachable) Keys(context.Context, *authorityv1.KeysRequest, ...grpc.CallOption) (*authorityv1.KeysResponse, error) {
	return nil, errors.New("dial " + unreachableAddress + ": connection refused")
}
