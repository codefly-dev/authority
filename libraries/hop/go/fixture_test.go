package hop

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
)

var updateFixture = flag.Bool("update-fixture", false, "rewrite ../testdata/stamped.json")

// signer is a test authority: a key derived from a seed in this file, so it is
// public and signs fixtures only. It is not Core's fixture key, which Core refuses.
type signer struct {
	id     string
	key    ed25519.PrivateKey
	issuer string
}

func newSigner(seed string) signer {
	sum := sha256.Sum256([]byte(seed))
	return signer{id: "hop-" + seed, key: ed25519.NewKeyFromSeed(sum[:]), issuer: "https://authority.hop.test"}
}

func (s signer) published() *authorityv1.PublicKey {
	return &authorityv1.PublicKey{KeyId: s.id, Algorithm: core.Algorithm, PublicKey: s.key.Public().(ed25519.PublicKey)}
}

func (s signer) issue(t *testing.T, at time.Time, audience string, scopes ...*basev0.WorkScopeV1) string {
	t.Helper()
	a := &core.Authority{Issuer: s.issuer, KeyID: s.id, Key: s.key, Revisions: core.FixtureRevisions(), Seals: core.FixtureSeals(), Now: func() time.Time { return at }}
	token, _, err := a.Start(context.Background(), core.StartInput{
		TenantID: core.FixtureTenant, OwnerPrincipalID: core.FixturePrincipal, OwnerPrincipalKind: "human",
		OrganizationID: core.FixtureOrganization, TaskID: core.FixtureTask, Audience: audience,
		AuthorityScopes: scopes, InstallationID: core.FixtureInstallation, TTL: 10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func forwarded(t *testing.T, token, proof, advisory string) metadata.MD {
	t.Helper()
	decoded, err := core.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	id := IdentityOf(decoded.Context())
	id.Advisory = advisory
	md := metadata.Pairs(WorkContextKey, token)
	Stamp(md, id, proof)
	return md
}

// keys is a switchable Keys answer that counts the reads.
type keys struct {
	response *authorityv1.KeysResponse
	err      error
	reads    int
}

func (k *keys) Keys(context.Context, *authorityv1.KeysRequest, ...grpc.CallOption) (*authorityv1.KeysResponse, error) {
	k.reads++
	return k.response, k.err
}

type stampFixture struct {
	Proof    string            `json:"proof"`
	Audience string            `json:"audience"`
	Now      int64             `json:"now"`
	Keys     json.RawMessage   `json:"keys"`
	Headers  map[string]string `json:"headers"`
	Identity map[string]any    `json:"identity"`
}

// The stamp's one contract, for every language a module is written in: the
// headers this hop writes for one call carrying a genuinely signed Work
// Context, the published keys that authenticate it at a fixed clock, and the
// identity read from it. The Python verifier (../python) reads it back.
func TestTheStampFixtureAuthenticatesAsTheHopWroteIt(t *testing.T) {
	path := filepath.Join("..", "testdata", "stamped.json")
	s := newSigner("fixture")
	if *updateFixture {
		at := time.Unix(1792818000, 0)
		token := s.issue(t, at, "documents", &basev0.WorkScopeV1{ResourceKind: "documents.collection", Actions: []string{"read"}}, &basev0.WorkScopeV1{ResourceKind: "documents.collection", Actions: []string{"write"}, ResourceIds: []string{"c-1"}})
		md := forwarded(t, token, "fixture-proof", "documents.collection:write is not held")
		published, _ := protojson.Marshal(&authorityv1.KeysResponse{Issuer: s.issuer, Keys: []*authorityv1.PublicKey{s.published()}})
		f := stampFixture{Proof: "fixture-proof", Audience: "documents", Now: at.Add(time.Minute).Unix(), Keys: published, Headers: map[string]string{}}
		for key, values := range md {
			f.Headers[key] = values[0]
		}
		id := IdentityOf(mustDecode(t, token))
		f.Identity = map[string]any{"owner": id.Owner, "owner_kind": id.OwnerKind, "tenant": id.Tenant, "actors": id.Actors, "scopes": id.Scopes, "binding": id.Binding, "task": id.Task, "expires": id.Expires, "advisory": "documents.collection:write is not held"}
		out, _ := json.MarshalIndent(f, "", "  ")
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f stampFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	published := &authorityv1.KeysResponse{}
	if err := protojson.Unmarshal(f.Keys, published); err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(context.Background(), &keys{response: published}, f.Audience, f.Proof)
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return time.Unix(f.Now, 0) }
	md := metadata.MD{}
	for key, value := range f.Headers {
		md.Set(key, value)
	}
	id, err := v.Verify(context.Background(), md)
	if err != nil {
		t.Fatalf("%s no longer authenticates; regenerate with -update-fixture: %v", path, err)
	}
	if want := forwarded(t, id.Context, f.Proof, id.Advisory); !reflect.DeepEqual(want, md) {
		t.Fatalf("%s is not what the hop writes; regenerate with -update-fixture", path)
	}
	if id.Owner != f.Identity["owner"] || id.Tenant != f.Identity["tenant"] || strings.Join(id.Scopes, ",") != "documents.collection:read" || id.Advisory != f.Identity["advisory"] || !id.Claims.Allows("documents.collection", "write", "c-1") {
		t.Fatalf("identity: %+v", id)
	}
}

func mustDecode(t *testing.T, token string) *basev0.WorkContextV1 {
	t.Helper()
	d, err := core.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	return d.Context()
}

// A rotated key is fetched when a token first names it, at most once per
// keyRetry; a removed key stops verifying within keyMaxAge; keys that cannot
// be re-read are trusted no longer than keyStale.
func TestPublishedKeysAreRereadOnRotationAndExpireWhenUnreadable(t *testing.T) {
	first, second := newSigner("first"), newSigner("second")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: first.issuer, Keys: []*authorityv1.PublicKey{first.published()}}}
	start := time.Unix(1792818000, 0)
	clock := start
	v, err := NewVerifier(context.Background(), source, "documents", "proof")
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return clock }
	v.tried, v.fetched = start, start
	verify := func(token string) error {
		_, err := v.Verify(context.Background(), forwarded(t, token, "proof", ""))
		return err
	}
	if err := verify(first.issue(t, clock, "documents")); err != nil {
		t.Fatal(err)
	}
	source.response = &authorityv1.KeysResponse{Issuer: first.issuer, Keys: []*authorityv1.PublicKey{second.published()}}
	clock = start.Add(time.Second)
	if err := verify(second.issue(t, clock, "documents")); err == nil || !strings.Contains(err.Error(), "no verification key") || source.reads != 1 {
		t.Fatalf("within keyRetry the keys are not re-read: %v (reads %d)", err, source.reads)
	}
	clock = start.Add(keyRetry + time.Second)
	if err := verify(second.issue(t, clock, "documents")); err != nil || source.reads != 2 {
		t.Fatalf("a rotated key is fetched: %v (reads %d)", err, source.reads)
	}
	if err := verify(first.issue(t, clock, "documents")); err == nil {
		t.Fatal("a key the authority no longer publishes still verifies")
	}
	source.err = errors.New("authority down")
	clock = clock.Add(keyMaxAge + time.Second)
	if err := verify(second.issue(t, clock, "documents")); err != nil {
		t.Fatalf("a failed re-read keeps the last keys until keyStale: %v", err)
	}
	clock = clock.Add(keyStale)
	if err := verify(second.issue(t, clock, "documents")); !errors.Is(err, workcontext.ErrUnauthenticated) || !strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("stale keys are refused, naming the outage: %v", err)
	}
}
