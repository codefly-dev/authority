package hop

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Run the same wire bytes through the public bare-token API as Python and TS.
func TestBareTokenSharedVectors(t *testing.T) {
	data, err := os.ReadFile("../../authority-client/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Name, Token, Audience, Issuer, Reason string
		Now                                   int64
		Keys                                  map[string]string
		Accept                                bool
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		t.Run(row.Name, func(t *testing.T) {
			response := &authorityv1.KeysResponse{Issuer: row.Issuer}
			for id, encoded := range row.Keys {
				raw, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					t.Fatal(err)
				}
				response.Keys = append(response.Keys, &authorityv1.PublicKey{KeyId: id, Algorithm: "Ed25519", PublicKey: raw})
			}
			v, err := NewTokenVerifier(context.Background(), &keys{response: response}, row.Audience)
			if err != nil {
				t.Fatal(err)
			}
			v.now = func() time.Time { return time.Unix(row.Now, 0) }
			id, err := v.VerifyToken(context.Background(), row.Token)
			if row.Accept {
				if err != nil {
					t.Fatalf("valid token refused: %v", err)
				}
				if id.Claims.Audience() != row.Audience {
					t.Fatal("wrong audience")
				}
			} else {
				var reason refusal.Reason
				if !errors.Is(err, workcontext.ErrUnauthenticated) || !errors.As(err, &reason) || reason.Code() != row.Reason {
					t.Fatalf("want %s, got %v", row.Reason, err)
				}
			}
		})
	}
}

var updateStamps = flag.Bool("update-vectors", false, "rewrite ../../authority-client/testdata/stamps.json")

// stampsPath is the wire-level half of the hop conformance target
// (libraries/conformance/hop/go): signed admissions on the wire, as the hop
// forwards them, each with the verdict every verifier must reach at a fixed
// clock. Go writes it from the cases below; Python and TypeScript replay the
// same file and must reach the same verdict, for the same reason, reading the
// same identity.
const stampsPath = "../../authority-client/testdata/stamps.json"

// stampVector is one call on the wire and Go's verdict on it.
type stampVector struct {
	Name string `json:"name"`
	// The module the verifier is, the procedure it observes the call on, and
	// its clock in unix seconds.
	Audience string `json:"audience"`
	Method   string `json:"method"`
	Now      int64  `json:"now"`
	// The authority's Keys as protojson; null when they cannot be read.
	Keys json.RawMessage `json:"keys"`
	// The call's metadata, in order, repeats kept.
	Headers [][2]string `json:"headers"`
	Accept  bool        `json:"accept"`
	// The refusal's code when not accepted.
	Reason string `json:"reason,omitempty"`
	// The code a second delivery of the same call, to another verifier on the
	// same replay store, is refused with.
	Replay string `json:"replay,omitempty"`
	// Who the call is for, when admitted: the identity every verifier derives.
	Identity *stampIdentity `json:"identity,omitempty"`
}

type stampIdentity struct {
	Owner     string   `json:"owner"`
	OwnerKind string   `json:"owner_kind"`
	Tenant    string   `json:"tenant"`
	Actors    []string `json:"actors"`
	Scopes    []string `json:"scopes"`
	Binding   string   `json:"binding"`
	Task      string   `json:"task"`
	Expires   int64    `json:"expires"`
}

// stampCase is what one vector varies: the Work Context the hop stamped
// (token), the one the call carries (carried, a swap when it differs), the hop
// signing the proof (label), what the proof names and when it was issued,
// what the verifier observes, the keys the authority publishes, and an edit of
// the finished headers. reason is the refusal the contract names; "" admits.
type stampCase struct {
	name                       string
	token, carried, proofToken string
	label                      string
	stampMethod, stampAudience string
	method, audience           string
	issued, expires            int64
	clock                      int64
	keys                       json.RawMessage
	fields                     func([]any) []any
	encode                     func(string) string
	edit                       func(metadata.MD)
	reason                     string
}

func stampVectors(t *testing.T) []stampVector {
	t.Helper()
	// The base material is the stamp fixture: a Work Context the test
	// authority signed, at the clock it was signed, and the keys publishing
	// that authority and the hop that signs as "fixture-proof".
	data, err := os.ReadFile(stampedPath)
	if err != nil {
		t.Fatal(err)
	}
	var f stampFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	const method, hopLabel = "/test.Service/Read", "fixture-proof"
	now, lifetime, skew := f.Now, int64(stamp.Lifetime/time.Second), int64(stamp.Skew/time.Second)
	token := f.Headers[WorkContextKey]
	fixture := newSigner("fixture")
	// The authority's Keys, as the fixture publishes them, edited.
	published := func(edit func(*authorityv1.KeysResponse)) json.RawMessage {
		response := &authorityv1.KeysResponse{}
		if err := protojson.Unmarshal(f.Keys, response); err != nil {
			t.Fatal(err)
		}
		if edit != nil {
			edit(response)
		}
		out, err := protojson.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	// A Work Context derived from the fixture's, signed by key.
	derived := func(key ed25519.PrivateKey, change func(*basev0.WorkContextV1)) string {
		body := proto.Clone(mustDecode(t, token)).(*basev0.WorkContextV1)
		change(body)
		payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, payload))
	}
	// Another genuine Work Context, for the same owner.
	other := derived(fixture.key, func(c *basev0.WorkContextV1) { c.TaskId = "task-other" })
	owned := derived(fixture.key, func(c *basev0.WorkContextV1) {
		c.AuthorityScopes = []*basev0.WorkScopeV1{{ResourceKind: "documents", Actions: []string{"read"}, ResourceOwnerId: "principal-u"}}
	})
	expired := derived(fixture.key, func(c *basev0.WorkContextV1) {
		c.IssuedAtUnix, c.NotBeforeUnix, c.ExpiresAtUnix = now-7200, now-7200, now-3600
	})
	elsewhere := derived(fixture.key, func(c *basev0.WorkContextV1) { c.Audience = "records" })
	hopSeed := sha256.Sum256([]byte(hopLabel))
	hopSigned := derived(ed25519.NewKeyFromSeed(hopSeed[:]), func(c *basev0.WorkContextV1) { c.KeyId = publishedHop(hopLabel).GetKeyId() })
	rotated := derived(newSigner("rotated").key, func(c *basev0.WorkContextV1) { c.KeyId = "hop-rotated" })
	payload, _, _ := strings.Cut(token, ".")
	forged := payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	admitted := func(name string, change func(*stampCase)) stampCase {
		c := stampCase{name: name, token: token, label: hopLabel, stampMethod: method, stampAudience: f.Audience, method: method, audience: f.Audience, issued: now, expires: now + lifetime, clock: now, keys: published(nil)}
		if change != nil {
			change(&c)
		}
		return c
	}
	refused := func(name, reason string, change func(*stampCase)) stampCase {
		c := admitted(name, change)
		c.reason = reason
		return c
	}
	set := func(key, value string) func(*stampCase) {
		return func(c *stampCase) { c.edit = func(md metadata.MD) { md.Set(key, value) } }
	}
	window := func(issued, expires int64) func(*stampCase) {
		return func(c *stampCase) { c.issued, c.expires = issued, expires }
	}
	cases := []stampCase{
		admitted("admitted", nil),
		admitted("admitted inside its lifetime", window(now-5, now+5)),
		admitted("issued the allowance ahead", window(now+skew, now+skew+lifetime)),
		admitted("expired inside the allowance", window(now-lifetime-1, now-1)),
		admitted("signed by the retiring key during a rotation's overlap", func(c *stampCase) {
			c.label = "retiring"
			c.keys = published(func(r *authorityv1.KeysResponse) { r.AdmissionKeys = append(r.AdmissionKeys, publishedHop("retiring")) })
		}),
		admitted("an owner-selected scope is not the whole kind", func(c *stampCase) { c.token = owned }),
		refused("issued further ahead than the allowance", "stamp_issued", window(now+skew+1, now+skew+1+lifetime)),
		refused("expired by the allowance", "stamp_window", window(now-lifetime-skew, now-skew)),
		refused("a span longer than the lifetime", "stamp_window", window(now, now+lifetime+1)),
		refused("a span longer than the lifetime inside the window", "stamp_window", window(now-20, now+lifetime-19)),
		refused("expiring when issued", "stamp_window", window(now, now)),
		refused("a negative issue instant", "stamp_window", window(-1, now+lifetime)),
		refused("signed for another procedure", "stamp_method", func(c *stampCase) { c.stampMethod = "/test.Service/Write" }),
		refused("observed without its leading slash", "stamp_method", func(c *stampCase) { c.method = "test.Service/Read" }),
		refused("observed with an http verb before the procedure", "stamp_method", func(c *stampCase) { c.method = "POST " + method }),
		refused("no procedure observed", "stamp_method", func(c *stampCase) { c.method = "" }),
		refused("signed for another module", "stamp_audience", func(c *stampCase) { c.stampAudience = "records" }),
		refused("signed by an unpublished key", "stamp_proof", func(c *stampCase) { c.label = "an-unpublished-hop" }),
		refused("signed by the retiring key after it is withdrawn", "stamp_proof", func(c *stampCase) { c.label = "retiring" }),
		refused("signed by an admission key published among the work context keys", "stamp_proof", func(c *stampCase) {
			c.label = "misplaced"
			c.keys = published(func(r *authorityv1.KeysResponse) { r.Keys = append(r.Keys, publishedHop("misplaced")) })
		}),
		refused("no admission key published", "keys_unavailable", func(c *stampCase) {
			c.keys = published(func(r *authorityv1.KeysResponse) { r.AdmissionKeys = nil })
		}),
		refused("an admission key published under another purpose", "keys_unavailable", func(c *stampCase) {
			c.keys = published(func(r *authorityv1.KeysResponse) {
				for _, key := range r.AdmissionKeys {
					key.Purpose = workContextPurpose
				}
			})
		}),
		refused("the authority's keys cannot be read", "keys_unavailable", func(c *stampCase) { c.keys = nil }),
		refused("no proof", "stamp_proof", func(c *stampCase) { c.edit = func(md metadata.MD) { md.Delete(ProofKey) } }),
		refused("a proof that is no signature", "stamp_proof", set(ProofKey, "another-run")),
		refused("a proof with padding", "stamp_proof", func(c *stampCase) {
			c.encode = func(proof string) string {
				payload, signature, _ := strings.Cut(proof, ".")
				return payload + "=." + signature
			}
		}),
		refused("a proof in three parts", "stamp_proof", func(c *stampCase) { c.encode = func(proof string) string { return proof + ".x" } }),
		refused("a proof over another domain", "stamp_proof", func(c *stampCase) {
			c.fields = func(fields []any) []any {
				fields[0] = "codefly-hop-v0"
				return fields
			}
		}),
		refused("a proof with six fields", "stamp_proof", func(c *stampCase) { c.fields = func(fields []any) []any { return fields[:6] } }),
		refused("a proof whose nonce is sixteen bytes", "stamp_proof", func(c *stampCase) {
			c.fields = func(fields []any) []any {
				fields[4] = fields[4].(string)[:32]
				return fields
			}
		}),
		refused("a proof whose nonce is upper-case hex", "stamp_proof", func(c *stampCase) {
			c.fields = func(fields []any) []any {
				fields[4] = strings.ToUpper(fields[4].(string))
				return fields
			}
		}),
		refused("two proofs", "stamp_proof", func(c *stampCase) {
			c.edit = func(md metadata.MD) { md.Append(ProofKey, md.Get(ProofKey)[0]) }
		}),
		refused("a swapped work context", "stamp_digest", func(c *stampCase) { c.carried = other }),
		refused("a forged work context under a rewritten digest", "stamp_digest", func(c *stampCase) { c.carried = forged }),
		refused("a context digest disagreeing with the proof", "stamp_digest", set(ContextKey, strings.Repeat("0", 64))),
		refused("no work context", "stamp_token", func(c *stampCase) { c.edit = func(md metadata.MD) { md.Delete(WorkContextKey) } }),
		refused("two work contexts", "stamp_token", func(c *stampCase) {
			c.edit = func(md metadata.MD) { md.Append(WorkContextKey, token) }
		}),
		refused("an advisory refusal", "stamp_advisory", set(AdvisoryKey, "write scope missing")),
		refused("a stamped tenant the token does not bear out", "stamp_identity", set(TenantKey, "globex")),
		refused("a stamped scope the token does not bear out", "stamp_identity", set(ScopesKey, "documents.collection:read,documents.collection:admin")),
		refused("a stamped owner the token does not bear out", "stamp_identity", set(OwnerKey, "remi")),
		refused("a stamped actor the token does not bear out", "stamp_identity", set(ActorsKey, "robin")),
		refused("a stamped identity header repeated", "stamp_identity", func(c *stampCase) {
			c.edit = func(md metadata.MD) { md.Append(TenantKey, md.Get(TenantKey)[0]) }
		}),
		refused("an expired work context under a fresh stamp", "expired", func(c *stampCase) { c.token = expired }),
		refused("a work context for another module under a stamp for this one", "audience", func(c *stampCase) { c.token = elsewhere }),
		refused("a work context signed by the hop's admission key", "unknown_key", func(c *stampCase) { c.token = hopSigned }),
		refused("a work context signed by a key the authority does not publish", "unknown_key", func(c *stampCase) { c.token = rotated }),
		refused("a forged work context signature under a stamp over it", "signature", func(c *stampCase) {
			c.carried, c.proofToken = forged, forged
		}),
	}
	out := make([]stampVector, 0, len(cases))
	for _, c := range cases {
		out = append(out, c.vector(t))
	}
	return out
}

// stampedPath is the stamp fixture the vectors derive from.
const stampedPath = "../testdata/stamped.json"

// vector is the case on the wire: the hop's stamp for the Work Context, the
// proof the suite signs with the hop's key, the edits, and the verdict.
func (c stampCase) vector(t *testing.T) stampVector {
	t.Helper()
	decoded := mustDecode(t, c.token)
	md := metadata.Pairs(WorkContextKey, c.token)
	// The hop's stamp for the identity headers and the context digest, signed
	// at the token's own start; the proof is then the deterministic one below.
	if err := Stamp(md, IdentityOf(decoded), testSigner(c.label), c.stampMethod, c.stampAudience, time.Unix(decoded.GetNotBeforeUnix(), 0)); err != nil {
		t.Fatal(err)
	}
	proofToken := c.token
	if c.proofToken != "" {
		proofToken = c.proofToken
	}
	nonce := sha256.Sum256([]byte("nonce:" + c.name))
	fields := []any{"codefly-hop-v1", c.stampMethod, c.stampAudience, digest(proofToken), hex.EncodeToString(nonce[:]), c.issued, c.expires}
	if c.fields != nil {
		fields = c.fields(fields)
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte(c.label))
	proof := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), payload))
	if c.encode != nil {
		proof = c.encode(proof)
	}
	md.Set(ProofKey, proof)
	if c.carried != "" {
		md.Set(WorkContextKey, c.carried)
		md.Set(ContextKey, digest(c.carried))
	}
	if c.edit != nil {
		c.edit(md)
	}
	v := stampVector{Name: c.name, Audience: c.audience, Method: c.method, Now: c.clock, Keys: c.keys, Accept: c.reason == "", Reason: c.reason}
	for _, key := range slices.Sorted(maps.Keys(md)) {
		for _, value := range md[key] {
			v.Headers = append(v.Headers, [2]string{key, value})
		}
	}
	if v.Accept {
		v.Replay = refusal.StampReplayed.Code()
		id := IdentityOf(decoded)
		v.Identity = &stampIdentity{Owner: id.Owner, OwnerKind: id.OwnerKind, Tenant: id.Tenant, Actors: nonNil(id.Actors), Scopes: nonNil(id.Scopes), Binding: id.Binding, Task: id.Task, Expires: id.Expires}
	}
	return v
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// verdict is what Go's verifier answers for the vector, at the vector's clock:
// admission, or the refusal's code, and for an admitted call the code a second
// delivery to another verifier on the same store is refused with.
func (v stampVector) verdict(t *testing.T) (accept bool, reason, replay string, id Identity) {
	t.Helper()
	ctx := context.Background()
	source := &keys{literalResponse: true}
	if v.Keys == nil {
		source.err = errors.New("dial authority.internal:4000: connection refused")
	} else {
		source.response = &authorityv1.KeysResponse{}
		if err := protojson.Unmarshal(v.Keys, source.response); err != nil {
			t.Fatal(err)
		}
	}
	// A store that keeps every nonce it is given: Core's in-memory store
	// evicts by the wall clock, which is years past the vectors' clock.
	store, err := NewFileReplayStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	build := func() *Verifier {
		verifier, err := NewVerifier(ctx, source, v.Audience, store)
		if err != nil {
			t.Fatal(err)
		}
		verifier.now = func() time.Time { return time.Unix(v.Now, 0) }
		return verifier
	}
	md := metadata.MD{}
	for _, pair := range v.Headers {
		md.Append(pair[0], pair[1])
	}
	id, err = build().Verify(ctx, md, v.Method)
	if err != nil {
		var refusedAs refusal.Reason
		if !errors.Is(err, workcontext.ErrUnauthenticated) || !errors.As(err, &refusedAs) {
			t.Fatalf("a refusal without a reason: %v", err)
		}
		for _, pair := range v.Headers {
			if len(pair[1]) > 16 && strings.Contains(err.Error(), pair[1]) {
				t.Fatalf("the refusal names the call's %s", pair[0])
			}
		}
		return false, refusedAs.Code(), "", id
	}
	_, again := build().Verify(ctx, md, v.Method)
	var refusedAs refusal.Reason
	if !errors.As(again, &refusedAs) {
		t.Fatalf("a second delivery was admitted: %v", again)
	}
	return true, "", refusedAs.Code(), id
}

// Every verdict in the stamp vectors is the contract's, and Go reaches it by
// the one check a module runs; the file is regenerated from these cases, never
// edited. Python and TypeScript replay the file and must reach the same
// verdicts.
func TestTheStampVectorsAreGosVerdicts(t *testing.T) {
	cases := stampVectors(t)
	want, err := json.MarshalIndent(cases, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	if *updateStamps {
		if err := os.WriteFile(stampsPath, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := os.ReadFile(stampsPath); err != nil || string(got) != string(want) {
		t.Fatalf("%s is not what these cases produce; regenerate with -update-vectors: %v", stampsPath, err)
	}
	for _, v := range cases {
		t.Run(v.Name, func(t *testing.T) {
			accept, reason, replay, id := v.verdict(t)
			if accept != v.Accept || reason != v.Reason || replay != v.Replay {
				t.Fatalf("Go admits %v, refuses as %q, refuses a replay as %q; the contract says admit %v, refuse as %q, refuse a replay as %q", accept, reason, replay, v.Accept, v.Reason, v.Replay)
			}
			if !v.Accept {
				return
			}
			got := stampIdentity{Owner: id.Owner, OwnerKind: id.OwnerKind, Tenant: id.Tenant, Actors: nonNil(id.Actors), Scopes: nonNil(id.Scopes), Binding: id.Binding, Task: id.Task, Expires: id.Expires}
			if gotJSON, _ := json.Marshal(got); string(gotJSON) != string(must(json.Marshal(v.Identity))) {
				t.Fatalf("Go reads %s, the contract says %s", gotJSON, must(json.Marshal(v.Identity)))
			}
		})
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
