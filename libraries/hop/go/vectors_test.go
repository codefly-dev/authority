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
	"github.com/codefly-dev/authority/libraries/hop/go/policy"
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
	// What each method the module serves declares, as the module hands it to
	// its verifier (Declarations); absent when it hands none.
	Declared map[string]stampDeclared `json:"declared,omitempty"`
	// What admitted the call, as every verifier hands it to the handler;
	// absent for an admitted call the hop stamped no admission on, which is
	// handed none.
	Admission *stampAdmission `json:"admission,omitempty"`
}

// stampDeclared is one method's declaration: each permission a [kind, action]
// pair, never joined.
type stampDeclared struct {
	AnyCheckedCaller bool        `json:"any_checked_caller"`
	Requires         [][2]string `json:"requires"`
	Carries          [][2]string `json:"carries"`
}

// stampAdmission is every reading an Admission answers, so a verifier in
// another language is held to each of them.
type stampAdmission struct {
	Method           string `json:"method"`
	Declared         bool   `json:"declared"`
	AnyCheckedCaller bool   `json:"any_checked_caller"`
	// What the call holds, as AdmittedKey carries it once decoded.
	Grants   [][]any        `json:"grants"`
	Required stampSelection `json:"required"`
	Carried  stampSelection `json:"carried"`
	Each     []stampHeld    `json:"each"`
}

type stampHeld struct {
	Kind      string         `json:"kind"`
	Action    string         `json:"action"`
	Carried   bool           `json:"carried"`
	Selection stampSelection `json:"selection"`
}

// stampSelection is a Selection's answers. Allows is Allows(owner, id) for
// every owner and id the call's grants name, the empty one and one they do not.
type stampSelection struct {
	Empty         bool            `json:"empty"`
	Whole         bool            `json:"whole"`
	Owners        []string        `json:"owners"`
	Named         []stampNamed    `json:"named"`
	Allows        []stampAllows   `json:"allows"`
	OwnerSelected *stampSelection `json:"owner_selected,omitempty"`
}

type stampNamed struct {
	Owner     string   `json:"owner"`
	Resources []string `json:"resources"`
}

type stampAllows struct {
	Owner   string `json:"owner"`
	ID      string `json:"id"`
	Allowed bool   `json:"allowed"`
}

func declaredOf(methods map[string]policy.Method) map[string]stampDeclared {
	if methods == nil {
		return nil
	}
	pairs := func(permissions []policy.Permission) [][2]string {
		out := [][2]string{}
		for _, p := range permissions {
			out = append(out, [2]string{p.Kind, p.Action})
		}
		return out
	}
	out := map[string]stampDeclared{}
	for method, m := range methods {
		out[method] = stampDeclared{AnyCheckedCaller: m.AnyCheckedCaller, Requires: pairs(m.Requires), Carries: pairs(m.Carries)}
	}
	return out
}

// admissionRead is every reading of a, probed over what grants name.
func admissionRead(a *Admission, grants []Grant) *stampAdmission {
	if a == nil {
		return nil
	}
	owners, ids := []string{"", "another-owner"}, []string{"", "another-id"}
	out := &stampAdmission{Method: a.Method, Declared: a.Declared, AnyCheckedCaller: a.AnyCheckedCaller, Grants: [][]any{}, Each: []stampHeld{}}
	for _, g := range canonical(grants) {
		owners, ids = append(owners, g.Owner), append(ids, g.Resources...)
		out.Grants = append(out.Grants, []any{g.Kind, g.Action, g.Owner, nonNil(g.Resources)})
	}
	slices.Sort(owners)
	slices.Sort(ids)
	owners, ids = slices.Compact(owners), slices.Compact(ids)
	var read func(s Selection, nested bool) stampSelection
	read = func(s Selection, nested bool) stampSelection {
		r := stampSelection{Empty: s.Empty(), Whole: s.Whole(), Owners: s.Owners(), Named: []stampNamed{}, Allows: []stampAllows{}}
		for _, n := range s.Named() {
			r.Named = append(r.Named, stampNamed{Owner: n.Owner, Resources: n.Resources})
		}
		for _, owner := range owners {
			for _, id := range ids {
				r.Allows = append(r.Allows, stampAllows{Owner: owner, ID: id, Allowed: s.Allows(owner, id)})
			}
		}
		if !nested {
			selected := read(s.OwnerSelected(), true)
			r.OwnerSelected = &selected
		}
		return r
	}
	out.Required, out.Carried = read(a.Required(), false), read(a.Carried(), false)
	for _, h := range a.Each() {
		out.Each = append(out.Each, stampHeld{Kind: h.Permission.Kind, Action: h.Permission.Action, Carried: h.Carried, Selection: read(h.Selection, false)})
	}
	return out
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
	// declared is what the module hands its verifier (Declarations).
	declared map[string]policy.Method
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
	cases = append(cases, admissionCases(admitted, refused, set, func(scopes []*basev0.WorkScopeV1, actors ...*basev0.WorkActorV1) string {
		return derived(fixture.key, func(c *basev0.WorkContextV1) { c.AuthorityScopes, c.ActorChain = scopes, actors })
	})...)
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
	v := stampVector{Name: c.name, Audience: c.audience, Method: c.method, Now: c.clock, Keys: c.keys, Accept: c.reason == "", Reason: c.reason, Declared: declaredOf(c.declared)}
	for _, key := range slices.Sorted(maps.Keys(md)) {
		for _, value := range md[key] {
			v.Headers = append(v.Headers, [2]string{key, value})
		}
	}
	if v.Accept {
		v.Replay = refusal.StampReplayed.Code()
		id := IdentityOf(decoded)
		v.Identity = &stampIdentity{Owner: id.Owner, OwnerKind: id.OwnerKind, Tenant: id.Tenant, Actors: nonNil(id.Actors), Scopes: nonNil(id.Scopes), Binding: id.Binding, Task: id.Task, Expires: id.Expires}
		// What the contract says the handler is handed: the method's
		// declaration read against what the Work Context holds. The verdict
		// below is what a real Verifier hands, held to this.
		if len(md.Get(AdmittedKey)) == 1 {
			declared, _ := (&Verifier{declared: c.declared}).declaration(c.method)
			v.Admission = admissionRead(AdmissionOf(declared, c.method, id.Grants), id.Grants)
		}
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
		var opts []VerifierOption
		if v.Declared != nil {
			declared := map[string]policy.Method{}
			for method, d := range v.Declared {
				m := policy.Method{AnyCheckedCaller: d.AnyCheckedCaller}
				for _, p := range d.Requires {
					m.Requires = append(m.Requires, policy.Of(p[0], p[1]))
				}
				for _, p := range d.Carries {
					m.Carries = append(m.Carries, policy.Of(p[0], p[1]))
				}
				declared[method] = m
			}
			opts = append(opts, Declarations(declared))
		}
		verifier, err := NewVerifier(ctx, source, v.Audience, store, opts...)
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
			if got, want := must(json.Marshal(admissionRead(id.Admitted, id.Grants))), must(json.Marshal(v.Admission)); string(got) != string(want) {
				t.Fatalf("Go hands the handler %s, the contract says %s", got, want)
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

// admissionCases are the vectors of what admitted a call (AdmittedKey): the
// stamp held to the authenticated Work Context, and every reading a handler is
// handed over the declaration of the method the call arrived on.
func admissionCases(admitted func(string, func(*stampCase)) stampCase, refused func(string, string, func(*stampCase)) stampCase,
	set func(string, string) func(*stampCase), holding func([]*basev0.WorkScopeV1, ...*basev0.WorkActorV1) string) []stampCase {
	const method, kind = "/test.Service/Read", "documents.collection"
	scope := func(kind, owner string, ids []string, actions ...string) *basev0.WorkScopeV1 {
		return &basev0.WorkScopeV1{ResourceKind: kind, Actions: actions, ResourceOwnerId: owner, ResourceIds: ids}
	}
	on := func(method string, m policy.Method) map[string]policy.Method {
		return map[string]policy.Method{method: m}
	}
	reads := policy.Method{Requires: []policy.Permission{policy.Of(kind, "read")}}
	content := policy.Method{Requires: []policy.Permission{policy.Of(kind, "read")}, Carries: []policy.Permission{policy.Of(kind, "read_content")}}
	readsAndWrites := policy.Method{Requires: []policy.Permission{policy.Of(kind, "read"), policy.Of(kind, "write")}}
	// Two owners' metadata, one owner's content, and grants no declaration here names.
	twoOwners := holding([]*basev0.WorkScopeV1{
		scope(kind, "installation-b", nil, "read"),
		scope(kind, "installation-a", nil, "read", "read_content"),
		scope(kind, "installation-c", nil, "write"),
		scope("documents.types", "", nil, "read"),
	})
	encoded := func(grants ...Grant) string {
		value, err := EncodeGrants(grants)
		if err != nil {
			panic(err)
		}
		return value
	}
	declaring := func(token string, declared map[string]policy.Method) func(*stampCase) {
		return func(c *stampCase) {
			c.declared = declared
			if token != "" {
				c.token = token
			}
		}
	}
	over := func(request string, token string, declared map[string]policy.Method) func(*stampCase) {
		return func(c *stampCase) {
			declaring(token, declared)(c)
			c.method, c.stampMethod = request, request
		}
	}
	return []stampCase{
		admitted("what admitted the call: the whole kind required, a named resource carried", declaring("", on(method, policy.Method{
			Requires: []policy.Permission{policy.Of(kind, "read")}, Carries: []policy.Permission{policy.Of(kind, "write")}}))),
		admitted("what admitted the call: the owners a list is narrowed to", declaring(twoOwners, on(method, reads))),
		admitted("what admitted the call: content carried on one owner of the two that hold metadata", declaring(twoOwners, on(method, content))),
		admitted("what admitted the call: only what the method requires is held, so nothing is carried",
			declaring(holding([]*basev0.WorkScopeV1{scope(kind, "installation-a", nil, "read")}), on(method, content))),
		admitted("what admitted the call: carried named resources within the required owner",
			declaring(holding([]*basev0.WorkScopeV1{
				scope(kind, "installation-a", nil, "read"),
				scope(kind, "installation-a", []string{"c-2", "c-1", "c-2"}, "read_content"),
				scope(kind, "installation-b", []string{"c-9"}, "read_content"),
				scope(kind, "", []string{"c-1", "c-7"}, "read_content"),
			}), on(method, content))),
		admitted("what admitted the call: the last actor's narrower grant, not the owner's authority",
			declaring(holding([]*basev0.WorkScopeV1{scope(kind, "", nil, "read", "write")},
				&basev0.WorkActorV1{PrincipalId: "wiki", PrincipalKind: "service", DelegationId: "delegation-wiki", PrincipalEpoch: 1, GrantedScopes: []*basev0.WorkScopeV1{scope(kind, "installation-a", nil, "read", "write")}},
				&basev0.WorkActorV1{PrincipalId: "reader", PrincipalKind: "service", DelegationId: "delegation-reader", PrincipalEpoch: 1, GrantedScopes: []*basev0.WorkScopeV1{scope(kind, "installation-a", []string{"c-2", "c-1"}, "read")}},
			), on(method, reads))),
		admitted("what admitted the call: an actor granted nothing holds nothing",
			declaring(holding([]*basev0.WorkScopeV1{scope(kind, "", nil, "read")},
				&basev0.WorkActorV1{PrincipalId: "wiki", PrincipalKind: "service", DelegationId: "delegation-wiki", PrincipalEpoch: 1}), on(method, reads))),
		admitted("what admitted the call: every action holds each permission of the kind",
			declaring(holding([]*basev0.WorkScopeV1{scope(kind, "installation-a", nil, policy.AnyAction), scope(kind, "installation-b", nil, "read")}), on(method, content))),
		admitted("what admitted the call: two required permissions are held together where both reach",
			declaring(holding([]*basev0.WorkScopeV1{
				scope(kind, "installation-a", nil, "read"), scope(kind, "installation-b", []string{"c-1", "c-2"}, "read"), scope(kind, "", []string{"c-5"}, "read"),
				scope("documents.types", "", nil, "read"), scope("documents.types", "installation-b", []string{"c-2", "c-3"}, "read"), scope("documents.types", "installation-c", nil, "read"),
				scope(kind, "installation-b", nil, "write"), scope(kind, "installation-a", []string{"c-4"}, "write"),
			}), on(method, policy.Method{
				Requires: []policy.Permission{policy.Of("documents.types", "read"), policy.Of(kind, "read"), policy.Of(kind, "read")},
				Carries:  []policy.Permission{policy.Of(kind, "write"), policy.Of(kind, "read"), policy.Of("documents.types", "define")}}))),
		// A method that requires two permissions: where each is held, held
		// together, and what a grant that selects no owner lends (nothing, once
		// the reading is cut to owner-selected grants).
		admitted("what admitted the call: two required permissions held on different owners reach nothing",
			declaring(holding([]*basev0.WorkScopeV1{scope(kind, "installation-a", nil, "read"), scope(kind, "installation-b", nil, "write")}), on(method, readsAndWrites))),
		admitted("what admitted the call: one required permission on the whole kind lends an owner nothing owner-selected",
			declaring(holding([]*basev0.WorkScopeV1{scope(kind, "installation-a", nil, "read"), scope(kind, "", nil, "write")}), on(method, readsAndWrites))),
		admitted("what admitted the call: a required permission held on the whole kind and on the owner is owner-selected there",
			declaring(holding([]*basev0.WorkScopeV1{
				scope(kind, "installation-a", nil, "read"), scope(kind, "installation-b", nil, "read"),
				scope(kind, "", nil, "write"), scope(kind, "installation-a", nil, "write"),
			}), on(method, readsAndWrites))),
		admitted("what admitted the call: both required permissions on the whole kind are the whole kind, and nothing owner-selected",
			declaring(holding([]*basev0.WorkScopeV1{scope(kind, "", nil, "read", "write")}), on(method, readsAndWrites))),
		admitted("what admitted the call: one required permission on an owner, the other on resources named within it",
			declaring(holding([]*basev0.WorkScopeV1{
				scope(kind, "installation-a", nil, "read"), scope(kind, "installation-a", []string{"c-1", "c-2"}, "write"), scope(kind, "installation-b", []string{"c-3"}, "write"),
			}), on(method, readsAndWrites))),
		admitted("what admitted the call: resources named with no owner lend an owner nothing owner-selected",
			declaring(holding([]*basev0.WorkScopeV1{
				scope(kind, "installation-a", nil, "read"), scope(kind, "", []string{"c-1"}, "write"), scope(kind, "installation-a", []string{"c-2"}, "write"),
			}), on(method, readsAndWrites))),
		admitted("what admitted the call: one of two required permissions held on nothing reaches nothing",
			declaring(holding([]*basev0.WorkScopeV1{scope(kind, "", nil, "write"), scope(kind, "installation-a", nil, "write"), scope("documents.types", "installation-a", nil, "read")}), on(method, readsAndWrites))),
		admitted("what admitted the call: two kinds required, one on the whole kind and one on an owner",
			declaring(holding([]*basev0.WorkScopeV1{
				scope(kind, "installation-a", nil, "read"), scope(kind, "installation-b", nil, "read"),
				scope("documents.types", "", nil, "read"), scope("documents.types", "installation-b", nil, "read"), scope("documents.types", "installation-c", nil, "read"),
			}), on(method, policy.Method{Requires: []policy.Permission{policy.Of(kind, "read"), policy.Of("documents.types", "read")}}))),
		admitted("what admitted the call: required on the whole kind lends what is carried on an owner nothing owner-selected",
			declaring(holding([]*basev0.WorkScopeV1{scope(kind, "", nil, "read"), scope(kind, "installation-a", nil, "read_content")}), on(method, content))),
		admitted("what admitted the call: carried on the whole kind lends what is required on an owner nothing owner-selected",
			declaring(holding([]*basev0.WorkScopeV1{
				scope(kind, "installation-a", nil, "read"), scope(kind, "installation-b", nil, "read"),
				scope(kind, "", nil, "read_content"), scope(kind, "installation-b", nil, "read_content"),
			}), on(method, content))),
		admitted("what admitted the call: a method that requires nothing selects nothing", declaring(twoOwners, on(method, policy.Method{AnyCheckedCaller: true}))),
		admitted("what admitted the call: a declaration that says two things selects nothing",
			declaring(twoOwners, on(method, policy.Method{AnyCheckedCaller: true, Requires: reads.Requires}))),
		admitted("what admitted the call: a method that only carries declares nothing and reads what it carries",
			declaring(twoOwners, on(method, policy.Method{Carries: content.Carries}))),
		admitted("what admitted the call: a method the module does not declare selects nothing", declaring(twoOwners, on("/test.Service/Write", reads))),
		admitted("what admitted the call: ids are ordered by their bytes and escaped as the hop escapes them",
			declaring(holding([]*basev0.WorkScopeV1{
				scope(kind, "installation-a", []string{"\uff5e", "\U0001F600", "<&>", "\u00e9", "\u2028", "\u2029", "say \"c\\1\"", "\x01", "\x7f", "\b\f\n\r\t", " c", "c"}, "read", "r<e>&d"),
			}), on(method, reads))),
		admitted("what admitted the call: an http request is read on the one route template it is an instance of",
			over("GET /v1/collections/c-9", twoOwners, map[string]policy.Method{
				"GET /v1/collections/{id}": reads, "POST /v1/collections/{id}": content, "GET /v1/collections/{id}/content": content})),
		admitted("what admitted the call: an http request named exactly is read before any template",
			over("GET /v1/collections/c-9", twoOwners, map[string]policy.Method{
				"GET /v1/collections/{id}": reads, "GET /v1/{kind}/c-9": reads, "GET /v1/collections/c-9": content})),
		admitted("what admitted the call: an http request two templates match selects nothing",
			over("GET /v1/collections/c-9", twoOwners, map[string]policy.Method{"GET /v1/collections/{id}": reads, "GET /v1/{kind}/c-9": content})),
		admitted("what admitted the call: a template's final wildcard spans the rest of the path",
			over("GET /v1/files/a/b.txt", twoOwners, map[string]policy.Method{"GET /v1/files/{path=**}": content, "GET /v1/files/{id}": reads})),
		admitted("what admitted the call: a template's final wildcard spans at least one character",
			over("GET /v1/files/f-", twoOwners, map[string]policy.Method{"GET /v1/files/f-{path=**}": content})),
		admitted("what admitted the call: a path ending in a separator is an instance of no template",
			over("GET /v1/collections/c-9/", twoOwners, map[string]policy.Method{"GET /v1/collections/{id}/{part=**}": content, "GET /v1/collections/{id}/": reads})),
		admitted("what admitted the call: a variable inside a segment",
			over("GET /v1/collections/c-9:export", twoOwners, map[string]policy.Method{"GET /v1/collections/{id}:export": content, "GET /v1/collections/{id}:import": reads})),
		admitted("what admitted the call: a path that is not canonical is an instance of no template",
			over("GET /v1/collections/../c-9", twoOwners, map[string]policy.Method{"GET /v1/collections/{id}/{part}": reads})),
		admitted("what admitted the call: a hop that stamps none hands the handler none", func(c *stampCase) {
			declaring(twoOwners, on(method, reads))(c)
			c.edit = func(md metadata.MD) { md.Delete(AdmittedKey) }
		}),
		refused("a stamped admission the token does not bear out", "stamp_identity", set(AdmittedKey, encoded(Grant{Kind: kind, Action: "read"}, Grant{Kind: kind, Action: "write"}))),
		refused("a stamped admission naming an owner the token does not", "stamp_identity", func(c *stampCase) {
			c.token = twoOwners
			c.edit = func(md metadata.MD) {
				md.Set(AdmittedKey, encoded(Grant{Kind: kind, Action: "read", Owner: "installation-c"}))
			}
		}),
		refused("a stamped admission repeated", "stamp_identity", func(c *stampCase) {
			c.edit = func(md metadata.MD) { md.Append(AdmittedKey, md.Get(AdmittedKey)[0]) }
		}),
		refused("an empty admission where the token holds grants", "stamp_identity", set(AdmittedKey, "")),
		refused("a stamped admission that is no encoding", "stamp_identity", set(AdmittedKey, "not an admission")),
		refused("a stamped admission holding the same grants in another encoding", "stamp_identity", func(c *stampCase) {
			c.edit = func(md metadata.MD) {
				raw, err := base64.RawURLEncoding.DecodeString(md.Get(AdmittedKey)[0])
				if err != nil {
					panic(err)
				}
				md.Set(AdmittedKey, base64.RawURLEncoding.EncodeToString([]byte(strings.ReplaceAll(string(raw), ",", ", "))))
			}
		}),
	}
}
