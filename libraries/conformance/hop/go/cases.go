package hopconformance

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc/metadata"
)

// keys: the proof signature is judged under the authority's published
// admission keys and under no other key, each key for its own purpose.
func (s suite) keys(t *testing.T) {
	ctx := context.Background()
	t.Run("a genuine stamp under the published admission key admits, and who the call is for is the token's", func(t *testing.T) {
		a := authority(t)
		token := a.Issue(t, Audience, read)
		id := admitted(t)(s.verifier(t, a, Audience, newReservations()).Verify(ctx, forward(t, token, Hop, Method), Method))
		decoded, _ := core.Decode(token)
		if id.Owner != core.FixturePrincipal || id.OwnerKind != "human" || id.Tenant != core.FixtureTenant || id.Task != core.FixtureTask || id.Expires != decoded.Context().GetExpiresAtUnix() {
			t.Fatalf("identity: %+v", id)
		}
		if !id.Has("documents", "read") || id.Has("documents", "write") || len(id.Actors) != 0 || id.Binding != "" || id.Advisory != "" {
			t.Fatalf("identity: %+v", id)
		}
		if id.Context != token || id.Claims == nil || !id.Claims.Allows("documents", "read", "any") || id.Claims.Allows("documents", "write", "any") {
			t.Fatalf("the authenticated claims are not the token's: %+v", id)
		}
	})
	t.Run("a stamp signed by a key the authority does not publish is refused by name, after at most one read however many arrive", func(t *testing.T) {
		a := authority(t)
		source := &counting{KeySource: a}
		v := s.verifier(t, source, Audience, newReservations())
		reads := source.reads.Load()
		for range 20 {
			_, err := v.Verify(ctx, forward(t, a.Issue(t, Audience, read), "an-unpublished-hop", Method), Method)
			refused(t, err, refusal.StampProof)
		}
		// A read the verifier started would have begun by now. A stamp under a
		// key the verifier does not hold may re-read the published keys once,
		// bounded by the implementation's interval; a caller presenting unknown
		// keys must not drive one read per call.
		time.Sleep(50 * time.Millisecond)
		if got := source.reads.Load(); got-reads > 1 {
			t.Fatalf("twenty stamps under an unpublished key caused %d key reads", got-reads)
		}
	})
	t.Run("a hop that registers after the verifier read Keys is admitted on its first stamp", func(t *testing.T) {
		// A restarted gateway registers a fresh admission key and signs with
		// it at once: the module must not refuse it until its keys age out.
		a := authority(t)
		v := s.verifier(t, a, Audience, newReservations())
		admitted(t)(v.Verify(ctx, forward(t, a.Issue(t, Audience, read), Hop, Method), Method))
		a.PublishHop("restarted")
		admitted(t)(v.Verify(ctx, forward(t, a.Issue(t, Audience, read), "restarted", Method), Method))
	})
	t.Run("a rotation's overlap admits both keys, and a verifier reading Keys after the retiring key is withdrawn refuses it", func(t *testing.T) {
		a := hoptest.New(t).PublishHop("retiring", "current")
		store := newReservations()
		during := s.verifier(t, a, Audience, store)
		for _, label := range []string{"retiring", "current"} {
			admitted(t)(during.Verify(ctx, forward(t, a.Issue(t, Audience, read), label, Method), Method))
		}
		a.WithdrawHop("retiring")
		// A verifier that read Keys before the withdrawal keeps admitting the
		// retiring key until its next read, within the key age its
		// implementation states; the contract's line is the read after.
		after := s.verifier(t, a, Audience, store)
		_, err := after.Verify(ctx, forward(t, a.Issue(t, Audience, read), "retiring", Method), Method)
		refused(t, err, refusal.StampProof)
		admitted(t)(after.Verify(ctx, forward(t, a.Issue(t, Audience, read), "current", Method), Method))
	})
	t.Run("a key is used for its own purpose only", func(t *testing.T) {
		a := authority(t)
		// An admission key published among the Work Context keys admits
		// nothing.
		misplaced := editing{KeySource: a, edit: func(r *authorityv1.KeysResponse) { r.Keys = append(r.Keys, hoptest.Published("misplaced")) }}
		v := s.verifier(t, misplaced, Audience, newReservations())
		_, err := v.Verify(ctx, forward(t, a.Issue(t, Audience, read), "misplaced", Method), Method)
		refused(t, err, refusal.StampProof)
		// The hop's admission key never authenticates a Work Context, even
		// under the key id it is published with.
		forger := &core.Authority{Issuer: hoptest.Issuer, KeyID: hoptest.Published(Hop).GetKeyId(), Key: hoptest.AdmissionKey(Hop), Revisions: core.FixtureRevisions(), Seals: core.FixtureSeals()}
		forged, _, err := forger.Start(ctx, core.StartInput{
			TenantID: core.FixtureTenant, OwnerPrincipalID: core.FixturePrincipal, OwnerPrincipalKind: "human",
			OrganizationID: core.FixtureOrganization, TaskID: core.FixtureTask, Audience: Audience,
			ReplayPolicy: core.ReplayIdempotent, AuthorityScopes: []*basev0.WorkScopeV1{read}, InstallationID: core.FixtureInstallation, TTL: 10 * time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = v.Verify(ctx, forward(t, forged, Hop, Method), Method)
		refused(t, err, refusal.UnknownKey, forged)
	})
	t.Run("an authority that publishes no admission key admits nothing", func(t *testing.T) {
		a := hoptest.New(t) // publishes no hop
		v := s.verifier(t, a, Audience, newReservations())
		_, err := v.Verify(ctx, forward(t, a.Issue(t, Audience, read), Hop, Method), Method)
		refused(t, err, refusal.KeysUnavailable)
	})
	t.Run("a verifier that cannot read the authority's keys refuses rather than admits, naming no address", func(t *testing.T) {
		a := authority(t)
		v := s.verifier(t, unreachable{}, Audience, newReservations())
		token := a.Issue(t, Audience, read)
		_, err := v.Verify(ctx, forward(t, token, Hop, Method), Method)
		refused(t, err, refusal.KeysUnavailable, unreachableAddress, token)
	})
}

// binding: the stamp authenticates the method, the audience and the one Work
// Context the authority checked, and an advisory refusal never admits.
func (s suite) binding(t *testing.T) {
	ctx := context.Background()
	t.Run("a stamp for another procedure is refused, and the refusal does not consume the admission", func(t *testing.T) {
		a := authority(t)
		v := s.verifier(t, a, Audience, newReservations())
		md := forward(t, a.IssueSingleUse(t, Audience, read), Hop, Method)
		for _, other := range []string{"/documents.v1.Service/Delete", "/datasets.v1.Service/Register", "Get", "", "POST " + Method} {
			_, err := v.Verify(ctx, md, other)
			refused(t, err, refusal.StampMethod)
		}
		admitted(t)(v.Verify(ctx, md, Method))
	})
	t.Run("a stamp for another module is refused", func(t *testing.T) {
		a := authority(t)
		store := newReservations()
		documents := s.verifier(t, a, Audience, store)
		records := s.verifier(t, a, "records", store)
		md := forward(t, a.Issue(t, Audience, read), Hop, Method)
		_, err := records.Verify(ctx, md, Method)
		refused(t, err, refusal.StampAudience)
		// A call the hop admitted for another module, token and stamp alike.
		_, err = documents.Verify(ctx, forward(t, a.Issue(t, "records", read), Hop, Method), Method)
		refused(t, err, refusal.StampAudience)
		admitted(t)(documents.Verify(ctx, md, Method))
	})
	t.Run("the stamp binds the one Work Context the authority checked", func(t *testing.T) {
		a := authority(t)
		v := s.verifier(t, a, Audience, newReservations())
		genuine := a.Issue(t, Audience, read)
		payload, _, _ := strings.Cut(genuine, ".")
		raw, _ := base64.RawURLEncoding.DecodeString(payload)
		_, other, _ := ed25519.GenerateKey(nil)
		forged := payload + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(other, raw))
		unsigned := payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		// under writes token under the stamp the hop wrote for genuine, with
		// the context digest rewritten, as any holder of the stamp can.
		under := func(token string) metadata.MD {
			md := forward(t, genuine, Hop, Method)
			md.Set(hop.WorkContextKey, token)
			md.Set(hop.ContextKey, digest(token))
			return md
		}
		edit := func(change func(md metadata.MD)) metadata.MD {
			md := forward(t, genuine, Hop, Method)
			change(md)
			return md
		}
		for name, c := range map[string]struct {
			md   metadata.MD
			want refusal.Reason
		}{
			"a swapped token keeps the digest of the one checked": {edit(func(md metadata.MD) { md.Set(hop.WorkContextKey, a.Issue(t, Audience, read)) }), refusal.StampDigest},
			"a forged signature under a rewritten digest":         {under(forged), refusal.StampDigest},
			"an unsigned token under a rewritten digest":          {under(unsigned), refusal.StampDigest},
			"a context digest that disagrees with the proof":      {edit(func(md metadata.MD) { md.Set(hop.ContextKey, strings.Repeat("0", 64)) }), refusal.StampDigest},
			"no stamp":          {metadata.Pairs(hop.WorkContextKey, genuine), refusal.StampProof},
			"another run's hop": {forward(t, genuine, "another-run", Method), refusal.StampProof},
			"no token":          {edit(func(md metadata.MD) { md.Delete(hop.WorkContextKey) }), refusal.StampToken},
			"two tokens":        {edit(func(md metadata.MD) { md.Append(hop.WorkContextKey, genuine) }), refusal.StampToken},
		} {
			t.Run(name, func(t *testing.T) {
				_, err := v.Verify(ctx, c.md, Method)
				refused(t, err, c.want, genuine, forged)
			})
		}
	})
	t.Run("an advisory refusal never admits", func(t *testing.T) {
		a := authority(t)
		v := s.verifier(t, a, Audience, newReservations())
		md := forward(t, a.Issue(t, Audience, read), Hop, Method)
		md.Set(hop.AdvisoryKey, "write scope missing")
		_, err := v.Verify(ctx, md, Method)
		refused(t, err, refusal.StampAdvisory)
	})
}

// window: the lifetime and the clock allowance bound issue and expiry only,
// and the signed span is capped at the lifetime whatever the allowance.
func (s suite) window(t *testing.T) {
	ctx := context.Background()
	lifetime, skew := int64(stamp.Lifetime/time.Second), int64(stamp.Skew/time.Second)
	at := func(t *testing.T, a *hoptest.Authority, issued, expires int64) metadata.MD {
		return stampedAt(t, a.Issue(t, Audience, read), Hop, Method, Audience, issued, expires)
	}
	t.Run("an admission issued further ahead than the allowance is refused as issued, not as expired", func(t *testing.T) {
		a := authority(t)
		issued := time.Now().Unix() + skew + 60
		_, err := s.verifier(t, a, Audience, newReservations()).Verify(ctx, at(t, a, issued, issued+lifetime), Method)
		refused(t, err, refusal.StampIssued)
	})
	t.Run("an admission past its expiry and the allowance is refused", func(t *testing.T) {
		a := authority(t)
		expires := time.Now().Unix() - skew - 60
		_, err := s.verifier(t, a, Audience, newReservations()).Verify(ctx, at(t, a, expires-10, expires), Method)
		refused(t, err, refusal.StampWindow)
	})
	t.Run("the signed span is capped at the lifetime, inside the window or not", func(t *testing.T) {
		a := authority(t)
		v := s.verifier(t, a, Audience, newReservations())
		now := time.Now().Unix()
		for name, span := range map[string][2]int64{
			"a span of the lifetime and a second":               {now, now + lifetime + 1},
			"the same span with both ends inside the window":    {now - 10, now + lifetime - 9},
			"an admission expiring at the instant it is issued": {now, now},
		} {
			_, err := v.Verify(ctx, at(t, a, span[0], span[1]), Method)
			if err == nil {
				t.Fatalf("%s was admitted", name)
			}
			refused(t, err, refusal.StampWindow)
		}
	})
	t.Run("an admission issued the allowance ahead, or spanning exactly the lifetime, admits", func(t *testing.T) {
		a := authority(t)
		v := s.verifier(t, a, Audience, newReservations())
		now := time.Now().Unix()
		admitted(t)(v.Verify(ctx, at(t, a, now+skew, now+skew+lifetime), Method))
		admitted(t)(v.Verify(ctx, at(t, a, now, now+lifetime), Method))
	})
	t.Run("an admission is admissible for the allowance past its expiry, and refused at its end", func(t *testing.T) {
		a := authority(t)
		// The allowance is judged on the verifier's clock, so the case names
		// it: the last admissible instant is the second before the allowance
		// is spent (Expires+Skew <= now refuses), and that second refuses on
		// the window, not as a token the authority never signed. Both verdicts
		// are on one admission, read by two verifiers of one implementation.
		expires := time.Now().Unix()
		md := at(t, a, expires-10, expires)
		inside := func() time.Time { return time.Unix(expires+skew-1, 0) }
		spent := func() time.Time { return time.Unix(expires+skew, 0) }
		admitted(t)(s.verifierAt(t, a, Audience, newReservations(), inside).Verify(ctx, md, Method))
		_, err := s.verifierAt(t, a, Audience, newReservations(), spent).Verify(ctx, md, Method)
		refused(t, err, refusal.StampWindow)
	})
	t.Run("a fresh stamp does not revive an expired Work Context", func(t *testing.T) {
		a := authority(t)
		a.Now = func() time.Time { return time.Now().Add(-time.Hour) }
		expired := a.Issue(t, Audience, read)
		a.Now = nil
		now := time.Now().Unix()
		_, err := s.verifier(t, a, Audience, newReservations()).Verify(ctx, stampedAt(t, expired, Hop, Method, Audience, now, now+lifetime), Method)
		refused(t, err, refusal.Expired, expired)
	})
}

// replay: a single-use admission is reserved before the keys are read, held
// while its handler runs, refused across every verifier sharing the store, and
// a store that cannot answer admits nothing.
func (s suite) replay(t *testing.T) {
	ctx := context.Background()
	t.Run("a single-use admission is held while its handler runs and refused across verifiers sharing the store", func(t *testing.T) {
		a := authority(t)
		store := newReservations()
		first, second := s.verifier(t, a, Audience, store), s.verifier(t, a, Audience, store)
		md := forward(t, a.IssueSingleUse(t, Audience, read), Hop, Method)
		nonce := replayKey(t, md, Hop)
		call, err := stamp.Check(md, hoptest.PublicKey(Hop), Method, Audience, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		id, done, err := first.Admit(ctx, md, Method)
		if err != nil || id.Owner != core.FixturePrincipal {
			t.Fatalf("admit: %+v %v", id, err)
		}
		if !store.running(nonce) {
			t.Fatal("the admitted call holds no reservation while it runs")
		}
		for _, replica := range []Verifier{second, first} {
			_, err := replica.Verify(ctx, md, Method)
			refused(t, err, refusal.StampReplayed)
		}
		done()
		if store.running(nonce) {
			t.Fatal("the hold outlived the handler")
		}
		// Retained to the admission's expiry plus the allowance at least, so
		// a store evicting on its own clock never releases a nonce a lagging
		// verifier would still admit.
		if until, held := store.retention(nonce); !held || !until.Equal(time.Unix(call.Expires+int64(stamp.Skew/time.Second), 0)) {
			t.Fatalf("retained until %v, want the expiry plus the allowance", until)
		}
		_, err = second.Verify(ctx, md, Method)
		refused(t, err, refusal.StampReplayed)
	})
	t.Run("concurrent deliveries of one admission have one winner across verifiers", func(t *testing.T) {
		a := authority(t)
		store := newReservations()
		replicas := []Verifier{s.verifier(t, a, Audience, store), s.verifier(t, a, Audience, store)}
		md := forward(t, a.IssueSingleUse(t, Audience, read), Hop, Method)
		var accepted, replayed atomic.Int64
		var wg sync.WaitGroup
		for n := range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := replicas[n%2].Verify(ctx, md, Method)
				var reason refusal.Reason
				switch {
				case err == nil:
					accepted.Add(1)
				case errors.As(err, &reason) && reason == refusal.StampReplayed:
					replayed.Add(1)
				}
			}()
		}
		wg.Wait()
		if accepted.Load() != 1 || replayed.Load() != 31 {
			t.Fatalf("accepted %d times, refused as replayed %d times", accepted.Load(), replayed.Load())
		}
	})
	t.Run("a call refused after its reservation keeps the nonce and ends its hold, and an invalid stamp reserves nothing", func(t *testing.T) {
		a := authority(t)
		store := newReservations()
		v := s.verifier(t, a, Audience, store)
		genuine := a.Issue(t, Audience, read)
		payload, _, _ := strings.Cut(genuine, ".")
		forged := payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		now := time.Now().Unix()
		// A stamp the hop's key signed over a token the authority did not:
		// the admission reserves, the Work Context is refused, the hold ends.
		md := stampedAt(t, forged, Hop, Method, Audience, now, now+int64(stamp.Lifetime/time.Second))
		nonce := replayKey(t, md, Hop)
		_, err := v.Verify(ctx, md, Method)
		refused(t, err, refusal.Signature, forged)
		if _, held := store.retention(nonce); !held || store.running(nonce) {
			t.Fatal("a refused call did not keep its nonce, or kept its hold")
		}
		_, err = v.Verify(ctx, md, Method)
		refused(t, err, refusal.StampReplayed)
		// Nothing that fails the stamp reaches the store.
		before := store.count()
		_, err = v.Verify(ctx, forward(t, genuine, "an-unpublished-hop", Method), Method)
		refused(t, err, refusal.StampProof)
		_, err = v.Verify(ctx, forward(t, genuine, Hop, Method), "/documents.v1.Service/Delete")
		refused(t, err, refusal.StampMethod)
		if store.count() != before {
			t.Fatal("an invalid stamp reserved a nonce")
		}
	})
	t.Run("a store that cannot answer refuses admission, naming no backend failure", func(t *testing.T) {
		a := authority(t)
		store := newReservations()
		v := s.verifier(t, a, Audience, store)
		store.unavailable(errors.New("pq: connection reset by 10.0.0.7"))
		_, err := v.Verify(ctx, forward(t, a.Issue(t, Audience, read), Hop, Method), Method)
		refused(t, err, refusal.StampStore, "10.0.0.7")
	})
	t.Run("a reservation the store judges past its retention is refused on the window", func(t *testing.T) {
		a := authority(t)
		store := newReservations()
		v := s.verifier(t, a, Audience, store)
		// The store's clock runs ahead of the verifier's by more than the
		// admission lasts: by its clock the retention has passed.
		store.now = func() time.Time { return time.Now().Add(stamp.Lifetime + stamp.Skew + time.Minute) }
		_, err := v.Verify(ctx, forward(t, a.Issue(t, Audience, read), Hop, Method), Method)
		refused(t, err, refusal.StampWindow)
	})
}

// identity: who the call is for is read from the authenticated token, never
// from a stamp header alone.
func (s suite) identity(t *testing.T) {
	ctx := context.Background()
	t.Run("a stamp header the token does not bear out is refused", func(t *testing.T) {
		a := authority(t)
		v := s.verifier(t, a, Audience, newReservations())
		token := a.Issue(t, Audience, read)
		for name, change := range map[string]func(md metadata.MD){
			"the tenant":  func(md metadata.MD) { md.Set(hop.TenantKey, "globex") },
			"the owner":   func(md metadata.MD) { md.Set(hop.OwnerKey, "remi") },
			"the scopes":  func(md metadata.MD) { md.Set(hop.ScopesKey, "documents:read,documents:admin") },
			"the actors":  func(md metadata.MD) { md.Set(hop.ActorsKey, "robin") },
			"the binding": func(md metadata.MD) { md.Set(hop.BindingKey, "binding-elsewhere") },
			"the task":    func(md metadata.MD) { md.Set(hop.TaskKey, "task-elsewhere") },
			"the expiry":  func(md metadata.MD) { md.Set(hop.ExpiresKey, "4102444800") },
			"a repeated header": func(md metadata.MD) {
				md.Append(hop.TenantKey, core.FixtureTenant)
			},
		} {
			t.Run(name, func(t *testing.T) {
				md := forward(t, token, Hop, Method)
				change(md)
				_, err := v.Verify(ctx, md, Method)
				refused(t, err, refusal.StampIdentity, "globex", "remi", "robin")
			})
		}
	})
	t.Run("an owner-selected scope never reads as the whole kind", func(t *testing.T) {
		a := authority(t)
		owned := &basev0.WorkScopeV1{ResourceKind: "documents", Actions: []string{"read"}, ResourceOwnerId: "principal-u"}
		id := admitted(t)(s.verifier(t, a, Audience, newReservations()).Verify(ctx, forward(t, a.Issue(t, Audience, owned), Hop, Method), Method))
		if id.Has("documents", "read") || slices.Contains(id.Scopes, "documents:read") {
			t.Fatalf("an owner-selected scope was stamped as the whole kind: %v", id.Scopes)
		}
		if id.Claims.Allows("documents", "read", "") || id.Claims.Allows("documents", "read", "any") {
			t.Fatal("the claims admit an owner-selected scope without the resource's owner")
		}
		if !id.Claims.AllowsOwned("documents", "read", "any", "principal-u") || id.Claims.AllowsOwned("documents", "read", "any", "principal-v") {
			t.Fatal("the claims must admit the owner's resource and refuse another owner's")
		}
	})
	t.Run("a resource-limited scope is read from the claims, never widened to its kind", func(t *testing.T) {
		a := authority(t)
		limited := &basev0.WorkScopeV1{ResourceKind: "documents", Actions: []string{"write"}, ResourceIds: []string{"d-1"}}
		id := admitted(t)(s.verifier(t, a, Audience, newReservations()).Verify(ctx, forward(t, a.Issue(t, Audience, read, limited), Hop, Method), Method))
		if !id.Has("documents", "read") || id.Has("documents", "write") {
			t.Fatalf("scopes: %v", id.Scopes)
		}
		if !id.Claims.Allows("documents", "write", "d-1") || id.Claims.Allows("documents", "write", "d-2") || id.Claims.Allows("documents", "write", "") {
			t.Fatal("the claims do not answer the resource-exact question")
		}
	})
}

// hop: what the one hop writes. A hop in another language is proved by the
// stamps it writes being admitted by a verifier that passed this suite, and
// by never writing what these cases refuse.
func (s suite) hop(t *testing.T) {
	ctx := context.Background()
	t.Run("the hop strips every stamp a caller sent before writing its own", func(t *testing.T) {
		a := authority(t)
		token := a.Issue(t, Audience, read)
		decoded, _ := core.Decode(token)
		md := metadata.Pairs(hop.WorkContextKey, token, hop.OwnerKey, "remi", "X-Codefly-Hop-Proof", "a caller's proof", hop.AdvisoryKey, "a caller's advisory")
		if err := hop.Stamp(md, hop.IdentityOf(decoded.Context()), hoptest.Signer(Hop), Method, Audience, time.Now()); err != nil {
			t.Fatal(err)
		}
		if got := md.Get(hop.OwnerKey); len(got) != 1 || got[0] != core.FixturePrincipal {
			t.Fatalf("the caller's owner survived: %v", got)
		}
		if got := md.Get(hop.ProofKey); len(got) != 1 || got[0] == "a caller's proof" {
			t.Fatalf("the caller's proof survived: %v", got)
		}
		if len(md.Get(hop.AdvisoryKey)) != 0 {
			t.Fatal("the caller's advisory survived")
		}
		id := admitted(t)(s.verifier(t, a, Audience, newReservations()).Verify(ctx, md, Method))
		if id.Owner != core.FixturePrincipal {
			t.Fatalf("admitted as %q", id.Owner)
		}
	})
	t.Run("the hop never signs an advisory refusal", func(t *testing.T) {
		a := authority(t)
		md := metadata.Pairs(hop.WorkContextKey, a.Issue(t, Audience, read))
		if err := hop.Stamp(md, hop.Identity{Advisory: "write scope missing"}, hoptest.Signer(Hop), Method, Audience, time.Now()); err == nil {
			t.Fatal("signed an advisory refusal")
		}
		if len(md.Get(hop.ProofKey)) != 0 {
			t.Fatal("the refusal left a usable proof")
		}
	})
	t.Run("the hop signs the exact procedure, the audience and the token's digest, within the lifetime", func(t *testing.T) {
		a := authority(t)
		token := a.Issue(t, Audience, read)
		md := forward(t, token, Hop, Method)
		encoded, _, ok := strings.Cut(md.Get(hop.ProofKey)[0], ".")
		if !ok {
			t.Fatal("the proof is not a payload and a signature")
		}
		payload, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		var fields []any
		if err := json.Unmarshal(payload, &fields); err != nil || len(fields) != 7 {
			t.Fatalf("the signed payload is not the seven fields: %v %v", fields, err)
		}
		nonce, _ := fields[4].(string)
		raw, err := hex.DecodeString(nonce)
		if fields[0] != "codefly-hop-v1" || fields[1] != Method || fields[2] != Audience || fields[3] != digest(token) || err != nil || len(raw) != 32 {
			t.Fatalf("the signed payload: %v", fields)
		}
		issued, expires := fields[5].(float64), fields[6].(float64)
		if expires <= issued || expires-issued > float64(stamp.Lifetime/time.Second) {
			t.Fatalf("the signed span: %v to %v", issued, expires)
		}
		if got := md.Get(hop.ContextKey); len(got) != 1 || got[0] != digest(token) {
			t.Fatalf("the context header is not the token's digest: %v", got)
		}
	})
	t.Run("the hop caps an admission at the Work Context's expiry and stamps no expired one", func(t *testing.T) {
		a := authority(t)
		// A token with ten seconds left of its ten minutes.
		a.Now = func() time.Time { return time.Now().Add(-10*time.Minute + 10*time.Second) }
		token := a.Issue(t, Audience, read)
		a.Now = func() time.Time { return time.Now().Add(-time.Hour) }
		expired := a.Issue(t, Audience, read)
		a.Now = nil
		md := forward(t, token, Hop, Method)
		call, err := stamp.Check(md, hoptest.PublicKey(Hop), Method, Audience, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		decoded, _ := core.Decode(token)
		if call.Expires != decoded.Context().GetExpiresAtUnix() {
			t.Fatalf("the admission expires at %d, the token at %d", call.Expires, decoded.Context().GetExpiresAtUnix())
		}
		admitted(t)(s.verifier(t, a, Audience, newReservations()).Verify(ctx, md, Method))
		expiredMD := metadata.Pairs(hop.WorkContextKey, expired)
		d, _ := core.Decode(expired)
		if err := hop.Stamp(expiredMD, hop.IdentityOf(d.Context()), hoptest.Signer(Hop), Method, Audience, time.Now()); err == nil {
			t.Fatal("the hop stamped an expired Work Context")
		}
	})
}

// startup: what a verifier needs, and what it refuses to start on.
func (s suite) startup(t *testing.T) {
	ctx := context.Background()
	t.Run("a verifier needs the authority's keys, an audience and a replay store", func(t *testing.T) {
		a := authority(t)
		for name, build := range map[string]func() (Verifier, error){
			"no keys":         func() (Verifier, error) { return s.target.New(ctx, nil, Audience, newReservations(), nil) },
			"no audience":     func() (Verifier, error) { return s.target.New(ctx, a, "", newReservations(), nil) },
			"no replay store": func() (Verifier, error) { return s.target.New(ctx, a, Audience, nil, nil) },
		} {
			if _, err := build(); err == nil {
				t.Fatalf("%s: a verifier was built", name)
			}
		}
	})
	t.Run("outside a local run a replay store that does not declare itself shared is refused, and one that does is admitted", func(t *testing.T) {
		a := authority(t)
		for _, environment := range []string{"", "staging", "production", "local-docker", " local"} {
			t.Setenv(resources.EnvironmentPrefix, environment)
			if _, err := s.target.New(ctx, a, Audience, hoptest.Replay(), nil); err == nil {
				t.Fatalf("environment %q admitted a process-local store", environment)
			}
			if _, err := s.target.New(ctx, a, Audience, newReservations(), nil); err != nil {
				t.Fatalf("environment %q refused a shared store: %v", environment, err)
			}
		}
		t.Setenv(resources.EnvironmentPrefix, "local")
		if _, err := s.target.New(ctx, a, Audience, hoptest.Replay(), nil); err != nil {
			t.Fatalf("a local run refused a process-local store: %v", err)
		}
	})
	t.Run("every refusal carries a stable code with fixed text", func(t *testing.T) {
		seen := map[string]string{}
		for _, reason := range []refusal.Reason{refusal.StampProof, refusal.StampToken, refusal.StampDigest, refusal.StampIdentity, refusal.StampMethod, refusal.StampAudience,
			refusal.StampWindow, refusal.StampIssued, refusal.StampAdvisory, refusal.StampReplayed, refusal.StampStore, refusal.KeysUnavailable, refusal.Configuration} {
			if reason.Code() == "" || reason.Text() == "" || seen[reason.Code()] != "" {
				t.Fatalf("reason %q: code %q text %q", reason, reason.Code(), reason.Text())
			}
			for code, text := range seen {
				if text == reason.Text() {
					t.Fatalf("%s and %s share one text", code, reason.Code())
				}
			}
			seen[reason.Code()] = reason.Text()
		}
	})
}
