package obintoken_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/obintoken"
	"github.com/codefly-dev/authority/libraries/authority-core/go/obintoken/obintest"
)

const (
	issuerName = "https://token-exchange.test.invalid"
	audience   = "authority-host"
)

var frontDoor = obintest.Actor{Sub: "system:serviceaccount:platform:front-door", Service: "front-door"}
var robin = obintest.Actor{Sub: "system:serviceaccount:platform:robin-data-plane", Service: "robin-service"}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type world struct {
	clock   *clock
	issuer  *obintest.Issuer
	adapter *obintoken.Adapter
}

func mapping() obintoken.Mapping {
	return obintoken.Mapping{
		Tenants:   map[string]string{"org_acme": "acme", "org_globex": "globex", "org_unseated": "initech"},
		Users:     map[string]map[string]string{"acme": {"user_maya": "maya", "user_alex": "alex"}, "globex": {"user_omar": "omar"}},
		Solutions: map[string]map[string]string{"acme": {"wiki": "installation-acme-wiki"}, "globex": {"wiki": "installation-globex-wiki"}},
		Roles:     map[string]map[string]string{"wiki": {"reader": "user", "editor": "admin"}},
		Actors:    map[string]string{frontDoor.Sub: "front-door", robin.Sub: "robin"},
	}
}

func newWorld(t *testing.T) *world {
	t.Helper()
	c := &clock{now: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)}
	issuer := obintest.New(t, issuerName, c.Now)
	issuer.Grants("wiki", "reader", "wiki:pages:read")
	issuer.Grants("wiki", "editor", "wiki:pages:read", "wiki:pages:write")
	issuer.Grants("wiki", "auditor", "wiki:pages:read")
	issuer.SetMember("org_acme", "user_maya", obintest.Member{Status: "active", TenantRole: "member", Solutions: map[string]string{"wiki": "reader"}})
	issuer.SetMember("org_acme", "user_alex", obintest.Member{Status: "active", TenantRole: "admin", Solutions: map[string]string{"wiki": "editor"}})
	issuer.SetMember("org_acme", "user_stranger", obintest.Member{Status: "active", Solutions: map[string]string{"wiki": "reader"}})
	issuer.SetMember("org_acme", "user_auditor", obintest.Member{Status: "active", Solutions: map[string]string{"wiki": "auditor"}})
	issuer.SetMember("org_unknown", "user_maya", obintest.Member{Status: "active", Solutions: map[string]string{"wiki": "reader"}})
	keys, err := obintoken.ParseKeySet(issuer.KeySet())
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := obintoken.New(obintoken.Config{Issuer: issuerName, Audience: audience, Keys: keys, Mapping: mapping(), SignIns: issuer, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	return &world{clock: c, issuer: issuer, adapter: adapter}
}

func (w *world) mint(t *testing.T, tenant, user string, actors ...obintest.Actor) string {
	t.Helper()
	if len(actors) == 0 {
		actors = []obintest.Actor{frontDoor}
	}
	token, err := w.issuer.Mint(tenant, user, audience, "wiki", actors...)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func refusedFor(t *testing.T, err error, reason string) {
	t.Helper()
	var refusal *obintoken.Refusal
	if !errors.As(err, &refusal) || !errors.Is(err, obintoken.ErrRefused) {
		t.Fatalf("want a refusal naming %q, got %v", reason, err)
	}
	if !strings.Contains(refusal.Reason, reason) {
		t.Fatalf("refused for %q, want a reason naming %q", refusal.Reason, reason)
	}
}

func TestATokenOfTheIssuerIsAdmittedAsWhoItNamesHere(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	adm, err := w.adapter.Admit(context.Background(), w.mint(t, "org_acme", "user_maya", robin, frontDoor))
	if err != nil {
		t.Fatal(err)
	}
	if adm.Organization != "acme" || adm.Person != "maya" || adm.Installation != "installation-acme-wiki" || adm.Role != "user" {
		t.Fatalf("admitted as %+v", adm)
	}
	if !slices.Equal(adm.Actors, []string{"robin", "front-door"}) {
		t.Fatalf("actors %v, want the current actor first", adm.Actors)
	}
	if !slices.Equal(adm.Scopes, []string{"wiki:pages:read"}) || adm.RolesVersion == "" || adm.TokenID == "" {
		t.Fatalf("admitted as %+v", adm)
	}
	if got := adm.ExpiresAt.Sub(adm.IssuedAt); got != obintest.Lifetime {
		t.Fatalf("lifetime %v", got)
	}
}

// Every row changes one thing about a token that is otherwise admitted.
func TestWhatCannotBeVerifiedOrMappedIsRefused(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": obintest.KeyID}
	claims := func(change func(map[string]any)) map[string]any {
		c, err := w.issuer.Claims("org_acme", "user_maya", audience, "wiki", frontDoor)
		if err != nil {
			t.Fatal(err)
		}
		change(c)
		return c
	}
	signed := func(change func(map[string]any)) string { return w.issuer.Sign(claims(change)) }
	deep := []obintest.Actor{frontDoor, frontDoor, frontDoor, frontDoor, frontDoor}
	for name, tc := range map[string]struct{ token, reason string }{
		"not a JWT":                          {"not-a-token", "not a signed JWT"},
		"unsigned (alg none)":                {w.issuer.SignWith(map[string]any{"alg": "none", "kid": obintest.KeyID}, claims(func(map[string]any) {}), w.issuer.Key()), "RS256"},
		"a symmetric algorithm":              {w.issuer.SignWith(map[string]any{"alg": "HS256", "kid": obintest.KeyID}, claims(func(map[string]any) {}), w.issuer.Key()), "RS256"},
		"no key id":                          {w.issuer.SignWith(map[string]any{"alg": "RS256"}, claims(func(map[string]any) {}), w.issuer.Key()), "names no key"},
		"a key id the issuer does not hold":  {w.issuer.SignWith(map[string]any{"alg": "RS256", "kid": "another"}, claims(func(map[string]any) {}), w.issuer.Key()), "names no key"},
		"another key under the issuer's id":  {w.issuer.SignWith(header, claims(func(map[string]any) {}), other), "signature does not verify"},
		"a critical header extension":        {w.issuer.SignWith(map[string]any{"alg": "RS256", "kid": obintest.KeyID, "crit": []string{"x"}}, claims(func(map[string]any) {}), w.issuer.Key()), "extension"},
		"claims changed after signing":       {tamper(w.mint(t, "org_acme", "user_maya")), "signature does not verify"},
		"a member given twice":               {obintest.SignRaw([]byte(`{"alg":"RS256","kid":"`+obintest.KeyID+`"}`), []byte(`{"sub":"user_maya","sub":"user_alex"}`), w.issuer.Key()), "given twice"},
		"another issuer":                     {signed(func(c map[string]any) { c["iss"] = "https://elsewhere.test.invalid" }), "another issuer"},
		"another audience":                   {signed(func(c map[string]any) { c["aud"] = "robin-service" }), "another audience"},
		"several audiences":                  {signed(func(c map[string]any) { c["aud"] = []string{audience, "robin-service"} }), "aud is missing or not a string"},
		"no expiry":                          {signed(func(c map[string]any) { delete(c, "exp") }), "exp is missing"},
		"a fractional expiry":                {signed(func(c map[string]any) { c["exp"] = 1.5e9 + 0.5 }), "whole seconds"},
		"expired":                            {signed(func(c map[string]any) { c["iat"], c["exp"] = c["iat"].(int64)-1200, c["iat"].(int64)-600 }), "expired"},
		"minted in the future":               {signed(func(c map[string]any) { c["iat"], c["exp"] = c["iat"].(int64)+120, c["exp"].(int64)+120 }), "future"},
		"a lifetime over the ceiling":        {signed(func(c map[string]any) { c["exp"] = c["iat"].(int64) + 3600 }), "lives longer"},
		"no token id":                        {signed(func(c map[string]any) { delete(c, "jti") }), "jti is missing"},
		"no principal kind":                  {signed(func(c map[string]any) { delete(c, "principal_kind") }), "principal_kind is missing"},
		"an agent's token":                   {signed(func(c map[string]any) { c["principal_kind"] = "agent" }), "only a user's"},
		"an acting agent":                    {signed(func(c map[string]any) { c["acting_agent"] = map[string]any{"address": "hello/greeter"} }), "acting_agent"},
		"a synthetic user":                   {signed(func(c map[string]any) { c["synthetic"] = true }), "synthetic"},
		"a tenant this host does not hold":   {w.mint(t, "org_unknown", "user_maya"), "tenant is no organisation"},
		"no tenant":                          {signed(func(c map[string]any) { delete(c, "tenant_id") }), "tenant_id is missing"},
		"a user this host does not hold":     {w.mint(t, "org_acme", "user_stranger"), "user is no person"},
		"a user of another organisation":     {signed(func(c map[string]any) { c["sub"] = "user_omar"; redigest(c) }), "user is no person"},
		"a solution not installed":           {signed(func(c map[string]any) { c["authorization_solution_id"] = "ledger"; redigest(c) }), "solution is no installation"},
		"no solution":                        {signed(func(c map[string]any) { delete(c, "authorization_solution_id") }), "authorization_solution_id is missing"},
		"a role with no counterpart":         {signed(func(c map[string]any) { c["solution_role"] = "auditor"; redigest(c) }), "role is no role"},
		"no role":                            {signed(func(c map[string]any) { c["solution_role"] = nil }), "solution_role is missing"},
		"a role its evidence does not cover": {signed(func(c map[string]any) { c["solution_role"] = "editor" }), "assignment evidence"},
		"no role evidence":                   {signed(func(c map[string]any) { delete(c, "authorization_assignment_digest") }), "authorization_assignment_digest is missing"},
		"evidence of another version":        {signed(func(c map[string]any) { c["authorization_assignment_digest"] = strings.Repeat("0", 64) }), "assignment evidence"},
		"no scope list":                      {signed(func(c map[string]any) { c["scope"] = "wiki:pages:read" }), "scope is missing"},
		"no actor":                           {signed(func(c map[string]any) { delete(c, "act") }), "actor chain is missing"},
		"an actor that is not an object":     {signed(func(c map[string]any) { c["act"] = frontDoor.Sub }), "actor chain is missing"},
		"an actor this host does not know":   {w.mint(t, "org_acme", "user_maya", obintest.Actor{Sub: "system:serviceaccount:solutions:hello", Service: "hello"}), "does not know"},
		"an unknown actor deeper in":         {w.mint(t, "org_acme", "user_maya", frontDoor, obintest.Actor{Sub: "google:serviceaccount:1", Service: "outside"}), "does not know"},
		"a nested actor that is malformed":   {signed(func(c map[string]any) { c["act"].(map[string]any)["act"] = "front-door" }), "actor chain is missing"},
		"a chain deeper than the limit":      {w.mint(t, "org_acme", "user_maya", deep...), "deeper than"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := w.adapter.Admit(context.Background(), tc.token)
			refusedFor(t, err, tc.reason)
		})
	}
}

// redigest restates the assignment evidence for the claims as changed, as an
// issuer that really minted them would: the row then tests the mapping alone.
func redigest(c map[string]any) {
	c["authorization_assignment_digest"] = obintoken.AssignmentDigest(c["sub"].(string), c["tenant_id"].(string), c["authorization_solution_id"].(string), c["solution_role"].(string))
}

// tamper flips one character of the token's claims.
func tamper(token string) string {
	parts := strings.Split(token, ".")
	body := []byte(parts[1])
	if body[10] == 'A' {
		body[10] = 'B'
	} else {
		body[10] = 'A'
	}
	return parts[0] + "." + string(body) + "." + parts[2]
}

func TestTheRoleVersionIsReadWhereThePlatformReadsIt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("a token minted before the role version moved is refused, and stays refused when it moves back", func(t *testing.T) {
		w := newWorld(t)
		token := w.mint(t, "org_acme", "user_maya")
		first, err := w.adapter.Admit(ctx, token)
		if err != nil {
			t.Fatal(err)
		}
		w.clock.Advance(time.Minute)
		if again, err := w.adapter.Admit(ctx, token); err != nil || again.RolesVersion != first.RolesVersion {
			t.Fatalf("the same token under the same roles: %v", err)
		}
		w.issuer.SetRole("org_acme", "user_maya", "wiki", "editor")
		_, err = w.adapter.Admit(ctx, token)
		refusedFor(t, err, "role version moved")
		var refusal *obintoken.Refusal
		if errors.As(err, &refusal); refusal.TokenID != first.TokenID {
			t.Fatalf("the refusal names token %q, want %q", refusal.TokenID, first.TokenID)
		}
		// Minted in the second the move was seen: refused, it cannot be told
		// from one minted just before.
		_, err = w.adapter.Admit(ctx, w.mint(t, "org_acme", "user_maya"))
		refusedFor(t, err, "role version moved")
		w.clock.Advance(time.Second)
		after, err := w.adapter.Admit(ctx, w.mint(t, "org_acme", "user_maya"))
		if err != nil || after.Role != "admin" || after.RolesVersion == first.RolesVersion {
			t.Fatalf("a token minted under the new roles: %+v, %v", after, err)
		}
		w.issuer.SetRole("org_acme", "user_maya", "wiki", "reader")
		w.clock.Advance(time.Second)
		_, err = w.adapter.Admit(ctx, token)
		refusedFor(t, err, "role version moved")
	})
	t.Run("a move this host sees first on an older token refuses it", func(t *testing.T) {
		w := newWorld(t)
		early := w.mint(t, "org_acme", "user_maya")
		w.clock.Advance(time.Minute)
		if _, err := w.adapter.Admit(ctx, w.mint(t, "org_acme", "user_maya")); err != nil {
			t.Fatal(err)
		}
		w.issuer.SetRole("org_acme", "user_maya", "wiki", "editor")
		w.clock.Advance(time.Minute)
		_, err := w.adapter.Admit(ctx, early)
		refusedFor(t, err, "role version moved")
	})
	t.Run("a token minted before the user's sign-ins were revoked is refused", func(t *testing.T) {
		w := newWorld(t)
		token := w.mint(t, "org_acme", "user_maya")
		w.clock.Advance(time.Second)
		w.issuer.Revoke("org_acme", "user_maya")
		_, err := w.adapter.Admit(ctx, token)
		refusedFor(t, err, "revoked")
		w.clock.Advance(time.Second)
		if _, err := w.adapter.Admit(ctx, w.mint(t, "org_acme", "user_maya")); err != nil {
			t.Fatalf("a token minted after the revocation: %v", err)
		}
	})
	t.Run("a sign-in check that cannot answer admits nobody", func(t *testing.T) {
		w := newWorld(t)
		token := w.mint(t, "org_acme", "user_maya")
		w.issuer.Down(true)
		_, err := w.adapter.Admit(ctx, token)
		refusedFor(t, err, "could not be read")
		// It refuses the call, not the token: it names none to end.
		var refusal *obintoken.Refusal
		if errors.As(err, &refusal); refusal.TokenID != "" {
			t.Fatalf("an unread standing names token %q as refused for good", refusal.TokenID)
		}
		w.issuer.Down(false)
		if _, err := w.adapter.Admit(ctx, token); err != nil {
			t.Fatalf("once the check answers again: %v", err)
		}
	})
	t.Run("a user who is no longer a member is refused", func(t *testing.T) {
		w := newWorld(t)
		token := w.mint(t, "org_acme", "user_maya")
		w.issuer.SetMember("org_other", "user_maya", obintest.Member{Status: "active"})
		// The record in the token's own tenant is the one read.
		if _, err := w.adapter.Admit(ctx, token); err != nil {
			t.Fatal(err)
		}
		forged, err := w.issuer.Claims("org_acme", "user_maya", audience, "wiki", frontDoor)
		if err != nil {
			t.Fatal(err)
		}
		forged["tenant_id"] = "org_unseated"
		forged["authorization_assignment_digest"] = obintoken.AssignmentDigest("user_maya", "org_unseated", "wiki", "reader")
		_, err = w.adapter.Admit(ctx, w.issuer.Sign(forged))
		refusedFor(t, err, "user is no person")
	})
}

func TestAnAdapterIsBuiltOnlyWhenItCanJudgeEverything(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	keys, err := obintoken.ParseKeySet(w.issuer.KeySet())
	if err != nil {
		t.Fatal(err)
	}
	whole := obintoken.Config{Issuer: issuerName, Audience: audience, Keys: keys, Mapping: mapping(), SignIns: w.issuer}
	for name, change := range map[string]func(*obintoken.Config){
		"no issuer":        func(c *obintoken.Config) { c.Issuer = "" },
		"no audience":      func(c *obintoken.Config) { c.Audience = "" },
		"no key":           func(c *obintoken.Config) { c.Keys = nil },
		"no sign-in check": func(c *obintoken.Config) { c.SignIns = nil },
		"a weak key": func(c *obintoken.Config) {
			weak, err := rsa.GenerateKey(rand.Reader, 1024)
			if err != nil {
				t.Fatal(err)
			}
			c.Keys = map[string]*rsa.PublicKey{"weak": &weak.PublicKey}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := whole
			change(&cfg)
			if _, err := obintoken.New(cfg); err == nil {
				t.Fatal("built")
			}
		})
	}
	for name, document := range map[string]string{
		"private material":  `{"keys":[{"kty":"RSA","kid":"a","n":"AQAB","e":"AQAB","d":"AQAB"}]}`,
		"a symmetric key":   `{"keys":[{"kty":"oct","kid":"a","k":"AQAB"}]}`,
		"no key id":         `{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB"}]}`,
		"an elliptic key":   `{"keys":[{"kty":"EC","kid":"a","crv":"P-256","x":"AQAB","y":"AQAB"}]}`,
		"a short modulus":   `{"keys":[{"kty":"RSA","kid":"a","n":"AQAB","e":"AQAB"}]}`,
		"no keys":           `{"keys":[]}`,
		"a member twice":    `{"keys":[],"keys":[]}`,
		"a key id twice":    strings.Replace(string(w.issuer.KeySet()), `]}`, `,`+strings.TrimSuffix(strings.TrimPrefix(string(w.issuer.KeySet()), `{"keys":[`), `]}`)+`]}`, 1),
		"an encryption key": strings.Replace(string(w.issuer.KeySet()), `"use":"sig"`, `"use":"enc"`, 1),
	} {
		t.Run("key set: "+name, func(t *testing.T) {
			if _, err := obintoken.ParseKeySet([]byte(document)); err == nil {
				t.Fatal("read")
			}
		})
	}
}

// The digest is token-exchange's, byte for byte: these are the values
// signing.authorization_assignment_digest answers for the same assignments.
func TestTheAssignmentDigestIsThePlatforms(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ subject, tenant, solution, role, want string }{
		{"user_maya", "org_acme", "wiki", "reader", "c329a3029749c62233006338352139809caca9160db5964e417cf50a8e1011fe"},
		{"mäya \"q\"\\\n ", "org_acme", "wiki", "reader", "be706e7c1e73c92f3b39eb377cfd4a953271908e2935809e689dcba57df43a29"},
	} {
		if got := obintoken.AssignmentDigest(tc.subject, tc.tenant, tc.solution, tc.role); got != tc.want {
			t.Errorf("digest of %q: %s, want %s", tc.subject, got, tc.want)
		}
	}
}
