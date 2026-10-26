package workcontext_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"google.golang.org/grpc/metadata"
	"os"
	"strings"
	"testing"
	"time"

	reader "github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/protobuf/proto"
)

type fixture struct {
	Name, Token, Audience string
	Scopes                []*basev0.WorkScopeV1
	Probes                []struct {
		Kind, Action string
		ResourceID   string `json:"resource_id"`
		Allowed      bool
	}
}

func fixtures(t *testing.T) []fixture {
	t.Helper()
	data, err := os.ReadFile("../../testdata/claims.json")
	if err != nil {
		t.Fatal(err)
	}
	var out []fixture
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func body(t *testing.T, name string) *basev0.WorkContextV1 {
	t.Helper()
	for _, f := range fixtures(t) {
		if f.Name == name {
			d, err := core.Decode(f.Token)
			if err != nil {
				t.Fatal(err)
			}
			return d.Context()
		}
	}
	t.Fatal("fixture missing")
	return nil
}

// The test authority: a key of the test's own, never Core's public fixture key.
var signer = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

func trustFor(c *basev0.WorkContextV1) reader.Trust {
	at := time.Unix(c.GetNotBeforeUnix(), 0).Add(time.Second)
	return reader.Trust{Issuer: c.GetIssuer(), Keys: map[string]ed25519.PublicKey{c.GetKeyId(): signer.Public().(ed25519.PublicKey)}, Now: func() time.Time { return at }}
}

func signWith(t *testing.T, key ed25519.PrivateKey, c *basev0.WorkContextV1) string {
	t.Helper()
	b, err := (proto.MarshalOptions{Deterministic: true}).Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, b))
}

func tokenFor(t *testing.T, c *basev0.WorkContextV1) string { return signWith(t, signer, c) }

func read(t *testing.T, c *basev0.WorkContextV1) *reader.Claims {
	t.Helper()
	out, err := reader.Authenticate(stampedToken(tokenFor(t, c)), "test-proof", c.GetAudience(), trustFor(c))
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestCoreFixtures(t *testing.T) {
	for _, f := range fixtures(t) {
		t.Run(f.Name, func(t *testing.T) {
			c := read(t, body(t, f.Name))
			if c.Audience() != f.Audience {
				t.Fatal("audience differs")
			}
			scopes := c.Scopes()
			if len(scopes) != len(f.Scopes) {
				t.Fatal("effective scope count differs")
			}
			for n, scope := range scopes {
				if !proto.Equal(scope, f.Scopes[n]) {
					t.Fatalf("scope %d differs", n)
				}
			}
			for _, p := range f.Probes {
				if c.Allows(p.Kind, p.Action, p.ResourceID) != p.Allowed {
					t.Fatalf("probe %s %s %s", p.Kind, p.Action, p.ResourceID)
				}
			}
		})
	}
}
func TestSeparateGrantsAndWholeKind(t *testing.T) {
	c := body(t, "session")
	c.AuthorityScopes = []*basev0.WorkScopeV1{
		{ResourceKind: "record", Actions: []string{"read"}, ResourceIds: []string{"a"}},
		{ResourceKind: "record", Actions: []string{"invoke"}, ResourceIds: []string{"b"}},
	}
	claims := read(t, c)
	for _, q := range []struct {
		action, id string
		allowed    bool
	}{{"read", "a", true}, {"invoke", "b", true}, {"invoke", "a", false}, {"read", "b", false}, {"read", "", false}} {
		if claims.Allows("record", q.action, q.id) != q.allowed {
			t.Fatal(q)
		}
	}
	copied := claims.Scopes()
	copied[0].Actions = append(copied[0].Actions, "invoke")
	copied[0].ResourceIds = append(copied[0].ResourceIds, "b")
	if claims.Allows("record", "invoke", "a") {
		t.Fatal("mutable scope escaped")
	}
	c.AuthorityScopes = []*basev0.WorkScopeV1{{ResourceKind: "record", Actions: []string{"read", "admin", "*"}}}
	claims = read(t, c)
	if !claims.Allows("record", "read", "") || !claims.Allows("record", "read", "a") || claims.Allows("record", "invoke", "a") || claims.Allows("", "read", "") || claims.Allows("record", "", "") {
		t.Fatal("literal scope semantics changed")
	}
	var empty reader.Claims
	if empty.Allows("record", "read", "") {
		t.Fatal("zero claims grant authority")
	}
}
func TestEmptyFinalActorGrantsNothing(t *testing.T) {
	c := body(t, "delegated")
	c.ActorChain[len(c.ActorChain)-1].GrantedScopes = nil
	claims := read(t, c)
	if len(claims.Scopes()) != 0 || claims.Allows("record", "read", "record-conformance") {
		t.Fatal("earlier scopes leaked")
	}
}
func TestEnvelopesAndClaimsCoreRefuses(t *testing.T) {
	session := body(t, "session")
	valid := tokenFor(t, session)
	payload, _, _ := strings.Cut(valid, ".")
	for _, token := range []string{"abc", "a.b.c", ".", "é.x", strings.Repeat("a", 32*1024+1), valid + "=", payload + ".AA", payload + "." + strings.Repeat("A", 85) + "B"} {
		if _, err := reader.Authenticate(stampedToken(token), "test-proof", session.GetAudience(), trustFor(session)); !errors.Is(err, reader.ErrUnauthenticated) {
			t.Fatalf("envelope not refused: %v", err)
		}
	}
	for _, where := range []string{"root", "nested", "duplicate", "audience", "structural"} {
		t.Run(where, func(t *testing.T) {
			c := body(t, "session")
			switch where {
			case "root":
				c.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 0x01})
			case "nested":
				c.AuthorityScopes[0].ProtoReflect().SetUnknown([]byte{0x78, 0x01})
			case "audience":
				c.Audience = ""
			case "structural":
				c.Seal = nil
			}
			token := tokenFor(t, c)
			if where == "duplicate" {
				p, _, _ := strings.Cut(token, ".")
				b, _ := base64.RawURLEncoding.DecodeString(p)
				b = append(b, b...)
				token = base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, b))
			}
			if _, err := reader.Authenticate(stampedToken(token), "test-proof", session.GetAudience(), trustFor(session)); !errors.Is(err, reader.ErrUnauthenticated) {
				t.Fatalf("malformed claims not refused: %v", err)
			}
		})
	}
}

// The defect this package exists to close: a party holding the run's proof
// writes the proof and the digest of any token it likes. Only the signature,
// the issuer, the audience and the window make the token one the authority
// issued for this module, now.
func TestAForgedOrMisaddressedContextIsRefusedByName(t *testing.T) {
	session := body(t, "session")
	trust := trustFor(session)
	_, other, _ := ed25519.GenerateKey(nil)
	payload, _, _ := strings.Cut(tokenFor(t, session), ".")
	foreign := proto.Clone(session).(*basev0.WorkContextV1)
	foreign.Issuer = "https://forger.example"
	for name, c := range map[string]struct {
		token, audience, reason string
		trust                   reader.Trust
	}{
		"forged":         {signWith(t, other, session), session.GetAudience(), "signature", trust},
		"unsigned":       {payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64)), session.GetAudience(), "signature", trust},
		"another issuer": {tokenFor(t, foreign), session.GetAudience(), "issued by", trust},
		"wrong audience": {tokenFor(t, session), "another-module", "minted for audience", trust},
		"expired":        {tokenFor(t, session), session.GetAudience(), "expired", reader.Trust{Issuer: trust.Issuer, Keys: trust.Keys, Now: func() time.Time { return time.Unix(session.GetExpiresAtUnix(), 0).Add(time.Hour) }}},
		"not yet valid":  {tokenFor(t, session), session.GetAudience(), "not valid before", reader.Trust{Issuer: trust.Issuer, Keys: trust.Keys, Now: func() time.Time { return time.Unix(session.GetNotBeforeUnix(), 0).Add(-time.Hour) }}},
		"unknown key":    {tokenFor(t, session), session.GetAudience(), "no verification key", reader.Trust{Issuer: trust.Issuer, Keys: map[string]ed25519.PublicKey{"rotated": trust.Keys[session.GetKeyId()]}, Now: trust.Now}},
		"no trust":       {tokenFor(t, session), session.GetAudience(), "names no issuer", reader.Trust{}},
		"no audience":    {tokenFor(t, session), "", "no audience", trust},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := reader.Authenticate(stampedToken(c.token), "test-proof", c.audience, c.trust)
			if !errors.Is(err, reader.ErrUnauthenticated) || !strings.Contains(err.Error(), c.reason) {
				t.Fatalf("want a refusal naming %q, got %v", c.reason, err)
			}
		})
	}
}

func stampedToken(token string) metadata.MD {
	sum := sha256.Sum256([]byte(token))
	return metadata.Pairs("x-codefly-work-context", token, "x-codefly-hop-proof", "test-proof", "x-codefly-hop-context", hex.EncodeToString(sum[:]))
}
func TestAuthenticateRequiresTheStamp(t *testing.T) {
	session := body(t, "session")
	token := tokenFor(t, session)
	for _, change := range []func(metadata.MD){
		func(md metadata.MD) { md.Delete("x-codefly-hop-proof") },
		func(md metadata.MD) { md.Set("x-codefly-hop-proof", "forged") },
		func(md metadata.MD) { md.Delete("x-codefly-hop-context") },
		func(md metadata.MD) { md.Set("x-codefly-work-context", tokenFor(t, body(t, "operation"))) },
		func(md metadata.MD) { md.Append("x-codefly-work-context", token) },
	} {
		md := stampedToken(token)
		change(md)
		if _, err := reader.Authenticate(md, "test-proof", session.GetAudience(), trustFor(session)); !errors.Is(err, reader.ErrUnauthenticated) {
			t.Fatalf("unbound claims accepted: %v", err)
		}
	}
	if _, err := reader.Authenticate(stampedToken(token), "", session.GetAudience(), trustFor(session)); err == nil {
		t.Fatal("empty proof accepted")
	}
	if c, err := reader.Authenticate(stampedToken(token), "test-proof", session.GetAudience(), trustFor(session)); err != nil || c.Context().GetTenantId() != session.GetTenantId() {
		t.Fatalf("an authentic, bound context: %v", err)
	}
}
