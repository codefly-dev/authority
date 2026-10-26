package conformance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	forwarded "github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

// forwardedContext is the module side of the hop, against this host: what the
// host publishes through Keys is exactly what authenticates what it issues, so
// a module that pins those keys accepts the host's context and refuses a
// forged, unsigned, misaddressed or expired one, naming the reason. It drives
// the same check every module runs behind the hop (workcontext.Authenticate,
// under hop.Verifier), never a copy of it.
func (c *client) forwardedContext(t *testing.T, ctx context.Context, f Fixture) {
	t.Run("a module authenticates the forwarded context against the published keys", func(t *testing.T) {
		published := c.must(t, ctx, "host.authority.v1.AuthorityService", "Keys", map[string]any{})
		trust := forwarded.Trust{Issuer: str(published, "issuer"), Keys: map[string]ed25519.PublicKey{}}
		for _, key := range listMsgs(published, "keys") {
			if str(key, "algorithm") == "Ed25519" {
				trust.Keys[str(key, "key_id")] = ed25519.PublicKey(field(key, "public_key").Bytes())
			}
		}
		sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})
		read := []any{map[string]any{"resource_kind": f.ReadKind, "actions": []any{"read"}}}
		issued := c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.Audience, "scopes": read})
		token := str(issued, "token")
		// The window is judged at the host's own clock, which a fixture may fix.
		at := time.Unix(i64(msg(issued, "context"), "issued_at_unix"), 0).Add(time.Second)
		trust.Now = func() time.Time { return at }

		const proof = "conformance-proof"
		if claims, err := forwarded.Authenticate(stamped(token, proof), proof, f.Audience, trust); err != nil || claims.Audience() != f.Audience {
			t.Fatalf("the host's own context, under its published keys, is accepted: %v", err)
		}
		payload, _, _ := strings.Cut(token, ".")
		raw, err := base64.RawURLEncoding.DecodeString(payload)
		if err != nil {
			t.Fatal(err)
		}
		// The hop stamps who the call is for from Check's context and the module
		// derives it from the token; they agree only if Check answers the token's
		// own claims, byte for byte, never a re-derivation.
		checked := c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": token, "audience": f.Audience})
		answered, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg(checked, "context").Interface())
		if err != nil || !bytes.Equal(answered, raw) {
			t.Fatalf("Check answers the token's own claims unchanged: %v", err)
		}
		_, forger, _ := ed25519.GenerateKey(rand.Reader)
		later := trust
		later.Now = func() time.Time { return at.Add(25 * time.Hour) }
		for name, probe := range map[string]struct {
			token, audience, reason string
			trust                   forwarded.Trust
		}{
			"forged":         {payload + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(forger, raw)), f.Audience, "signature", trust},
			"unsigned":       {payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)), f.Audience, "signature", trust},
			"wrong audience": {token, f.Elsewhere, "minted for audience", trust},
			"expired":        {token, f.Audience, "expired", later},
		} {
			t.Run(name+" is refused by name", func(t *testing.T) {
				_, err := forwarded.Authenticate(stamped(probe.token, proof), proof, probe.audience, probe.trust)
				if !errors.Is(err, forwarded.ErrUnauthenticated) || !strings.Contains(err.Error(), probe.reason) {
					t.Fatalf("want a refusal naming %q: %v", probe.reason, err)
				}
			})
		}
	})
}

// stamped is the incoming metadata of a call the hop let through carrying
// token: the token, this run's proof and the stamp's digest of the token.
func stamped(token, proof string) metadata.MD {
	sum := sha256.Sum256([]byte(token))
	return metadata.Pairs("x-codefly-work-context", token, "x-codefly-hop-proof", proof, "x-codefly-hop-context", hex.EncodeToString(sum[:]))
}
