package workcontext_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	reader "github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/protobuf/encoding/protojson"
)

var updateVectors = flag.Bool("update-vectors", false, "rewrite ../testdata/vectors.json")

// vector is one token and the verdict Go reaches on it. Python and TypeScript
// run the same file and must reach the same verdict: rule for rule, one source.
type vector struct {
	Name     string            `json:"name"`
	Token    string            `json:"token"`
	Audience string            `json:"audience"`
	Issuer   string            `json:"issuer"`
	Now      int64             `json:"now"`
	Keys     map[string]string `json:"keys"`
	Accept   bool              `json:"accept"`
	Reason   string            `json:"reason,omitempty"`
}

func vectors(t *testing.T) []vector {
	fixturePublic, fixturePrivate := core.FixtureKeyPair()
	own := signer.Public().(ed25519.PublicKey)
	build := func(name, from string, change func(*basev0.WorkContextV1), key ed25519.PrivateKey, reason string) vector {
		c := body(t, from)
		if change != nil {
			change(c)
		}
		if key == nil {
			key = signer
		}
		public := own
		if key.Equal(fixturePrivate) {
			public = fixturePublic
		}
		return vector{Name: name, Token: signWith(t, key, c), Audience: body(t, from).GetAudience(), Issuer: c.GetIssuer(),
			Now: c.GetNotBeforeUnix() + 1, Keys: map[string]string{c.GetKeyId(): base64.StdEncoding.EncodeToString(public)},
			Accept: reason == "", Reason: reason}
	}
	widen := func(c *basev0.WorkContextV1) {
		c.ActorChain[0].GrantedScopes = []*basev0.WorkScopeV1{{ResourceKind: "record", Actions: []string{"admin"}}}
	}
	out := []vector{
		build("session", "session", nil, nil, ""),
		build("delegated", "delegated", nil, nil, ""),
		build("delegated operation", "delegated-operation", nil, nil, ""),
		build("operation", "operation", nil, nil, ""),
		build("grant", "grant", nil, nil, ""),
		build("several rows of one kind", "session", func(c *basev0.WorkContextV1) {
			c.AuthorityScopes = []*basev0.WorkScopeV1{{ResourceKind: "record", Actions: []string{"read"}, ResourceIds: []string{"a"}}, {ResourceKind: "record", Actions: []string{"write"}, ResourceIds: []string{"b"}}}
		}, nil, ""),
		build("an actor granted nothing", "delegated", func(c *basev0.WorkContextV1) { c.ActorChain[0].GrantedScopes = nil }, nil, ""),
		build("an actor widens the owner", "delegated", widen, nil, "attenuation"),
		build("no seal", "session", func(c *basev0.WorkContextV1) { c.Seal = nil }, nil, "malformed"),
		build("seal epoch zero", "session", func(c *basev0.WorkContextV1) { c.Seal.PrincipalEpoch = 0 }, nil, "malformed"),
		build("empty tenant", "session", func(c *basev0.WorkContextV1) { c.TenantId = "" }, nil, "malformed"),
		build("wrong type", "session", func(c *basev0.WorkContextV1) { c.Typ = "codefly.work-context/v0" }, nil, "malformed"),
		build("unknown replay policy", "session", func(c *basev0.WorkContextV1) { c.ReplayPolicy = "forever" }, nil, "malformed"),
		build("actor without an epoch", "delegated", func(c *basev0.WorkContextV1) { c.ActorChain[0].PrincipalEpoch = 0 }, nil, "malformed"),
		build("lifetime beyond a day", "session", func(c *basev0.WorkContextV1) { c.ExpiresAtUnix = c.NotBeforeUnix + 25*3600 }, nil, "lifetime"),
		build("grant without single use", "grant", func(c *basev0.WorkContextV1) { c.ReplayPolicy = core.ReplayIdempotent }, nil, "grant"),
		build("grant to another hop", "grant", func(c *basev0.WorkContextV1) { c.GrantHop.GrantId = "another-grant" }, nil, "grant"),
		build("signed with Core's public conformance key", "session", nil, fixturePrivate, "fixture_key"),
	}
	forged := build("forged signature", "session", nil, nil, "signature")
	other := ed25519.NewKeyFromSeed([]byte("a forger, not the authority, 32b"))
	payload, _, _ := strings.Cut(forged.Token, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(payload)
	forged.Token = payload + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(other, raw))
	unsigned := build("unsigned", "session", nil, nil, "signature")
	unsigned.Token = payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	elsewhere := build("another audience", "session", nil, nil, "audience")
	elsewhere.Audience = "another-module"
	expired := build("expired", "session", nil, nil, "expired")
	expired.Now = body(t, "session").GetExpiresAtUnix() + 3600
	early := build("not yet valid", "session", nil, nil, "not_yet_valid")
	early.Now = body(t, "session").GetNotBeforeUnix() - 3600
	issuer := build("another issuer", "session", nil, nil, "issuer")
	issuer.Issuer = "https://forger.example"
	unknown := build("a key the authority does not publish", "session", nil, nil, "unknown_key")
	unknown.Keys = map[string]string{"rotated": unknown.Keys[body(t, "session").GetKeyId()]}
	emptySignature := unsigned
	emptySignature.Name, emptySignature.Token = "empty signature", payload+"."
	out = append(out, forged, unsigned, emptySignature, elsewhere, expired, early, issuer, unknown)
	return append(out, encodingVectors(t, out[0])...)
}

// Encoding variants share a valid signed control. Text variants preserve the
// decoded bytes; protobuf variants are signed over the altered payload so a
// signature failure cannot disguise a missing canonical-encoding check.
func encodingVectors(t *testing.T, control vector) []vector {
	t.Helper()
	var out []vector
	add := func(name, token string) {
		v := control
		v.Name, v.Token, v.Accept, v.Reason = name, token, false, "malformed"
		out = append(out, v)
	}
	payload, signature, _ := strings.Cut(control.Token, ".")
	for _, segment := range []struct{ name, text string }{{"payload", payload}, {"signature", signature}} {
		join := func(text string) string {
			if segment.name == "payload" {
				return text + "." + signature
			}
			return payload + "." + text
		}
		for _, variant := range []struct{ name, text string }{
			{"padding", segment.text + "="},
			{"double padding", segment.text + "=="},
			{"CR", segment.text[:1] + "\r" + segment.text[1:]},
			{"LF", segment.text[:1] + "\n" + segment.text[1:]},
			{"CRLF", segment.text[:1] + "\r\n" + segment.text[1:]},
		} {
			add(segment.name+" "+variant.name, join(variant.text))
		}
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		if len(segment.text)%4 == 0 {
			t.Fatalf("%s fixture needs unused base64 bits", segment.name)
		}
		last := len(segment.text) - 1
		changed := segment.text[:last] + string(alphabet[strings.IndexByte(alphabet, segment.text[last])^1])
		add(segment.name+" unused bit", join(changed))
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	signed := func(name string, altered []byte) {
		add(name, base64.RawURLEncoding.EncodeToString(altered)+"."+base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, altered)))
	}
	// The canonical first field is the type string (tag 1, length-delimited).
	end := 2 + int(raw[1])
	signed("protobuf duplicate field", append(append([]byte{}, raw...), raw[:end]...))
	signed("protobuf reordered field", append(append([]byte{}, raw[end:]...), raw[:end]...))
	signed("protobuf overlong varint", append([]byte{raw[0], raw[1] | 0x80, 0}, raw[2:]...))
	signed("protobuf unknown field", append(append([]byte{}, raw...), 0xf8, 0x07, 0x01))
	jsonPayload, err := protojson.Marshal(body(t, "session"))
	if err != nil {
		t.Fatal(err)
	}
	// protojson may vary insignificant whitespace; keep the fixture reproducible.
	var compact bytes.Buffer
	if err := json.Compact(&compact, jsonPayload); err != nil {
		t.Fatal(err)
	}
	// Work Context accepts protobuf only, including when JSON contains the same claims.
	signed("JSON claims", compact.Bytes())
	return out
}

// Every verdict in ../testdata/vectors.json is Go's, reached by the one check a
// module runs; the file is regenerated from these cases, never edited.
func TestTheSharedVectorsAreGosVerdicts(t *testing.T) {
	cases := vectors(t)
	want, err := json.MarshalIndent(cases, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	const path = "../../testdata/vectors.json"
	if *updateVectors {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(want) {
		t.Fatalf("%s is not what these cases produce; regenerate with -update-vectors: %v", path, err)
	}
	for _, v := range cases {
		t.Run(v.Name, func(t *testing.T) {
			keys := map[string]ed25519.PublicKey{}
			for id, encoded := range v.Keys {
				raw, _ := base64.StdEncoding.DecodeString(encoded)
				keys[id] = raw
			}
			at := time.Unix(v.Now, 0)
			trust := reader.Trust{Issuer: v.Issuer, Keys: keys, Now: func() time.Time { return at }}
			for _, mode := range []string{"stamped", "bare"} {
				t.Run(mode, func(t *testing.T) {
					var err error
					if mode == "stamped" {
						_, err = reader.Authenticate(stampedToken(v.Token), v.Audience, trust)
					} else {
						_, err = reader.AuthenticateToken(v.Token, v.Audience, trust)
					}
					if v.Accept {
						if err != nil {
							t.Fatalf("Go refuses a vector it should accept: %v", err)
						}
					} else {
						var reason refusal.Reason
						if !errors.Is(err, reader.ErrUnauthenticated) || !errors.As(err, &reason) || reason.Code() != v.Reason {
							t.Fatalf("want a refusal naming %q: %v", v.Reason, err)
						}
					}
				})
			}
		})
	}
}
