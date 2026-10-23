package delivery

import (
	"crypto"
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestTheAuthorityDocumentVerifiesOnlyAsSigned(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	sign := func(key ed25519.PrivateKey) func([]byte) ([]byte, error) {
		return func(m []byte) ([]byte, error) { return ed25519.Sign(key, m), nil }
	}
	keys := map[string]crypto.PublicKey{"release": public}
	document := []byte("methods")
	env, err := Sign(document, "release", sign(private))
	if err != nil {
		t.Fatal(err)
	}
	if id, err := Verify(document, env, keys); err != nil || id != "release" {
		t.Fatalf("signed: %q %v", id, err)
	}
	for name, c := range map[string]struct {
		document []byte
		env      func() []byte
		want     string
	}{
		"another document": {[]byte("looser methods"), func() []byte { return env }, "not the document delivered with it"},
		"another key":      {document, func() []byte { e, _ := Sign(document, "release", sign(other)); return e }, "does not verify"},
		"an unpinned key":  {document, func() []byte { e, _ := Sign(document, "stranger", sign(private)); return e }, "is not pinned"},
		"another payload": {document, func() []byte {
			return []byte(strings.Replace(string(env), PayloadType, "application/vnd.codefly.module-manifest+json", 1))
		}, "not the authority's document"},
	} {
		if _, err := Verify(c.document, c.env(), keys); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
