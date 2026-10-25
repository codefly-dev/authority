package authority

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/codefly-dev/core/workcontext"

	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

// The key set is Keys in the standard format a key-set reader parses.
func TestKeysArePublishedAsAJSONWebKeySet(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(nil)
	body, err := KeySet(&authorityv1.KeysResponse{Issuer: "i", Keys: []*authorityv1.PublicKey{
		{KeyId: "run-1", Algorithm: workcontext.Algorithm, PublicKey: public},
		{KeyId: "other", Algorithm: "RS256", PublicKey: []byte("x")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil || len(set.Keys) != 1 {
		t.Fatalf("one Ed25519 key: %s %v", body, err)
	}
	k := set.Keys[0]
	x, _ := base64.RawURLEncoding.DecodeString(k["x"])
	if k["kty"] != "OKP" || k["crv"] != "Ed25519" || k["kid"] != "run-1" || !ed25519.PublicKey(x).Equal(public) {
		t.Fatalf("key: %v", k)
	}
}
