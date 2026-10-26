package hop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	"github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"
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
