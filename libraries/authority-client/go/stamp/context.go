// Package stamp authenticates call attestations and extracts token bindings.
package stamp

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"

	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	"google.golang.org/grpc/metadata"
)

// Context extracts one digest-bound token. It does NOT authenticate hop admission;
// use Check plus a shared ReplayStore (normally through hop.Verifier). Its
// refusals are caller-safe reasons: they name no token, digest or claim.
func Context(md metadata.MD) (string, error) {
	tokens, digests := md.Get("x-codefly-work-context"), md.Get("x-codefly-hop-context")
	if len(tokens) != 1 || tokens[0] == "" || len(digests) != 1 {
		return "", refusal.StampToken
	}
	sum := sha256.Sum256([]byte(tokens[0]))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(digests[0])) != 1 {
		return "", refusal.StampDigest
	}
	return tokens[0], nil
}
