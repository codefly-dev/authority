// Package stamp authenticates call attestations and extracts token bindings.
package stamp

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"google.golang.org/grpc/metadata"
)

// Context extracts one digest-bound token. It does NOT authenticate hop admission;
// use Check plus a shared ReplayStore (normally through hop.Verifier).
func Context(md metadata.MD) (string, error) {
	tokens, digests := md.Get("x-codefly-work-context"), md.Get("x-codefly-hop-context")
	if len(tokens) != 1 || tokens[0] == "" || len(digests) != 1 {
		return "", errors.New("authority: context requires a single digest-bound token")
	}
	sum := sha256.Sum256([]byte(tokens[0]))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(digests[0])) != 1 {
		return "", errors.New("authority: context does not match the hop stamp")
	}
	return tokens[0], nil
}
