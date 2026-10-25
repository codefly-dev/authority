// Package stamp binds the forwarded Work Context to the trusted hop's proof.
package stamp

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"google.golang.org/grpc/metadata"
)

// Context returns only the token whose digest the authenticated hop stamped.
func Context(md metadata.MD, proof string) (string, error) {
	proofs, tokens, digests := md.Get("x-codefly-hop-proof"), md.Get("x-codefly-work-context"), md.Get("x-codefly-hop-context")
	if proof == "" || len(proofs) != 1 || subtle.ConstantTimeCompare([]byte(proofs[0]), []byte(proof)) != 1 || len(tokens) != 1 || tokens[0] == "" || len(digests) != 1 {
		return "", errors.New("authority: context requires this run's hop proof and a single stamped token")
	}
	sum := sha256.Sum256([]byte(tokens[0]))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(digests[0])) != 1 {
		return "", errors.New("authority: context does not match the hop stamp")
	}
	return tokens[0], nil
}
