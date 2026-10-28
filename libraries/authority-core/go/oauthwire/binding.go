package oauthwire

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

const S256 = "S256"

// ValidateChallenge checks the authorization request before a host records a
// code. Only the unpadded base64url encoding of a SHA-256 digest is accepted.
func ValidateChallenge(method, challenge string) error {
	if method != S256 || len(challenge) != 43 {
		return errors.New("an S256 PKCE challenge is required")
	}
	digest, err := base64.RawURLEncoding.Strict().DecodeString(challenge)
	if err != nil || len(digest) != sha256.Size {
		return errors.New("invalid S256 PKCE challenge")
	}
	return nil
}

// VerifyPKCE verifies a code's recorded challenge on redemption. The host must
// also bind the code to the client, exact redirect URI, resource, person and
// delegation, expire it, and consume it atomically at most once. This function
// does not provide code storage or replay protection.
func VerifyPKCE(method, challenge, verifier string) error {
	if err := ValidateChallenge(method, challenge); err != nil {
		return err
	}
	if len(verifier) < 43 || len(verifier) > 128 || strings.IndexFunc(verifier, func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c))
	}) >= 0 {
		return errors.New("invalid PKCE verifier")
	}
	digest := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) != 1 {
		return errors.New("PKCE verifier does not match")
	}
	return nil
}

// CheckResource compares the complete trusted resource binding, byte for byte.
// The authorization request must name one resource. On token/refresh requests
// an omitted resource is inherited from the stored binding by the caller, never
// interpreted as unbound. Repeated form parameters must be rejected by the HTTP
// adapter before calling this function.
func CheckResource(bound, presented string) error {
	if bound == "" || presented == "" || bound != presented {
		return errors.New("invalid_target: resource does not match the authorization")
	}
	return nil
}

// ExpiresIn reports whole seconds remaining, bounded by BOTH the authority's
// actual issued capability and the delegation's fixed end. It never promises a
// lifetime longer than either. The host re-reads the live delegation and issues
// anew through Issue(as=delegation) on refresh; neither rotation nor this helper
// extends the delegation. Expiry reporting does not cancel an in-flight call.
func ExpiresIn(now, capabilityEnd, delegationEnd time.Time) (int64, error) {
	if capabilityEnd.IsZero() || delegationEnd.IsZero() {
		return 0, errors.New("MCP acquisition requires a capability and an expiring delegation")
	}
	end := capabilityEnd
	if delegationEnd.Before(end) {
		end = delegationEnd
	}
	seconds := int64(end.Sub(now) / time.Second)
	if seconds <= 0 {
		return 0, errors.New("authorization has no whole second remaining")
	}
	return seconds, nil
}
