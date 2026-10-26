package hop

import (
	"context"
	"encoding/base64"
	"errors"
	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	core "github.com/codefly-dev/core/workcontext"
	"strings"
	"testing"
	"time"
)

func TestVerifyTokenUsesPublishedTrustAndSafeReasons(t *testing.T) {
	now := time.Now()
	signer := newSigner("bare")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: signer.issuer, Keys: []*authorityv1.PublicKey{signer.published()}}}
	v, err := NewTokenVerifier(t.Context(), source, "module")
	if err != nil {
		t.Fatal(err)
	}
	token := signer.issue(t, now, "module")
	if _, err := v.Verify(t.Context(), forwarded(t, token, "proof", ""), "/test.Service/Read"); err == nil {
		t.Fatal("bare-only verifier accepted a stamp")
	}
	id, err := v.VerifyToken(t.Context(), token)
	if err != nil || id.Claims == nil || id.Context != token || id.Advisory != "" {
		t.Fatalf("bare token: %v", err)
	}
	for _, tc := range []struct {
		name, token string
		reason      Reason
	}{
		{"forged", strings.Split(token, ".")[0] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64)), ReasonSignature},
		{"unsigned", strings.Split(token, ".")[0] + ".", ReasonSignature},
		{"expired", signer.issue(t, now.Add(-time.Hour), "module"), ReasonExpired},
		{"audience", signer.issue(t, now, "other"), ReasonAudience},
		{"malformed", "secret-token", ReasonMalformed},
		{"early", signer.issue(t, now.Add(time.Hour), "module"), ReasonNotYetValid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.VerifyToken(t.Context(), tc.token)
			var reason Reason
			if !errors.As(err, &reason) || reason != tc.reason {
				t.Fatalf("want %s, got %v", tc.reason, err)
			}
			if strings.Contains(err.Error(), tc.token) || strings.Contains(err.Error(), signer.id) {
				t.Fatal("unsafe refusal")
			}
		})
	}
}

func TestBareTokenWaitsForStaleRefreshAndRefusesFailure(t *testing.T) {
	now := time.Now()
	signer := newSigner("bare-refresh")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: signer.issuer, Keys: []*authorityv1.PublicKey{signer.published()}}}
	v, err := NewVerifier(t.Context(), source, "module", testSigner("proof").PublicKey(), core.NewMemoryReplayStore())
	if err != nil {
		t.Fatal(err)
	}
	token := signer.issue(t, now, "module")
	// Age only the cache: the freshly issued token remains valid.
	v.mu.Lock()
	v.fetched = now.Add(-keyStale - time.Second)
	v.tried = v.fetched
	v.mu.Unlock()
	hold := make(chan struct{})
	source.set(source.response, nil, hold)
	result := make(chan error, 1)
	go func() { _, err := v.VerifyToken(context.Background(), token); result <- err }()
	select {
	case err := <-result:
		t.Fatalf("did not wait: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(hold)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	v.mu.Lock()
	v.fetched = now.Add(-keyStale - time.Second)
	v.tried = v.fetched
	v.mu.Unlock()
	source.set(nil, errors.New("private-key-source-secret"), nil)
	_, err = v.VerifyToken(t.Context(), token)
	var reason Reason
	if !errors.As(err, &reason) || reason != ReasonKeysUnavailable || strings.Contains(err.Error(), "secret") {
		t.Fatalf("stale failure: %v", err)
	}
}
