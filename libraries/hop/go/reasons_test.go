package hop

import (
	"context"
	"errors"
	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc/metadata"
	"strings"
	"testing"
	"time"
)

func TestStampFailureCodesAreDistinctAndSafe(t *testing.T) {
	s := newSigner("reasons")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: s.issuer, Keys: []*authorityv1.PublicKey{s.published()}}}
	v, err := NewVerifier(t.Context(), source, "module", testSigner("proof").PublicKey(), core.NewMemoryReplayStore())
	if err != nil {
		t.Fatal(err)
	}
	token := s.issue(t, v.now(), "module")
	cases := []struct {
		want   Reason
		change func(metadata.MD)
	}{
		{ReasonStampProof, func(md metadata.MD) { md.Set(ProofKey, "private-proof") }},
		{ReasonStampToken, func(md metadata.MD) { md.Append(WorkContextKey, "private-token") }},
		{ReasonStampDigest, func(md metadata.MD) { md.Set(ContextKey, "private-digest") }},
		{ReasonStampIdentity, func(md metadata.MD) { md.Set(TenantKey, "private-tenant") }},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		md := forwarded(t, token, "proof", "")
		tc.change(md)
		_, err := v.Verify(t.Context(), md, "/test.Service/Read")
		var reason Reason
		if !errors.As(err, &reason) || reason != tc.want {
			t.Fatalf("want %s: %v", tc.want, err)
		}
		if seen[reason.Code()] || strings.Contains(err.Error(), "private-") {
			t.Fatalf("unsafe or repeated code: %v", err)
		}
		seen[reason.Code()] = true
	}
}

func TestConfigurationAndCancelledKeyWaitHaveNamedReasons(t *testing.T) {
	_, err := NewVerifier(t.Context(), nil, "module", testSigner("proof").PublicKey(), core.NewMemoryReplayStore())
	var reason Reason
	if !errors.As(err, &reason) || reason != ReasonConfiguration {
		t.Fatalf("configuration: %v", err)
	}
	s := newSigner("cancel-reason")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: s.issuer, Keys: []*authorityv1.PublicKey{s.published()}}}
	v, err := NewVerifier(t.Context(), source, "module", testSigner("proof").PublicKey(), core.NewMemoryReplayStore())
	if err != nil {
		t.Fatal(err)
	}
	hold := make(chan struct{})
	source.set(source.response, nil, hold)
	defer close(hold)
	v.mu.Lock()
	v.fetched = v.now().Add(-keyStale - time.Second)
	v.tried = v.fetched
	v.mu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = v.VerifyToken(ctx, s.issue(t, v.now(), "module"))
	if !errors.As(err, &reason) || reason != ReasonCancelled {
		t.Fatalf("cancelled: %v", err)
	}
}

func TestInvalidPublicationIsDistinctFromUnreadableKeys(t *testing.T) {
	s := newSigner("publication")
	token := s.issue(t, time.Now(), "module")
	for _, tc := range []struct {
		response *authorityv1.KeysResponse
		failure  error
		want     Reason
	}{
		{&authorityv1.KeysResponse{Issuer: s.issuer}, nil, ReasonInvalidKey},
		{&authorityv1.KeysResponse{Issuer: s.issuer, Keys: []*authorityv1.PublicKey{{KeyId: "secret-key-id", Algorithm: "Ed25519", PublicKey: []byte("secret-key")}}}, nil, ReasonInvalidKey},
		{nil, errors.New("secret-key-source"), ReasonKeysUnavailable},
	} {
		v, err := NewTokenVerifier(t.Context(), &keys{response: tc.response, err: tc.failure}, "module")
		if err != nil {
			t.Fatal(err)
		}
		_, err = v.VerifyToken(t.Context(), token)
		var reason Reason
		if !errors.As(err, &reason) || reason != tc.want || strings.Contains(err.Error(), "secret-") {
			t.Fatalf("publication classification: %v", err)
		}
	}
}
