package solutionhost

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestPAEGolden(t *testing.T) {
	// DSSE protocol v1.0.2, Test Vectors:
	// https://github.com/secure-systems-lab/dsse/blob/master/protocol.md#test-vectors
	for _, tc := range []struct {
		name, payloadType, payload, want string
	}{
		{"spec example", "http://example.com/HelloWorld", "hello world", "DSSEv1 29 http://example.com/HelloWorld 11 hello world"},
		{"empty", "", "", "DSSEv1 0  0 "},
		{"byte lengths", "é", "雪\x00\n", "DSSEv1 2 é 5 雪\x00\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(pae(tc.payloadType, []byte(tc.payload))); got != tc.want {
				t.Fatalf("PAE = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOnlySupportedKeyAlgorithms(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []any{rsaKey, p384, struct{}{}, ed25519.PrivateKey{}, (*ecdsa.PrivateKey)(nil)} {
		if _, err := NewInMemorySigner("key", key); err == nil {
			t.Fatalf("accepted private key %T", key)
		}
	}
	for _, key := range []any{rsaKey.Public(), p384.Public(), struct{}{}, ed25519.PublicKey{}, (*ecdsa.PublicKey)(nil)} {
		if err := verifySignature(key, []byte("message"), []byte("signature")); err == nil {
			t.Fatalf("accepted public key %T", key)
		}
	}
}
