package forward

import (
	"context"
	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	hop "github.com/codefly-dev/authority/libraries/hop/go"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc"
	"testing"
	"time"
)

type publishedRegistrar struct{}

func (publishedRegistrar) RegisterAdmissionKey(_ context.Context, in *authorityv1.RegisterAdmissionKeyRequest, _ ...grpc.CallOption) (*authorityv1.RegisterAdmissionKeyResponse, error) {
	return &authorityv1.RegisterAdmissionKeyResponse{Key: &authorityv1.PublicKey{KeyId: stamp.KeyID(in.PublicKey), PublicKey: in.PublicKey, Algorithm: core.Algorithm, Purpose: stamp.Purpose}, ExpiresAtUnix: time.Now().Add(time.Hour).Unix()}, nil
}

// Existing face tests receive an actual lease for the same signer; no always-ready production bypass.
func published(t *testing.T, signer *stamp.Signer) func() bool {
	t.Helper()
	l := (hop.Registration{Authority: publishedRegistrar{}, Signer: signer, Credential: func() (string, error) { return "header.eyJhdWQiOiJhdXRob3JpdHkifQ.signature", nil }}).Start(t.Context())
	t.Cleanup(l.Close)
	if !l.Ready() {
		t.Fatal("test registration failed")
	}
	return l.Ready
}
