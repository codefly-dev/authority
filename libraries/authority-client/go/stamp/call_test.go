package stamp

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"
)

func TestSignedCallBindingRejectsMutationAndExpiredOrAmbiguousProof(t *testing.T) {
	signer, err := NewSigner(strings.Repeat("01", 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	const token = "synthetic-context"
	proof, err := signer.Sign(token, "/pkg.Service/Read", "module", now, now.Add(time.Minute).Unix())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(token))
	md := metadata.Pairs("x-codefly-hop-proof", proof, "x-codefly-work-context", token, "x-codefly-hop-context", hex.EncodeToString(digest[:]))
	if _, err := Check(md, signer.PublicKey(), "/pkg.Service/Read", "module", now); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(metadata.MD){
		func(m metadata.MD) { m.Set("x-codefly-hop-proof", proof[:len(proof)-2]+"AA") },
		func(m metadata.MD) { m.Append("x-codefly-hop-proof", proof) },
		func(m metadata.MD) { m.Append("x-codefly-work-context", token) },
		func(m metadata.MD) { m.Append("x-codefly-hop-context", hex.EncodeToString(digest[:])) },
		func(m metadata.MD) { m.Set("x-codefly-hop-advisory", "refused") },
	} {
		changed := md.Copy()
		mutation(changed)
		if _, err := Check(changed, signer.PublicKey(), "/pkg.Service/Read", "module", now); err == nil {
			t.Fatal("mutated proof accepted")
		}
	}
	for _, at := range []time.Time{now.Add(-time.Second), now.Add(Lifetime)} {
		if _, err := Check(md, signer.PublicKey(), "/pkg.Service/Read", "module", at); err == nil {
			t.Fatal("invalid admission window accepted")
		}
	}
	if _, err := signer.Sign(token, "/pkg.Service/Read", "module", now, now.Unix()); err == nil {
		t.Fatal("signed expired capability")
	}
}
