package stamp

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
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
	// Inside the clock allowance, a verifier running behind or a little past the
	// expiry still admits the call: these are clock differences, not forgeries.
	for _, at := range []time.Time{now.Add(-Skew), now.Add(Lifetime), now.Add(Lifetime + Skew - time.Second)} {
		if _, err := Check(md, signer.PublicKey(), "/pkg.Service/Read", "module", at); err != nil {
			t.Fatalf("a clock difference of %v inside the allowance was refused: %v", at.Sub(now), err)
		}
	}
	// Beyond it, each bound is refused under its own reason.
	for _, tc := range []struct {
		at   time.Time
		want refusal.Reason
	}{
		{now.Add(-Skew - time.Second), refusal.StampIssued},
		{now.Add(Lifetime + Skew), refusal.StampWindow},
	} {
		_, err := Check(md, signer.PublicKey(), "/pkg.Service/Read", "module", tc.at)
		var reason refusal.Reason
		if !errors.As(err, &reason) || reason != tc.want {
			t.Fatalf("at %v want %s: %v", tc.at.Sub(now), tc.want, err)
		}
	}
	// The allowance widens no span: a signed span longer than Lifetime is
	// refused however the clocks sit.
	long, err := signer.Sign(token, "/pkg.Service/Read", "module", now, now.Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	wide := md.Copy()
	wide.Set("x-codefly-hop-proof", long)
	if call, err := Check(wide, signer.PublicKey(), "/pkg.Service/Read", "module", now); err != nil {
		t.Fatalf("a token outliving the admission caps the span, not refuses it: %v", err)
	} else if call.Expires-call.Issued != int64(Lifetime/time.Second) {
		t.Fatalf("span %ds, want %ds", call.Expires-call.Issued, int64(Lifetime/time.Second))
	}
	if _, err := signer.Sign(token, "/pkg.Service/Read", "module", now, now.Unix()); err == nil {
		t.Fatal("signed expired capability")
	}
}
