package hop_test

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// robin #512 finding 2 and evaluation #91 finding 1: a genuinely signed,
// single-use read capability cannot carry a captured read admission to a write.
func TestReviewReadStampCannotRetargetOrReplayAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	a := hoptest.New(t)
	token := a.IssueSingleUse(t, "documents", read)
	const readMethod = "/documents.v1.Service/Get"
	md := hoptest.Forward(t, token, proof, readMethod)
	store := hoptest.Replay()
	v, err := hop.NewVerifier(ctx, a.PublishHop(proof), "documents", store)
	if err != nil {
		t.Fatal(err)
	}
	replica, err := hop.NewVerifier(ctx, a.PublishHop(proof), "documents", store)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"/documents.v1.Service/Delete", "/datasets.v1.Service/Register", "Get", "", "POST " + readMethod} {
		if _, err := v.Verify(ctx, md, method); err == nil || !strings.Contains(err.Error(), "stamp_method") {
			t.Fatalf("retarget to %q: %v", method, err)
		}
	}
	other, _ := hop.NewVerifier(ctx, a.PublishHop(proof), "records", store)
	if _, err := other.Verify(ctx, md, readMethod); err == nil || !strings.Contains(err.Error(), "stamp_audience") {
		t.Fatalf("other audience: %v", err)
	}
	// Refused retargeting does not poison the legitimate reservation.
	if _, err := v.Verify(ctx, md, readMethod); err != nil {
		t.Fatal(err)
	}
	for _, verifier := range []*hop.Verifier{v, replica} {
		if _, err := verifier.Verify(ctx, md, readMethod); err == nil || !strings.Contains(err.Error(), "stamp_replayed") {
			t.Fatalf("replay admitted: %v", err)
		}
	}
}

func TestReviewZeroScopeSharedProofCannotFabricateAdmission(t *testing.T) {
	a := hoptest.New(t)
	token := a.Issue(t, "documents") // genuine zero-scope capability from evaluation probe
	md := hoptest.Forward(t, token, proof, "/datasets.v1.Service/Register")
	md.Set(hop.ProofKey, proof) // the old shared secret and a matching token digest
	if _, err := verifier(t, a, "documents").Verify(context.Background(), md, "/datasets.v1.Service/Register"); err == nil {
		t.Fatal("shared proof fabricated admission")
	}
}

func TestConcurrentReplayHasOneWinnerAcrossVerifiers(t *testing.T) {
	a := hoptest.New(t)
	store := hoptest.Replay()
	first, _ := hop.NewVerifier(context.Background(), a.PublishHop(proof), "documents", store)
	second, _ := hop.NewVerifier(context.Background(), a.PublishHop(proof), "documents", store)
	md := hoptest.Forward(t, a.IssueSingleUse(t, "documents", read), proof, "/documents.v1.Service/Get")
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for n := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := []*hop.Verifier{first, second}[n%2]
			if _, err := v.Verify(context.Background(), md, "/documents.v1.Service/Get"); err == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d times", accepted.Load())
	}
}

func TestUnaryAndStreamInterceptorsBindTheObservedProcedure(t *testing.T) {
	a := hoptest.New(t)
	v := verifier(t, a, "documents")
	md := hoptest.Forward(t, a.Issue(t, "documents", read), proof, "/documents.v1.Service/Get")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	reached := false
	_, err := v.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/documents.v1.Service/Delete"}, func(context.Context, any) (any, error) { reached = true; return nil, nil })
	if err == nil || reached {
		t.Fatal("unary reached retargeted handler")
	}
	err = v.StreamServerInterceptor()(nil, bindingStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: "/documents.v1.Service/Delete"}, func(any, grpc.ServerStream) error { reached = true; return nil })
	if err == nil || reached {
		t.Fatal("stream reached retargeted handler")
	}
}

type bindingStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s bindingStream) Context() context.Context { return s.ctx }

func TestAdvisoryRefusalCannotBecomeASignedAdmission(t *testing.T) {
	a := hoptest.New(t)
	token := a.Issue(t, "documents", read)
	md := metadata.Pairs(hop.WorkContextKey, token)
	if err := hop.Stamp(md, hop.Identity{Advisory: "write scope missing"}, hoptest.Signer(proof), "/documents.v1.Service/Delete", "documents", time.Now()); err == nil {
		t.Fatal("signed an advisory refusal")
	}
	if len(md.Get(hop.ProofKey)) != 0 {
		t.Fatal("refusal leaked a usable proof")
	}
}
