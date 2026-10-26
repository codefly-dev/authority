package hop_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"
	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const proof = "run-proof"

var read = &basev0.WorkScopeV1{ResourceKind: "documents", Actions: []string{"read"}}

func verifier(t *testing.T, a *hoptest.Authority, audience string) *hop.Verifier {
	t.Helper()
	v, err := hop.NewVerifier(context.Background(), a, audience, proof)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestTheModuleReadsWhoTheCallIsForFromTheAuthenticatedToken(t *testing.T) {
	a := hoptest.New(t)
	token := a.Issue(t, "documents", read)
	id, err := verifier(t, a, "documents").Verify(context.Background(), hoptest.Forward(t, token, proof))
	if err != nil {
		t.Fatal(err)
	}
	if id.Owner != "principal-owner" || id.Tenant != "tenant-conformance" || !id.Has("documents", "read") || id.Has("documents", "write") || id.Context != token || !id.Claims.Allows("documents", "read", "any") {
		t.Fatalf("identity: %+v", id)
	}
}

// The defect: every hop-fronted module holds the proof, so it can write the
// proof and the digest of any token. Nothing but the authority's signature,
// addressed to this module and current, is believed.
func TestAModuleHoldingTheProofCannotForgeAContext(t *testing.T) {
	a := hoptest.New(t)
	v := verifier(t, a, "documents")
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	genuine := a.Issue(t, "documents", read)
	payload, _, _ := strings.Cut(genuine, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(payload)
	forged := payload + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(otherKey, raw))
	unsigned := payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	elsewhere := a.Issue(t, "records", read)

	cases := map[string]struct {
		md     metadata.MD
		reason string
	}{
		"forged signature":   {stampedAs(t, a, forged, genuine), "signature"},
		"unsigned":           {stampedAs(t, a, unsigned, genuine), "signature"},
		"another audience":   {hoptest.Forward(t, elsewhere, proof), "audience"},
		"no stamp":           {metadata.Pairs(hop.WorkContextKey, genuine), "proof"},
		"another run's hop":  {hoptest.Forward(t, genuine, "another-run"), "proof"},
		"swapped token":      {swapped(hoptest.Forward(t, genuine, proof), a.Issue(t, "documents", read)), "does not match the hop stamp"},
		"stamped tenant lie": {with(hoptest.Forward(t, genuine, proof), hop.TenantKey, "globex"), "stamp_identity"},
		"stamped scope lie":  {with(hoptest.Forward(t, genuine, proof), hop.ScopesKey, "documents:read,documents:admin"), "stamp_identity"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), c.md)
			if !errors.Is(err, workcontext.ErrUnauthenticated) || !strings.Contains(err.Error(), c.reason) {
				t.Fatalf("want a refusal naming %q, got %v", c.reason, err)
			}
		})
	}
}

// stampedAs forwards token under the stamp the hop wrote for genuine, with the
// digest rewritten, as any holder of the proof can.
func stampedAs(t *testing.T, _ *hoptest.Authority, token, genuine string) metadata.MD {
	md := hoptest.Forward(t, genuine, proof)
	sum := sha256.Sum256([]byte(token))
	md.Set(hop.WorkContextKey, token)
	md.Set(hop.ContextKey, hex.EncodeToString(sum[:]))
	return md
}

// swapped replaces the token and keeps the digest of the one the hop checked.
func swapped(md metadata.MD, token string) metadata.MD {
	md.Set(hop.WorkContextKey, token)
	return md
}

func with(md metadata.MD, key, value string) metadata.MD {
	md.Set(key, value)
	return md
}

func TestTheInterceptorRefusesByNameAndLetsHealthThrough(t *testing.T) {
	a := hoptest.New(t)
	intercept := verifier(t, a, "console").UnaryServerInterceptor()
	handler := func(ctx context.Context, _ any) (any, error) {
		id, _ := hop.FromContext(ctx)
		return id.Owner, nil
	}
	call := func(md metadata.MD, method string) (any, error) {
		return intercept(metadata.NewIncomingContext(context.Background(), md), nil, &grpc.UnaryServerInfo{FullMethod: method}, handler)
	}
	if _, err := call(metadata.MD{}, "/api.ApiService/WhoAmI"); status.Code(err) != codes.Unauthenticated || !strings.Contains(err.Error(), "proof") {
		t.Fatalf("no stamp: %v", err)
	}
	if got, err := call(hoptest.Forward(t, a.Issue(t, "console", read), proof), "/api.ApiService/WhoAmI"); err != nil || got != "principal-owner" {
		t.Fatalf("forwarded: %v %v", got, err)
	}
	if _, err := call(metadata.MD{}, "/grpc.health.v1.Health/Check"); err != nil {
		t.Fatalf("the run probes health directly: %v", err)
	}
	for _, method := range []string{"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", "/grpc.health.v1.HealthX/Check"} {
		if _, err := call(metadata.MD{}, method); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("%s passed unstamped: %v", method, err)
		}
	}
}

func TestAVerifierNeedsPublishedKeysAnAudienceAndAProof(t *testing.T) {
	a := hoptest.New(t)
	for name, build := range map[string]func() (*hop.Verifier, error){
		"no keys":     func() (*hop.Verifier, error) { return hop.NewVerifier(context.Background(), nil, "documents", proof) },
		"no audience": func() (*hop.Verifier, error) { return hop.NewVerifier(context.Background(), a, "", proof) },
		"no proof":    func() (*hop.Verifier, error) { return hop.NewVerifier(context.Background(), a, "documents", "") },
	} {
		if _, err := build(); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestTheAudienceIsTheModuleTheCompositionStarted(t *testing.T) {
	t.Setenv("CODEFLY__MODULE", "documents")
	if got, err := hop.Audience(); err != nil || got != "documents" {
		t.Fatalf("audience: %q %v", got, err)
	}
	t.Setenv("CODEFLY__MODULE", "")
	if _, err := hop.Audience(); err == nil {
		t.Fatal("a process the composition names no module for has no audience")
	}
}
