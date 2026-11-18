package forward_test

import (
	"context"
	"testing"

	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"google.golang.org/grpc/metadata"
)

// The credentials a caller holds are for the hop and whoever stood before it:
// the session a browser sent, a bearer for another service. A module behind
// the hop receives the Work Context the authority checked and the hop's
// stamp, and no credential of the caller's. What names the caller's
// operation, not who it is, still arrives: modules read the effect id, the
// Idempotency-Key and the operation id to apply an effect once.
func TestTheHopForwardsNoCallerCredentialToTheModule(t *testing.T) {
	through, _, m, a, _ := setup(t)
	token := a.Issue(t, "console", identityRead)
	ctx := metadata.AppendToOutgoingContext(context.Background(), hop.WorkContextKey, token,
		"authorization", "Bearer the-callers-session", "cookie", "session=the-callers-session", "proxy-authorization", "Basic Zm9vOmJhcg==",
		"idempotency-key", "op-1", "x-codefly-effect-id", "effect-1", "x-codefly-operation-id", "operation-1", "traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	if _, err := version(ctx, through); err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{"authorization", "cookie", "proxy-authorization"} {
		if got := m.received.Get(credential); len(got) != 0 {
			t.Errorf("the module received the caller's %s: %v", credential, got)
		}
	}
	for key, want := range map[string]string{hop.WorkContextKey: token, "idempotency-key": "op-1", "x-codefly-effect-id": "effect-1", "x-codefly-operation-id": "operation-1",
		"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"} {
		if got := m.received.Get(key); len(got) != 1 || got[0] != want {
			t.Errorf("the module received %s %v, want %q", key, got, want)
		}
	}
}
