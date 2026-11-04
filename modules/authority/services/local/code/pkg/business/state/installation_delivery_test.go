package state

import (
	"context"
	"errors"
	"net/url"
	"testing"
)

func TestCallbackTransportDeadlineAndCancellation(t *testing.T) {
	clientTimeout := &url.Error{Op: "Post", URL: "https://example.invalid", Err: context.DeadlineExceeded}
	if err := callbackTransportError(context.Background(), clientTimeout); !errors.Is(err, ErrInstallationTransient) {
		t.Fatalf("client timeout: %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := callbackTransportError(cancelled, clientTimeout); !errors.Is(err, context.Canceled) || errors.Is(err, ErrInstallationTransient) {
		t.Fatalf("cancellation: %v", err)
	}
	if err := callbackTransportError(context.Background(), errors.New("certificate refused")); errors.Is(err, ErrInstallationTransient) {
		t.Fatalf("permanent failure: %v", err)
	}
}
