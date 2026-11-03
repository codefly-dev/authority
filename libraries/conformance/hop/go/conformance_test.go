package hopconformance_test

import (
	"context"
	"testing"
	"time"

	hopconformance "github.com/codefly-dev/authority/libraries/conformance/hop/go"
	hop "github.com/codefly-dev/authority/libraries/hop/go"
	core "github.com/codefly-dev/core/workcontext"
)

// The Go verifier, libraries/hop/go, is the first implementation the target
// proves; a second runs the same Run with its own New.
func TestTheGoVerifierPassesTheHopConformanceTarget(t *testing.T) {
	hopconformance.Run(t, hopconformance.Target{New: func(ctx context.Context, keys hop.KeySource, audience string, replay core.ReplayStore, now func() time.Time) (hopconformance.Verifier, error) {
		v, err := hop.NewVerifier(ctx, keys, audience, replay, hop.Clock(now))
		if err != nil {
			return nil, err
		}
		return v, nil
	}})
}
