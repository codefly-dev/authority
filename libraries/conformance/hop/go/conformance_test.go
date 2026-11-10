package hopconformance_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	hopconformance "github.com/codefly-dev/authority/libraries/conformance/hop/go"
	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/forward"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
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

// The library's front door (forward.New) is what the authority module's hop
// service stands: modules/authority/services/hop hands it exactly what Codefly
// delivers, so the hop the authority module ships is proved here. Another host
// (a gateway standing as the hop on a cell) runs RunFront with its own Stand.
func TestTheGoFrontDoorPassesTheHopFrontTarget(t *testing.T) {
	hopconformance.RunFront(t, hopconformance.FrontTarget{Stand: func(ctx context.Context, authority forward.Authority, modules []string, routes string) (http.Handler, func(), error) {
		front, err := forward.New(ctx, forward.Config{
			Signer: hoptest.Signer("front-target"), Authority: authority,
			// A workload credential names the audience it proves itself to.
			Credential: func() (string, error) { return "header.eyJhdWQiOiJhdXRob3JpdHkifQ.signature", nil },
			Modules:    modules, Routes: routes,
		})
		if err != nil {
			return nil, nil, err
		}
		return front.Handler, front.Close, nil
	}})
}
