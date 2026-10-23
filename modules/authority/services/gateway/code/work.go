package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"embed"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/codefly-dev/core/workloadidentity/native"

	"gateway/pkg/adapters"
	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/wiring"
)

// The fixtures this service can be run on: who exists, what they hold, what is
// installed. `--fixture <name>` selects one; nothing in them is an address or a key.
//
//go:embed fixtures/*.yaml
var fixtures embed.FS

// Audience is what the launcher's workload credentials are attested for.
const Audience = "https://authority.local.test"

// issuerName is the `iss` of every token this authority gateway signs: an identifier,
// not an address. A consumer verifies against Keys, never against this string.
const issuerName = "codefly.dev/authority/mini-gateway"

func init() {
	WithConfigure(configureMiniGateway)
	WithWork(func(context.Context) (Clean, error) { return nil, nil })
}

// configureMiniGateway builds the whole authority before the listeners start:
// the launcher's anchor from the run, the fixture named by the run, a signing
// key for this run, and the issuer over them. The registry's plugins read the
// result through the wiring package.
func configureMiniGateway(ctx context.Context, _ *adapters.Configuration) (Clean, error) {
	anchorPath := os.Getenv(native.AnchorEnvironment)
	if anchorPath == "" {
		return nil, fmt.Errorf("no launcher anchor: %s is unset, so no workload could be attested; run this service with codefly run", native.AnchorEnvironment)
	}
	anchor, err := native.ReadAnchor(anchorPath)
	if err != nil {
		return nil, fmt.Errorf("launcher anchor: %w", err)
	}
	st, err := state.New(anchor, Audience)
	if err != nil {
		return nil, err
	}
	name := os.Getenv("CODEFLY__FIXTURE")
	if name == "" {
		name = "local"
	}
	data, err := fixtures.ReadFile("fixtures/" + name + ".yaml")
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("fixture %q: this service carries no such fixture", name)
	}
	if err != nil {
		return nil, err
	}
	// A module composed before its organisations arrived gets its installation
	// when the fixture loads; a run composes modules through ApplyManifest.
	if err := st.LoadFixture(ctx, data); err != nil {
		return nil, fmt.Errorf("fixture %q: %w", name, err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	wiring.Set(st, issuer.New(st, issuerName, "run-"+time.Now().UTC().Format("20060102T150405Z"), signing, time.Now))
	return nil, nil
}
