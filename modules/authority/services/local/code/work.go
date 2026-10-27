package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"embed"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/codefly-dev/core/wool"
	"github.com/codefly-dev/core/workloadidentity"
	"github.com/codefly-dev/core/workloadidentity/native"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/jackc/pgx/v5/pgxpool"

	"gateway/pkg/adapters"
	"gateway/pkg/business/delivery"
	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/infra/postgres"
	"gateway/pkg/wiring"
)

// The fixtures this service can be run on: who exists, what they hold, what is
// installed. `--fixture <name>` selects one; nothing in them is an address or a key.
//
//go:embed fixtures/*.yaml
var fixtures embed.FS

// Audience is what the launcher's workload credentials are attested for.
const Audience = "https://authority.local.test"

// issuerName is the `iss` of every token this local authority signs: an identifier,
// not an address. Consumers validate this issuer along with its published Keys.
const issuerName = "codefly.dev/authority/local"

func init() {
	WithConfigure(configureLocalAuthority)
	WithWork(func(context.Context) (Clean, error) { return nil, nil })
}

// configureLocalAuthority builds the whole authority before the listeners start:
// the launcher's anchor from the run, the fixture named by the run, a signing
// key for this run, and the issuer over them. The registry's plugins read the
// result through the wiring package.
func configureLocalAuthority(ctx context.Context, _ *adapters.Configuration) (Clean, error) {
	// The fixture's people and the composition's grants are a laptop's: never
	// boot them in a pod, whatever anchor it was handed.
	if native.InPod() {
		return nil, errors.New("the local authority runs on a laptop only: it refuses to start in a pod")
	}
	anchorPath := os.Getenv(native.AnchorEnvironment)
	if anchorPath == "" {
		return nil, fmt.Errorf("no launcher anchor: %s is unset, so no workload could be attested; run this service with codefly run", native.AnchorEnvironment)
	}
	anchor, err := native.ReadAnchor(anchorPath)
	if err != nil {
		return nil, fmt.Errorf("launcher anchor: %w", err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	keyID := "run-" + time.Now().UTC().Format("20060102T150405Z")
	st, err := state.New(anchor, Audience, issuer.Config(issuerName, keyID, signing, time.Now))
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
	if err := applyComposition(ctx, st); err != nil {
		return nil, err
	}
	clean, err := approvalsFor(ctx, st)
	if err != nil {
		return nil, err
	}
	// Keys publishes the hop's admission key once the hop registers it
	// (RegisterAdmissionKey): nothing about the hop is configured here.
	wiring.Set(st, issuer.New(st, issuerName, keyID, signing.Public().(ed25519.PublicKey)))
	// A delivery is verified against the policy the run wrote for its host, and
	// carried only by the module's own delivery workload, attested by the
	// anchor. With no policy the carrier path refuses by name and says so.
	if dir := os.Getenv(delivery.TrustAnchorEnvironment); dir != "" {
		coordinate, err := codefly.For(ctx).WorkspaceValue("federation", "SOLUTION_HOST_COORDINATE")
		if err != nil || strings.TrimSpace(coordinate) == "" {
			return nil, fmt.Errorf("signed delivery requires the host's federation/SOLUTION_HOST_COORDINATE configuration")
		}
		wiring.SetCoordinate(coordinate)
		verifier, keys, err := delivery.VerifierFromDirectory(dir)
		if err != nil {
			return nil, fmt.Errorf("delivery trust: %w", err)
		}
		attester, err := native.NewAttester(anchor)
		if err != nil {
			return nil, err
		}
		wiring.SetDelivery(verifier, keys, func(ctx context.Context, credential, module string) error {
			attested, err := attester.Attest(ctx, credential, Audience)
			if err != nil {
				return err
			}
			if attested.Workload.Module != module || attested.Workload.Service != workloadidentity.DeliveryService {
				return fmt.Errorf("the carrier is %s/%s, not %s's delivery workload", attested.Workload.Module, attested.Workload.Service, module)
			}
			return nil
		})
	}
	return clean, nil
}

// applyComposition adds the composition's part of the fixture: the workspace
// configuration document fixture-composition, which the run merges from the
// fragment every composed module ships next to its code and the composition's
// own (libraries/fixture-composition). A document that does not read, or that
// the fixture refuses, refuses to boot.
func applyComposition(ctx context.Context, st *state.State) error {
	w := wool.Get(ctx).In("local")
	document, err := codefly.For(ctx).WorkspaceConfigurationDocument(state.CompositionDocument)
	if errors.Is(err, codefly.ErrConfigurationDocumentMissing) {
		return fmt.Errorf("no %s document was delivered; the run merges one from the composed modules' fragments (codefly generate %s), so this run did not compose it", state.CompositionDocument, state.CompositionDocument)
	}
	if err != nil {
		return err
	}
	lines, err := st.ApplyComposition(ctx, document)
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		w.Info("the composition adds nothing to the fixture")
	}
	for _, line := range lines {
		w.Info("the composition " + line)
	}
	return nil
}

// approvalsFor chooses where consent lives. The store is a declared dependency
// (service.codefly.yaml), so a run that composes it starts it first and
// delivers its read-write connection: approvals then persist there, and a
// restart still answers a run. A run that composes no store — `go test`
// through the testkit, a run selecting the local authority alone — delivers no
// connection and keeps them in memory. The boot line says which. A delivered
// connection that does not answer is refused, not fallen back from: the store
// was composed, so a local authority forgetting consent would be the wrong local authority.
func approvalsFor(ctx context.Context, st *state.State) (Clean, error) {
	w := wool.Get(ctx).In("local")
	connection, err := codefly.For(ctx).Service("store").Secret("postgres", "read-write-connection")
	if err != nil || strings.TrimSpace(connection) == "" {
		w.Info("approvals live in memory: this run composes no store, so a restart forgets consent")
		return nil, nil
	}
	pool, err := pgxpool.New(ctx, connection)
	if err != nil {
		return nil, fmt.Errorf("the store's read-write connection: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("the store is composed but does not answer: %w", err)
	}
	st.Approvals = postgres.NewApprovals(pool)
	w.Info("approvals persist in the authority's store")
	return pool.Close, nil
}
