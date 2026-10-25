// Package testkit composes a local authority for tests: the fixture, a launcher
// key, two modules and a solution, as a local run would deliver them.
package testkit

import (
	"crypto"

	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	delivery "github.com/codefly-dev/authority/libraries/delivery/go"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/solutionhost"
	"github.com/codefly-dev/core/workloadidentity"
	"github.com/codefly-dev/core/workloadidentity/native"

	conformance "github.com/codefly-dev/authority/libraries/conformance/go"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
)

// Kit is a composed local authority.
type Kit struct {
	State    *state.State
	Issuer   *issuer.Issuer
	Launcher *native.Issuer // the run's launcher, as the CLI is one
	Now      time.Time
}

// Audience is the name the launcher issues credentials to: this host.
const Audience = "https://authority.local.test"

// Workload is the process the launcher started for a module, as it declares it.
func Workload(module string) workloadidentity.Workload {
	return workloadidentity.Workload{TrustDomain: "local.test", Module: module, Service: module, Instance: module + "-1"}
}

// Credential is what the launcher signed for one module's process.
func (k *Kit) Credential(t *testing.T, module string) string {
	t.Helper()
	token, err := k.Launcher.Issue(native.Subject{Workload: Workload(module), Container: module}, Audience)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// Scope builds one scope.
func Scope(kind string, actions ...string) *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: kind, Actions: actions}
}

// Evaluation is the module whose kinds the fixture's evaluation grants name.
func Evaluation(generation uint64) state.Manifest {
	return state.Manifest{Module: "evaluation", Principal: "evaluation", Kind: "module", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("evaluation.runs", "read", "write"), Scope("evaluation.online", "read"), Scope("evaluation.definitions", "publish"),
			Scope("evaluation.datasets", "write"), Scope("evaluation.labels", "write", "approve", "admin")}}
}

// Documents is a module with one binding towards model.
func Documents(generation uint64) state.Manifest {
	return state.Manifest{Module: "documents", Principal: "documents", Kind: "module", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("documents", "read", "write", "ingest"), Scope("documents.collection", "read", "transfer", "admin")},
		Bindings: map[string]state.Binding{
			"model": {ID: "model", Audience: "model",
				InvokeScopes: []*basev0.WorkScopeV1{Scope("modelservice.profiles", "invoke", "read")}, HeadlessScopes: []*basev0.WorkScopeV1{Scope("modelservice.profiles", "invoke", "read")}},
			"runtime-admission": {ID: "runtime-admission", Audience: "runtime",
				InvokeScopes: []*basev0.WorkScopeV1{Scope("runtime.task", "admit", "read")}, HeadlessScopes: []*basev0.WorkScopeV1{Scope("runtime.task", "read")}},
		},
	}
}

// Model is the module documents calls.
func Model(generation uint64) state.Manifest {
	return state.Manifest{Module: "model", Principal: "model", Kind: "module", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("modelservice.profiles", "invoke", "read", "admin")}}
}

// Runtime is the module documents fans work out through.
func Runtime(generation uint64) state.Manifest {
	return state.Manifest{Module: "runtime", Principal: "runtime", Kind: "module", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("runtime.task", "admit", "read")}}
}

// Records is the module the directory page reads.
func Records(generation uint64) state.Manifest {
	return state.Manifest{Module: "records", Principal: "records", Kind: "module", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("records.records", "read", "write"), Scope("records.types", "read")}}
}

// OrgDirectory is a module with a page; it reads records for the viewer through
// its one binding, records, which is the binding its hop on the viewer's context
// names.
func OrgDirectory(generation uint64) state.Manifest {
	return state.Manifest{Module: "org-directory", Principal: "org-directory", Kind: "module", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("directory.entry", "read", "write")},
		Bindings: map[string]state.Binding{
			"records": {ID: "records", Audience: "records",
				InvokeScopes: []*basev0.WorkScopeV1{Scope("records.records", "read"), Scope("records.types", "read")}, HeadlessScopes: []*basev0.WorkScopeV1{Scope("records.types", "read")}},
			// The page asks documents for a person: the first hop of a delegate chain.
			"documents": {ID: "documents", Audience: "documents",
				InvokeScopes: []*basev0.WorkScopeV1{Scope("documents", "read", "write")}, HeadlessScopes: []*basev0.WorkScopeV1{Scope("documents", "read")},
				LookupScopes: []*basev0.WorkScopeV1{Scope("documents", "read")}},
		}}
}

// Wiki is a solution.
func Wiki(generation uint64) state.Manifest {
	return state.Manifest{Module: "wiki", Principal: "wiki", Kind: "solution", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("wiki.page", "read", "write", "publish")},
		Roles: map[string][]*basev0.WorkScopeV1{
			state.InstallerRole: {Scope("wiki.page", "read", "write", "publish")},
			"editor":            {Scope("wiki.page", "read", "write")},
			"viewer":            {Scope("wiki.page", "read")},
		}}
}

// ReleaseKeyID names the release key the kit pins; its seed is fixed so a run
// reproduces its signatures, and no deployed anchor ever pins it.
const ReleaseKeyID = "local-authority-release"

func releaseSigner() *solutionhost.InMemorySigner {
	seed := sha256.Sum256([]byte("local authority release key: " + ReleaseKeyID))
	signer, err := solutionhost.NewInMemorySigner(ReleaseKeyID, ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		panic(err)
	}
	return signer
}

// ReleaseVerifier pins the kit's release key for the host domain.
func ReleaseVerifier(t *testing.T, domain string) *solutionhost.Verifier {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(releaseSigner().Public())
	if err != nil {
		t.Fatal(err)
	}
	pem := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	keys, err := solutionhost.NewPinnedKeySet(solutionhost.PinnedKey{KeyID: ReleaseKeyID, PublicKeyPEM: pem, Kind: solutionhost.KeyKindRelease, OwnershipDomains: []string{domain}})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := solutionhost.NewVerifier(keys)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

// SignDocument signs a manifest document with the kit's release key: the DSSE
// envelope a carrier pairs with the document.
func SignDocument(document []byte) ([]byte, error) {
	return solutionhost.SignEnvelope(document, releaseSigner())
}

// SignAuthority signs the authority's own document with the same release key.
func SignAuthority(document []byte) ([]byte, error) {
	signer := releaseSigner()
	return delivery.Sign(document, signer.KeyID(), signer.Sign)
}

// ReleaseKeys pins the kit's release key by id, for the authority's document.
func ReleaseKeys() map[string]crypto.PublicKey {
	return map[string]crypto.PublicKey{ReleaseKeyID: releaseSigner().Public()}
}

// CarrierAuthority admits a credential as the named module's own workload under
// the launcher: on a native run the module's process delivers its own manifest.
// A module's first manifest arrives before it is composed, so the credential is
// attested by the anchor alone and not by the composition.
func (k *Kit) CarrierAuthority(ctx context.Context, credential, module string) error {
	attester, err := native.NewAttester(k.Launcher.Anchor())
	if err != nil {
		return err
	}
	attested, err := attester.Attest(ctx, credential, Audience)
	if err != nil {
		return err
	}
	if attested.Workload.Module != module {
		return fmt.Errorf("the carrier is %s, not %s", attested.Workload.Module, module)
	}
	return nil
}

// Proposals is a second solution, composed by tests that install one.
func Proposals(generation uint64) state.Manifest {
	return state.Manifest{Module: "proposals", Principal: "proposals", Kind: "solution", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("proposals.item", "read", "write")},
		Roles: map[string][]*basev0.WorkScopeV1{
			state.InstallerRole: {Scope("proposals.item", "read", "write")},
			"viewer":            {Scope("proposals.item", "read")},
		}}
}

// Matrix states what the fixture grants, allow and deny: the organisation's roles
// at module audiences, the installation's roles at the wiki, and nothing across
// organisations.
func Matrix() []conformance.Expectation {
	allow := func(token, audience, kind, action string) conformance.Expectation {
		return conformance.Expectation{Token: token, Audience: audience, Kind: kind, Action: action, Allowed: true}
	}
	deny := func(token, audience, kind, action string) conformance.Expectation {
		return conformance.Expectation{Token: token, Audience: audience, Kind: kind, Action: action}
	}
	return []conformance.Expectation{
		// Acme's organisation roles at documents and records.
		allow("fixture-maya", "documents", "documents", "read"), deny("fixture-maya", "documents", "documents", "write"),
		allow("fixture-remi", "documents", "documents", "write"), deny("fixture-remi", "documents", "documents", "ingest"),
		allow("fixture-alex", "documents", "documents", "ingest"), allow("fixture-alex", "documents", "documents.collection", "admin"),
		deny("fixture-alex", "documents", "documents.collection", "share"),
		allow("fixture-maya", "records", "records.records", "read"), deny("fixture-maya", "records", "records.records", "write"),
		allow("fixture-remi", "records", "records.records", "write"), deny("fixture-remi", "records", "records.types", "write"),
		// Evaluation (a module the kit composes for this matrix): a viewer reads
		// runs and scores, an editor runs an evaluation, an admin publishes and
		// approves, and nobody but the developer approves what they wrote and
		// runs it too.
		allow("fixture-maya", "evaluation", "evaluation.runs", "read"), deny("fixture-maya", "evaluation", "evaluation.runs", "write"),
		allow("fixture-remi", "evaluation", "evaluation.runs", "write"), allow("fixture-remi", "evaluation", "evaluation.online", "read"),
		deny("fixture-remi", "evaluation", "evaluation.labels", "approve"), allow("fixture-alex", "evaluation", "evaluation.labels", "approve"),
		allow("fixture-alex", "evaluation", "evaluation.definitions", "publish"), deny("fixture-alex", "evaluation", "evaluation.runs", "write"),
		allow("fixture-dev", "evaluation", "evaluation.labels", "approve"), allow("fixture-dev", "evaluation", "evaluation.runs", "write"),
		// A module no role names: nothing.
		deny("fixture-maya", "model", "modelservice.profiles", "read"),
		// The wiki: the installation's roles, not the organisation's. Rémi, an
		// editor of documents, is a viewer at the wiki like Maya.
		allow("fixture-alex", "wiki", "wiki.page", "publish"), allow("fixture-maya", "wiki", "wiki.page", "read"),
		deny("fixture-maya", "wiki", "wiki.page", "write"), allow("fixture-remi", "wiki", "wiki.page", "read"),
		deny("fixture-remi", "wiki", "wiki.page", "write"),
		// Globex: its own installation of the wiki, and a documents role of its own.
		allow("fixture-zoe", "wiki", "wiki.page", "publish"), allow("fixture-omar", "wiki", "wiki.page", "write"),
		deny("fixture-omar", "wiki", "wiki.page", "publish"), allow("fixture-zoe", "documents", "documents", "write"),
		allow("fixture-zoe", "documents", "documents.collection", "read"),
		deny("fixture-omar", "documents", "documents.collection", "read"),
		deny("fixture-omar", "documents", "documents", "read"),
	}
}

// FixturePath is the committed fixture.
func FixturePath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "fixtures", "local.yaml")
}

// New composes documents, model and the fixture, then installs the wiki from it.
func New(t *testing.T) *Kit {
	t.Helper()
	launcher, err := native.NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	// The launcher declares the processes it starts, one per module; its anchor
	// vouches for exactly those.
	// The suite's own modules are declared too: the suite delivers their
	// manifests from their own workloads.
	// robin and assistant are declared for the artifact tests, which compose
	// them themselves.
	for _, module := range []string{"model", "runtime", "records", "org-directory", "documents", "wiki", "proposals", "conformance-probe", "conformance-uninstalled", "conformance-solution", "conformance-methods", "robin", "assistant", "evaluation"} {
		launcher.Declare(Workload(module))
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	started := time.Now()
	st, err := state.New(launcher.Anchor(), Audience)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []state.Manifest{Model(1), Runtime(1), Records(1), OrgDirectory(1), Documents(1), Wiki(1), Evaluation(1)} {
		if _, err := st.ApplyManifest(m); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(FixturePath())
	if err != nil {
		t.Fatal(err)
	}
	// The fixture must be loaded after the modules are composed, because it
	// installs the wiki and a module installation exists per organisation.
	if err := st.LoadFixture(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	return &Kit{State: st, Launcher: launcher, Now: now,
		// The clock starts at a fixed instant, for readable timestamps, and
		// advances with the wall clock, so a window closes as it would on a laptop.
		Issuer: issuer.New(st, Audience, "local-1", signing, func() time.Time { return now.Add(time.Since(started)) })}
}
