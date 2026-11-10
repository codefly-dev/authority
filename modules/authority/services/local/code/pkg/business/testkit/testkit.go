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

// HopWorkload is the hop as the launcher starts it: the authority module's
// hop service, the one workload that registers admission keys.
// EdgeWorkload is the module edge's process, as the launcher declares it.
func EdgeWorkload() workloadidentity.Workload {
	return workloadidentity.Workload{TrustDomain: HopWorkload().TrustDomain, Module: issuer.EdgeModule, Service: issuer.EdgeService, Instance: "edge-1"}
}

func HopWorkload() workloadidentity.Workload {
	return workloadidentity.Workload{TrustDomain: "local.test", Module: issuer.HopModule, Service: issuer.HopService, Instance: "hop-1"}
}

// HopCredential is what the launcher signed for the hop's process.
func (k *Kit) HopCredential(t *testing.T) string {
	t.Helper()
	return k.HopInstanceCredential(t, HopWorkload().Instance)
}

// EdgeCredential is what the launcher signed for the module edge's process.
func (k *Kit) EdgeCredential(t *testing.T) string {
	t.Helper()
	token, err := k.Launcher.Issue(native.Subject{Workload: EdgeWorkload(), Container: issuer.EdgeService}, Audience)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// HopInstanceCredential is what the launcher signed for one hop process,
// named by its instance: another instance is another hop process (a
// restart under a new instance, or a rotation's new hop).
func (k *Kit) HopInstanceCredential(t *testing.T, instance string) string {
	t.Helper()
	workload := HopWorkload()
	workload.Instance = instance
	token, err := k.Launcher.Issue(native.Subject{Workload: workload, Container: issuer.HopService}, Audience)
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
	return state.Manifest{Name: "evaluation", Principal: "evaluation", Kind: "module", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("evaluation.runs", "read", "write"), Scope("evaluation.online", "read"), Scope("evaluation.definitions", "publish"),
			Scope("evaluation.datasets", "write"), Scope("evaluation.labels", "write", "approve", "admin")}}
}

// Documents is a module with one binding towards model. It checks owners, as
// the document store does: an organization role reaches nothing there on a
// person's own session (RBAC-4a); a solution's role and an installation reach
// their own principal's data.
func Documents(generation uint64) state.Manifest {
	return state.Manifest{Name: "documents", Principal: "documents", Kind: "module", Generation: generation, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("documents", "read", "write", "ingest"), Scope("documents.collection", "read", "transfer", "admin")},
		Bindings: map[string]state.Binding{
			"model": {ID: "model", Audience: "model",
				InvokeScopes: []*basev0.WorkScopeV1{Scope("modelservice.profiles", "invoke", "read"), Scope("modelservice.datasets", "read")}, HeadlessScopes: []*basev0.WorkScopeV1{Scope("modelservice.profiles", "invoke", "read")}},
			"runtime-admission": {ID: "runtime-admission", Audience: "runtime",
				InvokeScopes: []*basev0.WorkScopeV1{Scope("runtime.task", "admit", "read")}, HeadlessScopes: []*basev0.WorkScopeV1{Scope("runtime.task", "read")}},
		},
	}
}

// Model is the module documents calls. It checks owners of its datasets; its
// profiles are shared, so an organization role reaches them on a person's own
// session and an installation's datasets are its own.
func Model(generation uint64) state.Manifest {
	return state.Manifest{Name: "model", Principal: "model", Kind: "module", Generation: generation, OwnerAware: true,
		SharedKinds:   []string{"modelservice.profiles"},
		ResourceKinds: []*basev0.WorkScopeV1{Scope("modelservice.profiles", "invoke", "read", "admin"), Scope("modelservice.datasets", "read")}}
}

// Runtime is the module documents fans work out through.
func Runtime(generation uint64) state.Manifest {
	return state.Manifest{Name: "runtime", Principal: "runtime", Kind: "module", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("runtime.task", "admit", "read")}}
}

// Records is the module the directory page reads. It checks no owner, as the
// record store does, so a person's organization roles reach it on their own
// session; it calls the model as documents does, so a person's chain crosses
// modules their organization roles reach.
func Records(generation uint64) state.Manifest {
	return state.Manifest{Name: "records", Principal: "records", Kind: "module", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("records.records", "read", "write"), Scope("records.types", "read"), Scope("records.collection", "read", "admin")},
		Bindings:      map[string]state.Binding{"model": Documents(generation).Bindings["model"]}}
}

// OrgDirectory is a module with a page; it reads and writes records for the
// viewer through its binding records, which is the binding its hop on the
// viewer's context names, and a lookup through it reads alone. It checks no
// owner, as the directory does.
func OrgDirectory(generation uint64) state.Manifest {
	return state.Manifest{Name: "org-directory", Principal: "org-directory", Kind: "module", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("directory.entry", "read", "write")},
		Bindings: map[string]state.Binding{
			"records": {ID: "records", Audience: "records",
				InvokeScopes: []*basev0.WorkScopeV1{Scope("records.records", "read", "write")}, HeadlessScopes: []*basev0.WorkScopeV1{Scope("records.records", "read")},
				LookupScopes: []*basev0.WorkScopeV1{Scope("records.records", "read")}},
			// The page asks documents for a person: the first hop of a delegate chain.
			"documents": {ID: "documents", Audience: "documents",
				InvokeScopes: []*basev0.WorkScopeV1{Scope("documents", "read", "write")}, HeadlessScopes: []*basev0.WorkScopeV1{Scope("documents", "read")},
				LookupScopes: []*basev0.WorkScopeV1{Scope("documents", "read")}},
		}}
}

// Wiki is a solution.
func Wiki(generation uint64) state.Manifest {
	return state.Manifest{Name: "wiki", Principal: "wiki", Kind: "solution", Generation: generation, OwnerAware: true,
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
	return releaseVerifier(t, domain, releaseSigner())
}

// NewRelease gives an isolated fixture its own delivery signing key and trust.
func NewRelease(t *testing.T, domain string) (*solutionhost.InMemorySigner, *solutionhost.Verifier) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := solutionhost.NewInMemorySigner(ReleaseKeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	return signer, releaseVerifier(t, domain, signer)
}

func releaseVerifier(t *testing.T, domain string, signer *solutionhost.InMemorySigner) *solutionhost.Verifier {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
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
	return state.Manifest{Name: "proposals", Principal: "proposals", Kind: "solution", Generation: generation, OwnerAware: true,
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
		// Acme's organisation roles name documents, but documents checks
		// owners: on a person's own session they reach none of it, the
		// administrator's included (RBAC-4a). Records checks no owner, so the
		// same roles reach it.
		deny("fixture-maya", "documents", "documents", "read"), deny("fixture-maya", "documents", "documents", "write"),
		deny("fixture-remi", "documents", "documents", "write"), deny("fixture-remi", "documents", "documents", "ingest"),
		deny("fixture-alex", "documents", "documents", "ingest"), deny("fixture-alex", "documents", "documents.collection", "admin"),
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
		// Globex: its own installation of the wiki, and a documents role of its
		// own, which reaches nothing there on Zoe's own session either.
		allow("fixture-zoe", "wiki", "wiki.page", "publish"), allow("fixture-omar", "wiki", "wiki.page", "write"),
		deny("fixture-omar", "wiki", "wiki.page", "publish"), deny("fixture-zoe", "documents", "documents", "write"),
		deny("fixture-zoe", "documents", "documents.collection", "read"),
		deny("fixture-omar", "documents", "documents.collection", "read"),
		deny("fixture-omar", "documents", "documents", "read"),
	}
}

// FixturePath is the committed fixture.
func FixturePath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "fixtures", "local.yaml")
}

// CompositionPath is the test kit's fixture-composition document.
func CompositionPath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "testdata", "composition.yaml")
}

// DefaultCompositionPath is the empty fixture-composition document the
// authority module ships for a composition that supplies none.
func DefaultCompositionPath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "..", "..", "configurations", "local", "fixture-composition.yaml")
}

// Bare is a state and an issuer with nothing composed and no fixture loaded.
func Bare(t *testing.T) *Kit {
	t.Helper()
	// Existing fixtures keep their readable epoch and advancing wall clock.
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	started := time.Now()
	k := bareWithClock(t, func() time.Time { return now.Add(time.Since(started)) })
	k.Now = now
	return k
}

func bareWithClock(t *testing.T, clock func() time.Time) *Kit {
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
	for _, module := range []string{"model", "runtime", "records", "org-directory", "documents", "wiki", "proposals", "conformance-probe", "conformance-uninstalled", "conformance-solution", "conformance-methods", "robin", "assistant", "evaluation", "principal-a", "principal-b", "principal-c", "principal-store", "principal-legacy-store", "conformance-owner-a", "conformance-owner-b", "conformance-store", "conformance-declared", "conformance-declared-store", "conformance-page-module", "conformance-page-calls", "conformance-page-ledger", "conformance-page-store", "conformance-page-attach", "conformance-headless-roles", "conformance-redelivered", "conformance-reach", "conformance-reach-store"} {
		launcher.Declare(Workload(module))
	}
	launcher.Declare(HopWorkload())
	launcher.Declare(EdgeWorkload())
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.New(launcher.Anchor(), Audience, issuer.Config(Audience, "local-1", signing, clock))
	if err != nil {
		t.Fatal(err)
	}
	return &Kit{State: st, Launcher: launcher, Now: clock(), Issuer: issuer.New(st, Audience, "local-1", signing.Public().(ed25519.PublicKey))}
}

// New composes the suite's modules, loads the fixture, and applies the test
// kit's composition document, which grants their kinds and installs the wiki.
func New(t *testing.T) *Kit {
	t.Helper()
	return compose(t, Bare(t))
}

// NewWithClock composes an isolated host using the caller's issuance/check clock.
func NewWithClock(t *testing.T, clock func() time.Time) *Kit {
	t.Helper()
	return compose(t, bareWithClock(t, clock))
}

func compose(t *testing.T, k *Kit) *Kit {
	t.Helper()
	for _, m := range []state.Manifest{Model(1), Runtime(1), Records(1), OrgDirectory(1), Documents(1), Wiki(1), Evaluation(1)} {
		if _, err := k.State.ApplyManifest(m); err != nil {
			t.Fatal(err)
		}
	}
	// The fixture and the composition are loaded after the modules are
	// composed: a module installation exists per organisation, and the
	// composition installs the wiki.
	for _, load := range []struct {
		path  string
		apply func([]byte) error
	}{
		{FixturePath(), func(data []byte) error { return k.State.LoadFixture(context.Background(), data) }},
		{CompositionPath(), func(data []byte) error { _, err := k.State.ApplyComposition(context.Background(), data); return err }},
	} {
		data, err := os.ReadFile(load.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := load.apply(data); err != nil {
			t.Fatal(err)
		}
	}
	return k
}
