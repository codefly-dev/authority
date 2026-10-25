package composition

import (
	"context"
	"errors"
	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"gateway/pkg/business/testkit"
	compositionv1 "gateway/pkg/gen/host/composition/v1"
	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/protobuf/proto"
)

// rewriteCarrier signs a distinct, valid carrier through the same release key
// as the existing public ApplyManifest tests. It never changes attested bytes
// after signing, and deliberately carries no authority sidecar.
func rewriteCarrier(t *testing.T, request *compositionv1.ApplyManifestRequest, change func(*solutionhost.ModuleManifest)) *compositionv1.ApplyManifestRequest {
	t.Helper()
	out := proto.Clone(request).(*compositionv1.ApplyManifestRequest)
	manifest, err := solutionhost.ManifestFromVerified(out.Carrier.Document)
	if err != nil {
		t.Fatal(err)
	}
	change(manifest)
	document, err := solutionhost.SignedPayload(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := testkit.SignDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	out.Carrier = &compositionv1.SignedManifestV1{Document: document, Envelope: envelope}
	out.Authority = nil
	return out
}

func TestSignedCarrierIdenticalReplayReturnsTheAppliedReceipt(t *testing.T) {
	p, k := verifying(t)
	req := carrier(t, k, "conformance-probe", solutionhost.KindModule, 1, []string{"conformance.page"}, &compositionv1.AuthorityManifestV1{ScopeCeilings: []*authorityv1.WorkScopeV1{scope("conformance.page", "read")}})
	first, err := p.ApplyManifest(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := p.ApplyManifest(context.Background(), proto.Clone(req).(*compositionv1.ApplyManifestRequest))
	if err != nil {
		t.Fatalf("identical signed-carrier replay was refused: %v", err)
	}
	if !proto.Equal(first, replay) {
		t.Fatalf("replay changed receipt: first %v, replay %v", first, replay)
	}
}

func TestSignedCarrierRemovedWorkloadLosesIssuanceAuthority(t *testing.T) {
	p, k := verifying(t)
	ctx := context.Background()
	req := carrier(t, k, "conformance-probe", solutionhost.KindModule, 1, []string{"conformance.page"}, nil)
	req = rewriteCarrier(t, req, func(m *solutionhost.ModuleManifest) {
		m.Workloads = []solutionhost.Workload{{Service: "conformance-probe", Container: "conformance-probe"}}
	})
	if _, err := p.ApplyManifest(ctx, req); err != nil {
		t.Fatal(err)
	}
	credential := k.Credential(t, "conformance-probe")
	if _, err := k.State.VerifyWorkload(ctx, credential); err != nil {
		t.Fatalf("listed workload failed before removal: %v", err)
	}
	replacement := rewriteCarrier(t, req, func(m *solutionhost.ModuleManifest) {
		m.Generation++
		m.Workloads = []solutionhost.Workload{{Service: "replacement", Container: "replacement"}}
	})
	if _, err := p.ApplyManifest(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	if _, err := k.State.VerifyWorkload(ctx, credential); err == nil {
		t.Fatal("attested but no-longer-listed workload retains issuance authority")
	}
}

func TestSignedCarrierWithdrawalIsTerminalAndRevokesWorkloads(t *testing.T) {
	p, k := verifying(t)
	ctx := context.Background()
	live := carrier(t, k, "conformance-probe", solutionhost.KindModule, 1, []string{"conformance.page"}, nil)
	live = rewriteCarrier(t, live, func(m *solutionhost.ModuleManifest) {
		m.Workloads = []solutionhost.Workload{{Service: "conformance-probe", Container: "conformance-probe"}}
	})
	if _, err := p.ApplyManifest(ctx, live); err != nil {
		t.Fatal(err)
	}
	credential := k.Credential(t, "conformance-probe")
	if _, err := k.State.VerifyWorkload(ctx, credential); err != nil {
		t.Fatal(err)
	}
	withdrawal := rewriteCarrier(t, live, func(m *solutionhost.ModuleManifest) {
		m.Generation++
		m.Removed = true
		m.Workloads, m.Endpoints, m.Authority, m.Frontend, m.Group = nil, nil, nil, nil, nil
	})
	if _, err := p.ApplyManifest(ctx, withdrawal); err != nil {
		t.Fatalf("signed withdrawal refused: %v", err)
	}
	if _, err := k.State.VerifyWorkload(ctx, credential); err == nil {
		t.Error("withdrawn module still authenticates its workload")
	}
	if _, err := p.ApplyManifest(ctx, proto.Clone(withdrawal).(*compositionv1.ApplyManifestRequest)); err != nil {
		t.Errorf("identical terminal withdrawal cannot replay: %v", err)
	}
	resurrection := rewriteCarrier(t, live, func(m *solutionhost.ModuleManifest) { m.Generation = 3 })
	if _, err := p.ApplyManifest(ctx, resurrection); err == nil {
		t.Error("higher generation resurrected a terminally withdrawn binding")
	}
}

// Fixing replay must not admit a new policy under an already-applied generation.
func TestSignedCarrierReplayCannotRewriteItsAuthoritySidecar(t *testing.T) {
	p, k := verifying(t)
	ctx := context.Background()
	req := carrier(t, k, "conformance-probe", solutionhost.KindModule, 1, []string{"conformance.page"},
		&compositionv1.AuthorityManifestV1{ScopeCeilings: []*authorityv1.WorkScopeV1{scope("conformance.page", "read")}})
	if _, err := p.ApplyManifest(ctx, req); err != nil {
		t.Fatal(err)
	}
	rewrite := proto.Clone(req).(*compositionv1.ApplyManifestRequest)
	var document compositionv1.AuthorityManifestV1
	if err := proto.Unmarshal(rewrite.Authority.Document, &document); err != nil {
		t.Fatal(err)
	}
	document.ScopeCeilings[0].Actions = []string{"write"}
	bytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&document)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := testkit.SignAuthority(bytes)
	if err != nil {
		t.Fatal(err)
	}
	rewrite.Authority = &compositionv1.SignedManifestV1{Document: bytes, Envelope: signature}
	if _, err := p.ApplyManifest(ctx, rewrite); err == nil {
		t.Fatal("same-generation sidecar rewrote the admitted policy")
	}
	held, ok := k.State.Module("conformance-probe")
	if !ok || len(held.ResourceKinds) != 1 || !slices.Equal(held.ResourceKinds[0].GetActions(), []string{"read"}) {
		t.Fatalf("refused rewrite changed live authority: %+v", held)
	}
}

func withdrawn(t *testing.T, request *compositionv1.ApplyManifestRequest) *compositionv1.ApplyManifestRequest {
	t.Helper()
	return rewriteCarrier(t, request, func(m *solutionhost.ModuleManifest) {
		m.Generation++
		m.Removed = true
		m.Workloads, m.Endpoints, m.Authority, m.Frontend, m.Group = nil, nil, nil, nil, nil
	})
}

func TestSignedCarrierIdentityRefusalsLeaveTheLiveProjection(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		mutate func(*solutionhost.ModuleManifest)
	}{
		{"wrong host", func(m *solutionhost.ModuleManifest) { m.Host.Coordinate = "other" }},
		{"binding replacement", func(m *solutionhost.ModuleManifest) { m.Binding = "replacement" }},
		{"alias rename", func(m *solutionhost.ModuleManifest) { m.Alias = "another" }},
		{"withdrawal alias rewrite", func(m *solutionhost.ModuleManifest) {
			m.Alias = "another"
			m.Removed = true
			m.Workloads, m.Authority = nil, nil
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			p, k := verifying(t)
			req := carrier(t, k, "conformance-probe", solutionhost.KindModule, 1, []string{"conformance.page"}, nil)
			first, err := p.ApplyManifest(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			next := rewriteCarrier(t, req, func(m *solutionhost.ModuleManifest) { m.Generation++; scenario.mutate(m) })
			if _, err := p.ApplyManifest(context.Background(), next); err == nil {
				t.Fatal("invalid identity transition admitted")
			}
			if replay, err := p.ApplyManifest(context.Background(), req); err != nil || !proto.Equal(first, replay) {
				t.Fatalf("refused transition consumed state: %v %v", replay, err)
			}
		})
	}
}

func TestSignedCarrierCannotBeOverwrittenBySketchOrReplacedAfterWithdrawal(t *testing.T) {
	p, k := verifying(t)
	ctx := context.Background()
	req := carrier(t, k, "conformance-probe", solutionhost.KindModule, 1, []string{"conformance.page"}, nil)
	if _, err := p.ApplyManifest(ctx, req); err != nil {
		t.Fatal(err)
	}
	sketch := &compositionv1.ApplyManifestRequest{Manifest: &compositionv1.ModuleManifestV1{Module: "conformance-probe", Principal: "conformance-probe", Kind: "module", Generation: 100}}
	if _, err := p.ApplyManifest(ctx, sketch); err == nil {
		t.Fatal("sketch replaced signed projection")
	}
	if _, err := p.ApplyManifest(ctx, withdrawn(t, req)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ApplyManifest(ctx, sketch); err == nil {
		t.Fatal("sketch resurrected withdrawn binding")
	}
	replacement := rewriteCarrier(t, req, func(m *solutionhost.ModuleManifest) { m.Binding = "new-binding"; m.Generation = 3 })
	if _, err := p.ApplyManifest(ctx, replacement); err == nil {
		t.Fatal("new binding inherited old alias's installation identity")
	}
	replacement = carrier(t, k, "conformance-solution", solutionhost.KindModule, 1, []string{"conformance.page"}, nil)
	if _, err := p.ApplyManifest(ctx, replacement); err != nil {
		t.Fatalf("fresh alias refused: %v", err)
	}
}

func TestSignedCarrierReplayPreservesSidecarPresenceAndOwnsItsBytes(t *testing.T) {
	p, k := verifying(t)
	ctx := context.Background()
	req := carrier(t, k, "conformance-probe", solutionhost.KindModule, 1, []string{"conformance.page"}, &compositionv1.AuthorityManifestV1{ScopeCeilings: []*authorityv1.WorkScopeV1{scope("conformance.page", "read")}})
	original := proto.Clone(req).(*compositionv1.ApplyManifestRequest)
	first, err := p.ApplyManifest(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	without := proto.Clone(req).(*compositionv1.ApplyManifestRequest)
	without.Authority = nil
	if _, err := p.ApplyManifest(ctx, without); err == nil {
		t.Fatal("replay dropped sidecar")
	}
	req.Carrier.Document[0] ^= 1
	req.Authority.Document[0] ^= 1
	if replay, err := p.ApplyManifest(ctx, original); err != nil || !proto.Equal(first, replay) {
		t.Fatalf("caller mutated retained record: %v %v", replay, err)
	}
}

func pendingSolution(t *testing.T, p *Plugin, k *testkit.Kit) *compositionv1.ApplyManifestRequest {
	t.Helper()
	if err := k.State.LoadFixture(context.Background(), []byte(`installations:
  - organization: acme
    target: conformance-solution
    role: viewer
    owner: alex
    teams: [finance]
`)); err != nil {
		t.Fatal(err)
	}
	read := scope("conformance.page", "read")
	return carrier(t, k, "conformance-solution", solutionhost.KindSolution, 1, []string{"conformance.page"}, &compositionv1.AuthorityManifestV1{ScopeCeilings: []*authorityv1.WorkScopeV1{read}, Roles: []*compositionv1.RoleV1{
		{Name: state.InstallerRole, Scopes: []*authorityv1.WorkScopeV1{read}}, {Name: "viewer", Scopes: []*authorityv1.WorkScopeV1{read}},
	}})
}

func TestSignedCarrierReplayCompletesFailedInstallationWithoutReadmission(t *testing.T) {
	p, k := verifying(t)
	ctx := context.Background()
	req := pendingSolution(t, p, k)
	calls := 0
	k.State.OnInstall(func(_ context.Context, inst state.Installation) error {
		calls++
		if calls == 1 {
			return errors.New("not yet")
		}
		return nil
	})
	if _, err := p.ApplyManifest(ctx, req); err == nil {
		t.Fatal("failed install reported success")
	}
	id := state.InstallationID("acme", "conformance-solution")
	pending, _ := k.State.Installation(id)
	if pending.Status != state.Pending {
		t.Fatalf("lost pending installation: %+v", pending)
	}
	if _, err := p.ApplyManifest(ctx, req); err != nil {
		t.Fatalf("replay did not finish pending work: %v", err)
	}
	active, _ := k.State.Installation(id)
	if active.Status != state.Active || !slices.Equal(active.Teams, []string{"finance"}) || calls != 2 {
		t.Fatalf("completion: %+v, calls %d", active, calls)
	}
	revision, _ := k.State.AuthorizationRevision(ctx, "acme")
	if _, err := p.ApplyManifest(ctx, req); err != nil {
		t.Fatal(err)
	}
	after, _ := k.State.AuthorizationRevision(ctx, "acme")
	if after != revision || calls != 2 {
		t.Fatal("replay repeated grants or callback")
	}
}

func TestSignedCarrierWithdrawalFencesAnInFlightInstallCallback(t *testing.T) {
	p, k := verifying(t)
	ctx := context.Background()
	req := pendingSolution(t, p, k)
	entered, release := make(chan struct{}), make(chan struct{})
	k.State.OnInstall(func(ctx context.Context, inst state.Installation) error { close(entered); <-release; return nil })
	result := make(chan error, 1)
	go func() { _, err := p.ApplyManifest(ctx, req); result <- err }()
	<-entered
	if _, err := p.ApplyManifest(ctx, withdrawn(t, req)); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	if err := <-result; err == nil {
		t.Fatal("stale callback reported successful installation")
	}
	inst, _ := k.State.Installation(state.InstallationID("acme", "conformance-solution"))
	if inst.Status != state.Revoked || len(inst.Teams) != 0 {
		t.Fatalf("callback restored access: %+v", inst)
	}
}

func TestSignedCarrierConcurrentReplayWaitCanBeCancelled(t *testing.T) {
	p, k := verifying(t)
	ctx := context.Background()
	req := pendingSolution(t, p, k)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	k.State.OnInstall(func(ctx context.Context, inst state.Installation) error {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return nil
	})
	result := make(chan error, 1)
	go func() { _, err := p.ApplyManifest(ctx, req); result <- err }()
	<-entered
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := p.ApplyManifest(cancelled, req); err == nil {
		close(release)
		t.Fatal("cancelled waiter succeeded")
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if _, err := p.ApplyManifest(ctx, req); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("concurrent replay repeated callback")
	}
}

func TestSignedCarrierWithdrawalRevokesAlreadyIssuedPersonAuthority(t *testing.T) {
	p, k := verifying(t)
	ctx := context.Background()
	req := carrier(t, k, "documents", solutionhost.KindModule, 2, []string{"documents", "documents.collection"}, nil)
	if _, err := p.ApplyManifest(ctx, req); err != nil {
		t.Fatal(err)
	}
	session, err := k.State.SignIn("fixture-maya")
	if err != nil {
		t.Fatal(err)
	}
	person := issuer.WithSession(ctx, session.ID)
	request := &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents"}
	issued, err := k.Issuer.Issue(person, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Issuer.Check(ctx, issued.GetToken(), "documents", ""); err != nil {
		t.Fatalf("token before withdrawal: %v", err)
	}
	if _, err := p.ApplyManifest(ctx, withdrawn(t, req)); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Issuer.Check(ctx, issued.GetToken(), "documents", ""); err == nil {
		t.Fatal("old token remained valid")
	}
	if _, err := k.Issuer.Issue(person, request); err == nil {
		t.Fatal("new authority issued for withdrawn module")
	}
	revision, _ := k.State.AuthorizationRevision(ctx, "acme")
	if _, err := p.ApplyManifest(ctx, withdrawn(t, req)); err != nil {
		t.Fatal(err)
	}
	after, _ := k.State.AuthorizationRevision(ctx, "acme")
	if after != revision {
		t.Fatal("withdrawal replay repeated revocation")
	}
}

func TestSignedCarrierReplayCannotUndoExplicitInstallationRevocation(t *testing.T) {
	p, k := verifying(t)
	ctx := context.Background()
	req := pendingSolution(t, p, k)
	calls := 0
	k.State.OnInstall(func(_ context.Context, inst state.Installation) error { calls++; return errors.New("not yet") })
	if _, err := p.ApplyManifest(ctx, req); err == nil {
		t.Fatal("failed callback reported success")
	}
	id := state.InstallationID("acme", "conformance-solution")
	if err := k.State.Revoke(id); err != nil {
		t.Fatal(err)
	}
	revoked, _ := k.State.Installation(id)
	k.State.OnInstall(func(_ context.Context, inst state.Installation) error { calls++; return nil })
	if _, err := p.ApplyManifest(ctx, req); err == nil {
		t.Fatal("replay undid explicit uninstall")
	}
	after, _ := k.State.Installation(id)
	if after.Status != state.Revoked || after.Revision != revoked.Revision || calls != 1 {
		t.Fatalf("replay changed revoked install: %+v, callbacks %d", after, calls)
	}
}

func TestSignedCarrierReplayCannotAttachToAnExplicitReinstallation(t *testing.T) {
	p, k := verifying(t)
	ctx := context.Background()
	req := pendingSolution(t, p, k)
	k.State.OnInstall(func(_ context.Context, inst state.Installation) error { return errors.New("not yet") })
	if _, err := p.ApplyManifest(ctx, req); err == nil {
		t.Fatal("failed callback reported success")
	}
	id := state.InstallationID("acme", "conformance-solution")
	pending, _ := k.State.Installation(id)
	if err := k.State.Revoke(id); err != nil {
		t.Fatal(err)
	}
	k.State.OnInstall(nil)
	fresh, err := k.State.Install(ctx, "acme", "conformance-solution", "viewer", "alex")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Revision <= pending.Revision {
		t.Fatal("reinstall reset revision")
	}
	if _, err := p.ApplyManifest(ctx, req); err == nil {
		t.Fatal("old intent attached to new attempt")
	}
	after, _ := k.State.Installation(id)
	if len(after.Teams) != 0 || after.Revision != fresh.Revision {
		t.Fatalf("old fixture intent exposed new installation: %+v", after)
	}
}

func TestSignedCarrierRejectedPolicyDoesNotConsumeTheGeneration(t *testing.T) {
	p, k := verifying(t)
	ctx := context.Background()
	first := carrier(t, k, "conformance-probe", solutionhost.KindModule, 1, []string{"conformance.page"}, nil)
	if _, err := p.ApplyManifest(ctx, first); err != nil {
		t.Fatal(err)
	}
	bad := carrier(t, k, "conformance-probe", solutionhost.KindModule, 2, []string{"conformance.page"}, &compositionv1.AuthorityManifestV1{Methods: []*compositionv1.MethodPolicyV1{{Method: "/probe.Service/Read", AnyCheckedCaller: true, Requires: []*authorityv1.WorkScopeV1{scope("conformance.page", "read")}}}})
	if _, err := p.ApplyManifest(ctx, bad); err == nil {
		t.Fatal("ambiguous policy admitted")
	}
	if _, err := p.ApplyManifest(ctx, first); err != nil {
		t.Fatalf("rejected candidate replaced current carrier: %v", err)
	}
	good := carrier(t, k, "conformance-probe", solutionhost.KindModule, 2, []string{"conformance.page"}, &compositionv1.AuthorityManifestV1{Methods: []*compositionv1.MethodPolicyV1{{Method: "/probe.Service/Read", Requires: []*authorityv1.WorkScopeV1{scope("conformance.page", "read")}}}})
	if _, err := p.ApplyManifest(ctx, good); err != nil {
		t.Fatalf("rejected policy consumed generation: %v", err)
	}
}

func TestSignedCarrierPartialCompletionDoesNotRepeatEarlierGrants(t *testing.T) {
	p, k := verifying(t)
	ctx := context.Background()
	req := pendingSolution(t, p, k)
	if err := k.State.LoadFixture(ctx, []byte(`installations:
  - organization: globex
    target: conformance-solution
    role: viewer
    owner: zoe
    teams: [ops]
`)); err != nil {
		t.Fatal(err)
	}
	fail := true
	k.State.OnInstall(func(_ context.Context, inst state.Installation) error {
		if inst.Organization == "globex" && fail {
			return errors.New("not yet")
		}
		return nil
	})
	if _, err := p.ApplyManifest(ctx, req); err == nil {
		t.Fatal("partial failure reported success")
	}
	id := state.InstallationID("acme", "conformance-solution")
	before, _ := k.State.Installation(id)
	if before.Status != state.Active || len(before.Teams) != 1 {
		t.Fatalf("first intent did not complete: %+v", before)
	}
	if err := k.State.Revoke(id); err != nil {
		t.Fatal(err)
	}
	fail = false
	if _, err := p.ApplyManifest(ctx, req); err != nil {
		t.Fatalf("unfinished second intent did not resume: %v", err)
	}
	first, _ := k.State.Installation(id)
	second, _ := k.State.Installation(state.InstallationID("globex", "conformance-solution"))
	if first.Status != state.Revoked || second.Status != state.Active || !slices.Equal(second.Teams, []string{"ops"}) {
		t.Fatalf("partial completion replay: first=%+v second=%+v", first, second)
	}
}

func TestSignedCarrierReplacementWaitsForAndFencesEarlierCompletion(t *testing.T) {
	p, k := verifying(t)
	ctx := context.Background()
	req := pendingSolution(t, p, k)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	k.State.OnInstall(func(_ context.Context, inst state.Installation) error {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return nil
	})
	result := make(chan error, 1)
	go func() { _, err := p.ApplyManifest(ctx, req); result <- err }()
	<-entered
	read := scope("conformance.page", "read")
	next := carrier(t, k, "conformance-solution", solutionhost.KindSolution, 2, []string{"conformance.page"}, &compositionv1.AuthorityManifestV1{ScopeCeilings: []*authorityv1.WorkScopeV1{read}, Roles: []*compositionv1.RoleV1{
		{Name: state.InstallerRole, Scopes: []*authorityv1.WorkScopeV1{read}}, {Name: "viewer", Scopes: []*authorityv1.WorkScopeV1{read}},
	}})
	cancelled, cancel := context.WithCancel(ctx)
	defer cancel()
	replacementResult := make(chan error, 1)
	go func() { _, err := p.ApplyManifest(cancelled, next); replacementResult <- err }()
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		live, _ := k.State.Module("conformance-solution")
		if live.Generation == 2 {
			break
		}
		select {
		case <-deadline:
			close(release)
			t.Fatal("replacement never committed")
		case <-ticker.C:
		}
	}
	cancel()
	if err := <-replacementResult; err == nil {
		close(release)
		t.Fatal("blocked completion ignored cancellation")
	}
	if calls.Load() != 1 {
		close(release)
		t.Fatal("new callback overlapped old attempt")
	}
	close(release)
	if err := <-result; err == nil {
		t.Fatal("superseded callback acknowledged")
	}
	if _, err := p.ApplyManifest(ctx, next); err != nil {
		t.Fatalf("new delivery lost pending intent: %v", err)
	}
	inst, _ := k.State.Installation(state.InstallationID("acme", "conformance-solution"))
	if inst.Status != state.Active || calls.Load() != 2 || !slices.Equal(inst.Teams, []string{"finance"}) {
		t.Fatalf("replacement completion: %+v, calls %d", inst, calls.Load())
	}
}
