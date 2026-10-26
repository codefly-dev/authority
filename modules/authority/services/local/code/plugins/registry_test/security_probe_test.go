package registry_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	artifactv1 "gateway/pkg/gen/host/artifact/v1"
	"gateway/pkg/gen/host/artifact/v1/artifactv1connect"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	"gateway/pkg/gen/host/authority/v1/authorityv1connect"
	compositionv1 "gateway/pkg/gen/host/composition/v1"
	"gateway/pkg/gen/host/composition/v1/compositionv1connect"
	installationv1 "gateway/pkg/gen/host/installation/v1"
	"gateway/pkg/gen/host/installation/v1/installationv1connect"
	"gateway/plugins/artifact"
	"gateway/plugins/authority"
	"gateway/plugins/composition"
	"gateway/plugins/installation"

	"connectrpc.com/connect"
	"connectrpc.com/vanguard/vanguardgrpc"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	delivery "github.com/codefly-dev/authority/libraries/delivery/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func reviewWire(m state.Manifest) *compositionv1.ModuleManifestV1 {
	out := &compositionv1.ModuleManifestV1{Module: m.Name, Principal: m.Principal, Kind: m.Kind, Generation: m.Generation}
	for _, sc := range m.ResourceKinds {
		out.ResourceKinds = append(out.ResourceKinds, &compositionv1.ResourceKindV1{Kind: sc.ResourceKind, Actions: sc.Actions})
	}
	for name, scopes := range m.Roles {
		r := &compositionv1.RoleV1{Name: name}
		for _, sc := range scopes {
			r.Scopes = append(r.Scopes, &authorityv1.WorkScopeV1{ResourceKind: sc.ResourceKind, Actions: sc.Actions})
		}
		out.Roles = append(out.Roles, r)
	}
	return out
}

// Negative assertion: unauthenticated composition must not reach InstallAsHost.
func TestReviewUnauthenticatedSketchReachesHost(t *testing.T) {
	for _, protocol := range []string{"connect", "grpc"} {
		t.Run(protocol, func(t *testing.T) {
			k := testkit.New(t)
			if err := k.State.LoadFixture(t.Context(), []byte("installations:\n  - {organization: acme, target: proposals, role: viewer, owner: alex}\n")); err != nil {
				t.Fatal(err)
			}
			var steps, carriers atomic.Int32
			var admit atomic.Bool
			k.State.OnInstall(func(context.Context, state.Installation) error { steps.Add(1); return nil })
			server := grpc.NewServer()
			(&composition.Plugin{State: k.State, Coordinate: "local", Verifier: testkit.ReleaseVerifier(t, "local"), Keys: testkit.ReleaseKeys(), Carrier: func(ctx context.Context, credential, module string) error {
				carriers.Add(1)
				if admit.Load() {
					return k.CarrierAuthority(ctx, credential, module)
				}
				return fmt.Errorf("no delivery credential")
			}}).RegisterGRPC(server)
			handler, err := vanguardgrpc.NewTranscoder(server)
			if err != nil {
				t.Fatal(err)
			}
			web := httptest.NewUnstartedServer(handler)
			web.EnableHTTP2 = true
			web.StartTLS()
			t.Cleanup(web.Close)
			t.Cleanup(server.Stop)
			var opts []connect.ClientOption
			if protocol == "grpc" {
				opts = append(opts, connect.WithGRPC())
			}
			client := compositionv1connect.NewCompositionServiceClient(web.Client(), web.URL, opts...)
			_, err = client.ApplyManifest(t.Context(), connect.NewRequest(&compositionv1.ApplyManifestRequest{Manifest: reviewWire(testkit.Proposals(1))}))
			inst, found := k.State.Installation(state.InstallationID("acme", "proposals"))
			t.Logf("error=%v carrier_checks=%d host_install_callbacks=%d installation_exists=%v status=%s", err, carriers.Load(), steps.Load(), found, inst.Status)
			if err == nil || steps.Load() != 0 || found {
				t.Error("unauthenticated unsigned request reached host installation power")
			}
			signed := reviewSignedProposals(t, k)
			for _, name := range []string{"unsigned-module", "missing-credential", "forged-credential", "missing-signature", "wrong-workload"} {
				req := proto.CloneOf(signed)
				switch name {
				case "unsigned-module":
					req = &compositionv1.ApplyManifestRequest{Manifest: &compositionv1.ModuleManifestV1{Module: "unsigned-probe", Principal: "unsigned-probe", Kind: "module", Generation: 1}}
				case "missing-credential":
					req.Credential = ""
				case "forged-credential":
					req.Credential = "not-a-credential"
				case "missing-signature":
					req.Carrier.Envelope = nil
				case "wrong-workload":
					req.Credential = k.Credential(t, "wiki")
				}
				admit.Store(true)
				_, err := client.ApplyManifest(t.Context(), connect.NewRequest(req))
				if connect.CodeOf(err) != connect.CodePermissionDenied || steps.Load() != 0 {
					t.Fatalf("%s reached host: %v, steps=%d", name, err, steps.Load())
				}
				for _, target := range []string{"proposals", "unsigned-probe"} {
					if _, ok := k.State.Installation(state.InstallationID("acme", target)); ok {
						t.Fatalf("%s installed %s", name, target)
					}
				}
			}
			// A legitimate signed, attested delivery still completes the pending
			// fixture intent, and replay never repeats host installation work.
			for n := 0; n < 2; n++ {
				if _, err := client.ApplyManifest(t.Context(), connect.NewRequest(signed)); err != nil {
					t.Fatal(err)
				}
				inst, found := k.State.Installation(state.InstallationID("acme", "proposals"))
				if !found || inst.Status != state.Active || steps.Load() != 1 {
					t.Fatalf("signed delivery: %+v, callbacks=%d", inst, steps.Load())
				}
			}

		})
	}
}

// Use the same release signer and workload attestation as the composition tests.
func reviewSignedProposals(t *testing.T, k *testkit.Kit) *compositionv1.ApplyManifestRequest {
	t.Helper()
	m := testkit.Proposals(1)
	manifest := &solutionhost.ModuleManifest{
		Schema: solutionhost.SchemaModuleManifestV1, Binding: m.Name, Alias: m.Name, Kind: solutionhost.KindSolution, Generation: m.Generation,
		Host:      solutionhost.HostTarget{Coordinate: "local", Domain: "local"},
		Release:   solutionhost.Release{Publisher: "test", Name: m.Name, Version: "0.1.0"},
		Workloads: []solutionhost.Workload{{Service: m.Name, Container: m.Name}},
		Authority: &solutionhost.Authority{Principal: m.Principal},
	}
	doc := &compositionv1.AuthorityManifestV1{Module: m.Name, Generation: m.Generation, OwnerAware: true, Roles: reviewWire(m).Roles}
	for _, sc := range m.ResourceKinds {
		manifest.Authority.ResourceKinds = append(manifest.Authority.ResourceKinds, sc.ResourceKind)
		doc.ScopeCeilings = append(doc.ScopeCeilings, &authorityv1.WorkScopeV1{ResourceKind: sc.ResourceKind, Actions: sc.Actions})
	}
	raw, err := solutionhost.SignedPayload(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := testkit.SignDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	doc.CoreManifestDigest = delivery.Digest(raw)
	policy, err := proto.MarshalOptions{Deterministic: true}.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := testkit.SignAuthority(policy)
	if err != nil {
		t.Fatal(err)
	}
	return &compositionv1.ApplyManifestRequest{Carrier: &compositionv1.SignedManifestV1{Document: raw, Envelope: envelope}, Authority: &compositionv1.SignedManifestV1{Document: policy, Envelope: signature}, Credential: k.Credential(t, m.Name)}
}

func TestReviewRoleResponsesForeignAbsent(t *testing.T) {
	k := testkit.New(t)
	server := grpc.NewServer()
	(&installation.Plugin{State: k.State}).RegisterGRPC(server)
	handler, err := vanguardgrpc.NewTranscoder(server)
	if err != nil {
		t.Fatal(err)
	}
	web := httptest.NewUnstartedServer(handler)
	web.EnableHTTP2 = true
	web.StartTLS()
	t.Cleanup(web.Close)
	t.Cleanup(server.Stop)
	client := installationv1connect.NewInstallationServiceClient(web.Client(), web.URL, connect.WithGRPC())
	foreign := state.InstallationID("globex", "wiki")
	absent := state.InstallationID("acme", "proposals")
	present := state.InstallationID("acme", "wiki")
	for _, who := range []string{"anonymous", "forged", "fixture-maya", "fixture-alex", "fixture-zoe"} {
		t.Run(who, func(t *testing.T) {
			bearer := ""
			if who == "forged" {
				bearer = "not-a-session"
			} else if strings.HasPrefix(who, "fixture-") {
				s, e := k.State.SignIn(who)
				if e != nil {
					t.Fatal(e)
				}
				bearer = s.ID
			}
			normalized := func(err error, id string) string {
				if err == nil {
					return "OK"
				}
				return fmt.Sprintf("%s:%s", connect.CodeOf(err), strings.ReplaceAll(err.Error(), id, "<id>"))
			}
			calls := map[string]func(string) error{
				"grant": func(id string) error {
					r := connect.NewRequest(&installationv1.GrantRoleRequest{OrganizationId: "acme", InstallationId: id, PersonId: "maya", Role: "viewer"})
					if bearer != "" {
						r.Header().Set("Authorization", "Bearer "+bearer)
					}
					_, e := client.GrantRole(t.Context(), r)
					return e
				},
				"revoke": func(id string) error {
					r := connect.NewRequest(&installationv1.RevokeRoleRequest{OrganizationId: "acme", InstallationId: id, PersonId: "maya", Role: "viewer"})
					if bearer != "" {
						r.Header().Set("Authorization", "Bearer "+bearer)
					}
					_, e := client.RevokeRole(t.Context(), r)
					return e
				},
				"list": func(id string) error {
					r := connect.NewRequest(&installationv1.ListRoleGrantsRequest{OrganizationId: "acme", InstallationId: id})
					if bearer != "" {
						r.Header().Set("Authorization", "Bearer "+bearer)
					}
					_, e := client.ListRoleGrants(t.Context(), r)
					return e
				},
			}
			for method, call := range calls {
				a, b := normalized(call(foreign), foreign), normalized(call(absent), absent)
				if a != b {
					t.Errorf("%s foreign=%s absent=%s", method, a, b)
				}
				if who != "fixture-alex" {
					c := normalized(call(present), present)
					if c != b {
						t.Errorf("%s present=%s absent=%s", method, c, b)
					}
				}
				t.Logf("%s foreign/absent=%s", method, a)
			}
		})
	}
}

// Every concrete consent operation must check the stored installation owner before
// touching approval storage, even when the capability has the right vocabulary.
func TestReviewArtifactCannotEscapeScopeOwner(t *testing.T) {
	for _, protocol := range []string{"connect", "grpc"} {
		for _, scenario := range []string{"same-owner", "cross-owner", "unowned-installation", "resource-limited", "foreign-source"} {
			t.Run(protocol+"/"+scenario, func(t *testing.T) {
				k := testkit.New(t)
				m := testkit.Proposals(1)
				m.ResourceKinds = append(m.ResourceKinds, testkit.Scope("proposals.item", "activate", "run"))
				m.Roles["viewer"] = []*basev0.WorkScopeV1{testkit.Scope("proposals.item", "read", "activate", "run")}
				if _, err := k.State.ApplyManifest(m); err != nil {
					t.Fatal(err)
				}
				own, err := k.State.InstallAsHost(t.Context(), "acme", m.Name, "viewer", "alex")
				if err != nil {
					t.Fatal(err)
				}
				if err := k.State.GrantRole(domain.RoleGrant{InstallationID: own.ID, Role: "viewer", PersonID: "maya"}); err != nil {
					t.Fatal(err)
				}
				other, ok := k.State.Installation(state.InstallationID("acme", "wiki"))
				if !ok || own.PrincipalID == other.PrincipalID {
					t.Fatal("missing distinct target owner")
				}
				server := grpc.NewServer()
				(&authority.Plugin{Issuer: k.Issuer}).RegisterGRPC(server)
				(&artifact.Plugin{Issuer: k.Issuer}).RegisterGRPC(server)
				handler, err := vanguardgrpc.NewTranscoder(server)
				if err != nil {
					t.Fatal(err)
				}
				web := httptest.NewUnstartedServer(handler)
				web.EnableHTTP2 = true
				web.StartTLS()
				t.Cleanup(web.Close)
				t.Cleanup(server.Stop)
				var opts []connect.ClientOption
				if protocol == "grpc" {
					opts = append(opts, connect.WithGRPC())
				}
				ac := authorityv1connect.NewAuthorityServiceClient(web.Client(), web.URL, opts...)
				artifacts := artifactv1connect.NewArtifactServiceClient(web.Client(), web.URL, opts...)
				sess, err := k.State.SignIn("fixture-maya")
				if err != nil {
					t.Fatal(err)
				}
				req := connect.NewRequest(&authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: m.Principal})
				if scenario == "resource-limited" {
					req.Msg.Scopes = []*authorityv1.WorkScopeV1{{ResourceKind: "proposals.item", Actions: []string{"activate", "run"}, ResourceOwnerId: own.PrincipalID, ResourceIds: []string{"one-item"}}}
				}
				req.Header().Set("Authorization", "Bearer "+sess.ID)
				issued, err := ac.Issue(t.Context(), req)
				if err != nil {
					t.Fatal(err)
				}
				if len(issued.Msg.Context.AuthorityScopes) == 0 {
					t.Fatal("missing scopes")
				}
				for _, sc := range issued.Msg.Context.AuthorityScopes {
					if sc.ResourceOwnerId != own.PrincipalID {
						t.Fatal("fixture did not issue owned scopes")
					}
				}
				target := own
				if scenario == "cross-owner" {
					target = other
				}
				if scenario == "unowned-installation" {
					target, ok = k.State.Installation(state.InstallationID("acme", "documents"))
					if !ok || target.PrincipalID != "" {
						t.Fatal("expected module installation without solution principal")
					}
				}
				identity := &artifactv1.Identity{Schema: "review/v1", Source: state.Namespace(target), Subject: []byte(`{"name":"artifact"}`)}
				if scenario == "foreign-source" {
					identity.Source = state.Namespace(other)
				}
				raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(identity)
				if err != nil {
					t.Fatal(err)
				}
				digest := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
				// Trusted fixture setup ensures read/revoke have an existing record even
				// when the public approve is correctly refused.
				approval, err := k.State.Approvals.Approve(t.Context(), target.ID, "proposals.item", digest, 0)
				if err != nil {
					t.Fatal(err)
				}
				storage := &reviewApprovals{Approvals: k.State.Approvals}
				k.State.Approvals = storage
				request := &artifactv1.ArtifactRequest{ParentToken: issued.Msg.Token, ActorCredential: k.Credential(t, m.Name), InstallationId: target.ID, Policy: "proposals.item", Identity: identity}
				calls := []struct {
					name string
					call func() error
				}{
					{"approve", func() error { _, e := artifacts.Approve(t.Context(), connect.NewRequest(request)); return e }},
					{"authorize", func() error { _, e := artifacts.Authorize(t.Context(), connect.NewRequest(request)); return e }},
					{"revoke", func() error {
						_, e := artifacts.Revoke(t.Context(), connect.NewRequest(&artifactv1.RevokeRequest{ParentToken: request.ParentToken, ActorCredential: request.ActorCredential, InstallationId: target.ID, Policy: request.Policy, ApprovalId: approval.ID}))
						return e
					}},
				}
				for _, call := range calls {
					before := storage.calls.Load()
					err := call.call()
					// Revoke uses only the stored installation/policy, not a supplied identity.
					allowed := scenario == "same-owner" || (scenario == "foreign-source" && call.name == "revoke")
					if allowed {
						if err != nil {
							t.Errorf("%s: %v", call.name, err)
						}
					} else {
						if connect.CodeOf(err) != connect.CodePermissionDenied {
							t.Errorf("%s escaped %s: %v", call.name, scenario, err)
						}
						if storage.calls.Load() != before {
							t.Errorf("%s touched approval storage before admission", call.name)
						}
					}
				}
			})
		}
	}
}

type reviewApprovals struct {
	state.Approvals
	calls atomic.Int32
}

func (s *reviewApprovals) Approve(ctx context.Context, installation, policy, digest string, revision int64) (state.Approval, error) {
	s.calls.Add(1)
	return s.Approvals.Approve(ctx, installation, policy, digest, revision)
}
func (s *reviewApprovals) Standing(ctx context.Context, installation, policy, digest string) (state.Approval, error) {
	s.calls.Add(1)
	return s.Approvals.Standing(ctx, installation, policy, digest)
}
func (s *reviewApprovals) Revoke(ctx context.Context, installation, policy, id string) (state.Approval, error) {
	s.calls.Add(1)
	return s.Approvals.Revoke(ctx, installation, policy, id)
}

func TestReviewInstallationIssueResponsesForeignAbsent(t *testing.T) {
	k := testkit.New(t)
	server := grpc.NewServer()
	(&authority.Plugin{Issuer: k.Issuer}).RegisterGRPC(server)
	handler, err := vanguardgrpc.NewTranscoder(server)
	if err != nil {
		t.Fatal(err)
	}
	web := httptest.NewUnstartedServer(handler)
	web.EnableHTTP2 = true
	web.StartTLS()
	t.Cleanup(web.Close)
	t.Cleanup(server.Stop)
	ac := authorityv1connect.NewAuthorityServiceClient(web.Client(), web.URL, connect.WithGRPC())
	credential := k.Credential(t, "wiki")
	var answers []string
	for _, id := range []string{state.InstallationID("globex", "wiki"), state.InstallationID("acme", "proposals")} {
		_, err := ac.Issue(t.Context(), connect.NewRequest(&authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Installation{Installation: &authorityv1.InstallationRef{InstallationId: id}}, Actor: &authorityv1.WorkloadCredential{Credential: credential}, OrganizationId: "acme", Audience: "wiki"}))
		if err == nil {
			t.Fatal("unexpected issuance")
		}
		answers = append(answers, fmt.Sprintf("%s:%s", connect.CodeOf(err), strings.ReplaceAll(err.Error(), id, "<id>")))
	}
	if answers[0] != answers[1] {
		t.Fatalf("foreign=%s absent=%s", answers[0], answers[1])
	}
	t.Log(answers[0])
}

type reviewSigner struct {
	crypto.Signer
	armed            atomic.Bool
	entered, release chan struct{}
}

func (s *reviewSigner) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	if s.armed.CompareAndSwap(true, false) {
		close(s.entered)
		<-s.release
	}
	return s.Signer.Sign(r, d, o)
}
func TestReviewRevokeFenceThroughWrapper(t *testing.T) {
	for _, shape := range []string{"person", "child", "delegation"} {
		t.Run(shape, func(t *testing.T) {
			k := testkit.Bare(t)
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signer := &reviewSigner{Signer: key, entered: make(chan struct{}), release: make(chan struct{})}
			cfg := issuer.Config(testkit.Audience, "review", key, time.Now)
			cfg.Signer = signer
			st, err := state.New(k.Launcher.Anchor(), testkit.Audience, cfg)
			if err != nil {
				t.Fatal(err)
			}
			k.State = st
			k.Issuer = issuer.New(st, testkit.Audience, "review", key.Public().(ed25519.PublicKey))
			wiki := testkit.Wiki(1)
			wiki.Bindings = map[string]state.Binding{"documents": {ID: "documents", Audience: "documents", InvokeScopes: []*basev0.WorkScopeV1{testkit.Scope("documents", "read")}}}
			wiki.Roles["viewer"] = append(wiki.Roles["viewer"], testkit.Scope("documents", "read"))
			for _, m := range []state.Manifest{testkit.Model(1), testkit.Documents(1), wiki} {
				if _, err := st.ApplyManifest(m); err != nil {
					t.Fatal(err)
				}
			}
			data, err := os.ReadFile(testkit.FixturePath())
			if err != nil {
				t.Fatal(err)
			}
			if err := st.LoadFixture(t.Context(), data); err != nil {
				t.Fatal(err)
			}
			inst, err := st.InstallAsHost(t.Context(), "acme", "wiki", "viewer", "alex")
			if err != nil {
				t.Fatal(err)
			}
			if err := st.GrantRole(domain.RoleGrant{InstallationID: inst.ID, Role: "viewer", PersonID: "maya"}); err != nil {
				t.Fatal(err)
			}
			server := grpc.NewServer()
			(&authority.Plugin{Issuer: k.Issuer}).RegisterGRPC(server)
			(&installation.Plugin{State: st}).RegisterGRPC(server)
			handler, err := vanguardgrpc.NewTranscoder(server)
			if err != nil {
				t.Fatal(err)
			}
			web := httptest.NewUnstartedServer(handler)
			web.EnableHTTP2 = true
			web.StartTLS()
			t.Cleanup(web.Close)
			t.Cleanup(server.Stop)
			ac := authorityv1connect.NewAuthorityServiceClient(web.Client(), web.URL, connect.WithGRPC())
			ic := installationv1connect.NewInstallationServiceClient(web.Client(), web.URL, connect.WithGRPC())
			maya, err := st.SignIn("fixture-maya")
			if err != nil {
				t.Fatal(err)
			}
			alex, err := st.SignIn("fixture-alex")
			if err != nil {
				t.Fatal(err)
			}
			request := connect.NewRequest(&authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "wiki"})
			request.Header().Set("Authorization", "Bearer "+maya.ID)
			if shape == "child" {
				root, e := ac.Issue(t.Context(), request)
				if e != nil {
					t.Fatal(e)
				}
				request = connect.NewRequest(&authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: root.Msg.Token}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "wiki")}, OperationBindingId: "documents"})
			}
			if shape == "delegation" {
				dr := connect.NewRequest(&authorityv1.DelegateRequest{Module: "wiki", Scopes: []*authorityv1.WorkScopeV1{{ResourceKind: "documents", Actions: []string{"read"}, ResourceOwnerId: inst.PrincipalID}}, Purpose: "review race"})
				dr.Header().Set("Authorization", "Bearer "+maya.ID)
				d, e := ac.Delegate(t.Context(), dr)
				if e != nil {
					t.Fatal(e)
				}
				request = connect.NewRequest(&authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Delegation{Delegation: &authorityv1.DelegationRef{DelegationId: d.Msg.DelegationId}}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "wiki")}, OperationBindingId: "documents"})
			}
			signer.armed.Store(true)
			type result struct {
				out *connect.Response[authorityv1.IssueResponse]
				err error
			}
			done := make(chan result, 1)
			go func() { out, e := ac.Issue(t.Context(), request); done <- result{out, e} }()
			select {
			case <-signer.entered:
			case <-time.After(10 * time.Second):
				t.Fatal("issuance did not reach signer")
			}
			rr := connect.NewRequest(&installationv1.RevokeRoleRequest{OrganizationId: "acme", InstallationId: inst.ID, Role: "viewer", PersonId: "maya"})
			rr.Header().Set("Authorization", "Bearer "+alex.ID)
			_, revokeErr := ic.RevokeRole(t.Context(), rr)
			close(signer.release)
			if revokeErr != nil {
				t.Fatal(revokeErr)
			}
			got := <-done
			gr := connect.NewRequest(&installationv1.GrantRoleRequest{OrganizationId: "acme", InstallationId: inst.ID, Role: "viewer", PersonId: "maya"})
			gr.Header().Set("Authorization", "Bearer "+alex.ID)
			if _, e := ic.GrantRole(t.Context(), gr); e != nil {
				t.Fatal(e)
			}
			if got.err != nil {
				t.Logf("issuance refused across revoke: %s", connect.CodeOf(got.err))
				return
			}
			_, checkErr := ac.Check(t.Context(), connect.NewRequest(&authorityv1.CheckRequest{Token: got.out.Msg.Token, Audience: got.out.Msg.Context.Audience}))
			if checkErr == nil {
				t.Fatal("revoked capability became usable after regrant")
			}
			t.Logf("signed response remains revoked after regrant: %s", connect.CodeOf(checkErr))
		})
	}
}
