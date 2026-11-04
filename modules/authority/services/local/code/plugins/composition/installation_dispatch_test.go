package composition

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	compositionv1 "gateway/pkg/gen/host/composition/v1"
	installationv1 "gateway/pkg/gen/host/installation/v1"
	authorityplugin "gateway/plugins/authority"
	installationplugin "gateway/plugins/installation"
	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/core/solutionhost"
	wc "github.com/codefly-dev/sdk-go/workcontext"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type localTransport struct{}

func (localTransport) WorkspaceValueIfSet(string, string) (string, bool, error) {
	return "", false, nil
}
func (localTransport) IsLocalRun() bool { return true }

func dispatchOffer(t *testing.T, endpoints []solutionhost.Endpoint) (*Plugin, *testkit.Kit, authority.Person, domain.ConsentApproval, *compositionv1.ApplyManifestRequest) {
	t.Helper()
	p, k := verifying(t)
	read := scope("conformance.page", "read")
	req := carrier(t, k, "conformance-solution", solutionhost.KindSolution, 1, []string{"conformance.page"}, &compositionv1.AuthorityManifestV1{ScopeCeilings: []*authorityv1.WorkScopeV1{read}, Roles: []*compositionv1.RoleV1{{Name: state.InstallerRole, Scopes: []*authorityv1.WorkScopeV1{read}}, {Name: "viewer", Scopes: []*authorityv1.WorkScopeV1{read}}}}, func(m *solutionhost.ModuleManifest) { m.Endpoints = endpoints })
	if _, err := p.ApplyManifest(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	session, err := k.State.SignIn("fixture-alex")
	if err != nil {
		t.Fatal(err)
	}
	caller, err := k.State.Caller(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := k.State.Service().Review(context.Background(), caller, "acme", "conformance-solution")
	if err != nil {
		t.Fatal(err)
	}
	approval.OperationID = uuid.NewString()
	return p, k, caller, approval, req
}

func dispatchInstall(k *testkit.Kit, caller authority.Person, approval *domain.ConsentApproval) (domain.Installation, error) {
	return k.State.Service().Install(context.Background(), caller, "acme", "conformance-solution", "viewer", "alex", approval, func(ctx context.Context, inst domain.Installation) error {
		return k.State.DeliverInstallation(ctx, inst, localTransport{})
	})
}

func TestInstallationDispatchAuthenticatesAndRetriesUntilAcknowledged(t *testing.T) {
	var k *testkit.Kit
	var calls atomic.Int32
	var previousToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/_codefly/installations" || r.URL.RawQuery != "" {
			t.Errorf("unexpected callback: %s %s", r.Method, r.URL.String())
		}
		var body struct {
			ID           string `json:"installation_id"`
			Organization string `json:"organization_id"`
			Revision     uint64 `json:"revision"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		inst, ok := k.State.Installation(body.ID)
		if !ok || inst.Status != state.Pending || body.Organization != "acme" || body.Revision != inst.Revision || r.Header.Get(wc.InstallationIDHeaderName) != body.ID || r.Header.Get(wc.InstallationRevisionHeaderName) != strconv.FormatUint(body.Revision, 10) {
			t.Errorf("callback not bound to pending installation: %+v %+v", body, inst)
		}
		token := r.Header.Get(wc.HeaderName)
		checked, err := k.Issuer.Check(r.Context(), token, "conformance-solution", authority.InstallationStepHTTPMethod)
		if err != nil || checked == nil {
			t.Errorf("setup token failed real Check: %v", err)
		} else {
			claims := checked.GetContext()
			scopes := claims.GetAuthorityScopes()
			if claims.GetAudience() != "conformance-solution" || claims.GetOrganizationId() != body.Organization || claims.GetTenantId() != body.Organization || claims.GetSeal().GetInstallationId() != body.ID || claims.GetSeal().GetInstallationRevision() != body.Revision || len(scopes) != 1 || scopes[0].GetResourceKind() != "installations" || len(scopes[0].GetActions()) != 1 || scopes[0].GetActions()[0] != "install" || len(scopes[0].GetResourceIds()) != 1 || scopes[0].GetResourceIds()[0] != body.ID {
				t.Errorf("verified claims do not match the callback: %v", claims)
			}
		}
		if _, err := k.Issuer.Check(r.Context(), token, "conformance-solution", "POST /another"); err == nil {
			t.Error("setup token admitted to another method")
		}
		previousToken = token
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	_, kit, caller, approval, _ := dispatchOffer(t, []solutionhost.Endpoint{{Name: "web", Service: "api", API: "http", Address: server.URL}})
	k = kit
	first, err := dispatchInstall(k, caller, &approval)
	if err == nil || first.Status != domain.Pending {
		t.Fatalf("first callback must remain pending: %+v %v", first, err)
	}
	if status.Code(authorityplugin.Status(err)) != codes.Unavailable {
		t.Fatalf("temporary callback failure must remain retryable to delivery: %v", err)
	}
	active, err := dispatchInstall(k, caller, &approval)
	if err != nil || active.Status != domain.Active || active.Revision != first.Revision || calls.Load() != 2 {
		t.Fatalf("retry: %+v calls=%d err=%v", active, calls.Load(), err)
	}
	if _, err := k.Issuer.Check(context.Background(), previousToken, "conformance-solution", authority.InstallationStepHTTPMethod); err == nil {
		t.Error("active installation retained pending setup credential")
	}
	if _, err := dispatchInstall(k, caller, &approval); err != nil || calls.Load() != 2 {
		t.Fatalf("completed replay repeated callback: %v, calls=%d", err, calls.Load())
	}
}

func TestInstallationDispatchRefusesMissingAmbiguousAndRedirect(t *testing.T) {
	var leaked atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1); w.WriteHeader(204) }))
	defer sink.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	for _, tc := range []struct {
		name      string
		endpoints []solutionhost.Endpoint
	}{
		{"missing", nil},
		{"ambiguous", []solutionhost.Endpoint{{Name: "one", Service: "api", API: "http", Address: redirect.URL}, {Name: "two", Service: "api", API: "http", Address: sink.URL}}},
		{"redirect", []solutionhost.Endpoint{{Name: "one", Service: "api", API: "http", Address: redirect.URL}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, k, caller, approval, _ := dispatchOffer(t, tc.endpoints)
			inst, err := dispatchInstall(k, caller, &approval)
			if err == nil || inst.Status != domain.Pending {
				t.Fatalf("unsafe dispatch accepted: %+v %v", inst, err)
			}
		})
	}
	if got := leaked.Load(); got != 0 {
		t.Error(fmt.Sprintf("redirect/ambiguous endpoint received %d callbacks", got))
	}
}

func TestInstallationRPCDispatchFencesWithdrawalDuringCallback(t *testing.T) {
	entered, release := make(chan string, 1), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- r.Header.Get(wc.HeaderName)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	p, k, _, _, req := dispatchOffer(t, []solutionhost.Endpoint{{Name: "web", Service: "api", API: "http", Address: server.URL}})
	k.State.OnInstall(func(ctx context.Context, inst state.Installation) error {
		return k.State.DeliverInstallation(ctx, inst, localTransport{})
	})
	session, err := k.State.SignIn("fixture-alex")
	if err != nil {
		t.Fatal(err)
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+session.ID))
	plugin := &installationplugin.Plugin{State: k.State}
	approval, err := plugin.Review(ctx, &installationv1.ReviewRequest{OrganizationId: "acme", Target: "conformance-solution"})
	if err != nil {
		t.Fatal(err)
	}
	approval.OperationId = uuid.NewString()
	request := &installationv1.InstallRequest{OrganizationId: "acme", Target: "conformance-solution", Role: "viewer", OwnerPersonId: "alex", Approval: approval}
	done := make(chan error, 1)
	go func() { _, err := plugin.Install(ctx, request); done <- err }()
	var token string
	select {
	case token = <-entered:
	case err := <-done:
		t.Fatalf("install ended before callback: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("installation callback did not arrive")
	}
	if _, err := k.Issuer.Check(context.Background(), token, "conformance-solution", authority.InstallationStepHTTPMethod); err != nil {
		close(release)
		t.Fatalf("pending credential refused: %v", err)
	}
	if _, err := p.ApplyManifest(context.Background(), withdrawn(t, req)); err != nil {
		close(release)
		t.Fatal(err)
	}
	if _, err := k.Issuer.Check(context.Background(), token, "conformance-solution", authority.InstallationStepHTTPMethod); err == nil {
		t.Error("withdrawn setup credential remained valid")
	}
	close(release)
	if err := <-done; err == nil {
		t.Error("stale callback acknowledged a withdrawn installation")
	}
	inst, ok := k.State.Installation(state.InstallationID("acme", "conformance-solution"))
	if !ok || inst.Status != state.Revoked {
		t.Fatalf("withdrawal did not fence activation: %+v", inst)
	}
	if _, err := plugin.Install(ctx, request); err == nil {
		t.Error("old consent restored withdrawn installation")
	}
}

func TestInstallationDispatchRejectsStaleApprovalAfterRedelivery(t *testing.T) {
	var token string
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token = r.Header.Get(wc.HeaderName)
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	endpoints := []solutionhost.Endpoint{{Name: "web", Service: "api", API: "http", Address: server.URL}}
	p, k, caller, old, _ := dispatchOffer(t, endpoints)
	if _, err := dispatchInstall(k, caller, &old); err == nil {
		t.Fatal("failed callback activated")
	}
	staleToken := token
	read := scope("conformance.page", "read")
	replacement := carrier(t, k, "conformance-solution", solutionhost.KindSolution, 2, []string{"conformance.page"}, &compositionv1.AuthorityManifestV1{ScopeCeilings: []*authorityv1.WorkScopeV1{read}, Roles: []*compositionv1.RoleV1{{Name: state.InstallerRole, Scopes: []*authorityv1.WorkScopeV1{read}}, {Name: "viewer", Scopes: []*authorityv1.WorkScopeV1{read}}}}, func(m *solutionhost.ModuleManifest) { m.Endpoints = endpoints })
	if _, err := p.ApplyManifest(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Issuer.Check(context.Background(), staleToken, "conformance-solution", authority.InstallationStepHTTPMethod); err == nil {
		t.Error("redelivery retained prior setup credential")
	}
	if _, err := dispatchInstall(k, caller, &old); err == nil {
		t.Error("stale approval accepted")
	}
	if calls.Load() != 1 {
		t.Fatal("stale approval reached callback")
	}
	fresh, err := k.State.Service().Review(context.Background(), caller, "acme", "conformance-solution")
	if err != nil {
		t.Fatal(err)
	}
	fresh.OperationID = uuid.NewString()
	active, err := dispatchInstall(k, caller, &fresh)
	if err != nil || active.Status != domain.Active || calls.Load() != 2 {
		t.Fatalf("fresh consent could not converge: %+v %v calls=%d", active, err, calls.Load())
	}
}

func TestInstallationCallbackDeadlineIsTransient(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release }))
	defer server.Close()
	defer close(release)
	_, k, caller, approval, _ := dispatchOffer(t, []solutionhost.Endpoint{{Name: "web", Service: "api", API: "http", Address: server.URL}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	inst, err := k.State.Service().Install(ctx, caller, "acme", "conformance-solution", "viewer", "alex", &approval, func(ctx context.Context, inst domain.Installation) error {
		return k.State.DeliverInstallation(ctx, inst, localTransport{})
	})
	select {
	case <-entered:
	default:
		t.Fatal("callback was not reached")
	}
	if inst.Status != domain.Pending || status.Code(authorityplugin.Status(err)) != codes.Unavailable {
		t.Fatalf("deadline: %+v %v", inst, err)
	}
}

func TestInstallationCallbackRefusalIsNotTransient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer server.Close()
	_, k, caller, approval, _ := dispatchOffer(t, []solutionhost.Endpoint{{Name: "web", Service: "api", API: "http", Address: server.URL}})
	inst, err := dispatchInstall(k, caller, &approval)
	if err == nil || inst.Status != domain.Pending || status.Code(authorityplugin.Status(err)) == codes.Unavailable {
		t.Fatalf("refusal misclassified: %+v %v", inst, err)
	}
}
