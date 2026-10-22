// Package composition serves codefly.dev/composition: ApplyManifest.
package composition

import (
	"context"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	compositionv1 "gateway/pkg/gen/host/composition/v1"
	authorityplugin "gateway/plugins/authority"
)

// Plugin registers the composition service.
type Plugin struct {
	compositionv1.UnimplementedCompositionServiceServer
	State *state.State
}

// Name is the plugin's identifier.
func (p *Plugin) Name() string { return "composition" }

// RegisterGRPC registers the service.
func (p *Plugin) RegisterGRPC(s *grpc.Server) { compositionv1.RegisterCompositionServiceServer(s, p) }

// RegisterREST registers nothing.
func (p *Plugin) RegisterREST(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error {
	return nil
}

// Migrations: none.
func (p *Plugin) Migrations() []string { return nil }

// ApplyManifest records one module instance at a newer generation.
func (p *Plugin) ApplyManifest(_ context.Context, req *compositionv1.ApplyManifestRequest) (*compositionv1.ApplyManifestResponse, error) {
	m := Manifest(req.GetManifest())
	ids, err := p.State.ApplyManifest(m)
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	return &compositionv1.ApplyManifestResponse{Principal: m.Principal, Generation: m.Generation, InstallationIds: ids}, nil
}

// Manifest converts the wire manifest to the state's.
func Manifest(in *compositionv1.ModuleManifestV1) state.Manifest {
	m := state.Manifest{Module: in.GetModule(), Principal: in.GetPrincipal(), Kind: in.GetKind(), Generation: in.GetGeneration(), Bindings: map[string]state.Binding{}}
	for _, rk := range in.GetResourceKinds() {
		m.ResourceKinds = append(m.ResourceKinds, &basev0.WorkScopeV1{ResourceKind: rk.GetKind(), Actions: rk.GetActions()})
	}
	m.ResourceKinds = state.Normalize(m.ResourceKinds)
	for _, b := range in.GetBindings() {
		m.Bindings[b.GetId()] = state.Binding{ID: b.GetId(), Audience: b.GetAudience(), InvokeScopes: issuer.FromWire(b.GetInvokeScopes()), HeadlessScopes: issuer.FromWire(b.GetHeadlessScopes())}
	}
	return m
}
