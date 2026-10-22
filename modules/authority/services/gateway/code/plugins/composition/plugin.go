// Package composition serves codefly.dev/composition: ApplyManifest.
package composition

import (
	"context"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
	// Verifier holds the release keys this implementation pins; nil verifies nothing.
	Verifier *solutionhost.Verifier
	// Carrier admits a delivery credential as the named module's delivery workload.
	Carrier func(ctx context.Context, credential, module string) error
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
func (p *Plugin) ApplyManifest(ctx context.Context, req *compositionv1.ApplyManifestRequest) (*compositionv1.ApplyManifestResponse, error) {
	var m state.Manifest
	if req.GetCarrier() != nil {
		delivered, err := p.verified(ctx, req.GetCarrier(), req.GetCredential())
		if err != nil {
			return nil, err
		}
		m = FromCore(delivered)
	} else {
		m = Manifest(req.GetManifest())
	}
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

// verified reads the manifest from the carrier's verified document and admits
// the delivery only from the module's own delivery workload.
func (p *Plugin) verified(ctx context.Context, carrier *compositionv1.SignedManifestV1, credential string) (*solutionhost.ModuleManifest, error) {
	if p.Verifier == nil || p.Carrier == nil {
		return nil, status.Error(codes.FailedPrecondition, "this implementation verifies no delivery: no release keys are pinned")
	}
	delivered, err := solutionhost.VerifyDelivered(ctx, &solutionhost.Signed{Document: carrier.GetDocument(), Envelope: carrier.GetEnvelope()}, p.Verifier)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "the delivery does not verify: %v", err)
	}
	manifest, err := delivered.Manifest()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "the delivered manifest does not read: %v", err)
	}
	if err := p.Carrier(ctx, credential, manifest.Alias); err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "the delivery is not carried by %s's delivery workload: %v", manifest.Alias, err)
	}
	return manifest, nil
}

// FromCore reads core's module manifest as the state's. The manifest is the
// ceiling here: a resource kind declared with no actions serves whatever the
// roles grant on it, a binding's invoke scopes are its operations, and a module
// acting alone holds what it may invoke. The host narrows each of these by its
// release-signed envelope; the mini gateway has no second document.
func FromCore(in *solutionhost.ModuleManifest) state.Manifest {
	m := state.Manifest{Module: in.Alias, Principal: in.Alias, Kind: string(in.Kind), Generation: in.Generation, Bindings: map[string]state.Binding{}}
	if in.Authority == nil {
		return m
	}
	if in.Authority.Principal != "" {
		m.Principal = in.Authority.Principal
	}
	for _, kind := range in.Authority.ResourceKinds {
		m.ResourceKinds = append(m.ResourceKinds, &basev0.WorkScopeV1{ResourceKind: kind, Actions: []string{state.AnyAction}})
	}
	m.ResourceKinds = state.Normalize(m.ResourceKinds)
	for _, b := range in.Authority.Bindings {
		var invoke []*basev0.WorkScopeV1
		for kind, actions := range b.Operations {
			invoke = append(invoke, &basev0.WorkScopeV1{ResourceKind: kind, Actions: actions})
		}
		invoke = state.Normalize(invoke)
		m.Bindings[b.ID] = state.Binding{ID: b.ID, Audience: b.Audience, InvokeScopes: invoke, HeadlessScopes: invoke}
	}
	return m
}
