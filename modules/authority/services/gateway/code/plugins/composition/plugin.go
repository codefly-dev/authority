// Package composition serves codefly.dev/composition: ApplyManifest.
package composition

import (
	"context"
	"crypto"
	"gateway/pkg/framework"
	"gateway/pkg/wiring"
	"strings"

	delivery "github.com/codefly-dev/authority/libraries/delivery/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

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
	// Keys are the same pinned release keys, by key id, for the authority's own
	// document delivered with the manifest.
	Keys map[string]crypto.PublicKey
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
		delivered, signer, err := p.verified(ctx, req.GetCarrier(), req.GetCredential())
		if err != nil {
			return nil, err
		}
		m = FromCore(delivered)
		if req.GetAuthority() != nil {
			doc, err := p.document(req.GetAuthority(), req.GetCarrier(), delivered, signer)
			if err != nil {
				return nil, err
			}
			if m.Methods, err = methodsOf(doc); err != nil {
				return nil, err
			}
			if m, err = ceiled(m, issuer.FromWire(doc.GetScopeCeilings())); err != nil {
				return nil, err
			}
		}
	} else {
		if req.GetAuthority() != nil {
			return nil, status.Error(codes.InvalidArgument, "the authority's document travels only with a signed carrier")
		}
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
		m.Bindings[b.GetId()] = state.Binding{ID: b.GetId(), Audience: b.GetAudience(), InvokeScopes: issuer.FromWire(b.GetInvokeScopes()), HeadlessScopes: issuer.FromWire(b.GetHeadlessScopes()), LookupScopes: issuer.FromWire(b.GetLookupScopes())}
	}
	for _, r := range in.GetRoles() {
		if m.Roles == nil {
			m.Roles = map[string][]*basev0.WorkScopeV1{}
		}
		m.Roles[r.GetName()] = state.Normalize(issuer.FromWire(r.GetScopes()))
	}
	return m
}

// verified reads the manifest from the carrier's verified document and admits
// the delivery only from the module's own delivery workload.
func (p *Plugin) verified(ctx context.Context, carrier *compositionv1.SignedManifestV1, credential string) (*solutionhost.ModuleManifest, string, error) {
	if p.Verifier == nil || p.Carrier == nil {
		return nil, "", status.Error(codes.FailedPrecondition, "this implementation verifies no delivery: no release keys are pinned")
	}
	delivered, err := solutionhost.VerifyDelivered(ctx, &solutionhost.Signed{Document: carrier.GetDocument(), Envelope: carrier.GetEnvelope()}, p.Verifier)
	if err != nil {
		return nil, "", status.Errorf(codes.PermissionDenied, "the delivery does not verify: %v", err)
	}
	manifest, err := delivered.Manifest()
	if err != nil {
		return nil, "", status.Errorf(codes.InvalidArgument, "the delivered manifest does not read: %v", err)
	}
	if err := p.Carrier(ctx, credential, manifest.Alias); err != nil {
		return nil, "", status.Errorf(codes.PermissionDenied, "the delivery is not carried by %s's delivery workload: %v", manifest.Alias, err)
	}
	return manifest, delivered.Signer().KeyID, nil
}

// document reads the authority's document delivered with a verified carrier:
// signed by the key that signed the carrier, for the same module and
// generation, naming the carrier's digest. Anything else is refused, so a
// delivery cannot pair one release's manifest with another's method policy.
func (p *Plugin) document(signed, carrier *compositionv1.SignedManifestV1, core *solutionhost.ModuleManifest, signer string) (*compositionv1.AuthorityManifestV1, error) {
	keyID, err := delivery.Verify(signed.GetDocument(), signed.GetEnvelope(), p.Keys)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "the authority's document does not verify: %v", err)
	}
	if keyID != signer {
		return nil, status.Errorf(codes.PermissionDenied, "the authority's document is signed by %q and the manifest by %q", keyID, signer)
	}
	var doc compositionv1.AuthorityManifestV1
	if err := proto.Unmarshal(signed.GetDocument(), &doc); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "the authority's document does not read: %v", err)
	}
	switch {
	case doc.GetModule() != core.Alias:
		return nil, status.Errorf(codes.PermissionDenied, "the authority's document is for %q, the manifest for %q", doc.GetModule(), core.Alias)
	case doc.GetGeneration() != core.Generation:
		return nil, status.Errorf(codes.PermissionDenied, "the authority's document is at generation %d, the manifest at %d", doc.GetGeneration(), core.Generation)
	case doc.GetCoreManifestDigest() != delivery.Digest(carrier.GetDocument()):
		return nil, status.Errorf(codes.PermissionDenied, "the authority's document names another manifest than the one delivered with it")
	}
	return &doc, nil
}

// methodsOf reads what each method declares.
func methodsOf(doc *compositionv1.AuthorityManifestV1) (map[string]state.MethodPolicy, error) {
	methods := make(map[string]state.MethodPolicy, len(doc.GetMethods()))
	for _, method := range doc.GetMethods() {
		if _, twice := methods[method.GetMethod()]; twice || method.GetMethod() == "" {
			return nil, status.Errorf(codes.InvalidArgument, "the authority's document lists method %q twice or unnamed", method.GetMethod())
		}
		methods[method.GetMethod()] = state.MethodPolicy{Requires: issuer.FromWire(method.GetRequires()), AnyCheckedCaller: method.GetAnyCheckedCaller()}
	}
	return methods, nil
}

// ceiled gives each of the module's own kinds the actions its contract declares
// on it, in place of the any-action kind core's manifest leaves it with. A
// ceiling naming a kind core's manifest does not declare is refused: the
// authority's document narrows what core's manifest composes, never adds to it.
func ceiled(m state.Manifest, ceilings []*basev0.WorkScopeV1) (state.Manifest, error) {
	if len(ceilings) == 0 {
		return m, nil
	}
	declared := map[string]bool{}
	for _, kind := range m.ResourceKinds {
		declared[kind.GetResourceKind()] = true
	}
	ceiled := map[string]bool{}
	for _, ceiling := range ceilings {
		if !declared[ceiling.GetResourceKind()] {
			return m, status.Errorf(codes.InvalidArgument, "the authority's document ceils %s, which %s's manifest does not declare", ceiling.GetResourceKind(), m.Module)
		}
		if len(ceiling.GetActions()) == 0 {
			return m, status.Errorf(codes.InvalidArgument, "the authority's document ceils %s with no action", ceiling.GetResourceKind())
		}
		ceiled[ceiling.GetResourceKind()] = true
	}
	kinds := append([]*basev0.WorkScopeV1(nil), ceilings...)
	for _, kind := range m.ResourceKinds {
		if !ceiled[kind.GetResourceKind()] {
			kinds = append(kinds, kind)
		}
	}
	m.ResourceKinds = state.Normalize(kinds)
	return m, nil
}

// FromCore reads core's module manifest as the state's. Core's manifest carries
// no roles, so a solution delivered as a carrier is refused until it does (the
// sketch carries them through the transition). The manifest is the ceiling here: a resource kind declared with no actions serves whatever the
// roles grant on it, a binding's invoke scopes are its operations, and a module
// acting alone holds what it may invoke. The host narrows each of these by its
// release-signed envelope; the authority gateway has no second document.
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
		invoke := scopesOf(b.Operations["invoke"])
		headless := scopesOf(b.Operations["headless"])
		lookup := scopesOf(b.Operations["lookup"])
		m.Bindings[b.ID] = state.Binding{ID: b.ID, Audience: b.Audience, InvokeScopes: invoke, HeadlessScopes: headless, LookupScopes: lookup}
	}
	return m
}

// scopesOf reads one operation's requested scopes, each "<resource kind>:<action>"
// as core's manifest writes them, into scopes grouped by kind. An entry without
// a colon names nothing and is skipped; the manifest's own validation refuses it.
func scopesOf(entries []string) []*basev0.WorkScopeV1 {
	byKind := map[string][]string{}
	var kinds []string
	for _, entry := range entries {
		kind, action, ok := strings.Cut(entry, ":")
		if !ok || kind == "" || action == "" {
			continue
		}
		if _, seen := byKind[kind]; !seen {
			kinds = append(kinds, kind)
		}
		byKind[kind] = append(byKind[kind], action)
	}
	var out []*basev0.WorkScopeV1
	for _, kind := range kinds {
		out = append(out, &basev0.WorkScopeV1{ResourceKind: kind, Actions: byKind[kind]})
	}
	return state.Normalize(out)
}

// New is the registry's constructor: the plugin over what Configure wired.
func New() framework.Plugin {
	return &Plugin{State: wiring.State(), Verifier: wiring.Verifier(), Carrier: wiring.Carrier(), Keys: wiring.Keys()}
}
