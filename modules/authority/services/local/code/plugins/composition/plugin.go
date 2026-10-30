// Package composition serves codefly.dev/composition: ApplyManifest.
package composition

import (
	"context"
	"crypto"
	"gateway/pkg/framework"
	"gateway/pkg/wiring"
	"log"

	"github.com/codefly-dev/authority/libraries/authority-core/go/delivered"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
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
	// Coordinate is supplied by the host configuration, not by a delivery.
	Coordinate string
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

// ApplyManifest admits only signed deliveries carried by the authenticated
// delivery workload. Core supports immutable replay and terminal withdrawal.
func (p *Plugin) ApplyManifest(ctx context.Context, req *compositionv1.ApplyManifestRequest) (*compositionv1.ApplyManifestResponse, error) {
	if req.GetCarrier() == nil {
		return nil, status.Error(codes.PermissionDenied, "a manifest requires a signed carrier and an authenticated delivery workload")
	}
	carrier, err := p.verified(ctx, req.GetCarrier(), req.GetCredential())
	if err != nil {
		return nil, err
	}
	var sidecar []byte
	manifest, err := carrier.Manifest()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "manifest: %v", err)
	}
	var doc *delivered.Document
	if req.GetAuthority() != nil {
		if doc, err = p.document(req.GetAuthority(), req.GetCarrier(), manifest, carrier.Signer().KeyID); err != nil {
			return nil, authorityplugin.Status(err)
		}
		sidecar = req.GetAuthority().GetDocument()
		if sidecar == nil {
			sidecar = []byte{}
		}
	}
	m, err := delivered.Module(manifest, doc)
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	ids, err := p.State.ApplyDelivered(ctx, p.Coordinate, carrier, sidecar, m)
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	for _, line := range p.State.PermissionReport() {
		log.Printf("permissions: %s", line)
	}
	return &compositionv1.ApplyManifestResponse{Principal: m.Principal, Generation: m.Generation, InstallationIds: ids}, nil
}

// verified reads the manifest from the carrier's verified document and admits
// the delivery only from the module's own delivery workload.
func (p *Plugin) verified(ctx context.Context, carrier *compositionv1.SignedManifestV1, credential string) (*solutionhost.Delivered, error) {
	if credential == "" {
		return nil, status.Error(codes.PermissionDenied, "a signed delivery requires its delivery workload credential")
	}
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
	return delivered, nil
}

// document reads the authority's document delivered with a verified carrier:
// signed by the key that signed the carrier, for the same module and
// generation, naming the carrier's digest (delivered.VerifyDocument and
// delivered.Pair). Anything else is refused, so a delivery cannot pair one
// release's manifest with another's method policy.
func (p *Plugin) document(signed, carrier *compositionv1.SignedManifestV1, core *solutionhost.ModuleManifest, signer string) (*delivered.Document, error) {
	if err := delivered.VerifyDocument(signed.GetDocument(), signed.GetEnvelope(), p.Keys, signer); err != nil {
		return nil, err
	}
	var wire compositionv1.AuthorityManifestV1
	if err := proto.Unmarshal(signed.GetDocument(), &wire); err != nil {
		return nil, domain.Malformed("the authority's document does not read: %v", err)
	}
	doc := DocumentOf(&wire)
	if err := delivered.Pair(*doc, carrier.GetDocument(), core); err != nil {
		return nil, err
	}
	return doc, nil
}

// DocumentOf reads this host's binding of the authority's document as the core's.
func DocumentOf(in *compositionv1.AuthorityManifestV1) *delivered.Document {
	doc := &delivered.Document{Module: in.GetModule(), Generation: in.GetGeneration(), CoreManifestDigest: in.GetCoreManifestDigest(),
		ScopeCeilings: issuer.FromWire(in.GetScopeCeilings()), OwnerAware: in.GetOwnerAware(), InstallationRole: in.GetInstallationRole()}
	for _, d := range in.GetEdgeDependencies() {
		doc.EdgeDependencies = append(doc.EdgeDependencies, domain.EdgeDependency{Module: d.GetModule(), Presence: d.GetPresence()})
	}
	for _, m := range in.GetMethods() {
		doc.Methods = append(doc.Methods, delivered.Method{Method: m.GetMethod(), Requires: issuer.FromWire(m.GetRequires()), AnyCheckedCaller: m.GetAnyCheckedCaller()})
	}
	for _, r := range in.GetRoles() {
		doc.Roles = append(doc.Roles, delivered.Role{Name: r.GetName(), Scopes: issuer.FromWire(r.GetScopes()), InstallationOwned: issuer.FromWire(r.GetInstallationOwnedScopes())})
	}
	return doc
}

// New is the registry's constructor: the plugin over what Configure wired.
func New() framework.Plugin {
	return &Plugin{State: wiring.State(), Coordinate: wiring.Coordinate(), Verifier: wiring.Verifier(), Carrier: wiring.Carrier(), Keys: wiring.Keys()}
}
