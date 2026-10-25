// Package artifact serves host.artifact.v1: Approve, Authorize, Revoke.
package artifact

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"

	"gateway/pkg/business/issuer"
	"gateway/pkg/framework"
	artifactv1 "gateway/pkg/gen/host/artifact/v1"
	"gateway/pkg/wiring"
	authorityplugin "gateway/plugins/authority"
)

// Plugin registers the artifact service.
type Plugin struct {
	artifactv1.UnimplementedArtifactServiceServer
	Issuer *issuer.Issuer
}

// Name is the plugin's identifier.
func (p *Plugin) Name() string { return "artifact" }

// RegisterGRPC registers the service.
func (p *Plugin) RegisterGRPC(s *grpc.Server) { artifactv1.RegisterArtifactServiceServer(s, p) }

// RegisterREST registers nothing: a module asks over gRPC.
func (p *Plugin) RegisterREST(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error {
	return nil
}

// Migrations: none.
func (p *Plugin) Migrations() []string { return nil }

// Approve records a person's consent to an artifact.
func (p *Plugin) Approve(ctx context.Context, req *artifactv1.ArtifactRequest) (*artifactv1.Approval, error) {
	out, err := p.Issuer.Artifact(ctx, "activate", req)
	return out, authorityplugin.Status(err)
}

// Authorize answers the standing approval, for a run.
func (p *Plugin) Authorize(ctx context.Context, req *artifactv1.ArtifactRequest) (*artifactv1.Approval, error) {
	out, err := p.Issuer.Artifact(ctx, "run", req)
	return out, authorityplugin.Status(err)
}

// Revoke withdraws an approval.
func (p *Plugin) Revoke(ctx context.Context, req *artifactv1.RevokeRequest) (*artifactv1.Approval, error) {
	out, err := p.Issuer.RevokeArtifact(ctx, req)
	return out, authorityplugin.Status(err)
}

// New is the registry's constructor: the plugin over what Configure wired.
func New() framework.Plugin { return &Plugin{Issuer: wiring.Issuer()} }
