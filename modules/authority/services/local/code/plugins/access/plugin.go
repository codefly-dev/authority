// Package access serves host.access.v1: Grant, Revoke, ListGrants, Check,
// CheckBatch and ListViewerGrants. Every decision is the shared access
// core's; the caller is the module its workload credential proves.
package access

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"

	"gateway/pkg/business/issuer"
	"gateway/pkg/framework"
	accessv1 "gateway/pkg/gen/host/access/v1"
	"gateway/pkg/wiring"
	authorityplugin "gateway/plugins/authority"
)

// Plugin registers the access service.
type Plugin struct {
	accessv1.UnimplementedAccessServiceServer
	Issuer *issuer.Issuer
}

// Name is the plugin's identifier.
func (p *Plugin) Name() string { return "access" }

// RegisterGRPC registers the service.
func (p *Plugin) RegisterGRPC(s *grpc.Server) { accessv1.RegisterAccessServiceServer(s, p) }

// RegisterREST registers nothing: a module asks over gRPC.
func (p *Plugin) RegisterREST(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error {
	return nil
}

// Migrations: none. The grants live in the authority's in-memory store.
func (p *Plugin) Migrations() []string { return nil }

// Grant makes or refreshes one grant.
func (p *Plugin) Grant(ctx context.Context, req *accessv1.GrantRequest) (*accessv1.GrantResponse, error) {
	out, err := p.Issuer.AccessGrant(ctx, req)
	return out, authorityplugin.Status(err)
}

// Revoke ends one grant; a grant that does not exist is NOT_FOUND.
func (p *Plugin) Revoke(ctx context.Context, req *accessv1.RevokeRequest) (*accessv1.RevokeResponse, error) {
	out, err := p.Issuer.AccessRevoke(ctx, req)
	return out, authorityplugin.Status(err)
}

// ListGrants answers the grants on one reference.
func (p *Plugin) ListGrants(ctx context.Context, req *accessv1.ListGrantsRequest) (*accessv1.ListGrantsResponse, error) {
	out, err := p.Issuer.AccessListGrants(ctx, req)
	return out, authorityplugin.Status(err)
}

// Check decides one action on one placed resource.
func (p *Plugin) Check(ctx context.Context, req *accessv1.CheckRequest) (*accessv1.CheckResponse, error) {
	out, err := p.Issuer.AccessCheck(ctx, req)
	return out, authorityplugin.Status(err)
}

// CheckBatch decides one action on many placed resources, in request order.
func (p *Plugin) CheckBatch(ctx context.Context, req *accessv1.CheckBatchRequest) (*accessv1.CheckBatchResponse, error) {
	out, err := p.Issuer.AccessCheckBatch(ctx, req)
	return out, authorityplugin.Status(err)
}

// ListViewerGrants pages the viewer's direct grants.
func (p *Plugin) ListViewerGrants(ctx context.Context, req *accessv1.ListViewerGrantsRequest) (*accessv1.ListViewerGrantsResponse, error) {
	out, err := p.Issuer.AccessListViewerGrants(ctx, req)
	return out, authorityplugin.Status(err)
}

// New is the registry's constructor: the plugin over what Configure wired.
func New() framework.Plugin { return &Plugin{Issuer: wiring.Issuer()} }
