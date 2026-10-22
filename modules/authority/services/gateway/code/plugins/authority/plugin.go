// Package authority serves codefly.dev/authority: Issue, Check, Keys.
package authority

import (
	"context"
	"errors"

	"github.com/codefly-dev/core/workcontext"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

// Plugin registers the authority service.
type Plugin struct {
	authorityv1.UnimplementedAuthorityServiceServer
	Issuer *issuer.Issuer
}

// Name is the plugin's identifier.
func (p *Plugin) Name() string { return "authority" }

// RegisterGRPC registers the service.
func (p *Plugin) RegisterGRPC(s *grpc.Server) { authorityv1.RegisterAuthorityServiceServer(s, p) }

// RegisterREST registers nothing; the interface is Connect/gRPC.
func (p *Plugin) RegisterREST(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error {
	return nil
}

// Migrations: none; the mini gateway holds state in memory.
func (p *Plugin) Migrations() []string { return nil }

// Issue signs for one owner shape.
func (p *Plugin) Issue(ctx context.Context, req *authorityv1.IssueRequest) (*authorityv1.IssueResponse, error) {
	out, err := p.Issuer.Issue(ctx, req)
	return out, Status(err)
}

// Check verifies for the audience the caller is.
func (p *Plugin) Check(ctx context.Context, req *authorityv1.CheckRequest) (*authorityv1.CheckResponse, error) {
	out, err := p.Issuer.Check(ctx, req.GetToken(), req.GetAudience())
	return out, Status(err)
}

// Keys returns the issuer and its keys.
func (p *Plugin) Keys(context.Context, *authorityv1.KeysRequest) (*authorityv1.KeysResponse, error) {
	return p.Issuer.Keys(), nil
}

// Status maps a refusal to a gRPC status that names its reason: every refusal
// reaches the caller, none stays only in a log.
func Status(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, state.ErrUnknown), errors.Is(err, workcontext.ErrNoBinding):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, workcontext.ErrRevoked), errors.Is(err, workcontext.ErrNoSeal),
		errors.Is(err, state.ErrForbidden), errors.Is(err, issuer.ErrRefused):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, workcontext.ErrInvalid), errors.Is(err, workcontext.ErrNotACoreToken), errors.Is(err, workcontext.ErrReplayed):
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.Is(err, state.ErrStale):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
