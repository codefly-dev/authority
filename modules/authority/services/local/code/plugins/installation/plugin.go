// Package installation serves codefly.dev/installation: Install, GrantToTeam, List.
package installation

import (
	"context"
	"gateway/pkg/framework"
	"gateway/pkg/wiring"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"

	"gateway/pkg/business/state"
	installationv1 "gateway/pkg/gen/host/installation/v1"
	authorityplugin "gateway/plugins/authority"
)

// Plugin registers the installation service.
type Plugin struct {
	installationv1.UnimplementedInstallationServiceServer
	State *state.State
}

// Name is the plugin's identifier.
func (p *Plugin) Name() string { return "installation" }

// RegisterGRPC registers the service.
func (p *Plugin) RegisterGRPC(s *grpc.Server) { installationv1.RegisterInstallationServiceServer(s, p) }

// RegisterREST registers nothing.
func (p *Plugin) RegisterREST(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error {
	return nil
}

// Migrations: none.
func (p *Plugin) Migrations() []string { return nil }

// Install composes an installation and runs the target's install step.
func (p *Plugin) Install(ctx context.Context, req *installationv1.InstallRequest) (*installationv1.Installation, error) {
	if err := p.State.RequireAdministrator(authorityplugin.Bearer(ctx), req.GetOrganizationId()); err != nil {
		return nil, authorityplugin.Status(err)
	}
	inst, err := p.State.Install(ctx, req.GetOrganizationId(), req.GetTarget(), req.GetRole(), req.GetOwnerPersonId())
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	return Wire(inst), nil
}

// GrantToTeam exposes an installation to a team.
func (p *Plugin) GrantToTeam(ctx context.Context, req *installationv1.GrantToTeamRequest) (*installationv1.Installation, error) {
	if err := p.State.RequireAdministrator(authorityplugin.Bearer(ctx), req.GetOrganizationId()); err != nil {
		return nil, authorityplugin.Status(err)
	}
	inst, err := p.State.GrantToTeam(ctx, req.GetOrganizationId(), req.GetInstallationId(), req.GetTeamId())
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	return Wire(inst), nil
}

// List answers what one organisation has installed.
func (p *Plugin) List(ctx context.Context, req *installationv1.ListRequest) (*installationv1.ListResponse, error) {
	if err := p.State.RequireAdministrator(authorityplugin.Bearer(ctx), req.GetOrganizationId()); err != nil {
		return nil, authorityplugin.Status(err)
	}
	out := &installationv1.ListResponse{}
	for _, inst := range p.State.List(req.GetOrganizationId()) {
		out.Installations = append(out.Installations, Wire(inst))
	}
	return out, nil
}

// Wire converts an installation to the interface's message.
func Wire(i state.Installation) *installationv1.Installation {
	st := map[state.Status]installationv1.Installation_Status{
		state.Pending: installationv1.Installation_STATUS_PENDING, state.Active: installationv1.Installation_STATUS_ACTIVE, state.Revoked: installationv1.Installation_STATUS_REVOKED,
	}[i.Status]
	return &installationv1.Installation{Id: i.ID, OrganizationId: i.Organization, Target: i.Target, Status: st, Revision: i.Revision, Role: i.Role, TeamIds: i.Teams, AgentPrincipalId: i.AgentPrincipal(), Namespace: i.Namespace()}
}

// New is the registry's constructor: the plugin over what Configure wired.
func New() framework.Plugin { return &Plugin{State: wiring.State()} }
