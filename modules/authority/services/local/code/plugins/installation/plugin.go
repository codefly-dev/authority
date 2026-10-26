// Package installation serves codefly.dev/installation: Install, the role
// grants on an installation (GrantRole, RevokeRole, ListRoleGrants), and List.
// Every decision is the core's; the caller is the person the bearer's session
// authenticates.
package installation

import (
	"context"
	"gateway/pkg/framework"
	"gateway/pkg/wiring"
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
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

// RegisterGRPC registers the installation interface and, beside it, the setup
// read over the same state.
func (p *Plugin) RegisterGRPC(s *grpc.Server) {
	installationv1.RegisterInstallationServiceServer(s, p)
	installationv1.RegisterOfferServiceServer(s, &Offers{plugin: p, runnables: composedRunnables})
}

// RegisterREST registers nothing.
func (p *Plugin) RegisterREST(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error {
	return nil
}

// Migrations: none.
func (p *Plugin) Migrations() []string { return nil }

func (p *Plugin) caller(ctx context.Context) (authority.Person, error) {
	return p.State.Caller(authorityplugin.Bearer(ctx))
}

// Install installs a solution at the caller's organisation, which the caller
// administers; owner_person_id names who installed it (the caller when
// empty). Nobody holds a role on it until granted one.
func (p *Plugin) Install(ctx context.Context, req *installationv1.InstallRequest) (*installationv1.Installation, error) {
	caller, err := p.caller(ctx)
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	inst, err := p.State.Service().Install(ctx, caller, req.GetOrganizationId(), req.GetTarget(), req.GetRole(), req.GetOwnerPersonId(), approvalFromWire(req.GetApproval()), p.installStep())
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	return p.wire(inst), nil
}

func (p *Plugin) installStep() authority.InstallStep {
	return func(ctx context.Context, inst state.Installation) error { return p.State.RunInstallStep(ctx, inst) }
}

// GrantRole grants a person or a team one of the solution's roles.
func (p *Plugin) GrantRole(ctx context.Context, req *installationv1.GrantRoleRequest) (*installationv1.Installation, error) {
	return p.change(ctx, p.State.Service().GrantRole, authority.RoleRequest{Organization: req.GetOrganizationId(), InstallationID: req.GetInstallationId(),
		Role: req.GetRole(), PersonID: req.GetPersonId(), TeamID: req.GetTeamId()})
}

// RevokeRole ends one grant.
func (p *Plugin) RevokeRole(ctx context.Context, req *installationv1.RevokeRoleRequest) (*installationv1.Installation, error) {
	return p.change(ctx, p.State.Service().RevokeRole, authority.RoleRequest{Organization: req.GetOrganizationId(), InstallationID: req.GetInstallationId(),
		Role: req.GetRole(), PersonID: req.GetPersonId(), TeamID: req.GetTeamId()})
}

func (p *Plugin) change(ctx context.Context, do func(context.Context, authority.Person, authority.RoleRequest) (state.Installation, error), r authority.RoleRequest) (*installationv1.Installation, error) {
	caller, err := p.caller(ctx)
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	inst, err := do(ctx, caller, r)
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	return p.wire(inst), nil
}

// ListRoleGrants answers who holds which role on the installation.
func (p *Plugin) ListRoleGrants(ctx context.Context, req *installationv1.ListRoleGrantsRequest) (*installationv1.ListRoleGrantsResponse, error) {
	caller, err := p.caller(ctx)
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	grants, err := p.State.Service().ListRoleGrants(ctx, caller, req.GetOrganizationId(), req.GetInstallationId())
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	out := &installationv1.ListRoleGrantsResponse{}
	for _, g := range grants {
		out.Grants = append(out.Grants, &installationv1.RoleGrant{Role: g.Role, PersonId: g.PersonID, TeamId: g.TeamID})
	}
	return out, nil
}

// List answers what one organisation has installed, for its administrator.
func (p *Plugin) List(ctx context.Context, req *installationv1.ListRequest) (*installationv1.ListResponse, error) {
	caller, err := p.caller(ctx)
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	all, err := p.State.Service().Installations(ctx, caller, req.GetOrganizationId())
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	slices.SortFunc(all, func(a, b state.Installation) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	out := &installationv1.ListResponse{}
	for _, inst := range all {
		out.Installations = append(out.Installations, p.wire(inst))
	}
	return out, nil
}

// wire converts an installation to the interface's message, with the roles
// its solution declares.
func (p *Plugin) wire(i state.Installation) *installationv1.Installation {
	st := map[state.Status]installationv1.Installation_Status{
		state.Pending: installationv1.Installation_STATUS_PENDING, state.Active: installationv1.Installation_STATUS_ACTIVE, state.Revoked: installationv1.Installation_STATUS_REVOKED,
	}[i.Status]
	out := &installationv1.Installation{Id: i.ID, OrganizationId: i.Organization, Target: i.Target, Status: st, Revision: i.Revision,
		Role: i.AgentRole, PrincipalId: i.PrincipalID, Namespace: state.Namespace(i)}
	if m, ok := p.State.Module(i.Target); ok {
		for name := range m.Roles {
			out.Roles = append(out.Roles, name)
		}
		slices.Sort(out.Roles)
	}
	return out
}

// New is the registry's constructor: the plugin over what Configure wired.
func New() framework.Plugin { return &Plugin{State: wiring.State()} }

func approvalFromWire(a *installationv1.ConsentApproval) *domain.ConsentApproval {
	if a == nil {
		return nil
	}
	return &domain.ConsentApproval{TargetID: a.GetTargetId(), Generation: a.GetGeneration(), ExpectedRevision: a.GetExpectedRevision(), OperationID: a.GetOperationId(), Digest: a.GetDigest()}
}

// Review reads the exact authority offer without recording consent.
func (p *Plugin) Review(ctx context.Context, req *installationv1.ReviewRequest) (*installationv1.ConsentApproval, error) {
	caller, err := p.caller(ctx)
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	a, err := p.State.Service().Review(ctx, caller, req.GetOrganizationId(), req.GetTarget())
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	return &installationv1.ConsentApproval{TargetId: a.TargetID, Generation: a.Generation, ExpectedRevision: a.ExpectedRevision, Digest: a.Digest}, nil
}
