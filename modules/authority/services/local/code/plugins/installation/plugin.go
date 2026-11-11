// Package installation serves codefly.dev/installation: Install, the role
// grants on an installation (GrantRole, RevokeRole, ListRoleGrants), List and
// a member's ListHeld.
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

// Current authenticates the module independently; the core verifies its parent
// and confines the read to its installation, without an admin session.
func (p *Plugin) Current(ctx context.Context, req *installationv1.CurrentInstallationRequest) (*installationv1.CurrentInstallation, error) {
	actor, err := p.State.VerifyWorkload(ctx, req.GetActorCredential())
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	// The namespace is where the parent authors: the installation's own, or,
	// for a parent owned by a solution installation, that installation's.
	inst, namespace, err := p.State.Service().CurrentAuthoring(ctx, req.GetParentToken(), authority.Workload{Module: actor.Name})
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	return &installationv1.CurrentInstallation{Id: inst.ID, OrganizationId: inst.Organization, Target: inst.Target, Revision: inst.Revision, Namespace: namespace}, nil
}

// Install installs a solution at the caller's organisation, which the caller
// administers; owner_person_id names who installed it (the caller when
// empty). Nobody holds a role on it until granted one. The install step is
// the host's hook (State.OnInstall); none set, the installation is active at
// once, as a solution without an install endpoint is. A module is refused:
// composition installs it.
func (p *Plugin) Install(ctx context.Context, req *installationv1.InstallRequest) (*installationv1.Installation, error) {
	caller, err := p.caller(ctx)
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	inst, err := p.State.Service().Install(ctx, caller, req.GetOrganizationId(), req.GetTarget(), req.GetRole(), req.GetOwnerPersonId(), approvalFromWire(req.GetApproval()), p.installStep())
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	return p.wire(ctx, inst), nil
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
	return p.wire(ctx, inst), nil
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
		out.Installations = append(out.Installations, p.wire(ctx, inst))
	}
	return out, nil
}

// ListHeld answers the signed-in person the installations of their
// organization they hold a role on, with those roles: their navigation.
func (p *Plugin) ListHeld(ctx context.Context, req *installationv1.ListHeldRequest) (*installationv1.ListHeldResponse, error) {
	caller, err := p.caller(ctx)
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	held, err := p.State.Service().HeldInstallations(ctx, caller, req.GetOrganizationId())
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	composed, err := p.State.Service().ComposedInstallations(ctx, caller, req.GetOrganizationId())
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	out := &installationv1.ListHeldResponse{}
	for _, h := range held {
		out.Installations = append(out.Installations, &installationv1.HeldInstallation{Installation: p.wire(ctx, h.Installation), Roles: h.Roles})
	}
	for _, c := range composed {
		out.Composed = append(out.Composed, wireComposed(c))
	}
	return out, nil
}

// wire converts an installation to the interface's message, with the roles
// its target declares, whether what is delivered, the target or a module its
// roles reach, offers an upgrade, and what its declared reach the
// composition leaves unreached (the core decides; a read it cannot make
// answers none).
func (p *Plugin) wire(ctx context.Context, i state.Installation) *installationv1.Installation {
	var roles, unreached []string
	upgrade := false
	if m, ok := p.State.Module(i.Target); ok {
		for name := range m.Roles {
			roles = append(roles, name)
		}
		slices.Sort(roles)
		upgrade, _ = p.State.Service().UpgradeAvailable(ctx, i)
		unreached, _ = p.State.Service().Unreached(ctx, i)
	}
	out := wireInstallation(i, roles, upgrade)
	out.Unreached = unreached
	return out
}

func wireInstallation(i state.Installation, roles []string, upgrade bool) *installationv1.Installation {
	st := map[state.Status]installationv1.Installation_Status{
		state.Pending: installationv1.Installation_STATUS_PENDING, state.Active: installationv1.Installation_STATUS_ACTIVE, state.Revoked: installationv1.Installation_STATUS_REVOKED,
	}[i.Status]
	return &installationv1.Installation{Id: i.ID, OrganizationId: i.Organization, Target: i.Target, Status: st, Revision: i.Revision,
		Role: i.AgentRole, PrincipalId: i.PrincipalID, Namespace: state.Namespace(i), Roles: roles,
		ApprovedGeneration: i.Consent.Generation, UpgradeAvailable: upgrade}
}

// wireComposed names a composed installation to ANY member of the
// organization, so it carries only what naming one requires: which
// installation, of what, and the source its authored agents belong to. It is
// deliberately not `wire`: nobody holds a role on a composed installation, so
// a member reading one has no claim on its principal, the generation its
// consent sits at, or what its declared reach leaves unreached. Those answer
// the administrator read (Installations), which is not this one.
func wireComposed(i state.Installation) *installationv1.Installation {
	return &installationv1.Installation{Id: i.ID, Target: i.Target, Namespace: state.Namespace(i)}
}

// New is the registry's constructor: the plugin over what Configure wired.
func New() framework.Plugin { return &Plugin{State: wiring.State()} }

func approvalFromWire(a *installationv1.ConsentApproval) *domain.ConsentApproval {
	if a == nil {
		return nil
	}
	return &domain.ConsentApproval{TargetID: a.GetTargetId(), Generation: a.GetGeneration(), ExpectedRevision: a.GetExpectedRevision(), OperationID: a.GetOperationId(), Digest: a.GetDigest(), ReachDigest: a.GetReachDigest()}
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
	return &installationv1.ConsentApproval{TargetId: a.TargetID, Generation: a.Generation, ExpectedRevision: a.ExpectedRevision, Digest: a.Digest, ReachDigest: a.ReachDigest}, nil
}
