package authority

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
)

// IssueRequest is what every owner shape asks: an audience (or the binding
// whose audience it is), the binding exercised and its operation, the
// organization of a workload's work, the scopes asked (none: everything held)
// and a lifetime.
type IssueRequest struct {
	Audience, Binding, Operation, Organization string
	Scopes                                     Scopes
	TTL                                        time.Duration
}

// Issued is a signed capability and its claims.
type Issued struct {
	Token   string
	Context *basev0.WorkContextV1
}

// held is what a person holds at an audience: at a solution, the scopes of the
// roles granted them on its installation, owned by its principal; at a
// module, their organization roles within what it serves.
func held(tx Tx, p domain.Person, audience domain.Module) (Scopes, error) {
	if audience.Kind == domain.KindSolution {
		inst, err := installationOf(tx, p.Organization, audience.Name)
		if errors.Is(err, domain.ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		grants, err := tx.RoleGrants(inst.ID)
		if err != nil {
			return nil, err
		}
		return scope.Intersect(decide.RoleScopes(audience, inst, decide.HeldRoles(p, grants)), audience.ResourceKinds), nil
	}
	roles, err := orgRoles(tx, p)
	if err != nil {
		return nil, err
	}
	return decide.OrgScopes(roles, audience), nil
}

// solutionCeiling intersects the current roles of each solution the verified
// path names; bounded distinguishes no solution from a solution granting nothing.
func solutionCeiling(tx Tx, p domain.Person, principals []string) (ceiling Scopes, bounded bool, err error) {
	seen := map[string]bool{}
	for _, principal := range principals {
		if seen[principal] {
			continue
		}
		seen[principal] = true
		m, err := tx.Module(principal)
		if err != nil {
			return nil, false, notFound(err)
		}
		if m.Kind != domain.KindSolution {
			continue
		}
		inst, err := installationOf(tx, p.Organization, m.Name)
		var role Scopes
		if err == nil {
			grants, gerr := tx.RoleGrants(inst.ID)
			if gerr != nil {
				return nil, false, gerr
			}
			role = decide.RoleScopes(m, inst, decide.HeldRoles(p, grants))
		} else if !errors.Is(err, domain.ErrNotFound) {
			return nil, false, err
		}
		if bounded {
			ceiling = scope.Intersect(ceiling, role)
		} else {
			ceiling = role
		}
		bounded = true
	}
	return ceiling, bounded, nil
}

// throughSolutions is what a person holds at audience on a path through
// principals: the solutions' roles alone when a solution is on the path
// (confined to its principal's data), the person's own grants otherwise.
func throughSolutions(tx Tx, p domain.Person, audience domain.Module, principals []string) (h, ceiling Scopes, bounded bool, err error) {
	if ceiling, bounded, err = solutionCeiling(tx, p, principals); err != nil {
		return
	}
	if !bounded {
		h, err = held(tx, p, audience)
		return
	}
	h = scope.Intersect(ceiling, audience.ResourceKinds)
	if audience.Kind == domain.KindSolution {
		var target Scopes
		if target, err = held(tx, p, audience); err != nil {
			return
		}
		h = scope.Intersect(h, target)
	}
	return
}

// solutionPrincipals are the current actor and the services of a verified chain.
func solutionPrincipals(wc *basev0.WorkContextV1, current string) []string {
	out := []string{current}
	for _, actor := range wc.GetActorChain() {
		if actor.GetPrincipalKind() == "service" {
			out = append(out, actor.GetPrincipalId())
		}
	}
	return out
}

func (s *Service) audienceOf(tx Tx, r *IssueRequest, actor string) error {
	if r.Audience != "" || r.Binding == "" || actor == "" {
		if r.Audience == "" {
			return domain.Refuse("an issue names its audience, or the binding whose audience it is")
		}
		return nil
	}
	m, err := tx.ModuleNamed(actor)
	if err != nil {
		return notFound(err)
	}
	b, ok := m.Bindings[r.Binding]
	if !ok {
		return domain.Missing("operation binding %q is not one %s declares", r.Binding, m.Name)
	}
	r.Audience = b.Audience
	return nil
}

// startAtRevision mints at the revision the decision read: a concurrent grant
// change must not turn old scopes into fresh authority.
func (s *Service) startAtRevision(ctx context.Context, revision uint64, in workcontext.StartInput) (Issued, error) {
	token, signed, err := s.authority.Start(ctx, in)
	if err != nil {
		return Issued{}, err
	}
	if signed.GetAuthorizationRevision() != revision {
		return Issued{}, domain.Refuse("permissions changed during issuance")
	}
	return Issued{token, signed}, nil
}

// IssueForPerson: owner = actor = the person; scopes = asked within what they
// hold at the audience (a solution: their granted roles on its principal's
// data); sealed to the audience's installation at their organization.
func (s *Service) IssueForPerson(ctx context.Context, who Person, r IssueRequest) (Issued, error) {
	var revision uint64
	var audience domain.Module
	var heldHere, scopes Scopes
	var inst domain.Installation
	err := s.store.Read(ctx, func(tx Tx) error {
		var err error
		if err = s.audienceOf(tx, &r, ""); err != nil {
			return err
		}
		if audience, err = tx.Module(r.Audience); err != nil {
			return notFound(err)
		}
		p, err := tx.Person(who.ID)
		if err != nil || p.Organization != who.Organization {
			return domain.Refuse("the session's person is no longer a member of %s", who.Organization)
		}
		if revision, err = tx.AuthorizationRevision(p.Organization); err != nil {
			return err
		}
		inst, err = installationOf(tx, p.Organization, audience.Name)
		if err != nil || inst.Status != domain.Active {
			return domain.NotNow("audience %q is not installed in this organization, so there is no installation to seal the capability to", audience.Principal)
		}
		if heldHere, err = held(tx, p, audience); err != nil {
			return err
		}
		if audience.Kind == domain.KindSolution && !audience.OwnerAware {
			return decide.OwnerAware(audience, decide.Scopes{{ResourceKind: audience.Name, ResourceOwnerId: inst.PrincipalID}})
		}
		if audience.Kind == domain.KindSolution && len(heldHere) == 0 {
			return domain.Refuse("%s holds no role on %s", p.ID, audience.Name)
		}
		if r.Binding != "" {
			binding, declared := audience.Bindings[r.Binding]
			if !declared {
				return domain.Missing("operation binding %q is not one %s declares", r.Binding, audience.Name)
			}
			target, err := tx.Module(binding.Audience)
			if err != nil {
				return notFound(err)
			}
			there, _, _, err := throughSolutions(tx, p, target, []string{audience.Principal})
			if err != nil {
				return err
			}
			through := scope.Intersect(there, binding.InvokeScopes)
			if len(through) == 0 {
				return domain.Refuse("%s holds nothing under operation binding %q", p.ID, r.Binding)
			}
			heldHere = scope.Normalize(append(heldHere, through...))
		}
		if scopes, err = decide.Issue(r.Scopes, heldHere); err != nil {
			return err
		}
		return decide.OwnerAware(audience, scopes)
	})
	if err != nil {
		return Issued{}, err
	}
	return s.startAtRevision(ctx, revision, workcontext.StartInput{
		TenantID: who.Organization, OrganizationID: who.Organization,
		OwnerPrincipalID: who.ID, OwnerPrincipalKind: "human", TaskID: s.cfg.NewID(), SessionID: who.SessionID,
		Audience: audience.Principal, AuthorityScopes: scope.Limits{}.Project(heldHere, scopes), AttributionTeamIDs: sortedTeams(who.Teams),
		InstallationID: inst.ID, TTL: clamp(r.TTL, s.cfg.MaxTTL),
	})
}

// IssueForWorkload: owner = actor = the module; scopes = its binding's
// headless scopes within asked; the binding names the audience.
func (s *Service) IssueForWorkload(ctx context.Context, w Workload, r IssueRequest) (Issued, error) {
	var module, audience domain.Module
	var through, scopes Scopes
	var org, instID string
	err := s.store.Read(ctx, func(tx Tx) error {
		var err error
		if module, err = tx.ModuleNamed(w.Module); err != nil {
			return notFound(err)
		}
		if r.Binding == "" {
			return domain.Refuse("a workload issue names the binding it exercises")
		}
		if err = s.audienceOf(tx, &r, w.Module); err != nil {
			return err
		}
		if audience, err = tx.Module(r.Audience); err != nil {
			return notFound(err)
		}
		org = r.Organization
		if org == "" {
			var orgs []string
			all, err := tx.Installations("")
			if err != nil {
				return err
			}
			for _, inst := range all {
				if inst.Target == module.Name && inst.Status == domain.Active {
					orgs = append(orgs, inst.Organization)
				}
			}
			switch len(orgs) {
			case 0:
				return domain.Refuse("module %q has no active installation; a workload must name the organization of the work item", module.Name)
			case 1:
				org = orgs[0]
			default:
				return domain.Refuse("module %q has ambiguous active installations across organizations; a workload must name the organization of the work item", module.Name)
			}
		}
		binding, ok := module.Bindings[r.Binding]
		if !ok {
			return workcontext.ErrNoBinding
		}
		if binding.Audience != audience.Principal {
			return domain.Refuse("binding %s is addressed to %s, not %s", r.Binding, binding.Audience, audience.Principal)
		}
		if through, err = decide.ScopesFor(binding, r.Operation, "headless"); err != nil {
			return err
		}
		if scopes, err = decide.Issue(r.Scopes, through); err != nil {
			return err
		}
		inst, err := installationOf(tx, org, module.Name)
		if err != nil {
			return domain.NotNow("%s is not installed at %s", module.Name, org)
		}
		instID = inst.ID
		return decide.OwnerAware(audience, scopes)
	})
	if err != nil {
		return Issued{}, err
	}
	token, signed, err := s.authority.Start(ctx, workcontext.StartInput{
		TenantID: org, OrganizationID: org, OwnerPrincipalID: module.Principal, OwnerPrincipalKind: "service",
		TaskID: s.cfg.NewID(), Audience: audience.Principal, AuthorityScopes: scope.Limits{}.Project(through, scopes),
		InstallationID: instID, OperationBindingID: org + "/" + module.Name + "/" + r.Binding, TTL: clamp(r.TTL, s.cfg.MaxTTL),
	})
	if err != nil {
		return Issued{}, err
	}
	if signed.GetSeal().GetPrincipalEpoch() != module.Generation || signed.GetOperationBinding().GetRevision() != module.Generation {
		return Issued{}, domain.Refuse("workload binding changed during issuance")
	}
	return Issued{token, signed}, nil
}

// IssueForInstallation: owner = the installation's principal acting for
// itself, with its agent role, confined to its own data; at another audience
// it acts through one of its solution's bindings. Its solution's workload asks.
func (s *Service) IssueForInstallation(ctx context.Context, w Workload, installationID string, r IssueRequest) (Issued, error) {
	var inst domain.Installation
	var solution, audience domain.Module
	var heldHere, scopes Scopes
	var revision uint64
	bindingID := ""
	err := s.store.Read(ctx, func(tx Tx) error {
		var err error
		if solution, err = tx.ModuleNamed(w.Module); err != nil {
			return notFound(err)
		}
		if inst, err = tx.Installation(installationID); err != nil {
			return notFound(err)
		}
		if r.Organization != "" && r.Organization != inst.Organization {
			return domain.Refuse("installation %s belongs to organization %q, not %q", inst.ID, inst.Organization, r.Organization)
		}
		if solution.Kind != domain.KindSolution || solution.Name != inst.Target {
			return domain.Refuse("installation issuance requires the installed solution's workload")
		}
		if inst.Status != domain.Active {
			return domain.NotNow("installation %s is %s: %s is not installed", inst.ID, inst.Status, inst.Target)
		}
		if err = s.audienceOf(tx, &r, w.Module); err != nil {
			return err
		}
		if audience, err = tx.Module(r.Audience); err != nil {
			return notFound(err)
		}
		if revision, err = tx.AuthorizationRevision(inst.Organization); err != nil {
			return err
		}
		// Everything the installation holds for itself is owner-selected.
		if err := decide.OwnerAware(audience, decide.Scopes{{ResourceKind: audience.Name, ResourceOwnerId: inst.PrincipalID}}); err != nil {
			return err
		}
		heldHere = scope.Intersect(decide.RoleScopes(solution, inst, []string{inst.AgentRole}), audience.ResourceKinds)
		if audience.Principal != solution.Principal {
			if r.Binding == "" {
				return domain.Refuse("the installation acting for itself reaches %s only through an operation binding its solution declares; it names no binding", audience.Principal)
			}
			binding, ok := solution.Bindings[r.Binding]
			if !ok {
				return domain.Missing("operation binding %q is not one %s declares", r.Binding, solution.Name)
			}
			if binding.Audience != audience.Principal {
				return domain.Refuse("binding %q is addressed to %s, not %s", r.Binding, binding.Audience, audience.Principal)
			}
			through, err := decide.ScopesFor(binding, r.Operation, "invoke")
			if err != nil {
				return err
			}
			heldHere = scope.Intersect(heldHere, through)
			bindingID = r.Binding
		}
		if scopes, err = decide.Issue(r.Scopes, heldHere); err != nil {
			return err
		}
		return decide.OwnerAware(audience, scopes)
	})
	if err != nil {
		return Issued{}, err
	}
	issued, err := s.startAtRevision(ctx, revision, workcontext.StartInput{
		TenantID: inst.Organization, OrganizationID: inst.Organization,
		OwnerPrincipalID: inst.PrincipalID, OwnerPrincipalKind: "agent", OwnerAgentID: inst.Target,
		TaskID: s.cfg.NewID(), Audience: audience.Principal, AuthorityScopes: scope.Limits{}.Project(heldHere, scopes),
		InstallationID: inst.ID, TTL: clamp(r.TTL, s.cfg.MaxTTL), ReplayPolicy: workcontext.ReplayIdempotent,
	})
	if err != nil {
		return Issued{}, err
	}
	if bindingID != "" {
		// Another audience is reached through the solution's binding, as a hop
		// of its workload, so revoking the binding reaches the capability.
		current, err := s.Verify(ctx, issued.Token, audience.Principal)
		if err != nil {
			return Issued{}, err
		}
		token, signed, err := s.authority.Child(ctx, current, workcontext.ChildInput{
			PrincipalID: solution.Principal, PrincipalKind: "service", DelegationID: current.Context().GetSessionId(),
			GrantedScopes: scopes, Audience: audience.Principal, TTL: clamp(r.TTL, s.cfg.MaxTTL), ReplayPolicy: workcontext.ReplayIdempotent,
			OperationBindingID: inst.Organization + "/" + solution.Name + "/" + bindingID,
		})
		if err != nil {
			return Issued{}, err
		}
		issued = Issued{token, signed}
	}
	if epoch, err := s.src.PrincipalEpoch(ctx, solution.Principal); err != nil || epoch != solution.Generation {
		return Issued{}, domain.Refuse("installation workload changed during issuance")
	}
	return issued, nil
}

// IssueChild is one more hop, inherited from the owner (rule A): the owner's
// current grants at the audience within the actor's binding, within every
// narrowing a parent made. A person's grants reach a solution's path only as
// its roles on its principal's data. The child is sealed to the actor's
// installation (core binds a binding to its module's installation), so a hop
// by a solution is sealed to that solution's installation: revoking a role
// there, or uninstalling it, ends it.
func (s *Service) IssueChild(ctx context.Context, parent string, actor Workload, r IssueRequest) (Issued, error) {
	var am, audience domain.Module
	var binding domain.Binding
	var through, scopes, authorityScopes Scopes
	var claims *basev0.WorkContextV1
	var verified *workcontext.Verified
	var sealTo string
	err := s.store.Read(ctx, func(tx Tx) error {
		var err error
		if am, err = tx.ModuleNamed(actor.Module); err != nil {
			return notFound(err)
		}
		if r.Binding == "" {
			return domain.Refuse("a module's hop names the binding it exercises")
		}
		if err = s.audienceOf(tx, &r, actor.Module); err != nil {
			return err
		}
		var ok bool
		if binding, ok = am.Bindings[r.Binding]; !ok {
			return domain.Missing("operation binding %q is not one %s declares", r.Binding, am.Name)
		}
		if audience, err = tx.Module(r.Audience); err != nil {
			return notFound(err)
		}
		if binding.Audience != audience.Principal {
			return domain.Refuse("binding %q is addressed to %s, not %s", r.Binding, binding.Audience, audience.Principal)
		}
		return nil
	})
	if err != nil {
		return Issued{}, err
	}
	decoded, err := workcontext.Decode(parent)
	if err != nil {
		return Issued{}, err
	}
	if verified, err = s.Verify(ctx, parent, decoded.Context().GetAudience()); err != nil {
		return Issued{}, err
	}
	claims = verified.Context()
	if claims.GetAudience() != am.Principal {
		return Issued{}, domain.Refuse("%s hops only on a token addressed to it; this one is addressed to %s", am.Name, claims.GetAudience())
	}
	err = s.store.Read(ctx, func(tx Tx) error {
		tenant := claims.GetTenantId()
		var heldHere, sourceCeiling, own Scopes
		bounded := false
		switch claims.GetOwnerPrincipalKind() {
		case "human":
			p, err := tx.Person(claims.GetOwnerPrincipalId())
			if err != nil {
				return domain.Refuse("the owner %s is no longer a member", claims.GetOwnerPrincipalId())
			}
			if heldHere, sourceCeiling, bounded, err = throughSolutions(tx, p, audience, solutionPrincipals(claims, am.Principal)); err != nil {
				return err
			}
			if bounded {
				roles, err := orgRoles(tx, p)
				if err != nil {
					return err
				}
				own = decide.OrgScopes(roles, audience)
			}
		case "agent":
			inst, err := tx.InstallationByPrincipal(claims.GetOwnerPrincipalId())
			if err != nil || inst.Status != domain.Active {
				return domain.Refuse("the installation %s acts for is not installed", claims.GetOwnerPrincipalId())
			}
			solution, err := tx.ModuleNamed(inst.Target)
			if err != nil {
				return notFound(err)
			}
			heldHere = scope.Intersect(decide.RoleScopes(solution, inst, []string{inst.AgentRole}), audience.ResourceKinds)
		default:
			heldHere = verified.EffectiveScopes()
		}
		if (bounded || claims.GetOwnerPrincipalKind() == "agent") && !audience.OwnerAware {
			return decide.OwnerAware(audience, decide.Scopes{{ResourceKind: audience.Name, ResourceOwnerId: claims.GetOwnerPrincipalId()}})
		}
		var err error
		if through, err = decide.ScopesFor(binding, r.Operation, "invoke"); err != nil {
			return err
		}
		ceiling := scope.Intersect(heldHere, through)
		if bounded {
			ceiling = scope.Intersect(ceiling, sourceCeiling)
		}
		if ceiling, err = delegationCeiling(tx, claims, ceiling); err != nil {
			return err
		}
		limits := scope.ParentLimits(claims)
		ceiling = limits.Constrain(ceiling)
		if len(ceiling) == 0 {
			return domain.Refuse("%s holds nothing at %s through binding %q", claims.GetOwnerPrincipalId(), audience.Name, r.Binding)
		}
		scopes = ceiling
		if len(r.Scopes) > 0 {
			if !scope.Attenuates(r.Scopes, ceiling) {
				return decide.Child(r.Scopes, ceiling, scope.Intersect(own, through), bounded, r.Binding)
			}
			scopes = scope.Normalize(r.Scopes)
		}
		if err := decide.OwnerAware(audience, scopes); err != nil {
			return err
		}
		authorityScopes = limits.Project(through, scopes)
		inst, err := installationOf(tx, tenant, am.Name)
		if err != nil {
			return domain.NotNow("%s is not installed at %s", am.Name, tenant)
		}
		sealTo = inst.ID
		return nil
	})
	if err != nil {
		return Issued{}, err
	}
	return s.derive(ctx, verified, am, audience, r, scopes, authorityScopes, sealTo)
}

// derive rebuilds the chain for the new audience, the parent's actors and
// then this one, and rechecks the parent once the child is signed.
func (s *Service) derive(ctx context.Context, verified *workcontext.Verified, am, audience domain.Module, r IssueRequest, scopes, authorityScopes Scopes, sealTo string) (Issued, error) {
	claims := verified.Context()
	ttl := clamp(r.TTL, s.cfg.MaxTTL)
	if remaining := time.Unix(claims.GetExpiresAtUnix(), 0).Sub(s.cfg.Clock()); remaining < ttl {
		ttl = remaining
	}
	if ttl <= 0 {
		return Issued{}, domain.Refuse("the parent has expired")
	}
	tenant := claims.GetTenantId()
	hops := slices.Clone(claims.GetActorChain())
	parentSession, rootSession := claims.GetSessionId(), ""
	if len(hops) == 0 {
		rootSession = parentSession
	}
	token, _, err := s.authority.Start(ctx, workcontext.StartInput{
		TenantID: tenant, OrganizationID: claims.GetOrganizationId(),
		OwnerPrincipalID: claims.GetOwnerPrincipalId(), OwnerPrincipalKind: claims.GetOwnerPrincipalKind(), OwnerAgentID: claims.GetOwnerAgentId(),
		TaskID: claims.GetTaskId(), Audience: audience.Principal, AuthorityScopes: authorityScopes, AttributionTeamIDs: claims.GetAttributionTeamIds(),
		InstallationID: sealTo, SessionID: rootSession, TTL: ttl, ReplayPolicy: workcontext.ReplayIdempotent,
	})
	if err != nil {
		return Issued{}, err
	}
	for n := 0; n <= len(hops); n++ {
		current, err := s.Verify(ctx, token, audience.Principal)
		if err != nil {
			return Issued{}, err
		}
		in := workcontext.ChildInput{GrantedScopes: scopes, Audience: audience.Principal, TTL: ttl, ReplayPolicy: workcontext.ReplayIdempotent}
		if n < len(hops) {
			in.GrantedScopes = authorityScopes
			in.PrincipalID, in.PrincipalKind, in.DelegationID = hops[n].GetPrincipalId(), hops[n].GetPrincipalKind(), hops[n].GetDelegationId()
			if n == len(hops)-1 {
				in.SessionID = parentSession
			}
		} else {
			in.PrincipalID, in.PrincipalKind, in.DelegationID = am.Principal, "service", claims.GetSessionId()
			in.OperationBindingID = tenant + "/" + am.Name + "/" + r.Binding
		}
		var signed *basev0.WorkContextV1
		if token, signed, err = s.authority.Child(ctx, current, in); err != nil {
			return Issued{}, err
		}
		if n == len(hops) {
			if signed.GetOperationBinding().GetRevision() != am.Generation {
				return Issued{}, domain.Refuse("actor binding changed during issuance")
			}
			v, err := s.verifier(ctx, claims.GetAudience())
			if err != nil {
				return Issued{}, err
			}
			if err := v.Recheck(ctx, verified); err != nil {
				return Issued{}, err
			}
			return Issued{token, signed}, nil
		}
	}
	return Issued{}, domain.Refuse("no hop was derived")
}

// delegationCeiling reads stored delegations named on the parent's hops.
func delegationCeiling(tx Tx, parent *basev0.WorkContextV1, ceiling Scopes) (Scopes, error) {
	for _, hop := range parent.GetActorChain() {
		d, err := tx.Delegation(hop.GetDelegationId())
		if errors.Is(err, domain.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		m, err := tx.Module(hop.GetPrincipalId())
		if err != nil {
			return nil, notFound(err)
		}
		if d.Revoked || d.Grantor != parent.GetOwnerPrincipalId() || d.Organization != parent.GetOrganizationId() || d.Module != m.Name {
			return nil, domain.Refuse("the explicit delegation does not authorize this actor chain")
		}
		ceiling = scope.Intersect(ceiling, d.Scopes)
	}
	return ceiling, nil
}
