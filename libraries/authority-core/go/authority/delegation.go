package authority

import (
	"context"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	"github.com/codefly-dev/core/workcontext"
)

// Delegate records a person's grant to a module of scopes they hold: at the
// module, or at an audience one of its bindings addresses (through a
// solution, its roles on its principal's data).
func (s *Service) Delegate(ctx context.Context, who Person, module string, scopes Scopes, purpose string) (domain.Delegation, error) {
	var d domain.Delegation
	err := s.store.Write(ctx, func(tx Tx) error {
		p, err := tx.Member(who.Organization, who.ID)
		if err != nil {
			return notFound(err)
		}
		m, err := tx.Module(module)
		if err != nil {
			return notFound(err)
		}
		if len(scopes) == 0 {
			return domain.Refuse("a delegation names what it grants")
		}
		holdings, err := held(tx, p, m)
		if err != nil {
			return err
		}
		for _, b := range m.Bindings {
			target, err := tx.Module(b.Audience)
			if err != nil {
				continue
			}
			there, _, _, err := throughSolutions(tx, p, target, []string{m.Principal})
			if err != nil {
				return err
			}
			if m.Kind != domain.KindSolution {
				if there, err = held(tx, p, target); err != nil {
					return err
				}
			}
			holdings = append(holdings, scope.Intersect(there, b.InvokeScopes)...)
			holdings = append(holdings, scope.Intersect(there, b.LookupScopes)...)
		}
		if !scope.Attenuates(scopes, holdings) {
			return domain.Refuse("%s delegates what they do not hold", p.ID)
		}
		d = domain.Delegation{ID: s.cfg.NewID(), Organization: p.Organization, Grantor: p.ID, Module: m.Name, Purpose: purpose, Scopes: scope.Normalize(scopes)}
		return tx.PutDelegation(d)
	})
	return d, err
}

// RevokeDelegation ends a delegation; only its grantor may. Its capabilities
// are refused at once.
func (s *Service) RevokeDelegation(ctx context.Context, who Person, id string) (domain.Delegation, error) {
	var d domain.Delegation
	err := s.store.Write(ctx, func(tx Tx) error {
		var err error
		if d, err = tx.Delegation(id); err != nil {
			return notFound(err)
		}
		if d.Grantor != who.ID {
			return domain.Refuse("only the grantor of %s may revoke it", id)
		}
		if d.Revoked {
			return nil
		}
		d.Revoked = true
		if err := tx.PutDelegation(d); err != nil {
			return err
		}
		return tx.BumpAuthorizationRevision(d.Organization)
	})
	return d, err
}

// Delegation reads one delegation for its module or its grantor; anyone else
// learns nothing, not even that it exists. Exactly one of who and module is set.
func (s *Service) Delegation(ctx context.Context, id string, who *Person, module *Workload) (domain.Delegation, error) {
	var d domain.Delegation
	err := s.store.Read(ctx, func(tx Tx) error {
		var err error
		d, err = tx.Delegation(id)
		if err == nil && ((module != nil && module.Module == d.Module) || (who != nil && who.ID == d.Grantor)) {
			return nil
		}
		return domain.Missing("delegation %q", id)
	})
	return d, err
}

// IssueForDelegation issues for a delegation's grantor through the module it
// was granted to: what was delegated, cut to what the grantor holds at the
// audience now and to the binding. No live capability is presented.
func (s *Service) IssueForDelegation(ctx context.Context, id string, actor Workload, r IssueRequest) (Issued, error) {
	var d domain.Delegation
	var am, audience domain.Module
	var through, scopes Scopes
	var f fence
	var sealTo string
	err := s.store.Read(ctx, func(tx Tx) error {
		var err error
		if d, err = tx.Delegation(id); err != nil {
			return notFound(err)
		}
		if d.Revoked {
			return domain.Refuse("delegation %s is revoked", id)
		}
		if am, err = tx.ModuleNamed(actor.Module); err != nil {
			return notFound(err)
		}
		if am.Name != d.Module {
			return domain.Refuse("delegation %s is granted to %s, not %s", id, d.Module, am.Name)
		}
		if r.Binding == "" {
			return domain.Refuse("an issue from a delegation names the binding it exercises")
		}
		if err = s.audienceOf(tx, &r, actor.Module); err != nil {
			return err
		}
		binding, ok := am.Bindings[r.Binding]
		if !ok {
			return domain.Missing("operation binding %q is not one %s declares", r.Binding, am.Name)
		}
		if audience, err = tx.Module(r.Audience); err != nil {
			return notFound(err)
		}
		if binding.Audience != audience.Principal {
			return domain.Refuse("binding %q is addressed to %s, not %s", r.Binding, binding.Audience, audience.Principal)
		}

		if through, err = decide.ScopesFor(binding, r.Operation, "invoke"); err != nil {
			return err
		}
		p, err := tx.Member(d.Organization, d.Grantor)
		if err != nil {
			return domain.Refuse("the grantor %s is no longer a member", d.Grantor)
		}
		h, _, _, err := throughSolutions(tx, p, audience, []string{am.Principal})
		if err != nil {
			return err
		}
		ceiling := scope.Intersect(scope.Intersect(d.Scopes, h), through)
		if len(ceiling) == 0 {
			return domain.Refuse("delegation %s grants nothing %s still holds at %s through binding %q", id, d.Grantor, audience.Name, r.Binding)
		}
		if scopes, err = decide.Issue(r.Scopes, ceiling); err != nil {
			return err
		}
		if err := decide.OwnerAware(audience, scopes); err != nil {
			return err
		}
		inst, err := installationOf(tx, d.Organization, am.Name)
		if err != nil {
			return domain.NotNow("%s is not installed at %s", am.Name, d.Organization)
		}
		sealTo = inst.ID
		f, err = s.src.fenceIn(tx, d.Organization, d.Grantor, sealTo)
		return err
	})
	if err != nil {
		return Issued{}, err
	}
	root, err := s.startFenced(ctx, f, workcontext.StartInput{
		TenantID: d.Organization, OrganizationID: d.Organization, OwnerPrincipalID: d.Grantor, OwnerPrincipalKind: "human",
		TaskID: s.cfg.NewID(), Audience: audience.Principal, AuthorityScopes: scope.Limits{}.Project(through, scopes),
		InstallationID: sealTo, TTL: clamp(r.TTL, s.cfg.MaxTTL), ReplayPolicy: workcontext.ReplayIdempotent,
	})
	if err != nil {
		return Issued{}, err
	}
	current, err := s.Verify(ctx, root.Token, audience.Principal)
	if err != nil {
		return Issued{}, err
	}
	token, signed, err := s.authority.Child(ctx, current, workcontext.ChildInput{
		PrincipalID: am.Principal, PrincipalKind: "service", DelegationID: d.ID, GrantedScopes: scopes, Audience: audience.Principal,
		TTL: clamp(r.TTL, s.cfg.MaxTTL), ReplayPolicy: workcontext.ReplayIdempotent, OperationBindingID: d.Organization + "/" + am.Name + "/" + r.Binding,
	})
	if err != nil {
		return Issued{}, err
	}
	if again, err := s.Delegation(ctx, id, nil, &actor); err != nil || again.Revoked {
		return Issued{}, domain.Refuse("delegation %s is revoked", id)
	}
	if signed.GetOperationBinding().GetRevision() != am.Generation {
		return Issued{}, domain.Refuse("actor binding changed during issuance")
	}
	return Issued{token, signed}, nil
}
