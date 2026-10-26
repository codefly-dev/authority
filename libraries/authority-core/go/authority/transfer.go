package authority

import (
	"context"
	"errors"
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	resources "github.com/codefly-dev/authority/libraries/resources/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// TransferRequest asks whether an existing resource may join a solution
// principal: the person's capability, the store attesting the resource and
// its current owner.
type TransferRequest struct {
	Token, Kind, ResourceID, From, To string
	Store                             Workload
}

// TransferDecision is what the store records.
type TransferDecision struct {
	PrincipalID, AuthorizedBy string
}

// AuthorizeTransfer authorizes a transfer and records the installation-owned id
// atomically, reading everything live. The caller
// is the kind's one serving module; the capability is addressed to it.
func (s *Service) AuthorizeTransfer(ctx context.Context, r TransferRequest) (TransferDecision, error) {
	if err := decide.ValidResourceID(r.ResourceID); err != nil {
		return TransferDecision{}, err
	}
	var store domain.Module
	err := s.store.Read(ctx, func(tx Tx) error {
		m, err := tx.ModuleNamed(r.Store.Module)
		if err != nil {
			return notFound(err)
		}
		servers, err := servingModules(tx, r.Kind)
		if err != nil {
			return err
		}
		if !slices.Contains(servers, m.Name) || len(servers) != 1 {
			return domain.Refuse("%s does not serve %s alone, so it attests none of its resources", m.Name, r.Kind)
		}
		store = m
		return nil
	})
	if err != nil {
		return TransferDecision{}, err
	}
	verified, err := s.Verify(ctx, r.Token, store.Principal)
	if err != nil {
		return TransferDecision{}, err
	}
	wc := verified.Context()
	var decision TransferDecision
	err = s.store.Write(ctx, func(tx Tx) error {
		current, err := attachmentServer(tx, r.Store, r.Kind)
		if err != nil {
			return err
		}
		if current.Principal != store.Principal || current.Generation != store.Generation {
			return domain.Refuse("serving module changed during transfer")
		}
		if err := s.attachmentFresh(tx, wc); err != nil {
			return err
		}
		t := decide.Transfer{OwnerKind: wc.GetOwnerPrincipalKind(), From: r.From, To: r.To}
		if t.OwnerKind != "human" {
			return decide.AuthorizeTransfer(t)
		}
		p, err := tx.Person(wc.GetOwnerPrincipalId())
		if err != nil {
			return domain.Refuse("the owner %s is no longer a member", wc.GetOwnerPrincipalId())
		}
		if p.Organization != wc.GetTenantId() {
			return domain.Refuse("the person no longer belongs to the capability's organization")
		}
		t.Person = p
		for _, principal := range solutionPrincipals(wc, wc.GetAudience()) {
			if m, err := tx.Module(principal); err == nil && m.Kind == domain.KindSolution {
				if inst, err := installationOf(tx, wc.GetTenantId(), m.Name); err == nil {
					t.Through = append(t.Through, inst.PrincipalID)
				}
			}
		}
		if _, err := tx.InstallationByPrincipal(r.From); err == nil {
			t.FromPrincipal = true
		} else if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		if fp, err := tx.Person(r.From); err == nil {
			t.FromPerson = &fp
		}
		roles, err := orgRoles(tx, p)
		if err != nil {
			return err
		}
		if matchers := decide.ResourceGrants(roles, r.Kind, "admin"); len(matchers) > 0 {
			covered, err := resources.Compile(matchers)
			t.Administers = err == nil && covered.Matches(r.ResourceID)
		}
		target, err := tx.InstallationByPrincipal(r.To)
		if err != nil {
			return notFound(err)
		}
		if target.Organization != wc.GetTenantId() || target.Status != domain.Active {
			return domain.Refuse("target installation %s is not active at %s", target.ID, wc.GetTenantId())
		}
		solution, err := tx.ModuleNamed(target.Target)
		if err != nil {
			return notFound(err)
		}
		grants, err := tx.RoleGrants(target.ID)
		if err != nil {
			return err
		}
		role, err := decide.RoleScopes(solution, target, decide.HeldRoles(p, target, grants))
		if err != nil {
			return err
		}
		t.Writes = scope.HoldsAction(role, r.Kind, "write")
		if err := decide.AuthorizeTransfer(t); err != nil {
			return err
		}
		if err := attachOwned(tx, target, r.Kind, r.ResourceID); err != nil {
			return err
		}
		decision = TransferDecision{PrincipalID: r.To, AuthorizedBy: p.ID}
		return nil
	})
	return decision, err
}

// servingModules are the modules declaring kind.
func servingModules(tx Tx, kind string) ([]string, error) {
	all, err := tx.Modules()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range all {
		if slices.ContainsFunc(m.ResourceKinds, func(sc *basev0.WorkScopeV1) bool { return sc.GetResourceKind() == kind }) {
			out = append(out, m.Name)
		}
	}
	return out, nil
}
