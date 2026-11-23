// Package declare renders a module's contract, resolved against its
// composition, into what it declares to its host: the authority block of core's
// signed manifest, and the contract's half of the authority's document
// delivered beside it. It is a projection and decides nothing: which roles a
// unit may declare and what each may grant are held by the host when the
// delivery arrives (decide.ValidateModule), so a change to that policy never
// changes this render, nor any producer that embeds it.
package declare

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/codefly-dev/authority/libraries/solutionhost/go"
	modulecontract "github.com/codefly-dev/core/contracts/module"
)

// Declaration is what a module's contract declares to its host, rendered in
// one place for every producer (the CLI's render and delivery, a test that
// composes the module in process): the authority block of its signed manifest,
// and the contract's half of the authority's document delivered beside it.
// Neither carries what the contract does not say: the method policies its
// package declares, and the prepared bindings a composition asks for.
type Declaration struct {
	Authority solutionhost.Authority `json:"authority"`
	Document  AuthorityDocument      `json:"document"`
}

// AuthorityDocument is the contract's half of the authority's document
// (codefly.dev/composition AuthorityManifestV1), in core's terms: the scope
// ceilings on the module's own kinds, its roles, its owner-aware and shared
// declarations, and its installation declaration.
type AuthorityDocument struct {
	ScopeCeilings    []DeclaredScope                 `json:"scope_ceilings,omitempty"`
	Roles            []DeclaredRole                  `json:"roles,omitempty"`
	OwnerAware       bool                            `json:"owner_aware,omitempty"`
	SharedKinds      []string                        `json:"shared_kinds,omitempty"`
	InstallationRole string                          `json:"installation_role,omitempty"`
	EdgeDependencies []modulecontract.EdgeDependency `json:"edge_dependencies,omitempty"`
}

// RoleAudience grants scopes at one resolved module principal.
type RoleAudience struct {
	Audience string          `json:"audience"`
	Scopes   []DeclaredScope `json:"scopes"`
}

// DeclaredRole is one role as the authority's document carries it: the scopes
// it grants, those it grants on what the installation owns, and those it names
// through each of the module's bindings, per binding in the order first named.
type DeclaredRole struct {
	Audiences               []RoleAudience  `json:"audiences,omitempty"`
	Name                    string          `json:"name"`
	Scopes                  []DeclaredScope `json:"scopes,omitempty"`
	InstallationOwnedScopes []DeclaredScope `json:"installation_owned_scopes,omitempty"`
	Through                 []RoleThrough   `json:"through,omitempty"`
}

// RoleThrough is what a role names downstream of one binding.
type RoleThrough struct {
	Binding string          `json:"binding"`
	Scopes  []DeclaredScope `json:"scopes"`
}

// DeclaredScope is a kind and its actions, never ids.
type DeclaredScope struct {
	ResourceKind string   `json:"resource_kind"`
	Actions      []string `json:"actions"`
}

// From renders contract, resolved against its composition (resolved is
// contract.Resolve's answer, for the environment class being delivered to),
// into its Declaration.
//
// The authority block names the module's principal, each binding the
// composition delivers with its scopes per operation, the installation
// declaration verbatim but for an edge's class-resolved presence, the scopes
// that govern its sources, its queues and namespaces, and its own kinds.
//
// The document carries each role in declaration order: a scope naming a
// binding through is carried in the role's through, per binding in the order
// first named, only when the composition delivers that binding (an optional
// binding it fills none of the slots of is left out, and the role reaches
// nothing through it). An empty list is nil throughout, so a list and its
// absence spell the same bytes.
func From(contract *modulecontract.Contract, resolved *modulecontract.Resolved) (*Declaration, error) {
	if contract == nil || resolved == nil {
		return nil, fmt.Errorf("a declaration is rendered from a contract and its resolution")
	}
	roles, err := declaredRoles(contract, resolved)
	if err != nil {
		return nil, err
	}
	out := &Declaration{
		Authority: solutionhost.Authority{
			Principal:        resolved.Principal,
			InstallationRole: resolved.InstallationRole,
			EdgeDependencies: cloned(resolved.EdgeDependencies),
			SourceGovernance: cloned(resolved.SourceGovernance),
			Queues:           cloned(resolved.Queues),
			Namespaces:       cloned(resolved.Namespaces),
		},
		Document: AuthorityDocument{
			Roles:            roles,
			OwnerAware:       resolved.OwnerAware,
			InstallationRole: resolved.InstallationRole,
			EdgeDependencies: cloned(resolved.EdgeDependencies),
		},
	}
	for _, binding := range resolved.Bindings {
		operations := make(map[string][]string, len(binding.Operations))
		for _, operation := range binding.Operations {
			operations[operation] = cloned(binding.Scopes[operation])
		}
		out.Authority.Bindings = append(out.Authority.Bindings, solutionhost.AuthorityBinding{ID: binding.ID, Audience: binding.Audience, Operations: operations})
	}
	for _, ceiling := range resolved.ScopeCeilings {
		if !slices.Contains(out.Authority.ResourceKinds, ceiling.ResourceKind) {
			out.Authority.ResourceKinds = append(out.Authority.ResourceKinds, ceiling.ResourceKind)
		}
		out.Document.ScopeCeilings = append(out.Document.ScopeCeilings, DeclaredScope{ResourceKind: ceiling.ResourceKind, Actions: cloned(ceiling.Actions)})
		if ceiling.Shared {
			out.Document.SharedKinds = append(out.Document.SharedKinds, ceiling.ResourceKind)
		}
	}
	return out, nil
}

// declaredRoles are contract's roles as the document carries them, each held
// to the one resolved addresses at the same position.
func declaredRoles(contract *modulecontract.Contract, resolved *modulecontract.Resolved) ([]DeclaredRole, error) {
	if len(contract.Roles) == 0 {
		return nil, nil
	}
	if len(resolved.Roles) != len(contract.Roles) {
		return nil, fmt.Errorf("the module contract of %s resolves %d roles of the %d it declares", contract.Principal, len(resolved.Roles), len(contract.Roles))
	}
	out := make([]DeclaredRole, 0, len(contract.Roles))
	for index, role := range contract.Roles {
		if resolved.Roles[index].Name != role.Name {
			return nil, fmt.Errorf("the module contract of %s resolves role %q where it declares %q", contract.Principal, resolved.Roles[index].Name, role.Name)
		}
		delivered := resolved.Roles[index].Through
		declared := DeclaredRole{Name: role.Name, InstallationOwnedScopes: declaredScopes(role.InstallationOwnedScopes)}
		for _, grant := range role.Bindings {
			for _, binding := range resolved.Bindings {
				if binding.ID != grant.Binding && binding.ID != modulecontract.AudienceBindingID(grant.Binding, binding.Audience) {
					continue
				}
				var scopes []DeclaredScope
				for _, permission := range binding.Scopes[grant.Operation] {
					kind, action, ok := strings.Cut(permission, ":")
					if !ok || kind == "" || action == "" {
						return nil, fmt.Errorf("invalid resolved permission %q", permission)
					}
					scopes = append(scopes, DeclaredScope{ResourceKind: kind, Actions: []string{action}})
				}
				if len(scopes) > 0 {
					declared.Audiences = append(declared.Audiences, RoleAudience{Audience: binding.Audience, Scopes: scopes})
				}
			}
		}
		var own []modulecontract.CeilingScope
		// The role as resolved: its own scopes with every bundle it includes
		// granted beside them (core's ResolvedRole.Scopes), never the
		// contract's, which names an include by name only.
		for _, scope := range resolved.Roles[index].Scopes {
			if scope.Through == "" {
				own = append(own, scope)
				continue
			}
			if _, held := delivered[scope.Through]; !held {
				continue // through an optional binding the composition leaves out
			}
			i := slices.IndexFunc(declared.Through, func(t RoleThrough) bool { return t.Binding == scope.Through })
			if i < 0 {
				declared.Through = append(declared.Through, RoleThrough{Binding: scope.Through})
				i = len(declared.Through) - 1
			}
			declared.Through[i].Scopes = append(declared.Through[i].Scopes, declaredScopes([]modulecontract.CeilingScope{scope})...)
		}
		declared.Scopes = declaredScopes(own)
		out = append(out, declared)
	}
	return out, nil
}

// declaredScopes spells contract scopes as kinds and actions; nil for none.
func declaredScopes(scopes []modulecontract.CeilingScope) []DeclaredScope {
	if len(scopes) == 0 {
		return nil
	}
	out := make([]DeclaredScope, 0, len(scopes))
	for _, scope := range scopes {
		out = append(out, DeclaredScope{ResourceKind: scope.ResourceKind, Actions: cloned(scope.Actions)})
	}
	return out
}

// cloned is a copy of in, nil when in is empty: the spelling every producer of
// a declaration used, so an empty list serializes the same everywhere.
func cloned[T any](in []T) []T { return append([]T(nil), in...) }

// Module is the declaration of the module named name at dir, as every
// producer renders it: dir must not ship the retired roles declaration; the
// contract is request when the caller has one (a composed solution's
// consumption, core's ConsumptionContract), else dir's own module contract
// (nil, nil when dir publishes none); its principal must be name, the
// principal every credential of the module is issued to (no check when name
// is empty); resolve is the composition's resolution (core's
// solutionhost.Resolver); and From
// renders the rest (From). The resolution is returned with it, for what a caller
// checks or reports of it.
//
// Each call resolves the contract again, which reads the composition: a caller
// renders a module once and reads every field it needs off that one
// Declaration.
func Module(dir, name string, request *modulecontract.Contract, resolve func(*modulecontract.Contract) (*modulecontract.Resolved, error)) (*Declaration, *modulecontract.Resolved, error) {
	if err := solutionhost.RefuseRetiredRoles(dir); err != nil {
		return nil, nil, err
	}
	contract := request
	if contract == nil {
		if dir == "" {
			return nil, nil, nil
		}
		loaded, err := modulecontract.Load(dir)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		if err != nil {
			return nil, nil, err
		}
		contract = loaded
	}
	if name != "" && contract.Principal != name {
		return nil, nil, fmt.Errorf("module %s publishes a contract whose principal is %q; the principal every credential of a module is issued to is the module's own name, so the contract declares principal: %s", name, contract.Principal, name)
	}
	resolved, err := resolve(contract)
	if err != nil {
		return nil, nil, fmt.Errorf("module %s: %w", contract.Principal, err)
	}
	declaration, err := From(contract, resolved)
	if err != nil {
		return nil, nil, err
	}
	return declaration, resolved, nil
}
