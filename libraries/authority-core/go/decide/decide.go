// Package decide is the authority's pure decisions: each takes its inputs
// explicitly and answers a result or a named refusal (domain.Refusal). It
// reads no store and signs nothing, so both hosts decide identically.
package decide

import (
	"slices"
	"strings"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	resources "github.com/codefly-dev/authority/libraries/resources/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// Scopes is a scope list.
type Scopes = []*basev0.WorkScopeV1

// IsAdministrator: an organization's administrators hold "admin" or "owner".
func IsAdministrator(p domain.Person) bool {
	return slices.Contains(p.Roles, "admin") || slices.Contains(p.Roles, "owner")
}

// OrgScopes is what a person's organization roles grant at audience: the
// union of their scopes (AnyKind spanning every served kind) within what the
// audience serves. Resource matchers are ListResources' (ResourceGrants).
func OrgScopes(roles []domain.OrgRole, audience domain.Module) Scopes {
	var held Scopes
	for _, role := range roles {
		for _, sc := range role.Scopes {
			if sc.Kind == scope.AnyKind {
				for _, kind := range audience.ResourceKinds {
					held = append(held, &basev0.WorkScopeV1{ResourceKind: kind.GetResourceKind(), Actions: slices.Clone(sc.Actions)})
				}
				continue
			}
			held = append(held, &basev0.WorkScopeV1{ResourceKind: sc.Kind, Actions: slices.Clone(sc.Actions)})
		}
	}
	return scope.Intersect(scope.Normalize(held), audience.ResourceKinds)
}

// ResourceGrants are the resource matchers of every organization-role scope
// holding action on kind, or every resource for a scope that names none.
func ResourceGrants(roles []domain.OrgRole, kind, action string) []resources.Grant {
	var grants []resources.Grant
	for _, role := range roles {
		for _, sc := range role.Scopes {
			if (sc.Kind != kind && sc.Kind != scope.AnyKind) || (!slices.Contains(sc.Actions, action) && !slices.Contains(sc.Actions, scope.AnyAction)) {
				continue
			}
			if len(sc.Resources) == 0 {
				return []resources.Grant{{All: true}}
			}
			grants = append(grants, sc.Resources...)
		}
	}
	return grants
}

// HeldRoles are the roles a person holds on an installation: granted to them,
// or to a team they belong to. Holding none is holding no role.
func HeldRoles(p domain.Person, grants []domain.RoleGrant) []string {
	var roles []string
	for _, g := range grants {
		if (g.PersonID != "" && g.PersonID == p.ID) || (g.TeamID != "" && slices.Contains(p.Teams, g.TeamID)) {
			roles = append(roles, g.Role)
		}
	}
	slices.Sort(roles)
	return slices.Compact(roles)
}

// RoleScopes is what roles grant on a solution's installation: the roles'
// scopes, each selecting only the resources the installation's principal owns.
func RoleScopes(solution domain.Module, inst domain.Installation, roles []string) Scopes {
	var held Scopes
	for _, role := range roles {
		held = append(held, solution.Roles[role]...)
	}
	if len(held) == 0 {
		return nil
	}
	return scope.Owned(held, inst.PrincipalID)
}

// Issue is asked within held: held when nothing is asked; refused, naming
// why, when the ask names an action the owner does not hold ("beyond") or
// resources or an owner wider than it holds them ("widens").
func Issue(asked, held Scopes) (Scopes, error) {
	if len(asked) == 0 {
		if len(held) == 0 {
			return nil, domain.Refuse("the owner holds nothing at this audience")
		}
		for _, sc := range held {
			if slices.Contains(sc.GetActions(), scope.AnyAction) {
				return nil, domain.Refuse("the audience declares %s without its actions; ask for the scopes you need", sc.GetResourceKind())
			}
		}
		return held, nil
	}
	if scope.Attenuates(asked, held) {
		return scope.Normalize(asked), nil
	}
	if scope.Attenuates(scope.Unowned(asked), scope.Unowned(held)) {
		return nil, domain.Refuse("the ask widens what the owner holds: beyond the resources or the owner it holds them on")
	}
	return nil, domain.Refuse("asked beyond what the owner holds")
}

// Child refuses an ask beyond a child's ceiling: "confined" when the person's
// own organization grants would cover it but the solution the capability is
// issued through confines it to its principal's data, "widens" otherwise.
func Child(asked, ceiling, ownGrants Scopes, confinedBySolution bool, binding string) error {
	if confinedBySolution && len(ownGrants) > 0 && scope.Attenuates(asked, ownGrants) {
		return domain.Refuse("the ask is confined to the solution principal's data; the person's own grants never flow into a capability issued through a solution")
	}
	return domain.Refuse("a child widens what its owner holds through binding %q", binding)
}

// OwnerAware refuses owner-selected scopes to an audience that does not
// declare owner-aware checking: its module could read them as the whole kind.
func OwnerAware(audience domain.Module, scopes Scopes) error {
	if scope.HasOwner(scopes) && !audience.OwnerAware {
		return domain.Refuse("%s does not declare owner-aware checking, so it receives no owner-selected scope", audience.Principal)
	}
	return nil
}

// ScopesFor is what a binding may do for one operation, or def's when the
// request names none.
func ScopesFor(b domain.Binding, operation, def string) (Scopes, error) {
	if operation == "" {
		operation = def
	}
	switch operation {
	case "invoke":
		return b.InvokeScopes, nil
	case "headless":
		return b.HeadlessScopes, nil
	case "lookup":
		return b.LookupScopes, nil
	}
	return nil, domain.Refuse("operation %q is none of invoke, headless and lookup", operation)
}

// RoleChange is one GrantRole, RevokeRole or ListRoleGrants request with the
// state it is decided against.
type RoleChange struct {
	// RequestOrganization is the organization the request names.
	RequestOrganization string
	Installation        domain.Installation
	Solution            domain.Module
	// Caller is the authenticated person; CallerRoles what they hold on the installation.
	Caller      domain.Person
	CallerRoles []string
	// List asks only who may read the grants.
	List                   bool
	Role, PersonID, TeamID string
	// Subject is the person granted, when PersonID names one the host knows.
	Subject *domain.Person
	// TeamOfOrganization: a person of the installation's organization belongs to TeamID.
	TeamOfOrganization bool
}

// ChangeRole decides a role change, in order: the organization the request
// names must be the installation's, before the caller's authority is read;
// then the caller must administer that organization or hold the installer
// role on that installation; then the installation must be active, the role
// declared, exactly one subject named, and that subject of the organization.
func ChangeRole(r RoleChange) error {
	inst := r.Installation
	if r.RequestOrganization != inst.Organization {
		return domain.Refuse("installation %s belongs to another organization than %q", inst.ID, r.RequestOrganization)
	}
	if r.Caller.Organization != inst.Organization || (!IsAdministrator(r.Caller) && !slices.Contains(r.CallerRoles, domain.InstallerRole)) {
		if r.List {
			return domain.Refuse("%s may not list the role grants of %s", r.Caller.ID, inst.ID)
		}
		return domain.Refuse("%s may not grant roles on %s: an administrator of %s or its installer grants", r.Caller.ID, inst.ID, inst.Organization)
	}
	if inst.Status != domain.Active {
		return domain.NotNow("installation %s is %s: %s is not installed", inst.ID, inst.Status, inst.Target)
	}
	if r.List {
		return nil
	}
	if _, declared := r.Solution.Roles[r.Role]; !declared {
		return domain.Missing("%s declares no role %q", inst.Target, r.Role)
	}
	if (r.PersonID == "") == (r.TeamID == "") {
		return domain.Malformed("a role grant names exactly one person or team")
	}
	if r.PersonID != "" && (r.Subject == nil || r.Subject.Organization != inst.Organization) {
		return domain.Refuse("%q is not a member of %s", r.PersonID, inst.Organization)
	}
	if r.TeamID != "" && !r.TeamOfOrganization {
		return domain.Refuse("%q is not a team of %s", r.TeamID, inst.Organization)
	}
	return nil
}

// Transfer is one AuthorizeTransfer with what it is decided against.
type Transfer struct {
	// OwnerKind and Person are the presented capability's owner.
	OwnerKind string
	Person    domain.Person
	// Through are the solution principals the capability was issued through.
	Through []string
	// From is the store-attested current owner; FromPrincipal: it is a
	// solution principal; FromPerson: the person it names, if any.
	From          string
	FromPrincipal bool
	FromPerson    *domain.Person
	To            string
	// Administers: the person's own organization grants hold admin on the resource.
	Administers bool
	// Writes: the person's current roles on To's installation hold write on the kind.
	Writes bool
}

// AuthorizeTransfer decides whether an existing resource joins a solution
// principal: a person's act, through that principal's installation, from the
// organization or a person of it, administered on that resource through the
// person's own grants, by a holder of write on the principal's data.
func AuthorizeTransfer(t Transfer) error {
	switch {
	case t.OwnerKind != "human":
		return domain.Refuse("a transfer is a person's act; this capability is owned by a %s", t.OwnerKind)
	case !slices.Contains(t.Through, t.To):
		return domain.Refuse("the capability was not issued through the installation of %s", t.To)
	case t.FromPrincipal:
		return domain.Refuse("%s is owned by a solution principal; a resource moves between principals by no transfer", t.From)
	case t.From != t.Person.Organization && (t.FromPerson == nil || t.FromPerson.Organization != t.Person.Organization):
		return domain.Refuse("%q is not a person or the organization of %s", t.From, t.Person.Organization)
	case !t.Administers:
		return domain.Refuse("%s holds no admin on the resource from their own organization grants", t.Person.ID)
	case !t.Writes:
		return domain.Refuse("%s holds no write on %s's data through their roles", t.Person.ID, t.To)
	}
	return nil
}

// ValidResourceID holds a resource id to core's scope-value rule (non-empty,
// no surrounding whitespace, no NUL, CR, LF or tab), refuses "*", and bounds
// it to 128 bytes. Ids are opaque and compared byte for byte.
func ValidResourceID(id string) error {
	if id == "" || strings.TrimSpace(id) != id || strings.ContainsAny(id, "\x00\r\n\t*") || len(id) > 128 {
		return domain.Refuse("resource id %q is not a usable id", id)
	}
	return nil
}
