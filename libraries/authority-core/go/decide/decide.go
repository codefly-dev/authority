// Package decide is the authority's pure decisions: each takes its inputs
// explicitly and answers a result or a named refusal (domain.Refusal). It
// reads no store and signs nothing, so both hosts decide identically.
package decide

import (
	"slices"
	"strings"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/protobuf/proto"
)

// Scopes is a scope list.
type Scopes = []*basev0.WorkScopeV1

// IsAdministrator: an organization's administrators hold "admin" or "owner".
func IsAdministrator(p domain.Person) bool {
	return slices.Contains(p.Roles, "admin") || slices.Contains(p.Roles, "owner")
}

// NoRoles is the refusal of a person's own session at a module that declares
// no roles. Organisation roles decide administration only (members, teams,
// installations, grants): none reaches a module, whatever it is called. A
// module is reached through a role on an installation, a solution's or a
// module page's; one that declares no roles has no installation role to hold
// and is reached through the binding of an installation that reaches it.
func NoRoles(audience domain.Module) error {
	return domain.Refuse("%s declares no roles, so a person's own session holds nothing there, whatever their organisation role: it is reached through a role on an installation that reaches it", audience.Name)
}

// HeldRoles are the roles a person holds on one installation: granted on it
// to them, or to a team they belong to, within their role view on it when
// the session has one (domain.RoleView). Grants on any other installation
// count for nothing here, however the caller gathered them, and so does a
// grant of a name that is no role (domain.IsRole), which only a store written
// before the roles were admin and user still holds: it is held as nothing,
// whatever a declaration of that time says of it.
func HeldRoles(p domain.Person, inst domain.Installation, grants []domain.RoleGrant) []string {
	var roles []string
	for _, g := range grants {
		if g.InstallationID != inst.ID || !domain.IsRole(g.Role) {
			continue
		}
		if p.Cast != "" {
			// Cast onto a team: this session holds what that team is granted
			// and nothing else — not the person's direct grants, not their
			// other teams. Membership is not consulted; the grant rule that
			// admits the cast is asked wherever the acting person is read
			// (authority.personFor), before this.
			if g.TeamID == p.Cast {
				roles = append(roles, g.Role)
			}
			continue
		}
		if (g.PersonID != "" && g.PersonID == p.ID) || (g.TeamID != "" && slices.Contains(p.Teams, g.TeamID)) {
			roles = append(roles, g.Role)
		}
	}
	slices.Sort(roles)
	roles = slices.Compact(roles)
	if view, viewing := p.View[inst.ID]; viewing {
		// A role view narrows: only what is both held and viewed.
		roles = slices.DeleteFunc(roles, func(r string) bool { return !slices.Contains(view, r) })
	}
	return roles
}

// RoleScopes is what roles grant on a solution's installation: the roles'
// scopes, each selecting only the resources the installation's principal
// owns. An installation with no principal grants nothing: its scopes would
// select every owner's resources. A module page's roles are returned as
// declared; what another module receives of them is ModuleRoleAt's.
func RoleScopes(solution domain.Module, inst domain.Installation, roles []string) (Scopes, error) {
	var literal, attached Scopes
	for _, role := range roles {
		literal = append(literal, solution.Roles[role]...)
		for _, sc := range solution.OwnedRoles[role] {
			if ids := inst.Owned[sc.GetResourceKind()]; len(ids) > 0 {
				attached = append(attached, &basev0.WorkScopeV1{ResourceKind: sc.GetResourceKind(), Actions: slices.Clone(sc.GetActions()), ResourceIds: slices.Clone(ids)})
			}
		}
	}
	if solution.Kind != domain.KindSolution {
		return scope.Normalize(literal), nil
	}
	if len(literal) > 0 {
		if inst.PrincipalID == "" {
			return nil, domain.Refuse("installation %s has no principal, so its roles grant nothing", inst.ID)
		}
		var err error
		literal, err = scope.Owned(literal, inst.PrincipalID)
		if err != nil {
			return nil, err
		}
	}
	return scope.Normalize(append(literal, attached...)), nil
}

// ModuleRoleAt is a role-gated module's role scopes as audience receives
// them: another module, or the module itself. An audience that checks owners
// receives them owner-selected to the module's installation's principal,
// exactly as a solution's roles are (RoleScopes): its own data, never the
// whole kind across every owner. That holds at the module itself too: a store
// that checks owners and declares a page is reached through its roles as its
// installation's data, which is what its page creates there (AttachResource
// counts that installation), never every owner's. A kind audience declares
// shared stays unselected. An installation recorded without a principal owns
// nothing there, so its roles carry nothing of the audience's owned kinds. An
// audience that checks no owner receives the roles as they are.
func ModuleRoleAt(m domain.Module, inst domain.Installation, audience domain.Module, role Scopes) Scopes {
	if m.Kind == domain.KindSolution || !audience.OwnerAware {
		return role
	}
	out := make(Scopes, 0, len(role))
	for _, sc := range role {
		switch {
		case slices.Contains(audience.SharedKinds, sc.GetResourceKind()):
			out = append(out, sc)
		case inst.PrincipalID != "":
			c := proto.CloneOf(sc)
			c.ResourceOwnerId = inst.PrincipalID
			out = append(out, c)
		}
	}
	return scope.Normalize(out)
}

// CreatingActions are the actions that bring data into being. A module holding
// one at a module that checks owners creates data there, and it is born owned.
var CreatingActions = []string{"define", "write", "create"}

// HeadlessAt is what a module's headless scopes carry at audience: the actions
// that create data are owner-selected to the module's installation exactly as
// ModuleRoleAt selects a role, so what the module defines is born owned by it;
// every other action (a read, a listing, a redaction) stays as declared, because
// a module reading a kind across owners creates nothing and selecting that read
// to its own installation would show it nothing. On a kind the module also
// creates there, its other actions are carried selected to its installation as
// well: it reads back what it defined, at an audience that honours only
// owner-selected scopes (the record store, RBAC-4a, reaches nothing through a
// scope naming no owner) as at one that honours both. The selected row widens
// nothing, since the declared row covers every owner's. withheld counts the
// creating scopes dropped for want of an installation principal.
func HeadlessAt(m domain.Module, inst domain.Installation, audience domain.Module, scopes Scopes) (out Scopes, withheld int) {
	if m.Kind == domain.KindSolution || !audience.OwnerAware || audience.Principal == m.Principal {
		return scopes, 0
	}
	creates := map[string]bool{}
	for _, sc := range scopes {
		if slices.ContainsFunc(sc.GetActions(), func(a string) bool { return slices.Contains(CreatingActions, a) }) {
			creates[sc.GetResourceKind()] = true
		}
	}
	for _, sc := range scopes {
		var creating, rest []string
		for _, a := range sc.GetActions() {
			if slices.Contains(CreatingActions, a) {
				creating = append(creating, a)
			} else {
				rest = append(rest, a)
			}
		}
		if len(rest) > 0 {
			r := proto.CloneOf(sc)
			r.Actions = rest
			out = append(out, r)
			if creates[sc.GetResourceKind()] {
				out = append(out, ModuleRoleAt(m, inst, audience, Scopes{r})...)
			}
		}
		if len(creating) > 0 {
			c := proto.CloneOf(sc)
			c.Actions = creating
			owned := ModuleRoleAt(m, inst, audience, Scopes{c})
			withheld += 1 - len(owned)
			out = append(out, owned...)
		}
	}
	return scope.Normalize(out), withheld
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

// Child is the refusal of an ask beyond a child's ceiling. Through a solution
// it says the capability is confined to the principal's data, the same words
// whatever the person's own grants would cover, so the module asking learns
// nothing of them.
func Child(binding string, throughSolution bool) error {
	if throughSolution {
		return domain.Refuse("a child widens what its owner holds through binding %q: a capability issued through a solution is confined to its principal's data, and the person's own grants never flow into it", binding)
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
	// RequestOrganization and RequestedID are the organization and the
	// installation id the request names, echoed by a refusal as asked.
	RequestOrganization, RequestedID string
	Installation                     domain.Installation
	Solution                         domain.Module
	// Caller is the authenticated person; CallerRoles what they hold on the installation.
	Caller      domain.Person
	CallerRoles []string
	// List asks only who may read the grants; Revoke ends a grant, which
	// stays revocable after its person left or its team is gone.
	List, Revoke           bool
	Role, PersonID, TeamID string
	// Subject is the person granted, when PersonID names one the host knows.
	Subject *domain.Person
	// TeamOfOrganization: the host's team directory holds TeamID in the
	// installation's organization, whether or not anyone belongs to it yet.
	TeamOfOrganization bool
}

// ChangeRole decides a role change, in order: the organization the request
// names must be the installation's, before the caller's authority is read;
// then the caller must administer that organization or hold the admin role
// on that installation (domain.HoldsAdmin). A caller of another organization
// is answered as for an installation theirs does not have
// (ForeignInstallation); a member of the installation's own who is neither is
// told so (NotRoleAdministrator), never that it is another organization's. A revoke then needs only exactly
// one subject, whatever the role is named, so a grant a store still holds of
// a name that is no role is revocable; a grant needs the installation active,
// the role one of the two (domain.IsRole) and declared, exactly one subject
// named, and that subject of the organization.
func ChangeRole(r RoleChange) error {
	inst := r.Installation
	if r.RequestOrganization != inst.Organization {
		return ForeignInstallation(r.RequestedID, r.RequestOrganization)
	}
	if r.Caller.Organization != inst.Organization {
		return ForeignInstallation(r.RequestedID, r.RequestOrganization)
	}
	if !IsAdministrator(r.Caller) && !domain.HoldsAdmin(r.CallerRoles) {
		return NotRoleAdministrator(r.Caller.ID, r.RequestOrganization, r.RequestedID)
	}
	if r.Revoke {
		// A grant stays revocable whatever happened since: an installation
		// uninstalled (a reinstall reuses its id), a role no longer declared
		// (a later generation may declare it again), a person who left.
		if (r.PersonID == "") == (r.TeamID == "") {
			return domain.Malformed("a role grant names exactly one person or team")
		}
		return nil
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
	if !domain.IsRole(r.Role) {
		// A declaration held from before the roles were the two may still
		// name another; nobody is granted it.
		return domain.Refuse("role %q is neither %q nor %q, the roles a person holds on %s", r.Role, domain.AdminRole, domain.UserRole, inst.Target)
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

// ForeignInstallation is the one answer for an installation the request's
// organization does not have, whether another organization has it or nobody
// does: a person learns nothing of another organization's installations. It
// echoes the id as requested. A host resolves the installation by
// (organization, id), or answers this before any other lookup, so the two
// cases also do the same work.
func ForeignInstallation(id, organization string) error {
	return domain.Refuse("installation %s belongs to another organization than %q", id, organization)
}

// NotRoleAdministrator is the answer to a member of the organization a request
// names who may not grant, revoke or list an installation's roles: they
// neither administer the organization nor hold the admin role on that
// installation. It says only what is true of the caller in their own
// organization, and echoes the id as requested. A host answers it for an
// installation that organization does not have too, when the caller does not
// administer it: holding no role on such an installation is equally true, so
// a member cannot tell their organization's installation from another's or
// from none.
func NotRoleAdministrator(person, organization, id string) error {
	return domain.Refuse("%s is neither an administrator of %s nor a holder of the admin role on installation %s", person, organization, id)
}

// NotAdministrator is the answer to a member of an organization for an act
// that is its administrator's alone, named by what: it says only what is true
// of the caller in their own organization.
func NotAdministrator(person, organization, what string) error {
	return domain.Refuse("%s is not an administrator of %s: %s", person, organization, what)
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
	// Administers: the person administers their organisation (IsAdministrator),
	// whose resource this is until it joins the installation.
	Administers bool
	// Writes: the person's current roles on To's installation hold write on the kind.
	Writes bool
}

// AuthorizeTransfer decides whether an existing resource joins a solution
// principal: a person's act, through that principal's installation, from the
// organization or a person of it, by an administrator of that organisation
// who holds write on the principal's data through their roles on its
// installation. Handing the organisation's resource to an installation is
// administration, so the organisation role decides it; what the person
// reaches in the store is their installation role.
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
		return NotAdministrator(t.Person.ID, t.Person.Organization, "an organisation's resource joins an installation by its administrator's act")
	case !t.Writes:
		return domain.Refuse("%s holds no write on %s's data through their roles", t.Person.ID, t.To)
	}
	return nil
}

// ValidResourceID holds a resource id to core's scope-value rule (non-empty,
// no surrounding whitespace, no NUL, CR, LF or tab), refuses any id containing
// "*", and bounds it to 128 bytes; a malformed id is Invalid. Ids are opaque and compared byte for byte.
func ValidResourceID(id string) error {
	if id == "" || strings.TrimSpace(id) != id || strings.ContainsAny(id, "\x00\r\n\t*") || len(id) > 128 {
		return domain.Malformed("resource id %q is not a usable id", id)
	}
	return nil
}
