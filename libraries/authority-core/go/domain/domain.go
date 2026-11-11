// Package domain is the authority's shared objects: what both hosts (the
// local authority and accounts) store and the decisions read. They carry no
// behaviour of a host: no transport, no store, no key.
package domain

import (
	"errors"
	"fmt"
	"time"

	resources "github.com/codefly-dev/authority/libraries/resources/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// Module kinds and the one reserved role.
const (
	KindModule    = "module"
	KindSolution  = "solution"
	InstallerRole = "installer"
)

// Organization is a tenant.
type Organization struct {
	ID, Name string
}

// Person is a member of one organization: its organization roles (an
// administrator holds "admin" or "owner") and its teams. Identity is the
// host's; the authority reads it.
type Person struct {
	ID, Organization string
	Roles, Teams     []string
	// View is the role view the person acts under: per installation id, the
	// only roles they use there. nil acts as every role they hold. It is set
	// by the authority from the session's stored view, never by a host or a
	// caller (authority.personFor), and only ever narrows.
	View map[string][]string
	// Cast is the team this session acts as a member of, and as nothing else.
	// Empty is the person's own session. A cast holds exactly what is granted
	// to that team: no direct grant of the person's, no other team of theirs,
	// no organisation role and no platform role (Roles is emptied with it).
	// It answers "what does a member of this team actually see", so an
	// administrator can be that and nothing more rather than proving nothing
	// by passing as themselves. Set by the authority from the session's
	// stored cast, never by a host or a caller. The rule that admits it
	// (OpenTeamCast) is that the person could GRANT the team's roles, which
	// is not the same as already holding them: an organisation administrator
	// may grant a role at an owner-aware module whose data their own session
	// reaches not at all, so a cast can hold what the person's own session
	// computes as nothing there. That is deliberate — granting is the
	// authority an administrator actually has — but it means a cast is not
	// simply "a subset of the person", and this comment says so rather than
	// implying otherwise. The person need not belong to the team.
	Cast string
}

// RoleView is a session's fixed role view: the roles a person chose to act
// as on an installation, for as long as the session lives. It is a server
// record keyed by the session, never a claim a client sends, and it only
// narrows: a view opened from a viewing session holds a subset of that
// session's effective roles. A view is never changed or widened; to act as
// all their roles again a person uses the session it was opened from.
type RoleView struct {
	// SessionID is the session the view fixes; Parent is the session it was
	// opened from.
	SessionID, Parent string
	// Person and Organization are who the session is.
	Person, Organization string
	// Roles are the roles viewed, per installation id. An installation absent
	// from it is not narrowed.
	Roles map[string][]string
	// Team, when set, makes this record a CAST: the session acts as a member
	// of that team and of nothing else, everywhere, rather than narrowing the
	// roles held on one installation. A cast is the same record because it is
	// the same thing — a session that only narrows — with a team as its unit
	// instead of a role list. Roles may still be set beside it, and then
	// narrows the cast further on the installations it names.
	Team string
}

// OrgRole is a named set of scopes at one organization.
type OrgRole struct {
	Organization, Name string
	Scopes             []RoleScope
}

// RoleScope is one organization-role scope: a kind (or AnyKind) and actions,
// optionally narrowed to resources by matcher.
type RoleScope struct {
	Kind      string
	Actions   []string
	Resources []resources.Grant
}

// Binding is a module's declared call towards another module.
type Binding struct {
	ID, Audience                               string
	InvokeScopes, HeadlessScopes, LookupScopes []*basev0.WorkScopeV1
}

// Module is what a delivery composed for one module or solution: its
// principal (the audience every capability to it names), what it serves, its
// bindings, the roles of a solution or of a module page, and whether it
// checks resource owners.
type Module struct {
	Name, Principal, Kind string
	Generation            uint64
	// StandIn is a module a fixture declares until its own delivery replaces it.
	StandIn bool
	// Page: core's signed manifest declares a frontend, the page a person
	// uses. Only a module with a page may declare roles. It is read when the
	// module is applied; decisions read Roles, so it is not part of the
	// review digest and a store need not keep it.
	Page          bool `json:"-"`
	ResourceKinds []*basev0.WorkScopeV1
	Bindings      map[string]Binding
	// Roles are a solution's roles, levels on the data its principal owns, or
	// a module page's, levels on what it serves at its organization.
	Roles map[string][]*basev0.WorkScopeV1
	// OwnedRoles resolve only to the exact ids attached to this installation.
	OwnedRoles map[string][]*basev0.WorkScopeV1
	// Through are, per role and per binding of the module's own, the scopes
	// the role names downstream of that binding: kinds a module it reaches
	// serves or consumes, carried onward at each hop and cut to each binding
	// there. They are part of the role (Roles holds them too); Through says
	// how each is reached, which delivery holds reachable in the composition
	// (decide.ValidateModuleIn).
	Through map[string]map[string][]*basev0.WorkScopeV1 `json:",omitempty"`
	// InstallationRole is the signed selector: absent leaves selection to the
	// caller; "none" selects no standing authority; otherwise it names a role.
	// Omit absent fields from the existing review digest's JSON representation.
	InstallationRole string `json:",omitempty"`
	// EdgeDependencies declares viewer-edge presence, never authority or grants.
	// Nil and empty are equivalent, including in the review digest.
	EdgeDependencies []EdgeDependency `json:",omitempty"`
	// SourceGovernance are the scopes whose holders on an installation govern
	// the data sources tied to it: the module's own, unshared kinds, each
	// action one of its roles grants (decide.ValidateModule). Read from core's
	// signed manifest, so an administrator's approval covers it; empty, the
	// module governs no source. It grants nothing: a host asks whether the
	// person is issued the scope there.
	SourceGovernance []*basev0.WorkScopeV1 `json:",omitempty"`
	// OwnerAware: the module compares a resource's owner with an
	// owner-selected scope, so it may receive one.
	OwnerAware bool
	// SharedKinds are the kinds the module declares unowned: shared
	// infrastructure (a model's profiles), no resource of which any owner
	// holds. A scope of one is issued unselected, even through a solution;
	// every other kind keeps its owner selector. Each is a kind it serves.
	SharedKinds []string `json:",omitempty"`
	// Methods are what each method the module serves requires of a call, from
	// its delivered authority document; nil when it declared none.
	Methods map[string]MethodPolicy
}

// NoInstallationRole is declaration-only. It is retained on an installation
// as a no-standing-authority marker, never looked up as a role or granted.
const NoInstallationRole = "none"

// EdgeDependency is a Core-validated viewer-edge presence requirement. Module
// is the exact signed Module.Principal. Hosts resolve it through their catalogue
// to a live target; it is not a target UUID, route alias or binding id.
type EdgeDependency struct {
	Module, Presence string
}

// MethodPolicy is one method's declaration: exactly one of its fields is set.
type MethodPolicy struct {
	Requires         []*basev0.WorkScopeV1
	AnyCheckedCaller bool
}

// Tombstone is what stays of a withdrawn module: its principal, which it
// keeps for life and no other module or installation may take, and the
// generation a redelivery must exceed. A tombstone is never cleared: a module
// that must change principal is delivered under a new name.
type Tombstone struct {
	Name, Principal string
	Generation      uint64
}

// Status is an installation's lifecycle.
type Status string

// The three states.
const (
	Pending Status = "pending"
	Active  Status = "active"
	Revoked Status = "revoked"
)

// Installation is one organization's installation of one target. A
// solution's installation is a principal (PrincipalID): its data is owned by
// it and it acts as it for itself, holding AgentRole unless it is the
// declaration-only NoInstallationRole marker (no standing authority). A
// module's composition installation is a principal too, owning what its page
// creates in a module that checks owners; it never acts for itself.
type Installation struct {
	ID, Organization, Target string
	Status                   Status
	Revision                 uint64
	AgentRole                string
	PrincipalID              string
	InstalledBy              string
	// Consent is the last reviewed operation; a later revision invalidates its receipt.
	Consent ConsentReceipt
	// Owned is the bounded set of attached resource ids, by kind.
	Owned map[string][]string
	// Bindings is what the host's consent allows of the target's operation
	// bindings at this installation. nil means every binding as delivered. A
	// non-nil map allows only the bindings it names, each used within both
	// what was delivered and what it states (every scope list intersected), so
	// a binding the consent dropped or narrowed, or one a later delivery
	// widened, issues no more than the consent allows.
	Bindings map[string]Binding
}

// RoleGrant is one role on one installation held by exactly one person or team.
type RoleGrant struct {
	InstallationID, Role, PersonID, TeamID string
}

// Client is an external public client identity. Registration gives it no scopes,
// bindings or installation. Its authority comes only from a person's delegation.
type Client struct {
	ID, Name     string
	RedirectURIs []string
	Revision     uint64
	Disabled     bool
}

// Delegation is a person's grant to a module or an external client to act for them.
type Delegation struct {
	ID, Organization, Grantor, Module, Purpose string
	// A client delegation names exactly one solution audience and its declared
	// public resource. Module and ClientID are mutually exclusive.
	ClientID, Audience, Resource string
	Scopes                       []*basev0.WorkScopeV1
	Revoked                      bool
	// ExpiresAt ends the delegation by itself; zero stands until revoked.
	ExpiresAt time.Time
}

// Active is whether the delegation still stands at now: not revoked, and not
// past its expiry.
func (d Delegation) Active(now time.Time) bool {
	return !d.Revoked && (d.ExpiresAt.IsZero() || now.Before(d.ExpiresAt))
}

// Code classifies a refusal the way a transport reports it.
type Code int

// The refusal codes.
const (
	Denied       Code = iota // the caller may not
	NotFound                 // the thing named does not exist
	Invalid                  // the request is malformed
	Precondition             // the state does not allow it now
)

// Refusal is a decision's named refusal: its code and its reason.
type Refusal struct {
	Code   Code
	Reason string
	// Cause is the sentinel a caller may test with errors.Is, when one names
	// the refusal.
	Cause error
}

func (r *Refusal) Error() string { return r.Reason }

// Unwrap is the refusal's sentinel, if any.
func (r *Refusal) Unwrap() error { return r.Cause }

// ErrNoInstallerRole names a solution, or a module page declaring roles, that
// declares no installer role.
var ErrNoInstallerRole = errors.New("a solution declares an installer role")

// ErrAlreadyInstalled names an install of a target its organization holds
// active already.
var ErrAlreadyInstalled = errors.New("already installed")

// ErrNotFound is what a store answers for a missing record.
var ErrNotFound = errors.New("not found")

// ErrApprovedDeclarationKept is what a store answers for a declaration
// written at a (module, generation) it already keeps a different one for: an
// approved declaration is what a consent approved, and is never replaced.
var ErrApprovedDeclarationKept = errors.New("a different declaration is kept for this approved generation")

// Refuse builds a Denied refusal.
func Refuse(format string, args ...any) error { return refusal(Denied, format, args...) }

// Missing builds a NotFound refusal.
func Missing(format string, args ...any) error { return refusal(NotFound, format, args...) }

// Malformed builds an Invalid refusal.
func Malformed(format string, args ...any) error { return refusal(Invalid, format, args...) }

// NotNow builds a Precondition refusal.
func NotNow(format string, args ...any) error { return refusal(Precondition, format, args...) }

func refusal(code Code, format string, args ...any) error {
	return &Refusal{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// CodeOf is err's refusal code, and false for an error that is no refusal.
func CodeOf(err error) (Code, bool) {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code, true
	}
	return 0, false
}

// ConsentApproval is the reviewed authority offer and caller's operation identity.
type ConsentApproval struct {
	TargetID                     string
	Generation, ExpectedRevision uint64
	OperationID, Digest          string
	// ReachDigest is the digest of what each of the target's roles reaches
	// in the composition reviewed (decide.EncodeReach): the consent covers
	// it, not the target's declaration alone.
	ReachDigest string
}

// ReachRow is one place a holder of a role on a target can cause an
// operation, as a static maximum (decide.Reach): Module, reached along Path
// (module names, the target first, Module last), Via the role on the target
// itself, the target's bindings acting for the holder, or the holder's own
// session; the Scopes the holder's capability there can carry at most (none
// on their own session, where their own grants decide), how the role
// confines them on the target, the Operations of Module those scopes are
// admitted to, and the Policies of every operation of Module as declared
// then, by operation: what roles held together are admitted to there.
type ReachRow struct {
	Path                     []string
	Module, Via, Confinement string
	Scopes                   []*basev0.WorkScopeV1
	Operations               []string
	Policies                 map[string]MethodPolicy
}

// ConsentReceipt binds an unchanged retry to its resulting installation
// revision, and records what the approval consented to: the generation and
// the offer digest reviewed. A redelivery whose reviewed offer asks nothing
// the approved one did not advances both (the installation re-converges); one
// that asks more leaves them, and the installation offers an upgrade until an
// administrator approves the new offer. Zero Generation is a receipt recorded
// before this was kept: it stands for the generation delivered then.
type ConsentReceipt struct {
	OperationID, Intent string
	Revision            uint64
	Generation          uint64
	Digest              string
	// Reach is the reach approved, each role's rows as canonical JSON
	// (decide.EncodeReach), and ReachDigest its digest: what holders hold
	// through the target at most until an administrator approves a wider
	// one. Empty ReachDigest is a receipt recorded before reach was kept:
	// it adopts, once, the reach its approved declaration has then
	// (installation.reach_adopted), and is held to that until adopted.
	ReachDigest, Reach string
}

// EventKind names one change of authority the core makes.
type EventKind string

// The changes a host journals.
const (
	ModuleApplied           EventKind = "module.applied"
	ModuleWithdrawn         EventKind = "module.withdrawn"
	InstallationRequested   EventKind = "installation.requested"
	InstallationActivated   EventKind = "installation.activated"
	InstallationUninstalled EventKind = "installation.uninstalled"
	// InstallationReconverged: a redelivery asked nothing new of an active
	// installation's consent, which now stands at the delivered generation.
	InstallationReconverged EventKind = "installation.reconverged"
	// RoleViewOpened: a person fixed a session to act as some of the roles
	// they hold on an installation; Detail "roles" names them.
	RoleViewOpened EventKind = "role_view.opened"
	// InstallationUpgradeAvailable: a redelivery asks more than an active
	// installation's consent approved; Detail "widened" names what. The
	// installation stays as it is until Install approves the new offer.
	InstallationUpgradeAvailable EventKind = "installation.upgrade_available"
	// InstallationReachUnreached: a delivery left what the installation's
	// target names through a binding unreached (decide.UnreachedOf); Detail
	// "unreached" names each. It grants nothing there until a delivery
	// reaches it again (InstallationReachRestored).
	InstallationReachUnreached EventKind = "installation.reach_unreached"
	// InstallationReachRestored: a delivery reaches again everything the
	// installation's target names through a binding.
	InstallationReachRestored EventKind = "installation.reach_restored"
	// InstallationReachAdopted: a consent recorded before reach was kept
	// adopted, once, the reach its approved declaration has as the
	// composition stands; Detail "reach" names its digest.
	InstallationReachAdopted EventKind = "installation.reach_adopted"
	// InstallationRoleReachWidened: a delivery widened what a module page's
	// role reaches through its bindings; the grants of that role on the
	// page's installation ended with it (each journaled as role.revoked),
	// and an administrator grants it again knowing what it now reaches.
	// Detail "roles" names the roles, "widened" what widened.
	InstallationRoleReachWidened EventKind = "installation.role_reach_widened"
	// InstallationUpgraded: an administrator approved a newer offer on an
	// active installation, which keeps its grants.
	InstallationUpgraded EventKind = "installation.upgraded"
	RoleGranted          EventKind = "role.granted"
	RoleRevoked          EventKind = "role.revoked"
	DelegationGranted    EventKind = "delegation.granted"
	DelegationRevoked    EventKind = "delegation.revoked"
	ResourceAttached     EventKind = "resource.attached"
	ResourceDetached     EventKind = "resource.detached"
	ResourceTransferred  EventKind = "resource.transferred"
)

// Event is one change of authority, journaled by the host in the transaction
// that makes it: the journal and the change commit together or not at all.
type Event struct {
	Kind EventKind
	// Organization is where it happened; empty for a module's delivery.
	Organization string
	// Actor is the person who acted, or the module whose workload did; empty
	// for the host's own setup and a delivery.
	Actor string
	// Subject is what changed: an installation, a delegation, a module.
	Subject string
	Detail  map[string]string
}
