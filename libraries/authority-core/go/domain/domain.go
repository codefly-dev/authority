// Package domain is the authority's shared objects: what both hosts (the
// local authority and accounts) store and the decisions read. They carry no
// behaviour of a host: no transport, no store, no key.
package domain

import (
	"errors"
	"fmt"

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
// bindings, a solution's roles, and whether it checks resource owners.
type Module struct {
	Name, Principal, Kind string
	Generation            uint64
	// StandIn is a module a fixture declares until its own delivery replaces it.
	StandIn       bool
	ResourceKinds []*basev0.WorkScopeV1
	Bindings      map[string]Binding
	// Roles are a solution's roles: levels on the data its principal owns.
	Roles map[string][]*basev0.WorkScopeV1
	// OwnedRoles resolve only to the exact ids attached to this installation.
	OwnedRoles map[string][]*basev0.WorkScopeV1
	// OwnerAware: the module compares a resource's owner with an
	// owner-selected scope, so it may receive one.
	OwnerAware bool
	// Methods are what each method the module serves requires of a call, from
	// its delivered authority document; nil when it declared none.
	Methods map[string]MethodPolicy
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
// it and it acts as it for itself, holding AgentRole.
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
}

// RoleGrant is one role on one installation held by exactly one person or team.
type RoleGrant struct {
	InstallationID, Role, PersonID, TeamID string
}

// Delegation is a person's grant to a module to act for them.
type Delegation struct {
	ID, Organization, Grantor, Module, Purpose string
	Scopes                                     []*basev0.WorkScopeV1
	Revoked                                    bool
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

// ErrNoInstallerRole names a solution that declares no installer role.
var ErrNoInstallerRole = errors.New("a solution declares an installer role")

// ErrAlreadyInstalled names an install of a target its organization holds
// active already.
var ErrAlreadyInstalled = errors.New("already installed")

// ErrNotFound is what a store answers for a missing record.
var ErrNotFound = errors.New("not found")

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
}

// ConsentReceipt binds an unchanged retry to its resulting installation revision.
type ConsentReceipt struct {
	OperationID, Intent string
	Revision            uint64
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
	RoleGranted             EventKind = "role.granted"
	RoleRevoked             EventKind = "role.revoked"
	DelegationGranted       EventKind = "delegation.granted"
	DelegationRevoked       EventKind = "delegation.revoked"
	ResourceAttached        EventKind = "resource.attached"
	ResourceDetached        EventKind = "resource.detached"
	ResourceTransferred     EventKind = "resource.transferred"
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
