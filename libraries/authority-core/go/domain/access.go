package domain

import (
	"slices"
	"time"
)

// AccessSubjectKind is what an access grant is made to.
type AccessSubjectKind string

// The three subjects of an access grant.
const (
	AccessPerson       AccessSubjectKind = "person"
	AccessTeam         AccessSubjectKind = "team"
	AccessInstallation AccessSubjectKind = "installation"
)

// AccessSubject is who holds an access grant: one person, one team or one
// installation of the grant's organization, by id.
type AccessSubject struct {
	Kind AccessSubjectKind
	ID   string
}

// AccessKey is an access grant's natural key: one grant per organization,
// reference (kind, id and version) and subject. An empty Version is the grant
// that follows every version; a set one is that version's alone.
type AccessKey struct {
	Organization, Kind, ResourceID, Version string
	Subject                                 AccessSubject
}

// AccessGrant is actions one subject holds on one collection, document or
// exact version, beyond what a role on an installation reaches. The host
// writes it (access.Service); the module serving the kind stores none.
type AccessGrant struct {
	// ID names the grant; a refresh keeps it.
	ID string
	AccessKey
	// Actions are what it gives, sorted.
	Actions []string
	// ExpiresAt ends it by itself; zero stands until revoked.
	ExpiresAt time.Time
	// GrantedBy is the principal that made or last refreshed it.
	GrantedBy string
	// CreatedAt is when it was first made.
	CreatedAt time.Time
}

// Live is whether the grant still stands at now: not past its expiry.
func (g AccessGrant) Live(now time.Time) bool {
	return g.ExpiresAt.IsZero() || now.Before(g.ExpiresAt)
}

// Gives is whether the grant gives action.
func (g AccessGrant) Gives(action string) bool { return slices.Contains(g.Actions, action) }

// AccessGranted and AccessRevoked are the changes of an access grant a host
// journals; AccessForgotten is an uninstalled installation's grants ended.
const (
	AccessGranted   EventKind = "access.granted"
	AccessRevoked   EventKind = "access.revoked"
	AccessForgotten EventKind = "access.forgotten"
)
