package access

import (
	"slices"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// Node is one resource as the serving module records it: a collection, a
// document, or one version of a document, and its owner.
type Node struct {
	Kind, ResourceID, Version string
	// Owner is the owner the module attests: a person, an installation's
	// principal, or empty.
	Owner string
}

// Placement is where a resource sits: itself and the collections above it,
// nearest first. The module passes it with every question; nothing about a
// document is registered at the host, so a move needs no write here.
type Placement struct {
	Resource  Node
	Ancestors []Node
}

// Basis is one way a subject holds a resource.
type Basis int

// The bases, in the order an answer lists them.
const (
	// RoleScope: the scopes the subject contributes select the resource or
	// an ancestor.
	RoleScope Basis = iota + 1
	// AncestorGrant: a grant on a collection above the resource.
	AncestorGrant
	// ResourceGrant: a grant on the resource that follows its versions.
	ResourceGrant
	// VersionGrant: a grant on exactly the version asked.
	VersionGrant
)

// Party is one subject the decision is made for.
type Party struct {
	// Subjects are whose grants count for the party.
	Subjects []domain.AccessSubject
	// Owns is the installation principal whose data is the party's own.
	Owns string
	// Scopes are the scopes the party contributes to the capability.
	Scopes []*basev0.WorkScopeV1
}

// Question is one decision's inputs, all read already: Decide reads nothing.
type Question struct {
	Action    string
	Placement Placement
	// Effective are the capability's effective scopes, after every hop.
	Effective []*basev0.WorkScopeV1
	// Owner is the capability's owner; Actors its chain.
	Owner  Party
	Actors []Party
	// OwnerAlone is an installed-content read: its binding is live (the
	// caller established it) and the owner alone must hold the resource.
	OwnerAlone bool
	// Grants are the organization's grants on the resource and its
	// ancestors; an expired one is ignored.
	Grants []domain.AccessGrant
	Now    time.Time
	// Standing, when set, is whether a grant still stands for an action: a
	// share made on by a grantee does only while the share it rests on does
	// (lineage.go). nil: every live grant stands.
	Standing func(g domain.AccessGrant, action string) bool
	// Expires is when the capability ends.
	Expires time.Time
}

// Decision is the answer.
type Decision struct {
	Allowed bool
	// Bases are how the capability's owner holds the resource, sorted; empty
	// when they do not. They are the owner's alone, whatever the actors hold.
	Bases []Basis
	// Reason is for the module's audit record. It names no resource.
	Reason string
	// ValidUntil is when an allowed decision stops holding by itself: the
	// capability's expiry, or the earliest expiry of a grant a required
	// subject holds the resource by. Zero when denied.
	ValidUntil time.Time
}

// Ceiling refuses a capability whose effective scopes do not hold action on
// kind at all, whatever resources they select: no grant widens what a
// capability may do at a kind, only which of its resources it reaches.
func Ceiling(effective []*basev0.WorkScopeV1, kind, action string) error {
	if !scope.HoldsAction(effective, kind, action) {
		return domain.Refuse("the capability holds no %s:%s", kind, action)
	}
	return nil
}

// Decide combines role scopes and grants for one action on one placed
// resource. The capability must already hold the action on the resource's
// kind (Ceiling, an error). Then every required subject must hold the
// resource: the owner and every actor of the chain, or the owner alone for an
// installed-content read. A subject holds it when the scopes it contributes
// select the resource or an ancestor, by id or by the owner the module
// attests; when it is an installation whose principal owns the resource or an
// ancestor (what a capability through it is confined to); or when a live
// grant to it, to a team it counts, or to its installation gives the action
// on an ancestor, on the resource with no version, or on exactly the
// resource's version.
func Decide(q Question) (Decision, error) {
	if err := Ceiling(q.Effective, q.Placement.Resource.Kind, q.Action); err != nil {
		return Decision{}, err
	}
	until := q.Expires
	owner, ownerUntil := holds(q.Owner, q)
	if len(owner) == 0 {
		return Decision{Reason: "the viewer holds neither a role scope nor a grant on the resource"}, nil
	}
	until = earliest(until, ownerUntil)
	if !q.OwnerAlone {
		for _, actor := range q.Actors {
			bases, actorUntil := holds(actor, q)
			if len(bases) == 0 {
				return Decision{Bases: owner, Reason: "an actor of the capability holds neither a role scope nor a grant on the resource"}, nil
			}
			until = earliest(until, actorUntil)
		}
	}
	reason := "every required subject holds the resource"
	if q.OwnerAlone {
		reason = "installed-content read: the viewer holds the resource"
	}
	return Decision{Allowed: true, Bases: owner, Reason: reason, ValidUntil: until}, nil
}

// holds answers how p holds the question's resource, sorted, and the
// earliest expiry among the grants it holds it by (zero when none expires).
func holds(p Party, q Question) ([]Basis, time.Time) {
	var bases []Basis
	var until time.Time
	nodes := append([]Node{q.Placement.Resource}, q.Placement.Ancestors...)
	if slices.ContainsFunc(nodes, func(n Node) bool {
		return (p.Owns != "" && n.Owner == p.Owns) || Selects(p.Scopes, n, q.Action)
	}) {
		bases = append(bases, RoleScope)
	}
	for _, g := range q.Grants {
		if !g.Live(q.Now) || !g.Gives(q.Action) || !slices.Contains(p.Subjects, g.Subject) {
			continue
		}
		if q.Standing != nil && !q.Standing(g, q.Action) {
			continue
		}
		basis, ok := covers(g, q.Placement)
		if !ok {
			continue
		}
		bases = append(bases, basis)
		until = earliest(until, g.ExpiresAt)
	}
	slices.Sort(bases)
	return slices.Compact(bases), until
}

// covers is how a grant covers the placed resource, if it does: on an
// ancestor (any version of the collection, or the one the module names), on
// the resource following its versions, or on exactly its version. A grant
// pinned to a version covers neither another version nor a question that
// names none.
func covers(g domain.AccessGrant, p Placement) (Basis, bool) {
	r := p.Resource
	if g.Kind == r.Kind && g.ResourceID == r.ResourceID {
		switch {
		case g.Version == "":
			return ResourceGrant, true
		case g.Version == r.Version:
			return VersionGrant, true
		}
		return 0, false
	}
	for _, a := range p.Ancestors {
		if g.Kind == a.Kind && g.ResourceID == a.ResourceID && (g.Version == "" || g.Version == a.Version) {
			return AncestorGrant, true
		}
	}
	return 0, false
}

// Selects is whether a scope of scopes selects node for action: of the
// node's kind, holding the action, naming the node's id when it names ids and
// the node's attested owner when it names an owner.
func Selects(scopes []*basev0.WorkScopeV1, n Node, action string) bool {
	return slices.ContainsFunc(scopes, func(sc *basev0.WorkScopeV1) bool {
		if sc.GetResourceKind() != n.Kind {
			return false
		}
		if !slices.Contains(sc.GetActions(), action) && !slices.Contains(sc.GetActions(), scope.AnyAction) {
			return false
		}
		if ids := sc.GetResourceIds(); len(ids) > 0 && !slices.Contains(ids, n.ResourceID) {
			return false
		}
		return sc.GetResourceOwnerId() == "" || sc.GetResourceOwnerId() == n.Owner
	})
}

// earliest is the earlier of two instants, a zero one being none.
func earliest(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero() || a.Before(b):
		return a
	}
	return b
}
