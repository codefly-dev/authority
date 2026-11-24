package access_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/access"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

const (
	docKind, collectionKind = "documents", "documents.collection"
	principalA, principalB  = "principal-a", "principal-b"
)

var (
	now     = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	expires = now.Add(15 * time.Minute)

	carol = domain.AccessSubject{Kind: domain.AccessPerson, ID: "carol"}
	team  = domain.AccessSubject{Kind: domain.AccessTeam, ID: "team"}
	instA = domain.AccessSubject{Kind: domain.AccessInstallation, ID: "installation-a"}
	instB = domain.AccessSubject{Kind: domain.AccessInstallation, ID: "installation-b"}

	// Da at v1 sits in C1, which installation A's principal owns; Dana owns Da.
	c1   = access.Node{Kind: collectionKind, ResourceID: "c1", Owner: principalA}
	c2   = access.Node{Kind: collectionKind, ResourceID: "c2", Owner: principalA}
	daV1 = access.Placement{Resource: access.Node{Kind: docKind, ResourceID: "da", Version: "v1", Owner: "dana"}, Ancestors: []access.Node{c1}}
)

func owned(kind, owner string, actions ...string) *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: kind, Actions: actions, ResourceOwnerId: owner}
}

func grant(subject domain.AccessSubject, kind, id, version string, actions ...string) domain.AccessGrant {
	return domain.AccessGrant{ID: "g", AccessKey: domain.AccessKey{Organization: "acme", Kind: kind, ResourceID: id, Version: version, Subject: subject}, Actions: actions}
}

func at(p access.Placement, version string) access.Placement {
	p.Resource.Version = version
	return p
}

func under(p access.Placement, ancestors ...access.Node) access.Placement {
	p.Ancestors = ancestors
	return p
}

// A person through installation A's page: the capability reads documents
// owned by A's principal and names no collection, so a document Dana owns in
// A's collection is reached by the installation and by nobody's role.
func throughA(q access.Question) access.Question {
	q.Action = "read"
	q.Effective = []*basev0.WorkScopeV1{owned(docKind, principalA, "read")}
	q.Owner = access.Party{Subjects: []domain.AccessSubject{carol}, Scopes: q.Effective}
	q.Actors = []access.Party{{Subjects: []domain.AccessSubject{instA}, Owns: principalA, Scopes: q.Effective}}
	q.Now, q.Expires = now, expires
	if q.Placement.Resource.Kind == "" {
		q.Placement = daV1
	}
	return q
}

func TestRoleScopesAndGrantsCombine(t *testing.T) {
	collectionReader := []*basev0.WorkScopeV1{owned(docKind, principalA, "read"), owned(collectionKind, principalA, "read")}
	throughB := func(q access.Question) access.Question {
		q = throughA(q)
		scopes := []*basev0.WorkScopeV1{owned(docKind, principalB, "read"), owned(collectionKind, principalB, "read")}
		q.Effective, q.Owner.Scopes = scopes, scopes
		q.Actors = []access.Party{{Subjects: []domain.AccessSubject{instB}, Owns: principalB, Scopes: scopes}}
		return q
	}
	for name, c := range map[string]struct {
		q       access.Question
		allowed bool
		bases   []access.Basis
		refusal string
		reason  string
	}{
		"the ceiling: a capability without the action on the kind is refused naming kind and action, whatever is granted": {
			q: func() access.Question {
				q := throughA(access.Question{Grants: []domain.AccessGrant{grant(carol, docKind, "da", "", "read")}})
				q.Effective = []*basev0.WorkScopeV1{owned(docKind, principalA, "write")}
				return q
			}(), refusal: "holds no documents:read"},
		"the ceiling ignores the resource selection: a scope selecting another owner still holds the kind": {
			q: throughA(access.Question{Grants: []domain.AccessGrant{grant(carol, docKind, "da", "", "read")}}), allowed: true, bases: []access.Basis{access.ResourceGrant}},
		"no role scope and no grant: denied, naming the viewer": {
			q: throughA(access.Question{}), reason: "the viewer"},
		"a role scope selecting the collection by its attested owner holds the document": {
			q: func() access.Question {
				q := throughA(access.Question{})
				q.Effective, q.Owner.Scopes = collectionReader, collectionReader
				return q
			}(), allowed: true, bases: []access.Basis{access.RoleScope}},
		"a role scope naming ids selects only those ids": {
			q: func() access.Question {
				q := throughA(access.Question{})
				scopes := []*basev0.WorkScopeV1{{ResourceKind: docKind, Actions: []string{"read"}, ResourceIds: []string{"other"}}}
				q.Effective, q.Owner.Scopes = scopes, scopes
				return q
			}(), reason: "the viewer"},
		"a role scope naming the document's id selects it": {
			q: func() access.Question {
				q := throughA(access.Question{})
				scopes := []*basev0.WorkScopeV1{{ResourceKind: docKind, Actions: []string{"read"}, ResourceIds: []string{"da"}}}
				q.Effective, q.Owner.Scopes = scopes, scopes
				return q
			}(), allowed: true, bases: []access.Basis{access.RoleScope}},
		"a grant on the document follows its versions": {
			q: throughA(access.Question{Placement: at(daV1, "v2"), Grants: []domain.AccessGrant{grant(carol, docKind, "da", "", "read")}}), allowed: true, bases: []access.Basis{access.ResourceGrant}},
		"a grant pinned to a version covers exactly it": {
			q: throughA(access.Question{Grants: []domain.AccessGrant{grant(carol, docKind, "da", "v1", "read")}}), allowed: true, bases: []access.Basis{access.VersionGrant}},
		"a grant pinned to a version covers no other version": {
			q: throughA(access.Question{Placement: at(daV1, "v2"), Grants: []domain.AccessGrant{grant(carol, docKind, "da", "v1", "read")}}), reason: "the viewer"},
		"a grant pinned to a version covers no question that names none": {
			q: throughA(access.Question{Placement: at(daV1, ""), Grants: []domain.AccessGrant{grant(carol, docKind, "da", "v1", "read")}}), reason: "the viewer"},
		"a grant on the collection covers a descendant": {
			q: throughA(access.Question{Grants: []domain.AccessGrant{grant(carol, collectionKind, "c1", "", "read")}}), allowed: true, bases: []access.Basis{access.AncestorGrant}},
		"a grant on the collection ends at a move: under another collection it covers nothing": {
			q: throughA(access.Question{Placement: under(daV1, c2), Grants: []domain.AccessGrant{grant(carol, collectionKind, "c1", "", "read")}}), reason: "the viewer"},
		"a grant on the document moves with it": {
			q: throughA(access.Question{Placement: under(daV1, c2), Grants: []domain.AccessGrant{grant(carol, docKind, "da", "", "read")}}), allowed: true, bases: []access.Basis{access.ResourceGrant}},
		"a grant on another kind with the same id covers nothing": {
			q: throughA(access.Question{Grants: []domain.AccessGrant{grant(carol, collectionKind, "da", "", "read")}}), reason: "the viewer"},
		"a grant that does not give the action covers nothing": {
			q: throughA(access.Question{Grants: []domain.AccessGrant{grant(carol, docKind, "da", "", "write")}}), reason: "the viewer"},
		"an expired grant covers nothing": {
			q: throughA(access.Question{Grants: []domain.AccessGrant{func() domain.AccessGrant {
				g := grant(carol, docKind, "da", "", "read")
				g.ExpiresAt = now
				return g
			}()}}), reason: "the viewer"},
		"a grant to a team counts for the person the team is counted for": {
			q: func() access.Question {
				q := throughA(access.Question{Grants: []domain.AccessGrant{grant(team, docKind, "da", "", "read")}})
				q.Owner.Subjects = []domain.AccessSubject{carol, team}
				return q
			}(), allowed: true, bases: []access.Basis{access.ResourceGrant}},
		"a cast counts its team alone: the person's own grant is not the cast's": {
			q: func() access.Question {
				q := throughA(access.Question{Grants: []domain.AccessGrant{grant(carol, docKind, "da", "", "read")}})
				q.Owner.Subjects = []domain.AccessSubject{team}
				return q
			}(), reason: "the viewer"},
		"every basis the viewer holds is listed, sorted": {
			q: func() access.Question {
				q := throughA(access.Question{Grants: []domain.AccessGrant{grant(carol, docKind, "da", "v1", "read"), grant(carol, docKind, "da", "", "read"), grant(carol, collectionKind, "c1", "", "read")}})
				q.Effective, q.Owner.Scopes = collectionReader, collectionReader
				return q
			}(), allowed: true, bases: []access.Basis{access.RoleScope, access.AncestorGrant, access.ResourceGrant, access.VersionGrant}},
		"ordinary delegation: an actor that does not hold the resource denies it, though the viewer does": {
			q: throughB(access.Question{Grants: []domain.AccessGrant{grant(carol, docKind, "da", "", "read")}}), bases: []access.Basis{access.ResourceGrant}, reason: "an actor"},
		"ordinary delegation: the actor's installation granted too allows it": {
			q: throughB(access.Question{Grants: []domain.AccessGrant{grant(carol, docKind, "da", "", "read"), grant(instB, docKind, "da", "", "read")}}), allowed: true, bases: []access.Basis{access.ResourceGrant}},
		"a grant to the actor's installation alone does not make the viewer hold it": {
			q: throughB(access.Question{Grants: []domain.AccessGrant{grant(instB, docKind, "da", "", "read")}}), reason: "the viewer"},
		"an installed-content read requires the owner alone": {
			q: func() access.Question {
				q := throughB(access.Question{Grants: []domain.AccessGrant{grant(carol, docKind, "da", "", "read")}})
				q.OwnerAlone = true
				return q
			}(), allowed: true, bases: []access.Basis{access.ResourceGrant}},
		"an installed-content read still requires the owner": {
			q: func() access.Question {
				q := throughB(access.Question{Grants: []domain.AccessGrant{grant(instB, docKind, "da", "", "read")}})
				q.OwnerAlone = true
				return q
			}(), reason: "the viewer"},
		"an installation's agent holds what its principal owns, by the collection above": {
			q: func() access.Question {
				q := throughA(access.Question{})
				q.Owner = access.Party{Subjects: []domain.AccessSubject{instA}, Owns: principalA, Scopes: q.Effective}
				return q
			}(), allowed: true, bases: []access.Basis{access.RoleScope}},
		"a sibling installation's agent holds nothing of it, nor a grant made to the other": {
			q: func() access.Question {
				q := throughB(access.Question{Grants: []domain.AccessGrant{grant(instA, docKind, "da", "", "read")}})
				q.Owner = access.Party{Subjects: []domain.AccessSubject{instB}, Owns: principalB, Scopes: q.Effective}
				return q
			}(), reason: "the viewer"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := access.Decide(c.q)
			if c.refusal != "" {
				if code, ok := domain.CodeOf(err); !ok || code != domain.Denied || !strings.Contains(err.Error(), c.refusal) {
					t.Fatalf("want a denial naming %q, got %v", c.refusal, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Allowed != c.allowed || !slices.Equal(got.Bases, c.bases) {
				t.Fatalf("decided allowed=%t bases=%v (%s), want allowed=%t bases=%v", got.Allowed, got.Bases, got.Reason, c.allowed, c.bases)
			}
			if !strings.Contains(got.Reason, c.reason) {
				t.Fatalf("reason %q, want it to name %q", got.Reason, c.reason)
			}
			for _, name := range []string{"da", "c1", "c2", "dana", "carol"} {
				if strings.Contains(" "+got.Reason+" ", " "+name+" ") {
					t.Fatalf("reason %q names %q; a reason names no resource and no person", got.Reason, name)
				}
			}
		})
	}
}

func TestAnAllowedDecisionHoldsUntilTheEarliestOfTheCapabilityAndItsGrants(t *testing.T) {
	soon, later := now.Add(time.Minute), now.Add(time.Hour)
	expiring := func(subject domain.AccessSubject, at time.Time) domain.AccessGrant {
		g := grant(subject, docKind, "da", "", "read")
		g.ExpiresAt = at
		return g
	}
	for name, c := range map[string]struct {
		grants []domain.AccessGrant
		want   time.Time
	}{
		"no grant expires: the capability's expiry":         {[]domain.AccessGrant{grant(carol, docKind, "da", "", "read")}, expires},
		"a grant expiring first bounds it":                  {[]domain.AccessGrant{expiring(carol, soon)}, soon},
		"a grant outliving the capability does not extend":  {[]domain.AccessGrant{expiring(carol, later)}, expires},
		"another subject's grant is not what it rests on":   {[]domain.AccessGrant{grant(carol, docKind, "da", "", "read"), expiring(team, soon)}, expires},
		"the earliest of the grants the viewer holds it by": {[]domain.AccessGrant{expiring(carol, soon), grant(carol, collectionKind, "c1", "", "read")}, soon},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := access.Decide(throughA(access.Question{Grants: c.grants}))
			if err != nil || !got.Allowed {
				t.Fatalf("decided %+v, %v", got, err)
			}
			if !got.ValidUntil.Equal(c.want) {
				t.Fatalf("valid until %s, want %s", got.ValidUntil, c.want)
			}
		})
	}
	denied, err := access.Decide(throughA(access.Question{}))
	if err != nil || denied.Allowed || !denied.ValidUntil.IsZero() {
		t.Fatalf("a denied decision holds until %s (%v), want no instant", denied.ValidUntil, err)
	}
}
