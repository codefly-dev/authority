package access_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/core/workcontext"
	"github.com/google/uuid"

	"github.com/codefly-dev/authority/libraries/authority-core/go/access"
	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/memstore"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The service over the real authority core and the in-memory store: two
// solutions A and B at acme, a store serving documents and collections, and
// people holding the user role (which reads and shares documents, and names
// no collection) or the admin role (which also administers collections).
const acme, globex = "acme", "globex"

type keys struct{ public ed25519.PublicKey }

func (k keys) PublicKeys(context.Context) (map[string]ed25519.PublicKey, error) {
	return map[string]ed25519.PublicKey{"k1": k.public}, nil
}

type world struct {
	t     *testing.T
	ctx   context.Context
	now   time.Time
	store *memstore.Store
	auth  *authority.Service
	svc   *access.Service
}

func sc(kind string, actions ...string) *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: kind, Actions: actions}
}

func solution(name string) domain.Module {
	note := name + ".note"
	return domain.Module{Name: name, Principal: name, Kind: domain.KindSolution, Generation: 1, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc(note, "read", "write")},
		Bindings: map[string]domain.Binding{"store": {ID: "store", Audience: "store",
			InvokeScopes: []*basev0.WorkScopeV1{sc(docKind, "admin", "read", "share", "write"), sc(collectionKind, "admin", "read", "share")}}},
		Roles: map[string][]*basev0.WorkScopeV1{
			domain.AdminRole: {sc(note, "read", "write"), sc(docKind, "admin", "read", "share", "write"), sc(collectionKind, "admin", "read", "share")},
			domain.UserRole:  {sc(note, "read"), sc(docKind, "read", "share")},
		}}
}

func newWorld(t *testing.T) *world {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, ctx: context.Background(), now: now, store: memstore.New()}
	replay := workcontext.NewMemoryReplayStore()
	replay.Now = func() time.Time { return w.now }
	n := 0
	w.auth, err = authority.New(w.store, authority.Config{Issuer: "https://authority.test", KeyID: "k1", Signer: private, Keys: keys{public}, Replay: replay,
		Clock: func() time.Time { return w.now }, NewID: func() string { n++; return fmt.Sprintf("id-%d", n) },
		Journal: access.Journal(nil)})
	if err != nil {
		t.Fatal(err)
	}
	w.svc, err = access.New(w.auth, w.store, access.Config{Clock: func() time.Time { return w.now }})
	if err != nil {
		t.Fatal(err)
	}
	for _, org := range []string{acme, globex} {
		w.store.PutOrganization(domain.Organization{ID: org, Name: org})
	}
	w.store.PutTeam(acme, "team")
	for _, p := range []domain.Person{
		{ID: "alex", Organization: acme, Roles: []string{"admin"}}, {ID: "dana", Organization: acme}, {ID: "carol", Organization: acme},
		{ID: "bob", Organization: acme}, {ID: "tom", Organization: acme, Teams: []string{"team"}},
		{ID: "zoe", Organization: globex, Roles: []string{"admin"}},
	} {
		w.store.PutPerson(p)
	}
	for _, m := range []domain.Module{
		{Name: "store", Principal: "store", Kind: domain.KindModule, Generation: 1, OwnerAware: true,
			ResourceKinds: []*basev0.WorkScopeV1{sc(docKind, "admin", "read", "share", "write"), sc(collectionKind, "admin", "read", "share")}},
		solution("a"), solution("b"),
	} {
		if _, err := w.auth.ApplyModule(w.ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []string{"a", "b"} {
		w.install(acme, "alex", target)
	}
	w.install(globex, "zoe", "a")
	for _, person := range []string{"dana", "carol", "bob", "tom"} {
		w.role("a", domain.UserRole, person)
	}
	w.role("a", domain.AdminRole, "alex")
	w.role("b", domain.UserRole, "carol")
	return w
}

func (w *world) person(id string) authority.Person {
	org := acme
	if id == "zoe" {
		org = globex
	}
	return authority.Person{ID: id, Organization: org, SessionID: "session-" + id}
}

func (w *world) install(org, admin, target string) domain.Installation {
	w.t.Helper()
	approval, err := w.auth.Review(w.ctx, w.person(admin), org, target)
	if err != nil {
		w.t.Fatal(err)
	}
	approval.OperationID = uuid.NewString()
	inst, err := w.auth.Install(w.ctx, w.person(admin), org, target, domain.AdminRole, admin, &approval, nil)
	if err != nil {
		w.t.Fatal(err)
	}
	return inst
}

func (w *world) role(target, role, person string) {
	w.t.Helper()
	if _, err := w.auth.GrantRole(w.ctx, w.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: authority.StableInstallationID(acme, target), Role: role, PersonID: person}); err != nil {
		w.t.Fatal(err)
	}
}

// through is person's capability at the store through solution target.
func (w *world) through(person authority.Person, target string) string {
	w.t.Helper()
	root, err := w.auth.IssueForPerson(w.ctx, person, authority.IssueRequest{Audience: target})
	if err != nil {
		w.t.Fatal(err)
	}
	child, err := w.auth.IssueChild(w.ctx, root.Token, authority.Workload{Module: target}, authority.IssueRequest{Binding: "store"})
	if err != nil {
		w.t.Fatal(err)
	}
	return child.Token
}

func (w *world) as(person, target string) string { return w.through(w.person(person), target) }

// agent is the installation of target acting for itself at the store.
func (w *world) agent(target string) string {
	w.t.Helper()
	out, err := w.auth.IssueForInstallation(w.ctx, authority.Workload{Module: target}, authority.StableInstallationID(acme, target), authority.IssueRequest{Audience: "store", Binding: "store"})
	if err != nil {
		w.t.Fatal(err)
	}
	return out.Token
}

var serving = authority.Workload{Module: "store"}

// doc is a document of owner in C1, which installation A's principal owns.
func (w *world) doc(id, owner string) access.Placement {
	return access.Placement{Resource: access.Node{Kind: docKind, ResourceID: id, Owner: owner},
		Ancestors: []access.Node{{Kind: collectionKind, ResourceID: "c1", Owner: authority.StablePrincipalID(acme, "a")}}}
}

func (w *world) share(token string, p access.Placement, subject domain.AccessSubject, actions ...string) domain.AccessGrant {
	w.t.Helper()
	g, _, err := w.svc.Grant(w.ctx, access.GrantRequest{Token: token, Actor: serving, Subject: subject, Actions: actions, Placement: p,
		Target: access.Target{Kind: p.Resource.Kind, ResourceID: p.Resource.ResourceID, Version: p.Resource.Version}})
	if err != nil {
		w.t.Fatal(err)
	}
	return g
}

func (w *world) check(token string, p access.Placement) access.Decision {
	w.t.Helper()
	out, _, err := w.svc.Check(w.ctx, access.CheckRequest{Token: token, Actor: serving, Action: "read", Placements: []access.Placement{p}})
	if err != nil {
		w.t.Fatal(err)
	}
	return out[0]
}

func refusal(t *testing.T, err error, code domain.Code, reason string) {
	t.Helper()
	if got, ok := domain.CodeOf(err); !ok || got != code || !strings.Contains(err.Error(), reason) {
		t.Fatalf("want refusal %v naming %q, got %v", code, reason, err)
	}
}

func person(id string) domain.AccessSubject {
	return domain.AccessSubject{Kind: domain.AccessPerson, ID: id}
}

func TestAShareIsHeldByItsGranteeThroughTheInstallationThatOwnsTheCollection(t *testing.T) {
	w := newWorld(t)
	da, db := w.doc("da", "dana"), w.doc("db", "bob")
	if got := w.check(w.as("carol", "a"), da); got.Allowed {
		t.Fatalf("before any share Carol is %+v", got)
	}
	g := w.share(w.as("dana", "a"), da, person("carol"), "read")
	if g.ID == "" || g.GrantedBy != "dana" || !g.CreatedAt.Equal(w.now) {
		t.Fatalf("grant %+v", g)
	}
	got := w.check(w.as("carol", "a"), da)
	if !got.Allowed || !slices.Equal(got.Bases, []access.Basis{access.ResourceGrant}) {
		t.Fatalf("Carol on the shared document: %+v", got)
	}
	if got := w.check(w.as("carol", "a"), db); got.Allowed {
		t.Fatalf("Carol on its sibling: %+v", got)
	}
	// Through B, whose installation holds nothing of A's collection.
	if got := w.check(w.as("carol", "b"), da); got.Allowed || !strings.Contains(got.Reason, "an actor") {
		t.Fatalf("Carol through B: %+v", got)
	}
	w.share(w.as("dana", "a"), da, domain.AccessSubject{Kind: domain.AccessInstallation, ID: authority.StableInstallationID(acme, "b")}, "read")
	if got := w.check(w.as("carol", "b"), da); !got.Allowed {
		t.Fatalf("Carol through B once B is granted: %+v", got)
	}
}

func TestARegrantRefreshesTheGrantAndKeepsItsIdentity(t *testing.T) {
	w := newWorld(t)
	da := w.doc("da", "dana")
	first := w.share(w.as("dana", "a"), da, person("carol"), "read")
	w.now = w.now.Add(time.Minute)
	second := w.share(w.as("dana", "a"), da, person("carol"), "share", "read")
	if second.ID != first.ID || !second.CreatedAt.Equal(first.CreatedAt) || !slices.Equal(second.Actions, []string{"read", "share"}) {
		t.Fatalf("refreshed %+v from %+v", second, first)
	}
	grants, _, err := w.svc.ListGrants(w.ctx, access.ListRequest{Token: w.as("dana", "a"), Actor: serving, Placement: da, Target: access.Target{Kind: docKind, ResourceID: "da"}})
	if err != nil || len(grants) != 1 {
		t.Fatalf("listed %v, %v", grants, err)
	}
}

func TestWhoMayGrantRevokeAndList(t *testing.T) {
	w := newWorld(t)
	da := w.doc("da", "dana")
	target := access.Target{Kind: docKind, ResourceID: "da"}
	w.share(w.as("dana", "a"), da, person("carol"), "read")
	// The collection's administrator shares what they do not own.
	w.share(w.as("alex", "a"), da, person("tom"), "read")
	for name, token := range map[string]string{"a grantee": w.as("carol", "a"), "a member who neither owns nor administers": w.as("bob", "a")} {
		t.Run(name, func(t *testing.T) {
			_, _, err := w.svc.Grant(w.ctx, access.GrantRequest{Token: token, Actor: serving, Target: target, Placement: da, Subject: person("bob"), Actions: []string{"read"}})
			refusal(t, err, domain.Denied, "neither owns")
			_, _, err = w.svc.ListGrants(w.ctx, access.ListRequest{Token: token, Actor: serving, Target: target, Placement: da})
			refusal(t, err, domain.Denied, "neither owns")
			// The same answer whether the grant exists.
			_, _, existing := w.svc.Revoke(w.ctx, access.RevokeRequest{Token: token, Actor: serving, Target: target, Placement: da, Subject: person("carol")})
			_, _, absent := w.svc.Revoke(w.ctx, access.RevokeRequest{Token: token, Actor: serving, Target: target, Placement: da, Subject: person("alex")})
			refusal(t, existing, domain.Denied, "neither owns")
			if existing.Error() != absent.Error() {
				t.Fatalf("revoking an existing grant answers %q, an absent one %q", existing, absent)
			}
		})
	}
	dana := w.as("dana", "a")
	for name, r := range map[string]struct {
		request access.GrantRequest
		code    domain.Code
		reason  string
	}{
		"an action the grantor does not hold": {access.GrantRequest{Subject: person("carol"), Actions: []string{"write"}}, domain.Denied, "holds no documents:write"},
		"an action no grant gives":            {access.GrantRequest{Subject: person("carol"), Actions: []string{"delete"}}, domain.Invalid, "not an action a grant gives"},
		"the wildcard":                        {access.GrantRequest{Subject: person("carol"), Actions: []string{"*"}}, domain.Invalid, "not an action a grant gives"},
		"no action":                           {access.GrantRequest{Subject: person("carol")}, domain.Invalid, "between 1 and"},
		"no subject":                          {access.GrantRequest{Actions: []string{"read"}}, domain.Invalid, "exactly one"},
		"a person the organization lacks":     {access.GrantRequest{Subject: person("nobody"), Actions: []string{"read"}}, domain.Denied, "not a member, a team or an active installation of acme"},
		"another organization's person":       {access.GrantRequest{Subject: person("zoe"), Actions: []string{"read"}}, domain.Denied, "not a member, a team or an active installation of acme"},
		"a team the host does not hold":       {access.GrantRequest{Subject: domain.AccessSubject{Kind: domain.AccessTeam, ID: "ghosts"}, Actions: []string{"read"}}, domain.Denied, "not a member, a team or an active installation of acme"},
		"another organization's installation": {access.GrantRequest{Subject: domain.AccessSubject{Kind: domain.AccessInstallation, ID: authority.StableInstallationID(globex, "a")}, Actions: []string{"read"}}, domain.Denied, "not a member, a team or an active installation of acme"},
		"an expiry in the past":               {access.GrantRequest{Subject: person("carol"), Actions: []string{"read"}, ExpiresAt: w.now}, domain.Invalid, "expires in the future"},
	} {
		t.Run(name, func(t *testing.T) {
			r.request.Token, r.request.Actor, r.request.Target, r.request.Placement = dana, serving, target, da
			_, _, err := w.svc.Grant(w.ctx, r.request)
			refusal(t, err, r.code, r.reason)
		})
	}
}

func TestRevokingNothingIsNotARevocation(t *testing.T) {
	w := newWorld(t)
	da := w.doc("da", "dana")
	target := access.Target{Kind: docKind, ResourceID: "da"}
	revoke := func() (domain.AccessGrant, error) {
		g, _, err := w.svc.Revoke(w.ctx, access.RevokeRequest{Token: w.as("dana", "a"), Actor: serving, Target: target, Placement: da, Subject: person("carol")})
		return g, err
	}
	_, err := revoke()
	refusal(t, err, domain.NotFound, access.NothingRevoked)
	granted := w.share(w.as("dana", "a"), da, person("carol"), "read")
	revoked, err := revoke()
	if err != nil || revoked.ID != granted.ID {
		t.Fatalf("revoked %+v, %v", revoked, err)
	}
	if got := w.check(w.as("carol", "a"), da); got.Allowed {
		t.Fatalf("after the revoke Carol is %+v", got)
	}
	_, err = revoke()
	refusal(t, err, domain.NotFound, access.NothingRevoked)
	// An expired grant is nothing to revoke either.
	_, _, err = w.svc.Grant(w.ctx, access.GrantRequest{Token: w.as("dana", "a"), Actor: serving, Target: target, Placement: da, Subject: person("carol"), Actions: []string{"read"}, ExpiresAt: w.now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	w.now = w.now.Add(2 * time.Minute)
	_, err = revoke()
	refusal(t, err, domain.NotFound, access.NothingRevoked)
}

func TestAGrantExpiresByTheInjectedClock(t *testing.T) {
	w := newWorld(t)
	da := w.doc("da", "dana")
	until := w.now.Add(time.Minute)
	_, _, err := w.svc.Grant(w.ctx, access.GrantRequest{Token: w.as("dana", "a"), Actor: serving, Target: access.Target{Kind: docKind, ResourceID: "da"}, Placement: da,
		Subject: person("carol"), Actions: []string{"read"}, ExpiresAt: until})
	if err != nil {
		t.Fatal(err)
	}
	got := w.check(w.as("carol", "a"), da)
	if !got.Allowed || !got.ValidUntil.Equal(until) {
		t.Fatalf("before the expiry: %+v", got)
	}
	w.now = until
	if got := w.check(w.as("carol", "a"), da); got.Allowed {
		t.Fatalf("at the expiry: %+v", got)
	}
}

func TestATeamGrantCountsForMembersNowAndACastCountsItsTeamAlone(t *testing.T) {
	w := newWorld(t)
	da, db := w.doc("da", "dana"), w.doc("db", "bob")
	w.share(w.as("dana", "a"), da, domain.AccessSubject{Kind: domain.AccessTeam, ID: "team"}, "read")
	w.share(w.as("bob", "a"), db, person("alex"), "read")
	if got := w.check(w.as("tom", "a"), da); !got.Allowed {
		t.Fatalf("a member of the team: %+v", got)
	}
	if got := w.check(w.as("carol", "a"), da); got.Allowed {
		t.Fatalf("a person outside the team: %+v", got)
	}
	// Alex administers acme, so may act as the team: the cast holds the
	// team's grant and not Alex's own.
	if _, err := w.auth.GrantRole(w.ctx, w.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: authority.StableInstallationID(acme, "a"), Role: domain.UserRole, TeamID: "team"}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.auth.OpenTeamCast(w.ctx, w.person("alex"), authority.TeamCastRequest{Organization: acme, Team: "team", SessionID: "cast-alex"}); err != nil {
		t.Fatal(err)
	}
	cast := w.through(authority.Person{ID: "alex", Organization: acme, SessionID: "cast-alex"}, "a")
	if got := w.check(cast, da); !got.Allowed {
		t.Fatalf("the cast on what the team is granted: %+v", got)
	}
	if got := w.check(cast, db); got.Allowed {
		t.Fatalf("the cast on what Alex alone is granted: %+v", got)
	}
	// A member who leaves stops counting the team at the next capability.
	w.store.PutPerson(domain.Person{ID: "tom", Organization: acme})
	if err := w.auth.PersonChanged(w.ctx, "tom"); err != nil {
		t.Fatal(err)
	}
	if got := w.check(w.as("tom", "a"), da); got.Allowed {
		t.Fatalf("after leaving the team: %+v", got)
	}
	// A team the host no longer holds counts for nobody.
	w.store.PutPerson(domain.Person{ID: "tom", Organization: acme, Teams: []string{"team"}})
	if err := w.auth.PersonChanged(w.ctx, "tom"); err != nil {
		t.Fatal(err)
	}
	w.store.DeleteTeam(acme, "team")
	w.role("a", domain.UserRole, "tom")
	if got := w.check(w.as("tom", "a"), da); got.Allowed {
		t.Fatalf("a deleted team's grant: %+v", got)
	}
}

func TestAnUninstalledInstallationsGrantsNeverDecideAgain(t *testing.T) {
	w := newWorld(t)
	// A document outside B's own collections, shared with installation B.
	da := w.doc("da", "dana")
	installationB := domain.AccessSubject{Kind: domain.AccessInstallation, ID: authority.StableInstallationID(acme, "b")}
	w.share(w.as("dana", "a"), da, installationB, "read")
	if got := w.check(w.agent("b"), da); !got.Allowed || !slices.Equal(got.Bases, []access.Basis{access.ResourceGrant}) {
		t.Fatalf("B's agent on what B is granted: %+v", got)
	}
	before := w.agent("b")
	if err := w.auth.UninstallAsHost(w.ctx, acme, installationB.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.svc.Check(w.ctx, access.CheckRequest{Token: before, Actor: serving, Action: "read", Placements: []access.Placement{da}}); err == nil {
		t.Fatal("a capability of the uninstalled installation was decided")
	}
	w.install(acme, "alex", "b")
	if got := w.check(w.agent("b"), da); got.Allowed {
		t.Fatalf("the reinstalled installation holds its predecessor's grant: %+v", got)
	}
	grants, _, err := w.svc.ListGrants(w.ctx, access.ListRequest{Token: w.as("dana", "a"), Actor: serving, Placement: da, Target: access.Target{Kind: docKind, ResourceID: "da"}})
	if err != nil || len(grants) != 0 {
		t.Fatalf("after the uninstall the document's grants are %v, %v", grants, err)
	}
}

func TestOnlyTheKindsOneServingModuleAsksAndOnlyWithACapabilityAddressedToIt(t *testing.T) {
	w := newWorld(t)
	da := w.doc("da", "dana")
	ask := func(token string, actor authority.Workload, p access.Placement) error {
		_, _, err := w.svc.Check(w.ctx, access.CheckRequest{Token: token, Actor: actor, Action: "read", Placements: []access.Placement{p}})
		return err
	}
	refusal(t, ask(w.as("carol", "a"), authority.Workload{Module: "a"}, da), domain.Denied, "does not serve")
	refusal(t, ask(w.as("carol", "a"), authority.Workload{Module: "nobody"}, da), domain.NotFound, "nobody")
	foreign := da
	foreign.Resource.Kind = "a.note"
	refusal(t, ask(w.as("carol", "a"), serving, foreign), domain.Denied, "does not serve a.note")
	root, err := w.auth.IssueForPerson(w.ctx, w.person("carol"), authority.IssueRequest{Audience: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ask(root.Token, serving, da); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("a capability addressed to another module: %v", err)
	}
	refusal(t, ask(w.as("carol", "a"), authority.Workload{Module: "store", Organization: globex}, da), domain.Denied, "bound to organization globex")
	for name, p := range map[string]access.Placement{
		"the wildcard id":   {Resource: access.Node{Kind: docKind, ResourceID: "*"}},
		"no kind":           {Resource: access.Node{ResourceID: "da"}},
		"an ancestor twice": {Resource: da.Resource, Ancestors: []access.Node{da.Ancestors[0], da.Ancestors[0]}},
		"nine ancestors": {Resource: da.Resource, Ancestors: func() []access.Node {
			var out []access.Node
			for i := range 9 {
				out = append(out, access.Node{Kind: collectionKind, ResourceID: fmt.Sprint("c", i)})
			}
			return out
		}()},
	} {
		t.Run(name, func(t *testing.T) {
			if code, ok := domain.CodeOf(ask(w.as("carol", "a"), serving, p)); !ok || code != domain.Invalid {
				t.Fatalf("want the placement refused as malformed, got %v", ask(w.as("carol", "a"), serving, p))
			}
		})
	}
	_, _, err = w.svc.Check(w.ctx, access.CheckRequest{Token: w.as("carol", "a"), Actor: serving, Action: "read", Placements: []access.Placement{da}, MinRevision: access.Minimum{Organization: acme, Opaque: []byte{1}}})
	refusal(t, err, domain.Precondition, "revision precondition")
	// Nor is the newest state promised by a host that serves no minimum.
	_, _, err = w.svc.Check(w.ctx, access.CheckRequest{Token: w.as("carol", "a"), Actor: serving, Action: "read", Placements: []access.Placement{da}, Head: true})
	refusal(t, err, domain.Precondition, "revision precondition")
	// A viewer of another organization holds nothing of this one's grants.
	w.share(w.as("dana", "a"), da, person("carol"), "read")
	if _, err := w.auth.GrantRole(w.ctx, w.person("zoe"), authority.RoleRequest{Organization: globex, InstallationID: authority.StableInstallationID(globex, "a"), Role: domain.UserRole, PersonID: "zoe"}); err != nil {
		t.Fatal(err)
	}
	if got := w.check(w.as("zoe", "a"), da); got.Allowed {
		t.Fatalf("another organization's viewer: %+v", got)
	}
}

func TestAViewersGrantsArePagedAndAPageFromBeforeAChangeIsStale(t *testing.T) {
	w := newWorld(t)
	dana := w.as("dana", "a")
	for _, id := range []string{"d1", "d2", "d3"} {
		w.share(dana, w.doc(id, "dana"), person("carol"), "read")
	}
	w.share(dana, access.Placement{Resource: access.Node{Kind: docKind, ResourceID: "d1", Version: "v1", Owner: "dana"}}, person("carol"), "read")
	w.share(dana, w.doc("d4", "dana"), person("carol"), "share")
	w.share(dana, w.doc("d5", "dana"), person("tom"), "read")
	page := func(token string) (access.ViewerGrants, error) {
		return w.svc.ListViewerGrants(w.ctx, access.ViewerGrantsRequest{Token: w.as("carol", "a"), Actor: serving, Kinds: []string{docKind}, Action: "read", PageSize: 2, PageToken: token})
	}
	first, err := page("")
	if err != nil {
		t.Fatal(err)
	}
	want := []access.Target{{Kind: docKind, ResourceID: "d1"}, {Kind: docKind, ResourceID: "d1", Version: "v1"}}
	if !slices.Equal(first.Resources, want) || first.NextPage == "" {
		t.Fatalf("first page %+v", first)
	}
	second, err := page(first.NextPage)
	if err != nil || !slices.Equal(second.Resources, []access.Target{{Kind: docKind, ResourceID: "d2"}, {Kind: docKind, ResourceID: "d3"}}) || second.NextPage != "" {
		t.Fatalf("second page %+v, %v", second, err)
	}
	if _, _, err := w.svc.Revoke(w.ctx, access.RevokeRequest{Token: dana, Actor: serving, Target: access.Target{Kind: docKind, ResourceID: "d3"}, Placement: w.doc("d3", "dana"), Subject: person("carol")}); err != nil {
		t.Fatal(err)
	}
	if _, err := page(first.NextPage); !errors.Is(err, access.ErrStale) {
		t.Fatalf("a page from before the revoke: %v", err)
	}
	restarted, err := page("")
	if err != nil {
		t.Fatal(err)
	}
	last, err := page(restarted.NextPage)
	if err != nil || !slices.Equal(last.Resources, []access.Target{{Kind: docKind, ResourceID: "d2"}}) {
		t.Fatalf("after the restart %+v, %v", last, err)
	}
	if _, err := page("not-a-token"); err == nil {
		t.Fatal("a token this host never issued was read")
	}
}

// A share that gives share lets its grantee share on what it gives, on the
// reference it is on, for no longer than it lasts, and end the shares they
// made: nobody grants what they do not hold.
func TestAGranteeSharesOnOnlyWhatTheirShareGives(t *testing.T) {
	w := newWorld(t)
	da := w.doc("da", "dana")
	target := access.Target{Kind: docKind, ResourceID: "da"}
	grant := func(token string, tg access.Target, subject string, expires time.Time, actions ...string) error {
		p := da
		p.Resource.Version = tg.Version
		_, _, err := w.svc.Grant(w.ctx, access.GrantRequest{Token: token, Actor: serving, Target: tg, Placement: p, Subject: person(subject), Actions: actions, ExpiresAt: expires})
		return err
	}
	revoke := func(token, subject string) error {
		_, _, err := w.svc.Revoke(w.ctx, access.RevokeRequest{Token: token, Actor: serving, Target: target, Placement: da, Subject: person(subject)})
		return err
	}
	// Read alone shares nothing on.
	w.share(w.as("dana", "a"), da, person("carol"), "read")
	refusal(t, grant(w.as("carol", "a"), target, "bob", time.Time{}, "read"), domain.Denied, "neither owns")
	// Read and share: Carol shares read on, and nothing her share lacks.
	w.share(w.as("dana", "a"), da, person("carol"), "read", "share")
	if err := grant(w.as("carol", "a"), target, "bob", time.Time{}, "read"); err != nil {
		t.Fatalf("a grantee holding share shares read on: %v", err)
	}
	if got := w.check(w.as("bob", "a"), da); !got.Allowed {
		t.Fatalf("Bob on what Carol shared on: %+v", got)
	}
	// Write is not hers to share on: neither her share nor her capability gives it.
	if err := grant(w.as("carol", "a"), target, "tom", time.Time{}, "write"); err == nil {
		t.Fatal("a grantee shared on an action their share does not give")
	}
	// Share is shared on like any action her share gives, named explicitly.
	if err := grant(w.as("carol", "a"), target, "tom", time.Time{}, "share"); err != nil {
		t.Fatalf("a grantee holding share shares share on: %v", err)
	}
	// Another document is not hers to share.
	other := w.doc("db", "dana")
	_, _, err := w.svc.Grant(w.ctx, access.GrantRequest{Token: w.as("carol", "a"), Actor: serving, Target: access.Target{Kind: docKind, ResourceID: "db"}, Placement: other, Subject: person("bob"), Actions: []string{"read"}})
	refusal(t, err, domain.Denied, "neither owns")
	// She never lists who else holds it.
	_, _, err = w.svc.ListGrants(w.ctx, access.ListRequest{Token: w.as("carol", "a"), Actor: serving, Target: target, Placement: da})
	refusal(t, err, domain.Denied, "neither owns")
	// She ends the share she made; the owner's, or one that is absent, is nothing of hers to revoke.
	w.share(w.as("dana", "a"), da, person("tom"), "read")
	refusal(t, revoke(w.as("carol", "a"), "tom"), domain.NotFound, access.NothingRevoked)
	refusal(t, revoke(w.as("carol", "a"), "alex"), domain.NotFound, access.NothingRevoked)
	if err := revoke(w.as("carol", "a"), "bob"); err != nil {
		t.Fatalf("a grantee revokes the share they made: %v", err)
	}
	if got := w.check(w.as("bob", "a"), da); got.Allowed {
		t.Fatalf("Bob after Carol revoked: %+v", got)
	}
	// Once her share is revoked she shares nothing on.
	if err := revoke(w.as("dana", "a"), "carol"); err != nil {
		t.Fatal(err)
	}
	refusal(t, grant(w.as("carol", "a"), target, "bob", time.Time{}, "read"), domain.Denied, "neither owns")

	// A share that expires is shared on for no longer than it lasts.
	until := w.now.Add(time.Hour)
	if err := grant(w.as("dana", "a"), target, "carol", until, "read", "share"); err != nil {
		t.Fatal(err)
	}
	refusal(t, grant(w.as("carol", "a"), target, "bob", time.Time{}, "read"), domain.Denied, "ends no later")
	refusal(t, grant(w.as("carol", "a"), target, "bob", until.Add(time.Second), "read"), domain.Denied, "ends no later")
	if err := grant(w.as("carol", "a"), target, "bob", until, "read"); err != nil {
		t.Fatalf("a share made on within the share it rests on: %v", err)
	}
	if err := revoke(w.as("dana", "a"), "carol"); err != nil {
		t.Fatal(err)
	}

	// A share pinned to a version shares that version on, never the document.
	v1 := access.Target{Kind: docKind, ResourceID: "da", Version: "v1"}
	if err := grant(w.as("dana", "a"), v1, "carol", time.Time{}, "read", "share"); err != nil {
		t.Fatal(err)
	}
	refusal(t, grant(w.as("carol", "a"), target, "tom", time.Time{}, "read"), domain.Denied, "neither owns")
	refusal(t, grant(w.as("carol", "a"), access.Target{Kind: docKind, ResourceID: "da", Version: "v2"}, "tom", time.Time{}, "read"), domain.Denied, "neither owns")
	if err := grant(w.as("carol", "a"), v1, "tom", time.Time{}, "read"); err != nil {
		t.Fatalf("a pinned share shares its version on: %v", err)
	}
}
