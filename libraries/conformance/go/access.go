package conformance

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/solutionhost/go"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const accessService = "host.access.v1.AccessService"

// AccessCase is the fixture of codefly.dev/access: grants on one collection,
// one document or one exact version, written and answered by the host, asked
// by the module serving the kind. The suite plays that module: it delivers
// Store serving Kind (documents) and CollectionKind (collections), holds
// StoreCredential, forwards the Work Context of whoever asks and attests
// where each resource sits.
//
// It reuses the solution-principal cast and hooks (SolutionPrincipalCase) and
// delivers its own declarations for them, so a host runs it on a fixture of
// its own, never beside RunSolutionPrincipalTarget:
//   - A, B and C are three solutions of Organization, each a principal. A
//     owns the two collections of the cast; B and C own nothing of them. C is
//     the sibling installation, and the one whose user role holds no read on
//     Kind.
//   - On A and B the user role reads and shares documents and names no
//     collection: a person through one holds a document by a grant, never by
//     their role. The admin role also administers collections, so the
//     installation's agent (installed with admin) reads its own collections.
//   - Author owns the documents shared (Dana), Member owns a sibling document
//     (Bob), UserHolder is granted (Carol), TeamMember and TeamLeaver belong
//     to Team (Tom and Lee), OrgLeaver leaves the organization (Rex),
//     AdminHolder administers A's collections, Reader holds a share and no
//     read on the kind, OtherAdmin administers OtherOrganization.
//
// CollectionKind is the second kind Store serves. Advance moves the host's
// clock forward, for a grant's expiry; nil, the suite waits in real time.
// InstalledRead, when the host has a class of installed-content read
// bindings, issues one for a person at Store through an installed module that
// holds nothing of the resource, and drops the binding; nil, the host has no
// such class, every chain is ordinary delegation, and the owner-alone leg of
// H11 is skipped by name.
//
// MinRevision says the host serves revision minimums: a decision asked with
// min_revision, item_min_revisions or FRESHNESS_HEAD is computed at a state at
// or past it. False, RunAccess holds the host to refusing each (H21), and the
// host does not run RunAccessRevisions; true, H21 holds it to serving them
// and the host also runs RunAccessRevisions, on a fixture of its own. Lag
// freezes the host's access reader at its state now, as a replica that
// stopped replaying, until the function it answers is called; nil, the host
// has one store and no reader to hold behind, and the cases that need one are
// skipped by name.
type AccessCase struct {
	SolutionPrincipalCase
	CollectionKind string
	Advance        func(ctx context.Context, d time.Duration) error
	InstalledRead  *InstalledReadCase
	MinRevision    bool
	Lag            func(t *testing.T) (catchUp func())
}

// InstalledReadCase is a host's installed-content read: Issue answers a Work
// Context for the person signed in by fixtureToken, addressed to Store,
// through a live installed-content read binding of a module whose
// installation is granted nothing; Drop removes that binding.
type InstalledReadCase struct {
	Issue func(ctx context.Context, fixtureToken string) (token string, err error)
	Drop  func(ctx context.Context) error
}

// accessContract is what the interface publishes; accessNeverNamed are the
// ways a request could name who is asking, none of which it has: the tenant,
// the viewer and the actors are read from the verified Work Context alone.
var accessContract = []struct{ message, element string }{
	{accessService, "Grant"}, {accessService, "Revoke"}, {accessService, "ListGrants"},
	{accessService, "Check"}, {accessService, "CheckBatch"}, {accessService, "ListViewerGrants"},
	{"host.access.v1.ResourceRef", "resource_kind"}, {"host.access.v1.ResourceRef", "resource_id"}, {"host.access.v1.ResourceRef", "version"},
	{"host.access.v1.Subject", "person_id"}, {"host.access.v1.Subject", "team_id"}, {"host.access.v1.Subject", "installation_id"},
	{"host.access.v1.PlacedNode", "ref"}, {"host.access.v1.PlacedNode", "owner_id"},
	{"host.access.v1.Placement", "resource"}, {"host.access.v1.Placement", "ancestors"},
	{"host.access.v1.AccessRevision", "organization_id"}, {"host.access.v1.AccessRevision", "opaque"},
	{"host.access.v1.AccessGrant", "grant_id"}, {"host.access.v1.AccessGrant", "expires_at_unix"}, {"host.access.v1.AccessGrant", "granted_by"},
	{"host.access.v1.GrantResponse", "grant"}, {"host.access.v1.GrantResponse", "revision"},
	{"host.access.v1.RevokeResponse", "revoked"}, {"host.access.v1.RevokeResponse", "revision"},
	{"host.access.v1.ListGrantsResponse", "grants"}, {"host.access.v1.ListGrantsResponse", "revision"},
	{"host.access.v1.CheckRequest", "min_revision"}, {"host.access.v1.CheckBatchRequest", "min_revision"}, {"host.access.v1.ListViewerGrantsRequest", "min_revision"},
	{"host.access.v1.CheckRequest", "freshness"}, {"host.access.v1.CheckBatchRequest", "freshness"}, {"host.access.v1.CheckBatchRequest", "item_min_revisions"},
	{"host.access.v1.CheckBatchResponse", "revision"}, {"host.access.v1.ListViewerGrantsResponse", "revision"},
	{"host.access.v1.CheckResponse", "decision"}, {"host.access.v1.CheckResponse", "viewer_bases"}, {"host.access.v1.CheckResponse", "reason"},
	{"host.access.v1.CheckResponse", "revision"}, {"host.access.v1.CheckResponse", "valid_until_unix"},
	{"host.access.v1.CheckBatchResponse", "results"},
	{"host.access.v1.ListViewerGrantsResponse", "resources"}, {"host.access.v1.ListViewerGrantsResponse", "next_page_token"},
}

var accessNeverNamed = []string{"viewer", "person", "principal", "owner", "tenant", "organization", "subject", "team", "session", "digest", "blob", "key"}

// accessDecisionRequests are the requests a decision is asked with: exactly
// these fields, so nothing in a body can say who is asking.
var accessDecisionRequests = map[string][]string{
	"host.access.v1.CheckRequest":            {"token", "actor", "action", "placement", "min_revision", "freshness"},
	"host.access.v1.CheckBatchRequest":       {"token", "actor", "action", "placements", "min_revision", "item_min_revisions", "freshness"},
	"host.access.v1.ListViewerGrantsRequest": {"token", "actor", "resource_kinds", "action", "page_size", "page_token", "min_revision"},
}

// RunAccess proves a host serves codefly.dev/access as every host does: the
// cases H1 to H23, each a named subtest that makes its own grants on
// resources of its own and can run alone.
func RunAccess(t *testing.T, conn grpc.ClientConnInterface, descriptors []byte, f AccessCase) {
	t.Helper()
	newAccessSuite(t, conn, descriptors, f).cases(t)
}

// newAccessSuite checks the published contract and the fixture, and delivers
// the cast.
func newAccessSuite(t *testing.T, conn grpc.ClientConnInterface, descriptors []byte, f AccessCase) *accessSuite {
	t.Helper()
	c, err := newClient(conn, descriptors)
	if err != nil {
		t.Fatalf("conformance: %v", err)
	}
	var lacks []string
	for _, want := range accessContract {
		if !c.hasElement(want.message, want.element) {
			lacks = append(lacks, want.message+"."+want.element)
		}
	}
	if len(lacks) > 0 {
		t.Fatalf("access: the published contract lacks %s", strings.Join(lacks, ", "))
	}
	if f.Uninstall == nil || f.RemoveFromTeam == nil || f.RemoveFromOrganization == nil || f.SignManifest == nil || f.SignAuthority == nil ||
		f.DeliveryCredential == nil || f.OtherOrganization == "" || f.Team == "" || f.Kind == "" || f.CollectionKind == "" || f.CollectionKind == f.Kind ||
		f.Store == "" || f.StoreCredential == "" || f.C.Solution == "" ||
		slices.Contains([]string{f.Admin, f.UserHolder, f.Author, f.Member, f.AdminHolder, f.TeamMember, f.TeamLeaver, f.OrgLeaver, f.Reader, f.OtherAdmin, f.OtherMember}, "") {
		t.Fatal("required conformance fixture missing: access case")
	}
	ctx := context.Background()
	as := &accessSuite{f: f, principalSuite: &principalSuite{c: c, f: f.SolutionPrincipalCase, ctx: ctx, sessions: map[string]protoreflect.Message{},
		installed: map[string]protoreflect.Message{}, storeGeneration: f.Generation}, generation: f.Generation}
	as.deliver(t)
	return as
}

// accessSuite is the cast at work: the principal suite's sessions and
// installations, and the module the suite plays.
type accessSuite struct {
	*principalSuite
	f AccessCase
	// generation is the next delivery generation of C, which H11 redelivers.
	generation uint64
}

// deliver delivers the store and the three solutions as this suite declares
// them: Store serving documents and collections and checking owners; A and B
// whose user role reads and shares documents; C whose user role holds no read
// on documents, and which also binds to the store through "reader".
func (as *accessSuite) deliver(t *testing.T) {
	t.Helper()
	f := as.f
	documents, collections := []string{"admin", "read", "share", "write"}, []string{"admin", "read", "share"}
	if _, err := as.c.deliver(as.ctx, as.delivery(), f.Store, "module", f.Generation, []string{f.Kind, f.CollectionKind}, map[string]any{
		"owner_aware":    true,
		"scope_ceilings": []any{scopeAsk(f.Kind, documents, nil), scopeAsk(f.CollectionKind, collections, nil)},
	}, 0); err != nil {
		t.Fatalf("deliver %s: %v", f.Store, err)
	}
	for _, s := range []SolutionUnderTest{f.A, f.B} {
		as.deliverSolution(t, s, f.Generation, []string{"read", "share"}, false)
	}
	as.deliverSolution(t, f.C, as.generation, []string{"write"}, true)
	as.generation++
}

func (as *accessSuite) deliverSolution(t *testing.T, s SolutionUnderTest, generation uint64, user []string, reader bool) {
	t.Helper()
	f := as.f
	own := s.Solution + ".note"
	documents, collections := []string{"admin", "read", "share", "write"}, []string{"admin", "read", "share"}
	bindings := []solutionhost.AuthorityBinding{{ID: "store", Audience: f.Store, Operations: map[string][]string{"invoke": {
		f.Kind + ":admin", f.Kind + ":read", f.Kind + ":share", f.Kind + ":write",
		f.CollectionKind + ":admin", f.CollectionKind + ":read", f.CollectionKind + ":share"}}}}
	if reader {
		bindings = append(bindings, solutionhost.AuthorityBinding{ID: "reader", Audience: f.Store, Operations: map[string][]string{"invoke": {f.Kind + ":read"}}})
	}
	if _, err := as.c.deliver(as.ctx, as.delivery(), s.Solution, "solution", generation, []string{own}, map[string]any{
		"owner_aware":    true,
		"scope_ceilings": []any{scopeAsk(own, []string{"read", "write"}, nil)},
		"roles": []any{
			map[string]any{"name": "admin", "scopes": []any{scopeAsk(own, []string{"read", "write"}, nil), scopeAsk(f.Kind, documents, nil), scopeAsk(f.CollectionKind, collections, nil)}},
			map[string]any{"name": "user", "scopes": []any{scopeAsk(own, []string{"read"}, nil), scopeAsk(f.Kind, user, nil)}},
		},
	}, 0, bindings...); err != nil {
		t.Fatalf("deliver %s: %v", s.Solution, err)
	}
}

// --- the module the suite plays ----------------------------------------------

func ref(kind, id, version string) map[string]any {
	return map[string]any{"resource_kind": kind, "resource_id": id, "version": version}
}

func placed(kind, id, version, owner string) map[string]any {
	return map[string]any{"ref": ref(kind, id, version), "owner_id": owner}
}

// place is a placement: the resource and the collections above it.
func place(resource map[string]any, ancestors ...map[string]any) map[string]any {
	above := make([]any, len(ancestors))
	for i, a := range ancestors {
		above[i] = a
	}
	return map[string]any{"resource": resource, "ancestors": above}
}

// collection is one of the cast's two collections, owned by A's principal.
func (as *accessSuite) collection(t *testing.T, id string) map[string]any {
	return placed(as.f.CollectionKind, id, "", as.principal(t, as.f.Organization, as.f.A))
}

// document places a document of owner (a fixture token's person) at version
// in C1; under moves it.
func (as *accessSuite) document(t *testing.T, id, version, owner string) map[string]any {
	return place(placed(as.f.Kind, id, version, as.personID(t, owner)), as.collection(t, "c1"))
}

func under(placement map[string]any, ancestors ...map[string]any) map[string]any {
	return place(placement["resource"].(map[string]any), ancestors...)
}

func atVersion(placement map[string]any, version string) map[string]any {
	node := clone(placement["resource"].(map[string]any))
	r := clone(node["ref"].(map[string]any))
	r["version"] = version
	node["ref"] = r
	out := clone(placement)
	out["resource"] = node
	return out
}

func targetOf(placement map[string]any) map[string]any {
	return placement["resource"].(map[string]any)["ref"].(map[string]any)
}

func (as *accessSuite) actor() map[string]any {
	return map[string]any{"credential": as.f.StoreCredential}
}

// seat grants role on s to each person, so they are issued a capability
// through it. A grant is idempotent.
func (as *accessSuite) seat(t *testing.T, s SolutionUnderTest, role string, people ...string) {
	t.Helper()
	for _, p := range people {
		as.grant(t, s, role, as.person(t, p))
	}
}

// token is a fresh Work Context of the person at the store through s.
func (as *accessSuite) token(t *testing.T, person string, s SolutionUnderTest) string {
	t.Helper()
	return str(as.must(t)(as.through(t, person, s, "store")), "token")
}

// agentToken is a fresh Work Context of s's installation acting for itself.
func (as *accessSuite) agentToken(t *testing.T, s SolutionUnderTest) string {
	t.Helper()
	return str(as.must(t)(as.agent(t, s, "store")), "token")
}

func (as *accessSuite) installationOf(t *testing.T, s SolutionUnderTest) map[string]any {
	return map[string]any{"installation_id": str(as.ensure(t, as.f.Organization, s), "id")}
}

func (as *accessSuite) share(token string, placement, subject map[string]any, expires int64, actions ...string) (protoreflect.Message, error) {
	given := make([]any, len(actions))
	for i, a := range actions {
		given[i] = a
	}
	return as.c.call(as.ctx, accessService, "Grant", map[string]any{"token": token, "actor": as.actor(), "target": targetOf(placement),
		"placement": placement, "subject": subject, "actions": given, "expires_at_unix": expires})
}

// shared makes a read grant that must be admitted.
func (as *accessSuite) shared(t *testing.T, token string, placement, subject map[string]any) protoreflect.Message {
	t.Helper()
	out, err := as.share(token, placement, subject, 0, "read")
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	return msg(out, "grant")
}

func (as *accessSuite) unshare(token string, placement, subject map[string]any) (protoreflect.Message, error) {
	return as.c.call(as.ctx, accessService, "Revoke", map[string]any{"token": token, "actor": as.actor(), "target": targetOf(placement), "placement": placement, "subject": subject})
}

func (as *accessSuite) acl(token string, placement map[string]any) (protoreflect.Message, error) {
	return as.c.call(as.ctx, accessService, "ListGrants", map[string]any{"token": token, "actor": as.actor(), "target": targetOf(placement), "placement": placement})
}

func (as *accessSuite) ask(token string, placement map[string]any) (protoreflect.Message, error) {
	return as.c.call(as.ctx, accessService, "Check", map[string]any{"token": token, "actor": as.actor(), "action": "read", "placement": placement})
}

// allowed requires an allowed decision whose viewer bases include each of
// bases, a reason, a revision of the organization and an expiry.
func (as *accessSuite) allowed(t *testing.T, token string, placement map[string]any, bases ...string) protoreflect.Message {
	t.Helper()
	out, err := as.ask(token, placement)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	as.isAllowed(t, out, bases...)
	return out
}

func (as *accessSuite) isAllowed(t *testing.T, out protoreflect.Message, bases ...string) {
	t.Helper()
	if enumName(out, "decision") != "DECISION_ALLOWED" {
		t.Fatalf("decided %s (%s), want DECISION_ALLOWED", enumName(out, "decision"), str(out, "reason"))
	}
	held := basesOf(out)
	for _, b := range bases {
		if !slices.Contains(held, b) {
			t.Fatalf("the viewer's bases are %v, want %s among them", held, b)
		}
	}
	if i64(out, "valid_until_unix") <= 0 || str(msg(out, "revision"), "organization_id") == "" || len(field(msg(out, "revision"), "opaque").Bytes()) == 0 {
		t.Fatalf("an allowed decision names when it stops holding and the revision it read: %v", out)
	}
}

// denied requires a decision, never an error, that denies and says why
// without naming a resource.
func (as *accessSuite) denied(t *testing.T, token string, placement map[string]any) protoreflect.Message {
	t.Helper()
	out, err := as.ask(token, placement)
	if err != nil {
		t.Fatalf("Check: %v; a resource the viewer does not hold is a denied decision, not an error", err)
	}
	as.isDenied(t, out, placement)
	return out
}

func (as *accessSuite) isDenied(t *testing.T, out protoreflect.Message, placement map[string]any) {
	t.Helper()
	if enumName(out, "decision") != "DECISION_DENIED" {
		t.Fatalf("decided %s with bases %v, want DECISION_DENIED", enumName(out, "decision"), basesOf(out))
	}
	reason := str(out, "reason")
	if reason == "" {
		t.Fatal("a denied decision carries a reason for the module's audit record")
	}
	names := []string{targetOf(placement)["resource_id"].(string)}
	for _, a := range placement["ancestors"].([]any) {
		names = append(names, a.(map[string]any)["ref"].(map[string]any)["resource_id"].(string))
	}
	for _, name := range names {
		if name != "" && strings.Contains(reason, name) {
			t.Fatalf("reason %q names the resource %q", reason, name)
		}
	}
}

func basesOf(out protoreflect.Message) []string {
	fd := out.Descriptor().Fields().ByName("viewer_bases")
	l := out.Get(fd).List()
	names := make([]string, l.Len())
	for i := range names {
		names[i] = string(fd.Enum().Values().ByNumber(l.Get(i).Enum()).Name())
	}
	return names
}

// subjectsOf are an ACL's subjects, as "person <id>", "team <id>" or
// "installation <id>", each with its version when pinned.
func subjectsOf(out protoreflect.Message) []string {
	var subjects []string
	for _, g := range listMsgs(out, "grants") {
		s, name := msg(g, "subject"), ""
		switch {
		case str(s, "person_id") != "":
			name = "person " + str(s, "person_id")
		case str(s, "team_id") != "":
			name = "team " + str(s, "team_id")
		default:
			name = "installation " + str(s, "installation_id")
		}
		if v := str(msg(g, "resource"), "version"); v != "" {
			name += " @" + v
		}
		subjects = append(subjects, name)
	}
	slices.Sort(subjects)
	return subjects
}

// wait moves the host's clock past d, or waits it out.
func (as *accessSuite) wait(t *testing.T, d time.Duration) {
	t.Helper()
	if as.f.Advance == nil {
		time.Sleep(d)
		return
	}
	if err := as.f.Advance(as.ctx, d); err != nil {
		t.Fatal(err)
	}
}
