package conformance

import (
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// cases are H1 to H24 and F1 to F4. Dana (Author) owns the documents shared, in C1, which
// A's principal owns; Carol (UserHolder) is who they are shared with. Every
// case names resources of its own, so none reads another's grants.
func (as *accessSuite) cases(t *testing.T) {
	f := as.f
	A, B, C := f.A, f.B, f.C
	dana, carol, bob := f.Author, f.UserHolder, f.Member
	person := func(t *testing.T, token string) map[string]any { return as.person(t, token) }
	// People through A hold read and share on documents and no collection.
	seated := func(t *testing.T) {
		t.Helper()
		as.seat(t, A, "user", dana, carol, bob)
		as.seat(t, A, "admin", f.AdminHolder)
	}

	t.Run("H1 a document shared with a person is theirs to read at every version, and its sibling is not", func(t *testing.T) {
		seated(t)
		da, db := as.document(t, "h1-da", "v1", dana), as.document(t, "h1-db", "v1", bob)
		as.denied(t, as.token(t, carol, A), da)
		grant := as.shared(t, as.token(t, dana, A), atVersion(da, ""), person(t, carol))
		if str(grant, "grant_id") == "" || str(grant, "organization_id") != f.Organization || str(grant, "granted_by") != as.personID(t, dana) || i64(grant, "created_at_unix") <= 0 {
			t.Fatalf("the grant answered is %v", grant)
		}
		as.allowed(t, as.token(t, carol, A), da, "BASIS_RESOURCE_GRANT")
		as.allowed(t, as.token(t, carol, A), atVersion(da, "v2"), "BASIS_RESOURCE_GRANT")
		as.denied(t, as.token(t, carol, A), db)
		// Bob owns the sibling and was granted nothing on Dana's document.
		as.denied(t, as.token(t, bob, A), da)
	})
	t.Run("H2 a share pinned to one version reads that version and no other, and nothing when no version is named", func(t *testing.T) {
		seated(t)
		da := as.document(t, "h2-da", "v1", dana)
		as.shared(t, as.token(t, dana, A), da, person(t, carol))
		out := as.allowed(t, as.token(t, carol, A), da, "BASIS_VERSION_GRANT")
		if slices.Contains(basesOf(out), "BASIS_RESOURCE_GRANT") {
			t.Fatalf("a pinned grant answered %v: it must not read as a grant on the whole document", basesOf(out))
		}
		as.denied(t, as.token(t, carol, A), atVersion(da, "v2"))
		as.denied(t, as.token(t, carol, A), atVersion(da, ""))
		// The pinned grant is another grant than the one following versions.
		listed, err := as.acl(as.token(t, dana, A), da)
		if err != nil || !slices.Equal(subjectsOf(listed), []string{"person " + as.personID(t, carol) + " @v1"}) {
			t.Fatalf("the document's grants are %v, %v", subjectsOf(listed), err)
		}
	})
	t.Run("H3 a share to a team is its members' while they belong to it", func(t *testing.T) {
		seated(t)
		as.seat(t, A, "user", f.TeamMember, f.TeamLeaver)
		da := as.document(t, "h3-da", "", dana)
		as.shared(t, as.token(t, dana, A), da, map[string]any{"team_id": f.Team})
		as.allowed(t, as.token(t, f.TeamMember, A), da, "BASIS_RESOURCE_GRANT")
		as.allowed(t, as.token(t, f.TeamLeaver, A), da, "BASIS_RESOURCE_GRANT")
		as.denied(t, as.token(t, carol, A), da)
		before := as.token(t, f.TeamLeaver, A)
		if err := f.RemoveFromTeam(as.ctx, as.personID(t, f.TeamLeaver), f.Team); err != nil {
			t.Fatal(err)
		}
		// What they were issued as a member decides nothing more, and a
		// capability issued since is denied the team's grant.
		if out, err := as.ask(before, da); err == nil && enumName(out, "decision") == "DECISION_ALLOWED" {
			t.Fatal("a capability issued before the member left the team is still allowed by the team's grant")
		}
		as.denied(t, as.token(t, f.TeamLeaver, A), da)
		as.allowed(t, as.token(t, f.TeamMember, A), da, "BASIS_RESOURCE_GRANT")
	})
	t.Run("H4 a grant expiring at T is held before T and not after the clock passes it", func(t *testing.T) {
		seated(t)
		da := as.document(t, "h4-da", "v1", dana)
		// The host's clock, read from the grant it stamps.
		now := i64(as.shared(t, as.token(t, dana, A), da, person(t, carol)), "created_at_unix")
		window := 3 * time.Second
		if f.Advance != nil {
			window = 90 * time.Second
		}
		until := now + int64(window/time.Second)
		refreshed, err := as.share(as.token(t, dana, A), da, person(t, carol), until, "read")
		if err != nil || i64(msg(refreshed, "grant"), "expires_at_unix") != until {
			t.Fatalf("a grant refreshed with an expiry answered %v, %v", refreshed, err)
		}
		out := as.allowed(t, as.token(t, carol, A), da, "BASIS_VERSION_GRANT")
		if got := i64(out, "valid_until_unix"); got > until {
			t.Fatalf("the decision holds until %d, past the grant's expiry %d", got, until)
		}
		_, err = as.share(as.token(t, dana, A), da, person(t, carol), now-1, "read")
		refused(t, err, codes.InvalidArgument, "expires")
		as.wait(t, window+time.Second)
		as.denied(t, as.token(t, carol, A), da)
		_, err = as.unshare(as.token(t, dana, A), da, person(t, carol))
		refused(t, err, codes.NotFound, "nothing was revoked")
	})
	t.Run("H5 a grant on a collection covers what sits under it, and ends when the document moves", func(t *testing.T) {
		seated(t)
		da := as.document(t, "h5-da", "v1", dana)
		c1 := place(as.collection(t, "h5-c1"))
		da = under(da, as.collection(t, "h5-c1"))
		// Dana does not own the collection; its administrator shares it.
		_, err := as.share(as.token(t, dana, A), c1, person(t, carol), 0, "read")
		refused(t, err, codes.PermissionDenied, "")
		as.shared(t, as.token(t, f.AdminHolder, A), c1, person(t, carol))
		out := as.allowed(t, as.token(t, carol, A), da, "BASIS_ANCESTOR_GRANT")
		if slices.Contains(basesOf(out), "BASIS_RESOURCE_GRANT") {
			t.Fatalf("a collection grant answered %v", basesOf(out))
		}
		as.denied(t, as.token(t, carol, A), under(da, as.collection(t, "h5-c2")))
	})
	t.Run("H6 a grant made on the document moves with it", func(t *testing.T) {
		seated(t)
		da := as.document(t, "h6-da", "v1", dana)
		as.shared(t, as.token(t, dana, A), atVersion(da, ""), person(t, carol))
		as.allowed(t, as.token(t, carol, A), da, "BASIS_RESOURCE_GRANT")
		as.allowed(t, as.token(t, carol, A), under(da, as.collection(t, "c2")), "BASIS_RESOURCE_GRANT")
	})
	t.Run("H7 revoking a grant answers the grant, and the next check is denied", func(t *testing.T) {
		seated(t)
		da := as.document(t, "h7-da", "", dana)
		granted := as.shared(t, as.token(t, dana, A), da, person(t, carol))
		as.allowed(t, as.token(t, carol, A), da)
		out, err := as.unshare(as.token(t, dana, A), da, person(t, carol))
		if err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if revoked := msg(out, "revoked"); str(revoked, "grant_id") != str(granted, "grant_id") || str(msg(revoked, "subject"), "person_id") != as.personID(t, carol) {
			t.Fatalf("the revoke answered %v, want the grant it removed", revoked)
		}
		if len(field(msg(out, "revision"), "opaque").Bytes()) == 0 {
			t.Fatal("a revoke answers the revision of the organization's grants after it")
		}
		as.denied(t, as.token(t, carol, A), da)
	})
	t.Run("H8 revoking a grant that never existed, or twice, is NotFound: nothing was revoked", func(t *testing.T) {
		seated(t)
		da := as.document(t, "h8-da", "", dana)
		_, err := as.unshare(as.token(t, dana, A), da, person(t, carol))
		refused(t, err, codes.NotFound, "nothing was revoked")
		as.shared(t, as.token(t, dana, A), da, person(t, carol))
		// The pinned grant is not the one that stands.
		_, err = as.unshare(as.token(t, dana, A), atVersion(da, "v1"), person(t, carol))
		refused(t, err, codes.NotFound, "nothing was revoked")
		if _, err := as.unshare(as.token(t, dana, A), da, person(t, carol)); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		_, err = as.unshare(as.token(t, dana, A), da, person(t, carol))
		refused(t, err, codes.NotFound, "nothing was revoked")
	})
	t.Run("H9 a person who neither owns nor administers revokes nothing, and learns nothing of whether the grant exists", func(t *testing.T) {
		seated(t)
		da := as.document(t, "h9-da", "", dana)
		as.shared(t, as.token(t, dana, A), da, person(t, carol))
		_, existing := as.unshare(as.token(t, bob, A), da, person(t, carol))
		_, absent := as.unshare(as.token(t, bob, A), da, person(t, f.AdminHolder))
		refused(t, existing, codes.PermissionDenied, "")
		refused(t, absent, codes.PermissionDenied, "")
		if status.Convert(existing).Message() != status.Convert(absent).Message() {
			t.Fatalf("revoking an existing grant answers %q, an absent one %q", status.Convert(existing).Message(), status.Convert(absent).Message())
		}
		// The grantee does not revoke their own grant either, nor grant on.
		_, err := as.unshare(as.token(t, carol, A), da, person(t, carol))
		refused(t, err, codes.PermissionDenied, "")
		_, err = as.share(as.token(t, carol, A), da, person(t, bob), 0, "read")
		refused(t, err, codes.PermissionDenied, "")
		as.allowed(t, as.token(t, carol, A), da)
	})
	t.Run("H10 a module acting for a person holds a share only when its own installation is granted too", func(t *testing.T) {
		seated(t)
		as.seat(t, B, "user", carol)
		da := as.document(t, "h10-da", "", dana)
		as.shared(t, as.token(t, dana, A), da, person(t, carol))
		as.allowed(t, as.token(t, carol, A), da)
		out := as.denied(t, as.token(t, carol, B), da)
		// The viewer does hold it; the installation acting does not.
		if !slices.Contains(basesOf(out), "BASIS_RESOURCE_GRANT") {
			t.Fatalf("denied for the actor, the viewer's bases are %v", basesOf(out))
		}
		as.shared(t, as.token(t, dana, A), da, as.installationOf(t, B))
		as.allowed(t, as.token(t, carol, B), da, "BASIS_RESOURCE_GRANT")
		// The installation's grant is not the person's: Bob through B holds none.
		as.seat(t, B, "user", bob)
		as.denied(t, as.token(t, bob, B), da)
	})
	t.Run("H11 a reader through an installed binding reads while the binding is live, and nothing once it is dropped", func(t *testing.T) {
		seated(t)
		as.seat(t, C, "admin", f.AdminHolder)
		da := as.document(t, "h11-da", "", dana)
		as.shared(t, as.token(t, dana, A), da, person(t, f.AdminHolder))
		as.shared(t, as.token(t, dana, A), da, as.installationOf(t, C))
		reader := str(as.must(t)(as.through(t, f.AdminHolder, C, "reader")), "token")
		as.allowed(t, reader, da, "BASIS_RESOURCE_GRANT")
		// C is delivered again without the binding.
		as.deliverSolution(t, C, as.generation, []string{"write"}, false)
		as.generation++
		out, err := as.ask(reader, da)
		if err == nil {
			t.Fatalf("a capability through a dropped binding was decided %s", enumName(out, "decision"))
		}
		if code := status.Code(err); code != codes.PermissionDenied && code != codes.NotFound {
			t.Fatalf("a capability through a dropped binding is refused %v, want PermissionDenied or NotFound", err)
		}
		_, err = as.through(t, f.AdminHolder, C, "reader")
		if err == nil {
			t.Fatal("a capability was issued through a dropped binding")
		}
		t.Run("installed-content read: the owner alone is required", func(t *testing.T) {
			if f.InstalledRead == nil {
				t.Skip("this host declares no class of installed-content read bindings (AccessCase.InstalledRead): every chain is ordinary delegation, and the owner-alone rule is proven by the core's decision table")
			}
			alone := as.document(t, "h11-alone", "", dana)
			as.shared(t, as.token(t, dana, A), alone, person(t, carol))
			installed, err := f.InstalledRead.Issue(as.ctx, carol)
			if err != nil {
				t.Fatal(err)
			}
			as.allowed(t, installed, alone, "BASIS_RESOURCE_GRANT")
			as.denied(t, installed, as.document(t, "h11-other", "", dana))
			if err := f.InstalledRead.Drop(as.ctx); err != nil {
				t.Fatal(err)
			}
			if out, err := as.ask(installed, alone); err == nil && enumName(out, "decision") == "DECISION_ALLOWED" {
				t.Fatal("an installed-content read was allowed after its binding was dropped")
			}
		})
	})
	t.Run("H12 a share to an installation is its agent's, and no sibling installation's", func(t *testing.T) {
		seated(t)
		da := as.document(t, "h12-da", "", dana)
		// A's own agent reads what sits in A's collection by its role.
		as.allowed(t, as.agentToken(t, A), da, "BASIS_ROLE_SCOPE")
		as.denied(t, as.agentToken(t, B), da)
		as.shared(t, as.token(t, dana, A), da, as.installationOf(t, B))
		as.allowed(t, as.agentToken(t, B), da, "BASIS_RESOURCE_GRANT")
		as.denied(t, as.agentToken(t, C), da)
	})
	t.Run("H13 an uninstalled installation's grants never decide again, a reinstall included", func(t *testing.T) {
		seated(t)
		da := as.document(t, "h13-da", "", dana)
		installation := as.installationOf(t, B)
		as.shared(t, as.token(t, dana, A), da, installation)
		before := as.agentToken(t, B)
		as.allowed(t, before, da, "BASIS_RESOURCE_GRANT")
		as.uninstall(t, f.Organization, B, func() {
			if out, err := as.ask(before, da); err == nil {
				t.Fatalf("an uninstalled installation's capability was decided %s", enumName(out, "decision"))
			}
			// Nothing is granted to an installation that is not installed.
			_, err := as.share(as.token(t, dana, A), da, installation, 0, "read")
			refused(t, err, codes.PermissionDenied, "not a member, a team or an active installation")
		})
		// The reinstall kept the installation's id and principal, and none of
		// its predecessor's grants.
		if again := as.installationOf(t, B); again["installation_id"] != installation["installation_id"] {
			t.Skipf("the reinstall is installation %v, not %v: this host gives an incarnation its own id, so the old grants name nothing", again["installation_id"], installation["installation_id"])
		}
		as.denied(t, as.agentToken(t, B), da)
		if out, err := as.ask(before, da); err == nil {
			t.Fatalf("the earlier incarnation's capability was decided %s after the reinstall", enumName(out, "decision"))
		}
		listed, err := as.acl(as.token(t, dana, A), da)
		if err != nil || len(subjectsOf(listed)) != 0 {
			t.Fatalf("after the uninstall the document's grants are %v, %v", subjectsOf(listed), err)
		}
	})
	t.Run("H14 a capability addressed elsewhere is refused by its audience, and a grant on another kind with the same id decides nothing", func(t *testing.T) {
		seated(t)
		da := as.document(t, "h14-same", "", dana)
		// Carol's own capability at A, never hopped to the store.
		elsewhere := str(as.must(t)(as.root(t, carol, A)), "token")
		_, err := as.ask(elsewhere, da)
		refused(t, err, codes.Unauthenticated, "audience")
		_, err = as.share(elsewhere, da, person(t, carol), 0, "read")
		refused(t, err, codes.Unauthenticated, "audience")
		// The same id, as a collection: a grant there is no grant here.
		sameID := place(placed(f.CollectionKind, "h14-same", "", as.principal(t, f.Organization, A)))
		as.shared(t, as.token(t, f.AdminHolder, A), sameID, person(t, carol))
		as.denied(t, as.token(t, carol, A), da)
		listed, err := as.acl(as.token(t, dana, A), da)
		if err != nil || len(subjectsOf(listed)) != 0 {
			t.Fatalf("the document lists the collection's grant: %v, %v", subjectsOf(listed), err)
		}
	})
	t.Run("H15 another organization grants nothing here and holds nothing here; a person who left holds nothing", func(t *testing.T) {
		seated(t)
		da := as.document(t, "h15-da", "", dana)
		as.shared(t, as.token(t, dana, A), da, person(t, carol))
		as.roleAs(t, f.OtherAdmin, "GrantRole", f.OtherOrganization, A, "admin", person(t, f.OtherAdmin))
		foreign := as.token(t, f.OtherAdmin, A)
		// Their own document, granted to a person of this organization: the
		// refusal names their organization and nothing of this one.
		theirs := place(placed(f.Kind, "h15-da", "", as.personID(t, f.OtherAdmin)))
		_, err := as.share(foreign, theirs, person(t, carol), 0, "read")
		refused(t, err, codes.PermissionDenied, f.OtherOrganization)
		_, absent := as.share(foreign, theirs, map[string]any{"person_id": "nobody-at-all"}, 0, "read")
		if status.Convert(err).Message() != status.Convert(absent).Message() {
			t.Fatalf("a person of another organization is refused %q, an absent one %q", status.Convert(err).Message(), status.Convert(absent).Message())
		}
		for _, name := range []string{f.Organization, as.personID(t, carol)} {
			if strings.Contains(status.Convert(err).Message(), name) {
				t.Fatalf("the refusal %q names %q", status.Convert(err).Message(), name)
			}
		}
		// This organization's reference, asked with their capability: their
		// organization holds no grant on it, whatever this one granted.
		as.denied(t, foreign, da)
		listed, err := as.acl(foreign, theirs)
		if err != nil || len(subjectsOf(listed)) != 0 {
			t.Fatalf("another organization lists this one's grants: %v, %v", subjectsOf(listed), err)
		}
		// And a grant they make on the same id is theirs alone.
		as.shared(t, foreign, theirs, person(t, f.OtherMember))
		here, err := as.acl(as.token(t, dana, A), da)
		if err != nil || !slices.Equal(subjectsOf(here), []string{"person " + as.personID(t, carol)}) {
			t.Fatalf("this organization's grants on the reference are %v, %v", subjectsOf(here), err)
		}
		// Rex is granted, then leaves the organization.
		as.seat(t, A, "user", f.OrgLeaver)
		as.shared(t, as.token(t, dana, A), da, person(t, f.OrgLeaver))
		rex := as.token(t, f.OrgLeaver, A)
		as.allowed(t, rex, da)
		if err := f.RemoveFromOrganization(as.ctx, as.personID(t, f.OrgLeaver)); err != nil {
			t.Fatal(err)
		}
		out, err := as.ask(rex, da)
		if err == nil {
			t.Fatalf("a person who left the organization was decided %s", enumName(out, "decision"))
		}
		refused(t, err, codes.PermissionDenied, "")
	})
	t.Run("H16 a share never lifts the ceiling: without read on the kind the capability is refused, naming kind and action", func(t *testing.T) {
		seated(t)
		// C's user role holds write on documents and no read.
		as.seat(t, C, "user", f.Reader)
		da := as.document(t, "h16-da", "", dana)
		as.shared(t, as.token(t, dana, A), da, person(t, f.Reader))
		as.shared(t, as.token(t, dana, A), da, as.installationOf(t, C))
		_, err := as.ask(as.token(t, f.Reader, C), da)
		refused(t, err, codes.PermissionDenied, f.Kind+":read")
		if strings.Contains(status.Convert(err).Message(), "h16-da") {
			t.Fatalf("the ceiling's refusal %q names the resource", status.Convert(err).Message())
		}
		// Nor does anyone grant an action they do not hold, or one no grant gives.
		_, err = as.share(as.token(t, f.Reader, C), place(placed(f.Kind, "h16-own", "", as.personID(t, f.Reader))), person(t, carol), 0, "read")
		refused(t, err, codes.PermissionDenied, "")
		_, err = as.share(as.token(t, dana, A), da, person(t, carol), 0, "write")
		refused(t, err, codes.PermissionDenied, f.Kind+":write")
		_, err = as.share(as.token(t, f.AdminHolder, A), da, person(t, carol), 0, "admin")
		refused(t, err, codes.InvalidArgument, "")
	})
	t.Run("H17 a derived document is shared by itself: its share needs no source, and its source's share does not cover it", func(t *testing.T) {
		seated(t)
		source, derived := as.document(t, "h17-da", "", dana), as.document(t, "h17-e", "", dana)
		as.shared(t, as.token(t, dana, A), derived, person(t, carol))
		as.allowed(t, as.token(t, carol, A), derived, "BASIS_RESOURCE_GRANT")
		as.denied(t, as.token(t, carol, A), source)
		as.shared(t, as.token(t, dana, A), source, person(t, bob))
		as.allowed(t, as.token(t, bob, A), source, "BASIS_RESOURCE_GRANT")
		as.denied(t, as.token(t, bob, A), derived)
	})
	t.Run("H18 a batch answers as the point checks do, in order, and an unknown id is denied, not an error", func(t *testing.T) {
		seated(t)
		da, db := as.document(t, "h18-da", "v1", dana), as.document(t, "h18-db", "v1", bob)
		as.shared(t, as.token(t, dana, A), da, person(t, carol))
		placements := []map[string]any{da, atVersion(da, "v2"), db, as.document(t, "h18-nobody-made-this", "", dana)}
		list := make([]any, len(placements))
		for i, p := range placements {
			list[i] = p
		}
		token := as.token(t, carol, A)
		batch, err := as.c.call(as.ctx, accessService, "CheckBatch", map[string]any{"token": token, "actor": as.actor(), "action": "read", "placements": list})
		if err != nil {
			t.Fatalf("CheckBatch: %v", err)
		}
		results := listMsgs(batch, "results")
		if len(results) != len(placements) {
			t.Fatalf("the batch answered %d results for %d placements", len(results), len(placements))
		}
		want := []string{"DECISION_ALLOWED", "DECISION_DENIED", "DECISION_DENIED", "DECISION_DENIED"}
		for i, p := range placements {
			point, err := as.ask(token, p)
			if err != nil {
				t.Fatalf("Check %d: %v", i, err)
			}
			if got := enumName(results[i], "decision"); got != want[i] || got != enumName(point, "decision") || !slices.Equal(basesOf(results[i]), basesOf(point)) {
				t.Fatalf("placement %d: the batch decided %s %v, the point check %s %v, want %s", i, got, basesOf(results[i]), enumName(point, "decision"), basesOf(point), want[i])
			}
		}
		if len(field(msg(batch, "revision"), "opaque").Bytes()) == 0 {
			t.Fatal("a batch answers the one revision every decision read")
		}
		_, err = as.c.call(as.ctx, accessService, "CheckBatch", map[string]any{"token": token, "actor": as.actor(), "action": "read", "placements": []any{}})
		refused(t, err, codes.InvalidArgument, "")
		over := make([]any, 1001)
		for i := range over {
			over[i] = da
		}
		_, err = as.c.call(as.ctx, accessService, "CheckBatch", map[string]any{"token": token, "actor": as.actor(), "action": "read", "placements": over})
		refused(t, err, codes.InvalidArgument, "1000")
	})
	t.Run("H19 a viewer's grants are paged in order, and a page from before a revoke is refused stale", func(t *testing.T) {
		seated(t)
		// Tom's grants are this case's alone.
		viewer := f.TeamMember
		as.seat(t, A, "user", viewer)
		ids := []string{"h19-a", "h19-b", "h19-c"}
		for _, id := range ids {
			as.shared(t, as.token(t, dana, A), as.document(t, id, "", dana), person(t, viewer))
		}
		as.shared(t, as.token(t, dana, A), as.document(t, "h19-a", "v1", dana), person(t, viewer))
		as.shared(t, as.token(t, dana, A), as.document(t, "h19-other-person", "", dana), person(t, bob))
		page := func(token string) (protoreflect.Message, error) {
			return as.c.call(as.ctx, accessService, "ListViewerGrants", map[string]any{"token": as.token(t, viewer, A), "actor": as.actor(),
				"resource_kinds": []any{f.Kind}, "action": "read", "page_size": int32(2), "page_token": token})
		}
		names := func(out protoreflect.Message) []string {
			var got []string
			for _, r := range listMsgs(out, "resources") {
				if str(r, "resource_kind") != f.Kind {
					t.Fatalf("listed a resource of kind %s", str(r, "resource_kind"))
				}
				got = append(got, strings.TrimSuffix(str(r, "resource_id")+"@"+str(r, "version"), "@"))
			}
			return got
		}
		all := func() []string {
			var got []string
			token := ""
			for {
				out, err := page(token)
				if err != nil {
					t.Fatalf("ListViewerGrants: %v", err)
				}
				got = append(got, names(out)...)
				if token = str(out, "next_page_token"); token == "" {
					return got
				}
			}
		}
		mine := func(listed []string) []string {
			return slices.DeleteFunc(listed, func(name string) bool { return !strings.HasPrefix(name, "h19-") })
		}
		if got, want := mine(all()), []string{"h19-a", "h19-a@v1", "h19-b", "h19-c"}; !slices.Equal(got, want) {
			t.Fatalf("the viewer's grants are %v, want %v in order", got, want)
		}
		first, err := page("")
		if err != nil || str(first, "next_page_token") == "" || len(names(first)) != 2 {
			t.Fatalf("the first page is %v, %v", first, err)
		}
		if _, err := as.unshare(as.token(t, dana, A), as.document(t, "h19-c", "", dana), person(t, viewer)); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		_, err = page(str(first, "next_page_token"))
		refused(t, err, codes.Aborted, "stale_revision")
		if got, want := mine(all()), []string{"h19-a", "h19-a@v1", "h19-b"}; !slices.Equal(got, want) {
			t.Fatalf("after the restart the viewer's grants are %v, want %v", got, want)
		}
		_, err = page("not-a-token")
		refused(t, err, codes.InvalidArgument, "")
	})
	t.Run("H20 the grants on a document are listed for its owner and its collection's administrator, and nobody else", func(t *testing.T) {
		seated(t)
		as.seat(t, A, "user", f.TeamMember)
		da := as.document(t, "h20-da", "", dana)
		as.shared(t, as.token(t, dana, A), da, person(t, carol))
		as.shared(t, as.token(t, dana, A), da, map[string]any{"team_id": f.Team})
		as.shared(t, as.token(t, dana, A), atVersion(da, "v3"), as.installationOf(t, B))
		want := []string{"installation " + as.installationOf(t, B)["installation_id"].(string) + " @v3", "person " + as.personID(t, carol), "team " + f.Team}
		for name, token := range map[string]string{"the owner": as.token(t, dana, A), "the collection's administrator": as.token(t, f.AdminHolder, A)} {
			listed, err := as.acl(token, da)
			if err != nil || !slices.Equal(subjectsOf(listed), want) {
				t.Fatalf("%s lists %v, %v; want %v", name, subjectsOf(listed), err, want)
			}
		}
		_, grantee := as.acl(as.token(t, carol, A), da)
		_, stranger := as.acl(as.token(t, bob, A), da)
		refused(t, grantee, codes.PermissionDenied, "")
		refused(t, stranger, codes.PermissionDenied, "")
		_, nothing := as.acl(as.token(t, bob, A), as.document(t, "h20-ungranted", "", dana))
		if status.Convert(stranger).Message() != status.Convert(nothing).Message() {
			t.Fatalf("a stranger is refused %q on a granted document and %q on an ungranted one", status.Convert(stranger).Message(), status.Convert(nothing).Message())
		}
	})
	t.Run("H23 a share that gives share is shared on by its grantee: only what it gives, on the reference it is on, for no longer than it lasts", func(t *testing.T) {
		seated(t)
		as.seat(t, A, "user", f.TeamMember)
		tom := f.TeamMember
		da := as.document(t, "h23-da", "", dana)
		// Read alone shares nothing on (H9); read and share does.
		if _, err := as.share(as.token(t, dana, A), da, person(t, carol), 0, "read", "share"); err != nil {
			t.Fatalf("Grant: %v", err)
		}
		on, err := as.share(as.token(t, carol, A), da, person(t, bob), 0, "read")
		if err != nil {
			t.Fatalf("a grantee holding share shares read on: %v", err)
		}
		if by := str(msg(on, "grant"), "granted_by"); by != as.personID(t, carol) {
			t.Fatalf("the share made on is granted by %q, want its grantor", by)
		}
		as.allowed(t, as.token(t, bob, A), da, "BASIS_RESOURCE_GRANT")
		// Delete is no action a grant gives, whoever grants.
		_, err = as.share(as.token(t, carol, A), da, person(t, tom), 0, "delete")
		refused(t, err, codes.InvalidArgument, "")
		_, err = as.share(as.token(t, dana, A), da, person(t, tom), 0, "delete")
		refused(t, err, codes.InvalidArgument, "")
		// Another document is not hers to share, and she never lists the grants.
		_, err = as.share(as.token(t, carol, A), as.document(t, "h23-db", "", dana), person(t, bob), 0, "read")
		refused(t, err, codes.PermissionDenied, "")
		_, err = as.acl(as.token(t, carol, A), da)
		refused(t, err, codes.PermissionDenied, "")
		// She ends the share she made. The owner's is nothing of hers to
		// revoke, answered as an absent one is.
		as.shared(t, as.token(t, dana, A), da, person(t, tom))
		_, owners := as.unshare(as.token(t, carol, A), da, person(t, tom))
		_, absent := as.unshare(as.token(t, carol, A), da, person(t, f.AdminHolder))
		refused(t, owners, codes.NotFound, "nothing was revoked")
		if status.Convert(owners).Message() != status.Convert(absent).Message() || status.Code(absent) != codes.NotFound {
			t.Fatalf("revoking the owner's grant answers %v, an absent one %v", owners, absent)
		}
		as.allowed(t, as.token(t, tom, A), da)
		if _, err := as.unshare(as.token(t, carol, A), da, person(t, bob)); err != nil {
			t.Fatalf("a grantee revokes the share they made: %v", err)
		}
		as.denied(t, as.token(t, bob, A), da)
		// A share that expires is shared on for no longer than it lasts.
		now := i64(msg(on, "grant"), "created_at_unix")
		if _, err := as.share(as.token(t, dana, A), da, person(t, carol), now+3600, "read", "share"); err != nil {
			t.Fatalf("Grant: %v", err)
		}
		_, err = as.share(as.token(t, carol, A), da, person(t, bob), 0, "read")
		refused(t, err, codes.PermissionDenied, "")
		_, err = as.share(as.token(t, carol, A), da, person(t, bob), now+7200, "read")
		refused(t, err, codes.PermissionDenied, "")
		if _, err := as.share(as.token(t, carol, A), da, person(t, bob), now+1800, "read"); err != nil {
			t.Fatalf("a share made on within the share it rests on: %v", err)
		}
		// Once her share is revoked she shares nothing on.
		if _, err := as.unshare(as.token(t, dana, A), da, person(t, carol)); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		_, err = as.share(as.token(t, carol, A), da, person(t, tom), 0, "read")
		refused(t, err, codes.PermissionDenied, "")
		// A share pinned to a version shares that version on, never the document.
		v1 := atVersion(da, "v1")
		if _, err := as.share(as.token(t, dana, A), v1, person(t, carol), 0, "read", "share"); err != nil {
			t.Fatalf("Grant: %v", err)
		}
		_, err = as.share(as.token(t, carol, A), da, person(t, f.AdminHolder), 0, "read")
		refused(t, err, codes.PermissionDenied, "")
		_, err = as.share(as.token(t, carol, A), atVersion(da, "v2"), person(t, f.AdminHolder), 0, "read")
		refused(t, err, codes.PermissionDenied, "")
		if _, err := as.share(as.token(t, carol, A), v1, person(t, f.AdminHolder), 0, "read"); err != nil {
			t.Fatalf("a pinned share shares its version on: %v", err)
		}
	})
	t.Run("H24 a share made on never outlives the share it was made from: revoked or narrowed, every share below it stops deciding, and restoring it revives none", func(t *testing.T) {
		seated(t)
		tom := f.TeamMember
		as.seat(t, A, "user", tom)
		da := as.document(t, "h24-da", "", dana)
		share := func(by, to string, actions ...string) {
			t.Helper()
			if _, err := as.share(as.token(t, by, A), da, person(t, to), 0, actions...); err != nil {
				t.Fatalf("Grant: %v", err)
			}
		}
		acl := func() []string {
			t.Helper()
			listed, err := as.acl(as.token(t, dana, A), da)
			if err != nil {
				t.Fatalf("ListGrants: %v", err)
			}
			return subjectsOf(listed)
		}
		// below is that neither Bob nor Tom holds the document, by a check,
		// as a viewer or in the ACL.
		below := func(why string) {
			t.Helper()
			as.denied(t, as.token(t, bob, A), da)
			as.denied(t, as.token(t, tom, A), da)
			if as.viewerHolds(t, as.token(t, bob, A), "h24-da") || as.viewerHolds(t, as.token(t, tom, A), "h24-da") {
				t.Fatalf("%s: a share made on is still listed among its grantee's", why)
			}
			if got := acl(); slices.Contains(got, "person "+as.personID(t, bob)) || slices.Contains(got, "person "+as.personID(t, tom)) {
				t.Fatalf("%s: the document still lists %v", why, got)
			}
		}
		// Dana shares with Carol, who shares on to Bob, who shares on to Tom.
		share(dana, carol, "read", "share")
		share(carol, bob, "read", "share")
		share(bob, tom, "read")
		as.allowed(t, as.token(t, bob, A), da, "BASIS_RESOURCE_GRANT")
		as.allowed(t, as.token(t, tom, A), da, "BASIS_RESOURCE_GRANT")
		if !as.viewerHolds(t, as.token(t, tom, A), "h24-da") || len(acl()) != 3 {
			t.Fatalf("the chain stands, and the document lists %v", acl())
		}
		if _, err := as.unshare(as.token(t, dana, A), da, person(t, carol)); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		below("Carol's share revoked")
		// What stopped standing is nothing to revoke, and shares nothing on.
		_, err := as.unshare(as.token(t, dana, A), da, person(t, bob))
		refused(t, err, codes.NotFound, "nothing was revoked")
		_, err = as.share(as.token(t, bob, A), da, person(t, tom), 0, "read")
		refused(t, err, codes.PermissionDenied, "")
		// Restored, Carol's share is another grant: nothing that rested on
		// the one revoked comes back until its grantor makes it again.
		share(dana, carol, "read", "share")
		as.allowed(t, as.token(t, carol, A), da)
		below("Carol's share restored")
		share(carol, bob, "read", "share")
		as.allowed(t, as.token(t, bob, A), da)
		as.denied(t, as.token(t, tom, A), da)
		share(bob, tom, "read")
		as.allowed(t, as.token(t, tom, A), da)
		// Narrowed below share, Carol's grant still reads and gives nothing on.
		share(dana, carol, "read")
		as.allowed(t, as.token(t, carol, A), da)
		below("Carol's share narrowed to read")
		// A grantee changes the grants they made and no other.
		share(dana, carol, "read", "share")
		share(dana, f.AdminHolder, "read")
		_, err = as.share(as.token(t, carol, A), da, person(t, f.AdminHolder), 0, "read")
		refused(t, err, codes.PermissionDenied, "")
	})
	t.Run("F1 forgetting a reference ends the grants on exactly it: the next check is denied and the others stand", func(t *testing.T) {
		seated(t)
		da := as.document(t, "f1-da", "", dana)
		v1 := atVersion(da, "v1")
		as.shared(t, as.token(t, dana, A), da, person(t, carol))
		as.shared(t, as.token(t, dana, A), v1, person(t, bob))
		out, err := as.forget(as.token(t, dana, A), targetOf(v1), false)
		if err != nil || i64(out, "forgotten") != 1 || len(field(msg(out, "revision"), "opaque").Bytes()) == 0 {
			t.Fatalf("Forget answered %v, %v; want the one grant on the version and a revision", out, err)
		}
		as.denied(t, as.token(t, bob, A), v1)
		as.allowed(t, as.token(t, carol, A), da)
		out, err = as.forget(as.token(t, dana, A), targetOf(da), false)
		if err != nil || i64(out, "forgotten") != 1 {
			t.Fatalf("Forget answered %v, %v; want the one grant following versions", out, err)
		}
		as.denied(t, as.token(t, carol, A), da)
		if listed, err := as.acl(as.token(t, dana, A), da); err != nil || len(subjectsOf(listed)) != 0 {
			t.Fatalf("a forgotten document still lists %v, %v", subjectsOf(listed), err)
		}
	})
	t.Run("F2 forgetting every version ends every grant on the resource, and no other resource's", func(t *testing.T) {
		seated(t)
		da, db := as.document(t, "f2-da", "", dana), as.document(t, "f2-db", "", dana)
		as.shared(t, as.token(t, dana, A), da, person(t, carol))
		as.shared(t, as.token(t, dana, A), atVersion(da, "v1"), person(t, bob))
		as.shared(t, as.token(t, dana, A), atVersion(da, "v2"), map[string]any{"team_id": f.Team})
		as.shared(t, as.token(t, dana, A), db, person(t, carol))
		out, err := as.forget(as.token(t, dana, A), targetOf(da), true)
		if err != nil || i64(out, "forgotten") != 3 {
			t.Fatalf("Forget answered %v, %v; want the three grants on the document", out, err)
		}
		as.denied(t, as.token(t, carol, A), da)
		as.denied(t, as.token(t, bob, A), atVersion(da, "v1"))
		as.allowed(t, as.token(t, carol, A), db)
		if as.viewerHolds(t, as.token(t, carol, A), "f2-da") || !as.viewerHolds(t, as.token(t, carol, A), "f2-db") {
			t.Fatal("a viewer's grants still list a forgotten document, or lost its sibling")
		}
		// Every version is named by naming none.
		_, err = as.forget(as.token(t, dana, A), targetOf(atVersion(da, "v1")), true)
		refused(t, err, codes.InvalidArgument, "")
	})
	t.Run("F3 forgetting twice, or what was never granted, is nothing and no error", func(t *testing.T) {
		seated(t)
		da := as.document(t, "f3-da", "", dana)
		as.shared(t, as.token(t, dana, A), da, person(t, carol))
		for i, want := range []int64{1, 0, 0} {
			out, err := as.forget(as.token(t, dana, A), targetOf(da), true)
			if err != nil || i64(out, "forgotten") != want {
				t.Fatalf("forget %d answered %v, %v; want %d forgotten and no error", i+1, out, err, want)
			}
		}
		out, err := as.forget(as.token(t, dana, A), ref(f.Kind, "f3-never-granted", ""), true)
		if err != nil || i64(out, "forgotten") != 0 {
			t.Fatalf("forgetting what was never granted answered %v, %v", out, err)
		}
	})
	t.Run("F4 only the kind's serving module forgets, and needs nothing of the resource to do it", func(t *testing.T) {
		seated(t)
		da := as.document(t, "f4-da", "", dana)
		as.shared(t, as.token(t, dana, A), da, person(t, carol))
		_, err := as.c.call(as.ctx, accessService, "Forget", map[string]any{"token": as.token(t, dana, A), "actor": map[string]any{"credential": A.Credential}, "target": targetOf(da), "every_version": true})
		refused(t, err, codes.PermissionDenied, "does not serve")
		if _, err := as.c.call(as.ctx, accessService, "Forget", map[string]any{"token": as.token(t, dana, A), "actor": map[string]any{"credential": "not-a-credential"}, "target": targetOf(da), "every_version": true}); err == nil {
			t.Fatal("a forget with no workload credential was answered")
		}
		_, err = as.forget(as.token(t, dana, A), ref(A.Solution+".note", "f4-note", ""), true)
		refused(t, err, codes.PermissionDenied, "does not serve")
		_, err = as.forget(as.token(t, dana, A), ref(f.Kind, "*", ""), true)
		refused(t, err, codes.InvalidArgument, "")
		as.allowed(t, as.token(t, carol, A), da)
		// The module asks for itself: the Work Context names the organization,
		// and a person who neither owns nor was granted the document carries it.
		out, err := as.forget(as.token(t, bob, A), targetOf(da), true)
		if err != nil || i64(out, "forgotten") != 1 {
			t.Fatalf("Forget answered %v, %v", out, err)
		}
		as.denied(t, as.token(t, carol, A), da)
	})
	t.Run("H21 a revision precondition is served or refused, never ignored", func(t *testing.T) {
		seated(t)
		da := as.document(t, "h21-da", "", dana)
		granted, err := as.share(as.token(t, dana, A), da, person(t, carol), 0, "read")
		if err != nil {
			t.Fatal(err)
		}
		min := revisionOf(t, granted)
		token := as.token(t, carol, A)
		asks := map[string]map[string]any{
			"Check":                   {"action": "read", "placement": da, "min_revision": min},
			"Check at the head":       {"action": "read", "placement": da, "freshness": "FRESHNESS_HEAD"},
			"CheckBatch":              {"action": "read", "placements": []any{da}, "min_revision": min},
			"CheckBatch by placement": {"action": "read", "placements": []any{da}, "item_min_revisions": []any{min}},
			"CheckBatch at the head":  {"action": "read", "placements": []any{da}, "freshness": "FRESHNESS_HEAD"},
			"ListViewerGrants":        {"action": "read", "resource_kinds": []any{f.Kind}, "min_revision": min},
		}
		for name, fields := range asks {
			request := clone(fields)
			request["token"], request["actor"] = token, as.actor()
			out, err := as.c.call(as.ctx, accessService, strings.Fields(name)[0], request)
			if !f.MinRevision {
				// A host that serves no minimum says so: it never answers as
				// though none had been asked.
				refused(t, err, codes.FailedPrecondition, "")
				continue
			}
			if err != nil {
				t.Fatalf("%s: %v; a host that serves minimums answers one it just issued", name, err)
			}
			if len(field(msg(out, "revision"), "opaque").Bytes()) == 0 {
				t.Fatalf("%s: the answer names no revision: %v", name, out)
			}
		}
		// Unset, the same question is answered.
		as.allowed(t, token, da)
	})
	t.Run("H22 only the kind's serving module asks, and no request can name who is asking", func(t *testing.T) {
		seated(t)
		da := as.document(t, "h22-da", "", dana)
		as.shared(t, as.token(t, dana, A), da, person(t, carol))
		token := as.token(t, carol, A)
		other := map[string]any{"credential": A.Credential}
		for method, fields := range map[string]map[string]any{
			"Check":            {"action": "read", "placement": da},
			"CheckBatch":       {"action": "read", "placements": []any{da}},
			"ListViewerGrants": {"action": "read", "resource_kinds": []any{f.Kind}},
			"ListGrants":       {"target": targetOf(da), "placement": da},
			"Grant":            {"target": targetOf(da), "placement": da, "subject": person(t, bob), "actions": []any{"read"}},
			"Revoke":           {"target": targetOf(da), "placement": da, "subject": person(t, carol)},
		} {
			t.Run(method, func(t *testing.T) {
				asked := clone(fields)
				asked["token"], asked["actor"] = token, other
				_, err := as.c.call(as.ctx, accessService, method, asked)
				refused(t, err, codes.PermissionDenied, "does not serve")
				asked["actor"] = map[string]any{"credential": "not-a-credential"}
				if _, err := as.c.call(as.ctx, accessService, method, asked); err == nil {
					t.Fatal("a request with no workload credential was answered")
				}
			})
		}
		// A kind the module does not serve is not its question to ask.
		_, err := as.ask(token, place(placed(A.Solution+".note", "h22-note", "", "")))
		refused(t, err, codes.PermissionDenied, "does not serve")
		for _, malformed := range []map[string]any{
			place(placed(f.Kind, "*", "", "")),
			place(placed(f.Kind, strings.Repeat("x", 129), "", "")),
			place(placed("", "h22-da", "", "")),
			place(placed(f.Kind, "h22-da", "", ""), as.collection(t, "c1"), as.collection(t, "c1")),
			place(placed(f.Kind, "h22-da", "", ""), func() []map[string]any {
				var nine []map[string]any
				for _, id := range []string{"1", "2", "3", "4", "5", "6", "7", "8", "9"} {
					nine = append(nine, as.collection(t, "h22-c"+id))
				}
				return nine
			}()...),
		} {
			_, err := as.ask(token, malformed)
			refused(t, err, codes.InvalidArgument, "")
		}
		// The descriptors: a decision is asked with exactly these fields, and
		// no request of the service carries one that could name the viewer.
		for message, want := range accessDecisionRequests {
			d, err := as.c.files.FindDescriptorByName(protoreflect.FullName(message))
			if err != nil {
				t.Fatal(err)
			}
			fields := d.(protoreflect.MessageDescriptor).Fields()
			var got []string
			for i := range fields.Len() {
				got = append(got, string(fields.Get(i).Name()))
			}
			for _, name := range got {
				// Fields a later revision of the contract adds are admitted
				// when they name nobody; the M1 fields must all be there.
				for _, never := range accessNeverNamed {
					if strings.Contains(name, never) && !slices.Contains(want, name) {
						t.Fatalf("%s carries %s: nothing in a request names who is asking", message, name)
					}
				}
			}
			for _, name := range want {
				if !slices.Contains(got, name) {
					t.Fatalf("%s lacks %s", message, name)
				}
			}
		}
	})
}
