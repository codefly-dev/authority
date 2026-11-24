package conformance

import (
	"bytes"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// RunAccessRevisions proves a host that serves revision minimums
// (AccessCase.MinRevision) serves them as every host does: a revision is
// returned by every change and every answer, an answer asked with a minimum is
// never computed at an earlier state, even while the host's reader is behind
// (AccessCase.Lag), and a revision the host never issued for the organization
// is refused. The suite treats a revision as the module does: bytes it stores
// and returns, compared only for equality. A host runs it on a fixture of its
// own, as it runs RunAccess.
//
// The cases keep the numbers of the design they come from. Not here, because
// the suite has no hook for them: R6 (the store holding the newest state does
// not answer) and R12 (a sequence past the newest state), which the shared
// core proves over its own stores, and R14 (interleaved readers), which it
// proves under the race detector.
func RunAccessRevisions(t *testing.T, conn grpc.ClientConnInterface, descriptors []byte, f AccessCase) {
	t.Helper()
	if !f.MinRevision {
		t.Fatal("RunAccessRevisions is for a host that serves revision minimums: AccessCase.MinRevision")
	}
	as := newAccessSuite(t, conn, descriptors, f)
	A := f.A
	dana, carol := f.Author, f.UserHolder
	person := func(t *testing.T, token string) map[string]any { return as.person(t, token) }
	seated := func(t *testing.T) {
		t.Helper()
		as.seat(t, A, "user", dana, carol)
	}
	// lag freezes the host's reader, or skips the case on a host without one.
	lag := func(t *testing.T) {
		t.Helper()
		if f.Lag == nil {
			t.Skip("this host has no reader to hold behind its store (AccessCase.Lag is nil)")
		}
		t.Cleanup(f.Lag(t))
	}
	check := func(t *testing.T, token string, placement map[string]any, fields map[string]any) protoreflect.Message {
		t.Helper()
		request := map[string]any{"token": token, "actor": as.actor(), "action": "read", "placement": placement}
		for k, v := range fields {
			request[k] = v
		}
		out, err := as.c.call(as.ctx, accessService, "Check", request)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		return out
	}
	// head is the publisher's question: the newest state, whose revision it records.
	head := func(t *testing.T, placement map[string]any) map[string]any {
		t.Helper()
		return revisionOf(t, check(t, as.token(t, dana, A), placement, map[string]any{"freshness": "FRESHNESS_HEAD"}))
	}
	revoke := func(t *testing.T, placement, subject map[string]any) map[string]any {
		t.Helper()
		out, err := as.unshare(as.token(t, dana, A), placement, subject)
		if err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		return revisionOf(t, out)
	}
	grant := func(t *testing.T, placement, subject map[string]any) map[string]any {
		t.Helper()
		out, err := as.share(as.token(t, dana, A), placement, subject, 0, "read")
		if err != nil {
			t.Fatalf("Grant: %v", err)
		}
		return revisionOf(t, out)
	}

	t.Run("R1 every change answers a revision of the organization, another than the one before it", func(t *testing.T) {
		seated(t)
		da := as.document(t, "r1-da", "", dana)
		granted := grant(t, da, person(t, carol))
		revoked := revoke(t, da, person(t, carol))
		again := grant(t, da, person(t, carol))
		seen := [][]byte{}
		for _, r := range []map[string]any{granted, revoked, again} {
			if r["organization_id"] != f.Organization {
				t.Fatalf("a change of %s answered a revision of %v", f.Organization, r["organization_id"])
			}
			if slices.ContainsFunc(seen, func(b []byte) bool { return bytes.Equal(b, r["opaque"].([]byte)) }) {
				t.Fatal("two changes answered one revision")
			}
			seen = append(seen, r["opaque"].([]byte))
		}
	})
	t.Run("R2 a decision asked with a revision just returned is answered, and names the revision it was computed at", func(t *testing.T) {
		seated(t)
		da := as.document(t, "r2-da", "", dana)
		granted := grant(t, da, person(t, carol))
		out := check(t, as.token(t, carol, A), da, map[string]any{"min_revision": granted})
		as.isAllowed(t, out, "BASIS_RESOURCE_GRANT")
		// The revision answered is itself a minimum the host serves.
		as.isAllowed(t, check(t, as.token(t, carol, A), da, map[string]any{"min_revision": revisionOf(t, out)}))
	})
	t.Run("R3 a decision asked at a revoke's revision is denied", func(t *testing.T) {
		seated(t)
		da := as.document(t, "r3-da", "", dana)
		grant(t, da, person(t, carol))
		revoked := revoke(t, da, person(t, carol))
		as.isDenied(t, check(t, as.token(t, carol, A), da, map[string]any{"min_revision": revoked}), da)
	})
	t.Run("R4 behind a revoke and asked no minimum, a host may still allow, and then names an earlier revision than the revoke's", func(t *testing.T) {
		seated(t)
		da := as.document(t, "r4-da", "", dana)
		grant(t, da, person(t, carol))
		lag(t)
		revoked := revoke(t, da, person(t, carol))
		out := check(t, as.token(t, carol, A), da, nil)
		if enumName(out, "decision") == "DECISION_ALLOWED" && bytes.Equal(revisionOf(t, out)["opaque"].([]byte), revoked["opaque"].([]byte)) {
			t.Fatal("a decision that names the revoke's own revision allowed what it revoked")
		}
	})
	t.Run("R5 a reader revoked before a publication is denied at the publisher's revision, while the host's reader is still behind", func(t *testing.T) {
		seated(t)
		da := as.document(t, "r5-da", "", dana)
		grant(t, da, person(t, carol))
		lag(t)
		revoke(t, da, person(t, carol))
		published := head(t, da)
		as.isDenied(t, check(t, as.token(t, carol, A), da, map[string]any{"min_revision": published}), da)
		as.isDenied(t, check(t, as.token(t, carol, A), da, map[string]any{"freshness": "FRESHNESS_HEAD"}), da)
	})
	t.Run("R7 a member who left the team before a publication is denied the team's grant at the publisher's revision", func(t *testing.T) {
		seated(t)
		as.seat(t, A, "user", f.TeamMember, f.TeamLeaver)
		da := as.document(t, "r7-da", "", dana)
		grant(t, da, map[string]any{"team_id": f.Team})
		as.isAllowed(t, check(t, as.token(t, f.TeamLeaver, A), da, nil))
		lag(t)
		if err := f.RemoveFromTeam(as.ctx, as.personID(t, f.TeamLeaver), f.Team); err != nil {
			t.Fatal(err)
		}
		published := head(t, da)
		as.isDenied(t, check(t, as.token(t, f.TeamLeaver, A), da, map[string]any{"min_revision": published}), da)
		as.isAllowed(t, check(t, as.token(t, f.TeamMember, A), da, map[string]any{"min_revision": published}))
	})
	t.Run("R8 a batch with a minimum per placement is one state at or past the latest, answering as the point checks do", func(t *testing.T) {
		seated(t)
		da, db := as.document(t, "r8-da", "", dana), as.document(t, "r8-db", "", dana)
		early := grant(t, da, person(t, carol))
		grant(t, db, person(t, carol))
		if f.Lag != nil {
			t.Cleanup(f.Lag(t))
		}
		late := revoke(t, db, person(t, carol))
		token := as.token(t, carol, A)
		out, err := as.c.call(as.ctx, accessService, "CheckBatch", map[string]any{"token": token, "actor": as.actor(), "action": "read",
			"placements": []any{da, db}, "item_min_revisions": []any{early, late}})
		if err != nil {
			t.Fatalf("CheckBatch: %v", err)
		}
		results := listMsgs(out, "results")
		if len(results) != 2 {
			t.Fatalf("a batch of 2 answered %d decisions", len(results))
		}
		as.isAllowed(t, results[0], "BASIS_RESOURCE_GRANT")
		as.isDenied(t, results[1], db)
		batch := revisionOf(t, out)["opaque"].([]byte)
		for i, r := range results {
			if !bytes.Equal(revisionOf(t, r)["opaque"].([]byte), batch) {
				t.Fatalf("decision %d names another revision than its batch: a batch is one state", i)
			}
		}
		// A minimum for some placements and not all is no request.
		_, err = as.c.call(as.ctx, accessService, "CheckBatch", map[string]any{"token": token, "actor": as.actor(), "action": "read",
			"placements": []any{da, db}, "item_min_revisions": []any{late}})
		refused(t, err, codes.InvalidArgument, "")
	})
	t.Run("R9 a viewer's grants asked at a revoke's revision leave the revoked reference out, while the host's reader is still behind", func(t *testing.T) {
		seated(t)
		viewer := f.TeamMember
		as.seat(t, A, "user", viewer)
		kept, gone := as.document(t, "r9-kept", "", dana), as.document(t, "r9-gone", "", dana)
		grant(t, kept, person(t, viewer))
		grant(t, gone, person(t, viewer))
		lag(t)
		revoked := revoke(t, gone, person(t, viewer))
		var listed []string
		for token := ""; ; {
			out, err := as.c.call(as.ctx, accessService, "ListViewerGrants", map[string]any{"token": as.token(t, viewer, A), "actor": as.actor(),
				"resource_kinds": []any{f.Kind}, "action": "read", "page_token": token, "min_revision": revoked})
			if err != nil {
				t.Fatalf("ListViewerGrants: %v", err)
			}
			for _, r := range listMsgs(out, "resources") {
				listed = append(listed, str(r, "resource_id"))
			}
			if token = str(out, "next_page_token"); token == "" {
				break
			}
		}
		if !slices.Contains(listed, "r9-kept") || slices.Contains(listed, "r9-gone") {
			t.Fatalf("at the revoke's revision the viewer's grants are %v", listed)
		}
	})
	t.Run("R10 another organization's revision is refused revision_foreign, the same whether that organization exists", func(t *testing.T) {
		seated(t)
		da := as.document(t, "r10-da", "", dana)
		granted := grant(t, da, person(t, carol))
		var said []string
		for _, org := range []string{f.OtherOrganization, "no-such-organization-" + f.Organization} {
			_, err := as.c.call(as.ctx, accessService, "Check", map[string]any{"token": as.token(t, carol, A), "actor": as.actor(), "action": "read", "placement": da,
				"min_revision": map[string]any{"organization_id": org, "opaque": granted["opaque"]}})
			refused(t, err, codes.InvalidArgument, "revision_foreign")
			said = append(said, err.Error())
		}
		if said[0] != said[1] {
			t.Fatalf("the refusal tells an organization that exists from one that does not: %q, %q", said[0], said[1])
		}
	})
	t.Run("R11 bytes the host never issued are refused revision_unknown", func(t *testing.T) {
		seated(t)
		da := as.document(t, "r11-da", "", dana)
		granted := grant(t, da, person(t, carol))["opaque"].([]byte)
		flipped := bytes.Clone(granted)
		flipped[len(flipped)/2] ^= 0xff
		for name, opaque := range map[string][]byte{
			"no bytes": {}, "one byte": granted[:1], "another encoding": append([]byte{0xfe}, granted[1:]...),
			"trailing bytes": append(bytes.Clone(granted), granted...), "a changed byte": flipped,
		} {
			_, err := as.c.call(as.ctx, accessService, "Check", map[string]any{"token": as.token(t, carol, A), "actor": as.actor(), "action": "read", "placement": da,
				"min_revision": map[string]any{"organization_id": f.Organization, "opaque": opaque}})
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("%s: want FAILED_PRECONDITION revision_unknown, got %v", name, err)
			}
			refused(t, err, codes.FailedPrecondition, "revision_unknown")
		}
	})
	t.Run("R13 a grant expires by the clock, whatever revision is asked", func(t *testing.T) {
		seated(t)
		da := as.document(t, "r13-da", "", dana)
		now := i64(as.shared(t, as.token(t, dana, A), da, person(t, carol)), "created_at_unix")
		window := 3 * time.Second
		if f.Advance != nil {
			window = 90 * time.Second
		}
		out, err := as.share(as.token(t, dana, A), da, person(t, carol), now+int64(window/time.Second), "read")
		if err != nil {
			t.Fatal(err)
		}
		granted := revisionOf(t, out)
		if f.Lag != nil {
			t.Cleanup(f.Lag(t))
		}
		as.isAllowed(t, check(t, as.token(t, carol, A), da, map[string]any{"min_revision": granted}))
		as.wait(t, window+time.Second)
		as.isDenied(t, check(t, as.token(t, carol, A), da, map[string]any{"min_revision": granted}), da)
	})
	t.Run("R15 a grant is read back at its own revision, while the host's reader is still behind", func(t *testing.T) {
		seated(t)
		da := as.document(t, "r15-da", "", dana)
		lag(t)
		granted := grant(t, da, person(t, carol))
		as.isAllowed(t, check(t, as.token(t, carol, A), da, map[string]any{"min_revision": granted}), "BASIS_RESOURCE_GRANT")
	})
}

// revisionOf is the revision an answer names, as a module stores it and
// returns it: the organization and the bytes.
func revisionOf(t *testing.T, out protoreflect.Message) map[string]any {
	t.Helper()
	r := msg(out, "revision")
	opaque := field(r, "opaque").Bytes()
	if str(r, "organization_id") == "" || len(opaque) == 0 {
		t.Fatalf("the answer names no revision: %v", out)
	}
	return map[string]any{"organization_id": str(r, "organization_id"), "opaque": bytes.Clone(opaque)}
}
