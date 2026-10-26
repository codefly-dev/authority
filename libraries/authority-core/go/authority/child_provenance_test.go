package authority_test

import (
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/core/workcontext"
	"google.golang.org/protobuf/proto"
)

// The public Issue request cannot originate optional task or actor provenance.
// Arrange an already verified parent using the host's production Core minter
// and live seal/revision sources; exercise only the public child and Check APIs.
func TestChildPreservesVerifiedTaskAndActorProvenance(t *testing.T) {
	for _, tc := range []struct {
		name      string
		populated bool
		actors    []string
	}{
		{name: "absent"},
		{name: "task", populated: true},
		{name: "foreign-human", actors: []string{"human"}},
		{name: "agent", actors: []string{"agent"}},
		{name: "task-and-chain", populated: true, actors: []string{"agent", "human"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			narrow := sc(kind, "read")
			narrow.ResourceIds = []string{"store-x"}
			root := h.must(h.root("rob", "store", narrow))
			c := root.Context
			minter := workcontext.Authority{Issuer: h.cfg.Issuer, KeyID: h.cfg.KeyID, Signer: h.cfg.Signer,
				Seals: h.svc.Seals(), Revisions: h.svc.Revisions(), Now: h.cfg.Clock}
			input := workcontext.StartInput{TenantID: c.GetTenantId(), OrganizationID: c.GetOrganizationId(),
				OwnerPrincipalID: c.GetOwnerPrincipalId(), OwnerPrincipalKind: c.GetOwnerPrincipalKind(),
				TaskID: c.GetTaskId(), Audience: c.GetAudience(), AuthorityScopes: c.GetAuthorityScopes(),
				InstallationID: c.GetSeal().GetInstallationId(), AttributionTeamIDs: []string{"team_a"},
				TTL: 5 * time.Minute, ReplayPolicy: workcontext.ReplayIdempotent}
			if tc.populated {
				input.WorkspaceID, input.ProjectID = "workspace_a", "project_a"
			}
			token, _, err := minter.Start(h.ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			for _, kind := range tc.actors {
				parent, err := h.svc.Verify(h.ctx, token, "store")
				if err != nil {
					t.Fatal(err)
				}
				actor := workcontext.ChildInput{PrincipalID: "omar", PrincipalKind: kind, OrganizationID: globex,
					DelegationID: parent.Context().GetSessionId(), Audience: "store",
					GrantedScopes: parent.EffectiveScopes(), TTL: 4 * time.Minute}
				if kind == "agent" {
					actor.PrincipalID, actor.AgentID = h.principal(globex, "a"), "a"
				}
				token, _, err = minter.Child(h.ctx, parent, actor)
				if err != nil {
					t.Fatal(err)
				}
			}
			// Both exchanges must preserve populated values and absent fields.
			for step := range 2 {
				parent, _, err := h.svc.Check(h.ctx, token, "store")
				if err != nil {
					t.Fatalf("parent %d was not valid: %v", step, err)
				}
				before := parent.Context()
				child := h.must(h.svc.IssueChild(h.ctx, token, authority.Workload{Module: "store"}, authority.IssueRequest{Binding: "self"}))
				checked, _, err := h.svc.Check(h.ctx, child.Token, "store")
				if err != nil {
					t.Fatal(err)
				}
				after := checked.Context()
				if !proto.Equal(after, child.Context) {
					t.Fatal("issued claims differ from the signed, checked claims")
				}
				if !reflect.DeepEqual(before.WorkspaceId, after.WorkspaceId) || !reflect.DeepEqual(before.ProjectId, after.ProjectId) {
					t.Errorf("step %d changed workspace/project provenance: (%q, %q) -> (%q, %q)", step,
						before.GetWorkspaceId(), before.GetProjectId(), after.GetWorkspaceId(), after.GetProjectId())
				}
				if before.GetTenantId() != after.GetTenantId() || before.GetOrganizationId() != after.GetOrganizationId() ||
					before.GetOwnerPrincipalId() != after.GetOwnerPrincipalId() || before.GetOwnerPrincipalKind() != after.GetOwnerPrincipalKind() ||
					before.GetTaskId() != after.GetTaskId() || !slices.Equal(before.GetAttributionTeamIds(), after.GetAttributionTeamIds()) {
					t.Fatal("child changed the task's attribution")
				}
				if len(after.GetActorChain()) != len(before.GetActorChain())+1 {
					t.Fatal("child did not append exactly one actor")
				}
				for n, old := range before.GetActorChain() {
					next := after.GetActorChain()[n]
					if old.GetPrincipalId() != next.GetPrincipalId() || old.GetPrincipalKind() != next.GetPrincipalKind() ||
						old.GetDelegationId() != next.GetDelegationId() || !reflect.DeepEqual(old.AgentId, next.AgentId) ||
						!reflect.DeepEqual(old.OrganizationId, next.OrganizationId) {
						t.Errorf("step %d changed actor %d identity: %v -> %v", step, n, old, next)
					}
				}
				last := after.GetActorChain()[len(after.GetActorChain())-1]
				if last.GetPrincipalId() != "store" || last.GetPrincipalKind() != "service" || last.GetDelegationId() != before.GetSessionId() ||
					after.GetParentSessionId() != before.GetSessionId() || after.GetSessionId() == before.GetSessionId() ||
					after.GetExpiresAtUnix() > before.GetExpiresAtUnix() || after.GetOperationBinding().GetBindingId() != acme+"/store/self" {
					t.Fatal("child changed the required binding, lineage or lifetime")
				}
				// The binding allows read/write; the owner holds read, and the
				// parent restricts its resources. Preserve both limits.
				exactly(t, child, kind, "", []string{"read"}, "store-x")
				if !workcontext.ScopesAttenuate(checked.EffectiveScopes(), parent.EffectiveScopes()) {
					t.Fatal("child recovered authority the parent did not hold")
				}
				token = child.Token
			}
		})
	}
}
