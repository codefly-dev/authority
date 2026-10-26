package authority_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
)

// Present real Core-signed capabilities, including the owner-free scope shape
// with no resource-owner selection. Attach must enforce its boundary
// even when a valid capability was minted by another host/version.
func attachmentToken(t *testing.T, h *harness, targets []string, scopes ...*basev0.WorkScopeV1) string {
	t.Helper()
	minter := workcontext.Authority{Issuer: h.cfg.Issuer, KeyID: h.cfg.KeyID, Signer: h.cfg.Signer, Seals: h.svc.Seals(), Revisions: h.svc.Revisions(), Now: h.cfg.Clock}
	audience := "store"
	if len(targets) > 0 {
		audience = targets[0]
	}
	token, _, err := minter.Start(h.ctx, workcontext.StartInput{TenantID: acme, OrganizationID: acme, OwnerPrincipalID: "alex", OwnerPrincipalKind: "human", TaskID: "attach-test", SessionID: "session", Audience: audience, AuthorityScopes: scopes, InstallationID: h.inst(acme, audience).ID, TTL: time.Minute, ReplayPolicy: workcontext.ReplayIdempotent})
	if err != nil {
		t.Fatal(err)
	}
	for index, target := range targets {
		parent, err := h.svc.Verify(h.ctx, token, audience)
		if err != nil {
			t.Fatal(err)
		}
		audience = "store"
		if index+1 < len(targets) {
			audience = targets[index+1]
		}
		token, _, err = minter.Child(h.ctx, parent, workcontext.ChildInput{PrincipalID: target, PrincipalKind: "service", OrganizationID: acme, DelegationID: "session", Audience: audience, GrantedScopes: scopes, TTL: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
	}
	return token
}

func attach(h *harness, token, id string) (string, error) {
	return h.svc.AttachResource(h.ctx, authority.AttachmentRequest{Token: token, Store: authority.Workload{Module: "store"}, Kind: kind, ResourceID: id})
}

func TestAttachmentRefusalsAndExclusiveBoundedLifecycle(t *testing.T) {
	h := newHarness(t)
	create := func(target string) string { return attachmentToken(t, h, []string{target}, sc(kind, "create")) }
	token := create("a")
	for _, id := range []string{"", " x", "x ", "x\n", "x\r", "x\t", "x\x00", "*", "x*", strings.Repeat("x", 129)} {
		_, err := attach(h, token, id)
		refused(t, err, "not a usable id")
	}
	for _, tc := range []struct{ name, token, reason string }{
		{"read", attachmentToken(t, h, []string{"a"}, sc(kind, "read")), "holds no create"},
		{"create on id", attachmentToken(t, h, []string{"a"}, owned(kind, "", []string{"create"}, "x")), "holds no create"},
		{"admin on another id", attachmentToken(t, h, []string{"a"}, owned(kind, "", []string{"admin"}, "y")), "holds no create"},
		{"create for another owner", attachmentToken(t, h, []string{"a"}, owned(kind, h.principal(acme, "b"), []string{"create"})), "holds no create"},
		{"selected owner admin", attachmentToken(t, h, []string{"a"}, owned(kind, h.principal(acme, "a"), []string{"admin"}, "x")), "holds no create"},
		{"no installation", attachmentToken(t, h, nil, sc(kind, "create")), "no installation"},
		{"two installations", attachmentToken(t, h, []string{"a", "b"}, sc(kind, "create")), "2 installations"},
	} {
		t.Run(tc.name, func(t *testing.T) { _, err := attach(h, tc.token, "x"); refused(t, err, tc.reason) })
	}
	_, err := h.svc.AttachResource(h.ctx, authority.AttachmentRequest{Token: token, Store: authority.Workload{Module: "a"}, Kind: kind, ResourceID: "x"})
	refused(t, err, "does not serve")
	wrong := h.must(h.root("ada", "store"))
	_, err = h.svc.AttachResource(h.ctx, authority.AttachmentRequest{Token: wrong.Token, Store: authority.Workload{Module: "a"}, Kind: "a.note", ResourceID: "x"})
	refused(t, err, "audience")
	var before domain.Installation
	if err := h.store.Read(h.ctx, func(tx authority.Tx) (err error) { before, err = tx.Installation(h.inst(acme, "a").ID); return err }); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		owner, err := attach(h, token, "x")
		if err != nil || owner != before.ID {
			t.Fatalf("attach: %s %v", owner, err)
		}
	}
	if len(before.Owned) != 0 {
		t.Fatal("mutated an earlier snapshot")
	}
	_, err = attach(h, create("b"), "x")
	refused(t, err, "owned by")
	admin := attachmentToken(t, h, []string{"b"}, owned(kind, "", []string{"admin"}, "x"))
	_, err = attach(h, admin, "x")
	refused(t, err, "AuthorizeTransfer")
	for n := 1; n < authority.MaxOwnedPerKind; n++ {
		if _, err := attach(h, token, fmt.Sprintf("id-%d", n)); err != nil {
			t.Fatal(err)
		}
	}
	_, err = attach(h, token, "extra")
	refused(t, err, "already owns 32")
	if _, err := h.svc.DetachResource(h.ctx, authority.Workload{Module: "a"}, acme, kind, "x"); err == nil {
		t.Fatal("non-server detached")
	}
	if _, err := h.svc.DetachResource(h.ctx, authority.Workload{Module: "store"}, acme, kind, "x"); err != nil {
		t.Fatal(err)
	}
	_, err = attach(h, token, "extra")
	if err == nil {
		t.Fatal("pre-detach capability stayed valid")
	}
	token = create("a")
	if _, err := attach(h, token, "extra"); err != nil {
		t.Fatal(err)
	}
	if id, err := h.svc.DetachResource(h.ctx, authority.Workload{Module: "store"}, acme, kind, "absent"); err != nil || id != "" {
		t.Fatalf("absent detach: %s %v", id, err)
	}
	if err := h.svc.Uninstall(h.ctx, h.person("alex"), acme, before.ID); err != nil {
		t.Fatal(err)
	}
	h.install(acme, "a")
	_, err = attach(h, token, "late")
	if err == nil {
		t.Fatal("pre-reinstall capability stayed valid")
	}
	if err := h.store.Read(h.ctx, func(tx authority.Tx) error {
		inst, err := tx.Installation(before.ID)
		if err == nil && len(inst.Owned) != 0 {
			t.Fatal("reinstall retained owned ids")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	admin = attachmentToken(t, h, []string{"a"}, owned(kind, "", []string{"admin"}, "existing"))
	_, err = attach(h, admin, "existing")
	refused(t, err, "AuthorizeTransfer")
}

func TestConcurrentAttachmentsHaveExactlyOneOwner(t *testing.T) {
	h := newHarness(t)
	tokens := []string{attachmentToken(t, h, []string{"a"}, sc(kind, "create")), attachmentToken(t, h, []string{"b"}, sc(kind, "create"))}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, token := range tokens {
		wg.Go(func() { _, err := attach(h, token, "contended"); results <- err })
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else {
			refused(t, err, "owned by")
		}
	}
	if success != 1 {
		t.Fatalf("%d attachments committed", success)
	}
}

func TestAttachmentRechecksRevisionUnderWriteTransaction(t *testing.T) {
	h := newHarness(t)
	token := attachmentToken(t, h, []string{"a"}, sc(kind, "create"))
	wrapped := &beforeWriteStore{Store: h.store, change: func() {
		if err := h.store.Write(h.ctx, func(tx authority.Tx) error { return tx.BumpAuthorizationRevision(acme) }); err != nil {
			t.Fatal(err)
		}
	}}
	svc, err := authority.New(wrapped, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.AttachResource(h.ctx, authority.AttachmentRequest{Token: token, Store: authority.Workload{Module: "store"}, Kind: kind, ResourceID: "late"})
	refused(t, err, "authorization revision superseded")
}

type beforeWriteStore struct {
	authority.Store
	change func()
}

func (s *beforeWriteStore) Write(ctx context.Context, f func(authority.Tx) error) error {
	if s.change != nil {
		change := s.change
		s.change = nil
		change()
	}
	return s.Store.Write(ctx, f)
}

func TestPublicIssuanceTransfersOnlyAfterLiveAuthorization(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "author", "ada")
	capability := h.must(h.through("ada", "a", "store"))
	for _, row := range effective(capability) {
		if row.GetResourceOwnerId() != h.principal(acme, "a") {
			t.Fatal("ordinary role lost its resource-owner selector")
		}
	}
	request := authority.TransferRequest{Token: capability.Token, Store: authority.Workload{Module: "store"}, Kind: kind,
		ResourceID: "store-x", From: acme, To: h.principal(acme, "a")}
	foreign := request
	foreign.To = h.principal(globex, "a")
	_, err := h.svc.AuthorizeTransfer(h.ctx, foreign)
	refused(t, err, "not active at acme")
	// A personal grant lost after issue is read live, even without a revision bump.
	h.store.PutPerson(domain.Person{ID: "ada", Organization: acme})
	_, err = h.svc.AuthorizeTransfer(h.ctx, request)
	refused(t, err, "own organization grants")
	h.store.PutPerson(domain.Person{ID: "ada", Organization: acme, Roles: []string{"store-admin"}})
	if err := h.store.Read(h.ctx, func(tx authority.Tx) error {
		inst, err := tx.Installation(h.inst(acme, "a").ID)
		if len(inst.Owned) != 0 {
			t.Fatal("refused transfer changed ownership")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	decision, err := h.svc.AuthorizeTransfer(h.ctx, request)
	if err != nil || decision.PrincipalID != request.To {
		t.Fatalf("transfer: %+v %v", decision, err)
	}
	if err := h.store.Read(h.ctx, func(tx authority.Tx) error {
		inst, err := tx.Installation(h.inst(acme, "a").ID)
		if !slices.Equal(inst.Owned[kind], []string{"store-x"}) {
			t.Fatalf("owned: %v", inst.Owned)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTransferUsesTheAttachmentBoundAndWriteFence(t *testing.T) {
	for _, test := range []string{"cap", "revision", "exclusive"} {
		t.Run(test, func(t *testing.T) {
			h := newHarness(t)
			h.grant("a", "author", "ada")
			capability := h.must(h.through("ada", "a", "store"))
			service := h.svc
			reason := "already owns 32"
			switch test {
			case "cap":
				h.grant("a", "author", "alex")
				created := h.must(h.through("alex", "a", "store"))
				for n := range authority.MaxOwnedPerKind {
					if _, err := attach(h, created.Token, fmt.Sprintf("id-%d", n)); err != nil {
						t.Fatal(err)
					}
				}
			case "exclusive":
				h.grant("b", "author", "alex")
				created := h.must(h.through("alex", "b", "store"))
				if _, err := attach(h, created.Token, "store-x"); err != nil {
					t.Fatal(err)
				}
				reason = "owned by installation"
			case "revision":
				wrapped := &beforeWriteStore{Store: h.store, change: func() {
					if err := h.store.Write(h.ctx, func(tx authority.Tx) error { return tx.BumpAuthorizationRevision(acme) }); err != nil {
						t.Fatal(err)
					}
				}}
				var err error
				service, err = authority.New(wrapped, h.cfg)
				if err != nil {
					t.Fatal(err)
				}
				reason = "authorization revision superseded"
			}
			_, err := service.AuthorizeTransfer(h.ctx, authority.TransferRequest{Token: capability.Token, Store: authority.Workload{Module: "store"}, Kind: kind,
				ResourceID: "store-x", From: acme, To: h.principal(acme, "a")})
			refused(t, err, reason)
		})
	}
}

func TestPublicCreationIsTenantBoundAndSupportsInstallationAgents(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.GrantRole(h.ctx, h.person("zoe"), authority.RoleRequest{Organization: globex, InstallationID: h.inst(globex, "a").ID, Role: "author", PersonID: "zoe"}); err != nil {
		t.Fatal(err)
	}
	for _, capability := range []authority.Issued{h.must(h.agent("a", "store")), h.must(h.through("zoe", "a", "store"))} {
		id, err := attach(h, capability.Token, "same-id")
		if err != nil {
			t.Fatal(err)
		}
		want := h.inst(capability.Context.GetTenantId(), "a").ID
		if id != want {
			t.Fatalf("attached to %s, want tenant installation %s", id, want)
		}
	}
}
