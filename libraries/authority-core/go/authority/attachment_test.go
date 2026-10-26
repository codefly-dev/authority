package authority_test

import (
	"context"
	"fmt"
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
// issued before solution-principal selection. Attach must enforce its boundary
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
		{"read", attachmentToken(t, h, []string{"a"}, sc(kind, "read")), "holds neither"},
		{"create on id", attachmentToken(t, h, []string{"a"}, owned(kind, "", []string{"create"}, "x")), "holds neither"},
		{"admin on another id", attachmentToken(t, h, []string{"a"}, owned(kind, "", []string{"admin"}, "y")), "holds neither"},
		{"create for another owner", attachmentToken(t, h, []string{"a"}, owned(kind, h.principal(acme, "b"), []string{"create"})), "holds neither"},
		{"selected owner admin", attachmentToken(t, h, []string{"a"}, owned(kind, h.principal(acme, "a"), []string{"admin"}, "x")), "holds neither"},
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
	refused(t, err, "owned by")
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
	if _, err := attach(h, admin, "existing"); err != nil {
		t.Fatal(err)
	}
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
