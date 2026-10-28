package authority_test

import (
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

func clientGrant(t *testing.T) (*harness, domain.Client, domain.Delegation) {
	t.Helper()
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	c, err := h.svc.RegisterClient(h.ctx, "External client", []string{"https://client.invalid/callback"})
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := h.svc.ClientScopes(h.ctx, h.person("maya"), "a")
	if err != nil {
		t.Fatal(err)
	}
	d, err := h.svc.DelegateToClient(h.ctx, h.person("maya"), c.ID, "a", h.cfg.Issuer+"/mcp/a", scopes, "explicit consent", 3600)
	if err != nil {
		t.Fatal(err)
	}
	return h, c, d
}

func TestClientActsAsItselfThroughThePersonsDelegation(t *testing.T) {
	h, c, d := clientGrant(t)
	if d.Module != "" || d.ClientID != c.ID || d.Audience != "a" {
		t.Fatalf("wrong grantee: %+v", d)
	}
	root := h.must(h.svc.IssueForClientDelegation(h.ctx, d.ID, c.ID, d.Resource, authority.IssueRequest{}))
	if err := h.check(root); err != nil {
		t.Fatal(err)
	}
	chain := root.Context.GetActorChain()
	if len(chain) != 1 || chain[0].GetPrincipalKind() != "client" || chain[0].GetPrincipalId() != c.ID || chain[0].GetDelegationId() != d.ID || root.Context.GetOwnerPrincipalId() != "maya" {
		t.Fatalf("client or grantor identity lost: %v", root.Context)
	}
	child := h.must(h.svc.IssueChild(h.ctx, root.Token, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store"}))
	if err := h.check(child); err != nil {
		t.Fatal(err)
	}
	chain = child.Context.GetActorChain()
	if len(chain) != 2 || chain[0].GetPrincipalId() != c.ID || chain[0].GetPrincipalKind() != "client" || chain[1].GetPrincipalId() != "a" || child.Context.GetOwnerPrincipalId() != "maya" {
		t.Fatalf("downstream call lost client provenance: %v", child.Context)
	}
	if _, _, err := h.svc.Check(h.ctx, root.Token, "b"); err == nil {
		t.Fatal("another solution accepted the token")
	}
	if _, err := h.svc.IssueForWorkload(h.ctx, authority.Workload{Module: c.ID}, authority.IssueRequest{Binding: "store"}); err == nil {
		t.Fatal("registration created a workload")
	}
	if _, err := h.svc.IssueForDelegation(h.ctx, d.ID, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store"}); err == nil {
		t.Fatal("a module borrowed the client's delegation")
	}
	if _, err := h.svc.RevokeDelegation(h.ctx, h.person("maya"), d.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.check(root); err == nil {
		t.Fatal("revoked client token accepted")
	}
	if err := h.check(child); err == nil {
		t.Fatal("revoked descendant accepted")
	}
}

func TestClientDelegationRefusesChangesAndRechecksLiveAuthority(t *testing.T) {
	for name, change := range map[string]func(*harness, *domain.Client, *domain.Delegation, *authority.IssueRequest){
		"another client":   func(_ *harness, c *domain.Client, _ *domain.Delegation, _ *authority.IssueRequest) { c.ID += "x" },
		"another resource": func(_ *harness, _ *domain.Client, d *domain.Delegation, _ *authority.IssueRequest) { d.Resource += "/" },
		"another solution": func(_ *harness, _ *domain.Client, _ *domain.Delegation, r *authority.IssueRequest) { r.Audience = "b" },
		"another organization": func(_ *harness, _ *domain.Client, _ *domain.Delegation, r *authority.IssueRequest) {
			r.Organization = globex
		},
		"a workload binding": func(_ *harness, _ *domain.Client, _ *domain.Delegation, r *authority.IssueRequest) {
			r.Binding = "store"
		},
		"headless operation": func(_ *harness, _ *domain.Client, _ *domain.Delegation, r *authority.IssueRequest) {
			r.Operation = "headless"
		},
		"expired delegation": func(h *harness, _ *domain.Client, d *domain.Delegation, _ *authority.IssueRequest) {
			h.now = d.ExpiresAt
		},
		"role lost": func(h *harness, _ *domain.Client, _ *domain.Delegation, _ *authority.IssueRequest) {
			h.revoke("a", "viewer", "maya", "")
		},
		"uninstalled": func(h *harness, _ *domain.Client, _ *domain.Delegation, _ *authority.IssueRequest) {
			if err := h.svc.UninstallAsHost(h.ctx, acme, h.inst(acme, "a").ID); err != nil {
				t.Fatal(err)
			}
		},
		"disabled client": func(h *harness, c *domain.Client, _ *domain.Delegation, _ *authority.IssueRequest) {
			c.Disabled = true
			if err := h.store.Write(h.ctx, func(tx authority.Tx) error { return tx.PutClient(*c) }); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, c, d := clientGrant(t)
			r := authority.IssueRequest{}
			change(h, &c, &d, &r)
			if _, err := h.svc.IssueForClientDelegation(h.ctx, d.ID, c.ID, d.Resource, r); err == nil {
				t.Fatal("invalid delegation issued")
			}
		})
	}
}

func TestClientDelegationCannotGrowAtRefresh(t *testing.T) {
	h, c, d := clientGrant(t)
	first := h.must(h.svc.IssueForClientDelegation(h.ctx, d.ID, c.ID, d.Resource, authority.IssueRequest{}))
	if first.Context.GetExpiresAtUnix() != h.now.Add(15*time.Minute).Unix() {
		t.Fatal("local MaxTTL was not retained")
	}
	h.grant("a", "author", "maya")
	// Newly held write is outside the already approved viewer delegation.
	_, err := h.svc.IssueForClientDelegation(h.ctx, d.ID, c.ID, d.Resource, authority.IssueRequest{Scopes: authority.Scopes{owned(kind, h.principal(acme, "a"), []string{"write"})}})
	if err == nil {
		t.Fatal("refresh widened the old consent")
	}
	h.now = d.ExpiresAt.Add(-30 * time.Second)
	last := h.must(h.svc.IssueForClientDelegation(h.ctx, d.ID, c.ID, d.Resource, authority.IssueRequest{}))
	if last.Context.GetExpiresAtUnix() != d.ExpiresAt.Unix() {
		t.Fatal("refresh extended the delegation end")
	}
}

func TestClientDelegationChangesDuringSigningRefuse(t *testing.T) {
	for _, change := range []string{"revoke", "narrow", "expire", "disable client"} {
		t.Run(change, func(t *testing.T) {
			h, c, d := clientGrant(t)
			h.cfg.Signer = &changeAfterSigning{Signer: h.cfg.Signer, change: func() {
				if err := h.store.Write(h.ctx, func(tx authority.Tx) error {
					switch change {
					case "revoke":
						d.Revoked = true
					case "narrow":
						d.Scopes = nil
					case "expire":
						d.ExpiresAt = h.now
					case "disable client":
						c.Disabled = true
						return tx.PutClient(c)
					}
					return tx.PutDelegation(d)
				}); err != nil {
					t.Fatal(err)
				}
			}}
			svc, err := authority.New(h.store, h.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.IssueForClientDelegation(h.ctx, d.ID, c.ID, d.Resource, authority.IssueRequest{}); err == nil {
				t.Fatal("changed grant issued a capability")
			}
		})
	}
}

func TestClientAndModulePrincipalsCannotCollide(t *testing.T) {
	h, c, _ := clientGrant(t)
	m := domain.Module{Name: "pretender", Principal: c.ID, Kind: domain.KindModule, Generation: 1, ResourceKinds: authority.Scopes{sc("pretender", "read")}}
	if _, err := h.svc.ApplyModule(h.ctx, m); err == nil {
		t.Fatal("module claimed a client's principal")
	}
	m.Principal = "client:collision"
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	h.cfg.NewID = func() string { return "collision" }
	svc, err := authority.New(h.store, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterClient(h.ctx, "client", []string{"https://client.invalid/callback"}); err == nil {
		t.Fatal("client claimed a module's principal")
	}
}

func TestClientStoreUsesTheAuthorityTransactionAndClonesMetadata(t *testing.T) {
	h, c, _ := clientGrant(t)
	c.RedirectURIs[0] = "https://modified.invalid/callback"
	stored, err := h.svc.Client(h.ctx, c.ID)
	if err != nil || stored.RedirectURIs[0] == c.RedirectURIs[0] {
		t.Fatalf("caller mutated stored client: %+v %v", stored, err)
	}
	err = h.store.Write(h.ctx, func(tx authority.Tx) error {
		if err := tx.PutClient(c); err != nil {
			return err
		}
		return domain.Refuse("rollback")
	})
	if err == nil {
		t.Fatal("transaction unexpectedly committed")
	}
	again, err := h.svc.Client(h.ctx, c.ID)
	if err != nil || again.RedirectURIs[0] != stored.RedirectURIs[0] {
		t.Fatalf("client write escaped rollback: %+v %v", again, err)
	}
}
