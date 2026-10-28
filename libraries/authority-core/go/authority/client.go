package authority

import (
	"context"
	"errors"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/oauthwire"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	"github.com/codefly-dev/core/workcontext"
)

// RegisterClient records public-client metadata; it creates no authority. The
// host bounds unauthenticated registration before calling this operation.
func (s *Service) RegisterClient(ctx context.Context, name string, redirects []string) (domain.Client, error) {
	if err := oauthwire.ValidateRegistration(name, redirects); err != nil {
		return domain.Client{}, domain.Malformed("%s", err)
	}
	c := domain.Client{ID: "client:" + s.cfg.NewID(), Name: name, RedirectURIs: redirects, Revision: 1}
	if c.Name == "" {
		c.Name = c.ID
	}
	err := s.store.Write(ctx, func(tx Tx) error {
		if _, err := tx.Client(c.ID); err == nil {
			return domain.NotNow("client identity collision")
		} else if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		for _, lookup := range []func() error{
			func() error { _, err := tx.Module(c.ID); return err },
			func() error { _, err := tx.Person(c.ID); return err },
			func() error { _, err := tx.InstallationByPrincipal(c.ID); return err },
			func() error { _, err := tx.TombstoneByPrincipal(c.ID); return err },
		} {
			if err := lookup(); err == nil {
				return domain.NotNow("client identity collides with an existing principal")
			} else if !errors.Is(err, domain.ErrNotFound) {
				return err
			}
		}
		return tx.PutClient(c)
	})
	return c, err
}

func (s *Service) Client(ctx context.Context, id string) (domain.Client, error) {
	var c domain.Client
	err := s.store.Read(ctx, func(tx Tx) (err error) { c, err = tx.Client(id); return err })
	if err == nil && c.Disabled {
		err = domain.Refuse("client is disabled")
	}
	return c, err
}

// ClientScopes previews the same live ceiling Delegate uses, for the edge's
// consent page. Approval repeats these checks; a preview grants nothing.
func (s *Service) ClientScopes(ctx context.Context, who Person, audience string) (Scopes, error) {
	var scopes Scopes
	err := s.store.Read(ctx, func(tx Tx) error {
		p, err := tx.Member(who.Organization, who.ID)
		if err != nil {
			return notFound(err)
		}
		m, err := tx.Module(audience)
		if err != nil {
			return notFound(err)
		}
		if m.Kind != domain.KindSolution {
			return domain.Refuse("a client authorizes one solution")
		}
		scopes, err = delegableScopes(tx, p, m, nil)
		return err
	})
	return scope.Normalize(scopes), err
}

// DelegateToClient extends the existing delegation, not a different grant. The
// host supplies the audience/resource pair from the solution's SDK-resolved
// declaration, never directly from an unauthenticated request. The signed-in
// person must explicitly approve scopes and expiry before this call.
func (s *Service) DelegateToClient(ctx context.Context, who Person, clientID, audience, resource string, scopes Scopes, purpose string, ttlSeconds int64) (domain.Delegation, error) {
	if clientID == "" {
		return domain.Delegation{}, domain.Malformed("a client delegation names its client")
	}
	return s.delegate(ctx, who, audience, clientID, resource, scopes, purpose, ttlSeconds)
}

// IssueForClientDelegation uses the same delegation, live holdings and core
// minter as module delegation. clientID is authenticated by the host's code or
// refresh redemption, not by possession of a public client ID. No module's
// credential, principal, binding or installation is borrowed for this actor.
func (s *Service) IssueForClientDelegation(ctx context.Context, id, clientID, resource string, r IssueRequest) (Issued, error) {
	var d domain.Delegation
	var audience domain.Module
	var scopes Scopes
	var inst domain.Installation
	var f fence
	err := s.store.Read(ctx, func(tx Tx) error {
		var err error
		if d, err = tx.Delegation(id); err != nil {
			return notFound(err)
		}
		if d.ClientID == "" || d.ClientID != clientID || d.Module != "" || !d.Active(s.cfg.Clock()) || d.ExpiresAt.IsZero() {
			return domain.Refuse("client delegation is absent, revoked, expired or belongs to another client")
		}
		c, err := tx.Client(clientID)
		if err != nil || c.Disabled {
			return domain.Refuse("unknown or disabled client")
		}
		if err := oauthwire.CheckResource(d.Resource, resource); err != nil {
			return domain.Refuse("%s", err)
		}
		if r.Binding != "" || r.Operation != "" && r.Operation != "invoke" || r.Audience != "" && r.Audience != d.Audience || r.Organization != "" && r.Organization != d.Organization {
			return domain.Refuse("a client delegation cannot change solution, organization or exercise a workload binding")
		}
		if audience, err = tx.Module(d.Audience); err != nil {
			return notFound(err)
		}
		if audience.Kind != domain.KindSolution {
			return domain.Refuse("the delegated audience is no longer a solution")
		}
		p, err := tx.Member(d.Organization, d.Grantor)
		if err != nil {
			return domain.Refuse("the grantor is no longer a member")
		}
		h, err := delegableScopes(tx, p, audience, d.Scopes)
		if err != nil {
			return err
		}
		scopes, err = decide.Issue(r.Scopes, scope.Intersect(d.Scopes, h))
		if err != nil {
			return err
		}
		if len(scopes) == 0 {
			return domain.Refuse("the client delegation grants nothing the person still holds")
		}
		if err := decide.OwnerAware(audience, scopes); err != nil {
			return err
		}
		if inst, err = installationOf(tx, d.Organization, audience.Name); err != nil {
			return err
		}
		f, err = s.src.fenceIn(tx, d.Organization, d.Grantor, inst.ID)
		return err
	})
	if err != nil {
		return Issued{}, err
	}
	ttl := min(clamp(r.TTL, s.cfg.MaxTTL), d.ExpiresAt.Sub(s.cfg.Clock()))
	if ttl <= 0 {
		return Issued{}, domain.Refuse("client delegation expired")
	}
	root, err := s.startFenced(ctx, f, workcontext.StartInput{
		TenantID: d.Organization, OrganizationID: d.Organization, OwnerPrincipalID: d.Grantor, OwnerPrincipalKind: "human",
		TaskID: s.cfg.NewID(), Audience: audience.Principal, AuthorityScopes: scopes,
		InstallationID: inst.ID, TTL: ttl, ReplayPolicy: workcontext.ReplayIdempotent,
	})
	if err != nil {
		return Issued{}, err
	}
	parent, err := s.Verify(ctx, root.Token, audience.Principal)
	if err != nil {
		return Issued{}, err
	}
	token, signed, err := s.authority.Child(ctx, parent, workcontext.ChildInput{
		PrincipalID: clientID, PrincipalKind: "client", DelegationID: d.ID, GrantedScopes: scopes,
		Audience: audience.Principal, TTL: ttl, ReplayPolicy: workcontext.ReplayIdempotent,
	})
	if err != nil {
		return Issued{}, err
	}
	err = s.store.Read(ctx, func(tx Tx) error {
		again, err := tx.Delegation(id)
		if err != nil || !again.Active(s.cfg.Clock()) || again.Module != "" || again.ClientID != clientID || again.Resource != resource || again.Audience != audience.Principal || again.Grantor != d.Grantor || again.Organization != d.Organization || !scope.Attenuates(scopes, again.Scopes) || signed.GetExpiresAtUnix() > again.ExpiresAt.Unix() {
			return domain.Refuse("client delegation changed while signing")
		}
		return nil
	})
	if err != nil {
		return Issued{}, err
	}
	if _, err := s.Verify(ctx, token, audience.Principal); err != nil {
		return Issued{}, err
	}
	if time.Unix(signed.GetExpiresAtUnix(), 0).After(d.ExpiresAt) {
		return Issued{}, domain.Refuse("capability outlives client delegation")
	}
	return Issued{token, signed}, nil
}
