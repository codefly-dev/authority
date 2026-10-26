// Package authority is the authority's service: every operation of the host
// interfaces as reads from a Store, a decision (package decide), writes, and
// a capability minted or verified with core's workcontext. Identity arrives
// authenticated (Person, Workload); the signing key stays with the host
// (Config.Signer, Config.Keys); transport stays out.
package authority

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
	"github.com/google/uuid"
)

// KeySource answers the public keys a capability is verified with, by key id.
type KeySource interface {
	PublicKeys(ctx context.Context) (map[string]ed25519.PublicKey, error)
}

// Config is what the host injects: the issuer name, the signer and its key
// id (the core never holds a key), the verification keys, the clock and the
// id sources, replay and approval-grant state.
type Config struct {
	Issuer, KeyID string
	Signer        crypto.Signer
	Keys          KeySource
	// Clock is now; nil means time.Now.
	Clock func() time.Time
	// NewID names tasks and delegations; nil means a random UUID.
	NewID func() string
	// InstallationID and PrincipalID name an organization's installation of a
	// target and the principal it is; nil means the stable UUIDs below, so a
	// reinstall keeps both and its data is never orphaned.
	InstallationID, PrincipalID func(organization, target string) string
	// MaxTTL clamps every capability; zero means 15 minutes.
	MaxTTL time.Duration
	// Replay consumes single-use capabilities. It is required: a deployed
	// host shares it across replicas, and nothing defaults to memory.
	Replay workcontext.ReplayStore
	// Grants answers approval grants; nil refuses every grant capability.
	Grants workcontext.GrantSource
}

var (
	installationNamespace = uuid.MustParse("6f1c2b0e-3a52-5d7c-9a1e-0c0de0a07b1a")
	principalNamespace    = uuid.MustParse("3c9b6f1e-8d2a-5b47-a0e1-50c1a7e0b1d2")
)

// StableInstallationID is the default installation id: a UUID named by
// organization and target.
func StableInstallationID(org, target string) string {
	return uuid.NewSHA1(installationNamespace, []byte(org+"\x00"+target)).String()
}

// StablePrincipalID is the default solution principal: a UUID named by
// organization and target under a namespace of its own, so it is never the
// installation id and never shared across organizations.
func StablePrincipalID(org, target string) string {
	return uuid.NewSHA1(principalNamespace, []byte(org+"\x00"+target)).String()
}

// Service is the authority over one store.
type Service struct {
	store     Store
	cfg       Config
	authority *workcontext.Authority
	src       sources
}

// New builds the service.
func New(store Store, cfg Config) (*Service, error) {
	if store == nil || cfg.Signer == nil || cfg.Keys == nil || cfg.Issuer == "" || cfg.KeyID == "" || cfg.Replay == nil {
		return nil, errors.New("authority: a store, an issuer, a key id, a signer, a key source and a replay store are required")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.NewID == nil {
		cfg.NewID = uuid.NewString
	}
	if cfg.InstallationID == nil {
		cfg.InstallationID = StableInstallationID
	}
	if cfg.PrincipalID == nil {
		cfg.PrincipalID = StablePrincipalID
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = 15 * time.Minute
	}
	s := &Service{store: store, cfg: cfg}
	s.src = sources{s: s}
	s.authority = &workcontext.Authority{Issuer: cfg.Issuer, KeyID: cfg.KeyID, Signer: cfg.Signer, Revisions: s.src, Seals: s.src, MaxTTL: cfg.MaxTTL, Now: cfg.Clock}
	return s, nil
}

// Seals and Revisions answer core's verifier and minter from the store.
func (s *Service) Seals() workcontext.SealSource         { return s.src }
func (s *Service) Revisions() workcontext.RevisionSource { return s.src }

// Person is an authenticated person: who the session is, at which organization.
type Person struct {
	ID, Organization, SessionID string
	// Teams is the session's snapshot, kept as attribution; authority reads
	// the person's teams live.
	Teams []string
}

// Workload is an attested module workload.
type Workload struct {
	Module string
}

func (s *Service) verifier(ctx context.Context, audience string) (*workcontext.Verifier, error) {
	keys, err := s.cfg.Keys.PublicKeys(ctx)
	if err != nil {
		return nil, err
	}
	grants := s.cfg.Grants
	if grants == nil {
		grants = noGrants{}
	}
	return &workcontext.Verifier{Issuer: s.cfg.Issuer, Audience: audience, Keys: keys, Revisions: s.src, Replay: s.cfg.Replay, Seals: s.src, Grants: grants, Now: s.cfg.Clock}, nil
}

// Verify checks a capability for the audience the caller is.
func (s *Service) Verify(ctx context.Context, token, audience string) (*workcontext.Verified, error) {
	v, err := s.verifier(ctx, audience)
	if err != nil {
		return nil, err
	}
	return v.Verify(ctx, token)
}

type noGrants struct{}

func (noGrants) Grant(_ context.Context, id string) (*workcontext.Grant, error) {
	return nil, domain.Missing("grant %q: this authority issues no approval grants", id)
}

// sources is the seal, epoch, binding and revision state core checks, read
// from the store. A seal's installation revision folds in what invalidates a
// capability sealed to it: the installation's own revision, the owner's
// grant epoch on it, and the installed solution's owner-aware revision.
//
// The sum never repeats a value it held before, because each term only grows
// and is keyed stably: an installation's revision grows on install,
// uninstall and narrowing; a grant epoch grows on revoke; an owner-aware
// revision grows on withdrawal and is keyed by the module's principal, which
// a module keeps for life (ApplyModule refuses a change). A capability sealed
// at an earlier sum is therefore refused for good.
type sources struct{ s *Service }

func (src sources) AuthorizationRevision(ctx context.Context, tenant string) (uint64, error) {
	var rev uint64
	err := src.s.store.Read(ctx, func(tx Tx) (err error) {
		rev, err = tx.AuthorizationRevision(tenant)
		return err
	})
	return rev, notFound(err)
}

func (src sources) Seal(ctx context.Context, principal, installationID string) (workcontext.Seal, error) {
	var seal workcontext.Seal
	err := src.s.store.Read(ctx, func(tx Tx) error {
		inst, err := tx.Installation(installationID)
		if err != nil || inst.Status != domain.Active {
			return workcontext.ErrNoSeal
		}
		if !src.holds(tx, principal, inst) {
			return workcontext.ErrNoSeal
		}
		epoch, err := tx.GrantEpoch(principal, inst.ID)
		if err != nil {
			return err
		}
		aware := uint64(0)
		if m, err := tx.ModuleNamed(inst.Target); err == nil {
			if aware, err = tx.OwnerAwareRevision(m.Principal); err != nil {
				return err
			}
		}
		seal = workcontext.Seal{InstallationID: inst.ID, InstallationRevision: inst.Revision + epoch + aware}
		return nil
	})
	return seal, err
}

// holds: the principal may use the installation: a person of its
// organization, a composed module, its own principal, or a solution
// principal of the same organization reaching a module installation.
func (src sources) holds(tx Tx, principal string, inst domain.Installation) bool {
	if principal == inst.PrincipalID && principal != "" {
		return true
	}
	if _, err := tx.Module(principal); err == nil {
		return true
	}
	if p, err := tx.Person(principal); err == nil {
		return p.Organization == inst.Organization
	}
	source, err := tx.InstallationByPrincipal(principal)
	return err == nil && source.Status == domain.Active && source.Organization == inst.Organization
}

func (src sources) PrincipalEpoch(ctx context.Context, principal string) (uint64, error) {
	var epoch uint64
	err := src.s.store.Read(ctx, func(tx Tx) error {
		if m, err := tx.Module(principal); err == nil {
			epoch = m.Generation
			return nil
		}
		if _, err := tx.Person(principal); err == nil {
			var perr error
			epoch, perr = tx.PersonEpoch(principal)
			return perr
		}
		if inst, err := tx.InstallationByPrincipal(principal); err == nil && inst.Status == domain.Active {
			// The installation's revision: it grows on every install and
			// uninstall, so a reinstall never repeats an epoch an earlier
			// incarnation's capabilities were sealed at.
			epoch = inst.Revision
			return nil
		}
		return domain.Missing("principal %q", principal)
	})
	return epoch, err
}

// OperationBinding answers "<organization>/<module>/<binding>". Its
// incarnation is the binding's audience's owner-aware revision, plus one: a
// capability through it issued before the audience last withdrew owner-aware
// checking is refused for good.
func (src sources) OperationBinding(ctx context.Context, id string) (workcontext.OperationBinding, error) {
	var out workcontext.OperationBinding
	err := src.s.store.Read(ctx, func(tx Tx) error {
		parts := strings.SplitN(id, "/", 3)
		if len(parts) != 3 {
			return workcontext.ErrNoBinding
		}
		m, err := tx.ModuleNamed(parts[1])
		if err != nil {
			return workcontext.ErrNoBinding
		}
		b, ok := m.Bindings[parts[2]]
		if !ok {
			return workcontext.ErrNoBinding
		}
		inst, err := installationOf(tx, parts[0], m.Name)
		if err != nil {
			return workcontext.ErrNoBinding
		}
		aware, err := tx.OwnerAwareRevision(b.Audience)
		if err != nil {
			return err
		}
		out = workcontext.OperationBinding{ID: id, PrincipalID: m.Principal, InstallationID: inst.ID,
			Revision: m.Generation, Incarnation: aware + 1, Revoked: inst.Status == domain.Revoked}
		return nil
	})
	return out, err
}

// installationOf is an organization's installation of target.
func installationOf(tx Tx, org, target string) (domain.Installation, error) {
	all, err := tx.Installations(org)
	if err != nil {
		return domain.Installation{}, err
	}
	for _, inst := range all {
		if inst.Target == target {
			return inst, nil
		}
	}
	return domain.Installation{}, fmt.Errorf("installation of %s at %s: %w", target, org, domain.ErrNotFound)
}

func notFound(err error) error {
	if errors.Is(err, domain.ErrNotFound) {
		return domain.Missing("%v", err)
	}
	return err
}

// orgRoles are a person's organization roles, those the catalogue defines.
func orgRoles(tx Tx, p domain.Person) ([]domain.OrgRole, error) {
	var out []domain.OrgRole
	for _, name := range p.Roles {
		r, err := tx.OrgRole(p.Organization, name)
		if errors.Is(err, domain.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func clamp(ttl, max time.Duration) time.Duration {
	if ttl <= 0 || ttl > max {
		return max
	}
	return ttl
}

func sortedTeams(teams []string) []string {
	out := slices.Clone(teams)
	slices.Sort(out)
	return slices.Compact(out)
}

// Scopes is a scope list.
type Scopes = []*basev0.WorkScopeV1
