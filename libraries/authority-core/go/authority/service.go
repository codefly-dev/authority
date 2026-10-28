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
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
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
	// MaxDelegationTTL clamps the lifetime a delegation is asked for; zero
	// means DefaultMaxDelegationTTL.
	MaxDelegationTTL time.Duration
	// Replay consumes single-use capabilities. It is required: a deployed
	// host shares it across replicas, and nothing defaults to memory.
	Replay workcontext.ReplayStore
	// Grants answers approval grants; nil refuses every grant capability.
	Grants workcontext.GrantSource
	// Journal records each change of authority in the transaction that makes
	// it; an error aborts the change. nil journals nothing.
	Journal func(ctx context.Context, tx Tx, e domain.Event) error
	// HostInstallsModules says the host decides which organizations hold each
	// composed module, by its own administrators' consent, and its store
	// answers those installations from the host's own records. The core then
	// never installs, reactivates or revokes a module installation itself:
	// delivery, a new organization and reconciliation install nothing,
	// withdrawal leaves the host's records to the host, and UninstallAsHost
	// refuses a module. It still raises a module installation's revision when
	// a redelivery narrows the module, which the store applies to the host's
	// record. false: every composed module is installed at every organization.
	HostInstallsModules bool
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
	if cfg.MaxDelegationTTL <= 0 {
		cfg.MaxDelegationTTL = DefaultMaxDelegationTTL
	}
	s := &Service{store: store, cfg: cfg}
	s.src = sources{s: s}
	s.authority = &workcontext.Authority{Issuer: cfg.Issuer, KeyID: cfg.KeyID, Signer: cfg.Signer, Revisions: s.src, Seals: s.src, MaxTTL: cfg.MaxTTL, Now: cfg.Clock}
	return s, nil
}

// journal records e in tx, when the host journals.
func (s *Service) journal(ctx context.Context, tx Tx, e domain.Event) error {
	if s.cfg.Journal == nil {
		return nil
	}
	return s.cfg.Journal(ctx, tx, e)
}

// Seals and Revisions answer core's verifier and minter from the store.
func (s *Service) Seals() workcontext.SealSource         { return s.src }
func (s *Service) Revisions() workcontext.RevisionSource { return s.src }

// Now is the service's clock: what a delegation's expiry is judged against.
func (s *Service) Now() time.Time { return s.cfg.Clock() }

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
	// Organization is the organization the workload's credential is bound to,
	// empty when it serves every organization that installed it. A workload
	// bound to one is issued nothing at another.
	Organization string
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
	verified, err := v.Verify(ctx, token)
	if errors.Is(err, workcontext.ErrRevoked) {
		// A seal, a grant or a membership moved since issue: say so by name.
		return nil, fmt.Errorf("the capability was revoked: %w", err)
	}
	return verified, err
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
// The sum never goes back to a value it held before, because each term only
// grows and is keyed stably: an installation's revision grows on install,
// uninstall, narrowing and a withdrawn module's redelivery; a grant epoch
// grows on revoke; an owner-aware revision grows on withdrawal and is keyed
// by the module's principal, which a module keeps for life, withdrawn and
// delivered again included (ApplyModule refuses a rename, against its
// tombstone once withdrawn). A module's generation never rewinds either. A
// capability sealed at an earlier sum is therefore refused for good.
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
	err := src.s.store.Read(ctx, func(tx Tx) (err error) {
		seal, err = src.sealIn(tx, principal, installationID)
		return err
	})
	return seal, err
}

func (src sources) sealIn(tx Tx, principal, installationID string) (workcontext.Seal, error) {
	inst, err := tx.Installation(installationID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && inst.Status != domain.Active) {
		return workcontext.Seal{}, workcontext.ErrNoSeal
	}
	if err != nil {
		return workcontext.Seal{}, err // the store's own failure, named as such
	}
	held, err := src.holds(tx, principal, inst)
	if err != nil {
		return workcontext.Seal{}, err
	}
	if !held {
		return workcontext.Seal{}, workcontext.ErrNoSeal
	}
	epoch, err := tx.GrantEpoch(principal, inst.ID)
	if err != nil {
		return workcontext.Seal{}, err
	}
	aware := uint64(0)
	if m, err := tx.ModuleNamed(inst.Target); err == nil {
		if aware, err = tx.OwnerAwareRevision(m.Principal); err != nil {
			return workcontext.Seal{}, err
		}
	}
	return workcontext.Seal{InstallationID: inst.ID, InstallationRevision: inst.Revision + epoch + aware}, nil
}

// holds: the principal may use the installation: a person of its
// organization, a composed module, its own principal, or a solution
// principal of the same organization reaching a module installation.
func (src sources) holds(tx Tx, principal string, inst domain.Installation) (bool, error) {
	if principal == inst.PrincipalID && principal != "" {
		return true, nil
	}
	if _, err := tx.Module(principal); err == nil {
		return true, nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return false, err
	}
	if _, err := tx.Member(inst.Organization, principal); err == nil {
		return true, nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return false, err
	}
	source, err := tx.InstallationByPrincipal(principal)
	if errors.Is(err, domain.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return source.Status == domain.Active && source.Organization == inst.Organization, nil
}

func (src sources) PrincipalEpoch(ctx context.Context, principal string) (uint64, error) {
	var epoch uint64
	err := src.s.store.Read(ctx, func(tx Tx) (err error) {
		epoch, err = src.epochIn(tx, principal)
		return err
	})
	return epoch, err
}

func (src sources) epochIn(tx Tx, principal string) (uint64, error) {
	if c, err := tx.Client(principal); err == nil {
		if c.Disabled {
			return 0, domain.Missing("disabled client %q", principal)
		}
		return c.Revision, nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return 0, err
	}
	if m, err := tx.Module(principal); err == nil {
		return m.Generation, nil
	}
	if _, err := tx.Person(principal); err == nil {
		return tx.PersonEpoch(principal)
	}
	if inst, err := tx.InstallationByPrincipal(principal); err == nil && inst.Status == domain.Active {
		// The installation's revision: it grows on every install and
		// uninstall, so a reinstall never repeats an epoch an earlier
		// incarnation's capabilities were sealed at.
		return inst.Revision, nil
	}
	return 0, domain.Missing("principal %q", principal)
}

// fence is what an issuance decided against: the organization's
// authorization revision, and the owner's seal on the installation and
// epoch, read in the decision's own snapshot. A capability minted after a
// revoke, a leave or an uninstall committed carries other values, and is
// refused rather than handed out.
type fence struct{ revision, seal, epoch uint64 }

func (src sources) fenceIn(tx Tx, organization, owner, installationID string) (fence, error) {
	revision, err := tx.AuthorizationRevision(organization)
	if err != nil {
		return fence{}, err
	}
	seal, err := src.sealIn(tx, owner, installationID)
	if errors.Is(err, workcontext.ErrNoSeal) {
		return fence{}, domain.Refuse("%s may not use installation %s now", owner, installationID)
	}
	if err != nil {
		return fence{}, err // the store's own failure, named as such
	}
	epoch, err := src.epochIn(tx, owner)
	if err != nil {
		return fence{}, err
	}
	return fence{revision, seal.InstallationRevision, epoch}, nil
}

func (f fence) holds(signed *basev0.WorkContextV1) error {
	if signed.GetAuthorizationRevision() != f.revision || signed.GetSeal().GetInstallationRevision() != f.seal || signed.GetSeal().GetPrincipalEpoch() != f.epoch {
		return domain.Refuse("permissions changed during issuance")
	}
	return nil
}

// OperationBinding answers "<organization>/<module>/<binding>". Its
// incarnation is the binding's audience's owner-aware revision plus the
// acting module's installation revision, both only growing: a capability
// through it issued before the audience last withdrew owner-aware checking,
// or before the installation was last uninstalled, is refused for good.
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
			Revision: m.Generation, Incarnation: aware + inst.Revision, Revoked: inst.Status == domain.Revoked}
		return nil
	})
	return out, err
}

// ceiled is m's delivered binding b as usable at org: within what the host's
// consent at m's installation there allows (domain.Installation.Bindings). An
// organization with no installation of m leaves b as delivered; whoever needs
// the installation refuses its absence.
func ceiled(tx Tx, org string, m domain.Module, b domain.Binding) (domain.Binding, error) {
	inst, err := installationOf(tx, org, m.Name)
	if errors.Is(err, domain.ErrNotFound) {
		return b, nil
	}
	if err != nil || inst.Bindings == nil {
		return b, err
	}
	consented, ok := inst.Bindings[b.ID]
	if !ok {
		return domain.Binding{}, domain.Refuse("%s's operation binding %q is not one its installation at %s consents to", m.Name, b.ID, org)
	}
	b.InvokeScopes = scope.Intersect(b.InvokeScopes, consented.InvokeScopes)
	b.HeadlessScopes = scope.Intersect(b.HeadlessScopes, consented.HeadlessScopes)
	b.LookupScopes = scope.Intersect(b.LookupScopes, consented.LookupScopes)
	return b, nil
}

// installationOf is an organization's installation of target: its active one
// when it has one, since a host that installs modules keeps the records of the
// installations it retired beside the one it made again.
func installationOf(tx Tx, org, target string) (domain.Installation, error) {
	all, err := tx.Installations(org)
	if err != nil {
		return domain.Installation{}, err
	}
	var found *domain.Installation
	for i, inst := range all {
		if inst.Target != target {
			continue
		}
		if inst.Status == domain.Active {
			return inst, nil
		}
		if found == nil {
			found = &all[i]
		}
	}
	if found != nil {
		return *found, nil
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
