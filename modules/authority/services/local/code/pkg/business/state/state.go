// Package state is the local authority's host half: the fixture it boots on
// (organisations, roles, people and their sign-in tokens), the composition as
// delivered, the open sessions, delivery admission and method admission. What
// the authority decides and records (modules, installations, role grants,
// delegations, revisions, and every issuance) is the generic authority core's,
// over its in-memory store: this package seeds that store and asks the core.
package state

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/access"
	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/memstore"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	fixturecomposition "github.com/codefly-dev/authority/libraries/fixture-composition/go"
	"github.com/codefly-dev/authority/libraries/solutionhost/go/workloadidentity"
	"github.com/codefly-dev/authority/libraries/solutionhost/go/workloadidentity/native"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// Errors a caller distinguishes for what this host decides itself; what the
// core decides arrives as a domain.Refusal with its code.
var (
	ErrUnknown         = errors.New("state: unknown")
	ErrUnauthenticated = errors.New("state: unauthenticated")
	ErrForbidden       = errors.New("state: forbidden")
	ErrStale           = errors.New("state: generation is not newer")
)

// Scope is one (kind, actions) pair a stand-in module serves, as the
// fixture-composition document spells it.
type Scope = fixturecomposition.Scope

// Person is a fixture person.
type Person struct {
	Name         string   `yaml:"name"`
	ID           string   `yaml:"id"`
	Email        string   `yaml:"email"`
	FixtureToken string   `yaml:"fixture_token"`
	Organization string   `yaml:"organization"`
	Roles        []string `yaml:"roles"`
	Teams        []string `yaml:"teams"`
}

// Role is an organisation role: a name people of one organisation hold. It
// decides administration only (the core's decide.IsAdministrator reads the
// name) and grants nothing at any module, so it carries no scope. A fixture
// that still states scopes, or the generated developer role that held every
// delivered kind, is refused by name (LoadFixture).
type Role struct {
	Organization string    `yaml:"organization"`
	Name         string    `yaml:"name"`
	Generated    bool      `yaml:"generated,omitempty"`
	Scopes       yaml.Node `yaml:"scopes"`
}

// The core's objects, as this host names them.
type (
	Manifest     = domain.Module
	MethodPolicy = domain.MethodPolicy
	Binding      = domain.Binding
	Installation = domain.Installation
	Status       = domain.Status
	Delegation   = domain.Delegation
	InstallStep  = authority.InstallStep
)

// The installation states, the two page roles and the wildcards.
const (
	Pending   = domain.Pending
	Active    = domain.Active
	Revoked   = domain.Revoked
	AdminRole = domain.AdminRole
	UserRole  = domain.UserRole
	AnyAction = scope.AnyAction
	AnyKind   = scope.AnyKind
)

// The core's scope algebra, for this host's own checks.
var (
	Normalize   = scope.Normalize
	Intersect   = scope.Intersect
	Attenuates  = scope.Attenuates
	HoldsAction = scope.HoldsAction
)

// InstallationID is the id of org's installation of target: a canonical UUID
// named by organisation and target, so a module's stored rows still name the
// installation after the authority restarts with its fixture.
func InstallationID(org, target string) string { return authority.StableInstallationID(org, target) }

// Namespace is the source an installation's authored content belongs to,
// named by the host so a module never chooses it: "<organization>.<target>".
func Namespace(i Installation) string { return decide.Namespace(i) }

// DelegationScope preserves the exact resource ceiling of a WorkScope.
// Role matchers are a separate contract; a delegation names IDs, not patterns.
type DelegationScope struct {
	Kind        string   `yaml:"kind"`
	Actions     []string `yaml:"actions"`
	ResourceIDs []string `yaml:"resource_ids,omitempty"`
}

// UnmarshalYAML refuses role-matcher syntax instead of silently decoding a
// restricted grant as an unrestricted one.
func (s *DelegationScope) UnmarshalYAML(node *yaml.Node) error {
	type plain DelegationScope
	var decoded struct {
		plain     `yaml:",inline"`
		Resources yaml.Node `yaml:"resources"`
	}
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	if decoded.Resources.Kind != 0 {
		return errors.New("delegation scopes use resource_ids, not role resources matchers")
	}
	*s = DelegationScope(decoded.plain)
	return nil
}

// fixtureDelegation is a delegation a fixture person has already granted.
type fixtureDelegation struct {
	ID           string            `yaml:"id"`
	Organization string            `yaml:"organization"`
	Grantor      string            `yaml:"grantor"`
	Module       string            `yaml:"module"`
	Purpose      string            `yaml:"purpose"`
	Scopes       []DelegationScope `yaml:"scopes"`
}

// Session is an open sign-in.
type Session struct {
	PersonDisplayName       string
	OrganizationDisplayName string
	ID                      string
	Person                  string
	Organization            string
	Roles                   []string
	Teams                   []string
	// RoleView is the roles this session acts as, per installation, when it
	// was opened as a role view; the authority core holds the record.
	RoleView map[string][]string
	// CastTeam is the team this session was cast onto, when it is a cast: it
	// acts as that team and nothing else; the authority core holds the record.
	CastTeam string
	// Parent is the session this one was opened from, when it is a role view
	// or a cast: ending that one ends this one.
	Parent string
	// ExpiresAt is when the session ends on its own; a role view or a cast
	// carries its parent's.
	ExpiresAt time.Time
	Ended     bool
}

type fixtureFile struct {
	Organizations []struct {
		ID   string `yaml:"id"`
		Name string `yaml:"name"`
	} `yaml:"organizations"`
	Teams []struct {
		ID           string `yaml:"id"`
		Organization string `yaml:"organization"`
	} `yaml:"teams"`
	Roles         []Role                `yaml:"roles"`
	People        []Person              `yaml:"people"`
	Installations []FixtureInstallation `yaml:"installations"`
	// Modules are modules a local run supervises itself rather than composing
	// them through Codefly, declared so they can be an audience. A delivered
	// manifest of the same module supersedes it.
	Modules     []FixtureModule     `yaml:"modules"`
	Delegations []fixtureDelegation `yaml:"delegations"`
}

// FixtureModule is one module the fixture composes: its name, which is its
// principal, and the kinds and actions it serves.
type FixtureModule = fixturecomposition.Module

// FixtureInstallation is one installation the fixture performs through the
// real install path, once its target is composed: Role is the installation's
// own (its agent's), Owner installed it and is granted the admin role,
// and each of Teams is granted Role.
type FixtureInstallation = fixturecomposition.Installation

// State is the host; every method is safe for concurrent use.
type State struct {
	mu         sync.RWMutex
	store      *memstore.Store
	svc        *authority.Service
	access     *access.Service
	accessLag  *memstore.Lagged
	attester   *native.Attester
	audience   string
	orgs       map[string]string // id → display name
	people     map[string]Person
	order      []string // people's ids, in the fixture's order
	byToken    map[string]string
	roles      map[string]Role // org/name: the organisation roles the fixture defines
	sessions   map[string]Session
	deliveries map[string]*appliedDelivery // binding → verified record, including withdrawals
	// trustDomain is the run's: the one trust domain the launcher's anchor
	// declares its workloads under when the host starts, or empty when it
	// declares none or several.
	trustDomain string
	// pendingInstalls are fixture installations whose target was not composed
	// when the fixture loaded; each is performed when its target applies.
	pendingInstalls []FixtureInstallation
	// every are the fixture rows standing for every role-gated target, named
	// the rows naming one (org/target), and members what those seat (teams.go).
	every       []FixtureInstallation
	named       map[string]bool
	members     map[string]map[string][]string
	installStep InstallStep
	// Approvals are the artifacts people have consented to: in memory until a
	// run that composes the store swaps in its Postgres (work.go approvalsFor).
	Approvals Approvals
}

type keySet map[string]ed25519.PublicKey

func (k keySet) PublicKeys(context.Context) (map[string]ed25519.PublicKey, error) { return k, nil }

// New returns an empty host that attests workloads against one launcher
// anchor, issuing through the core with cfg's issuer, key id, signer and
// clock. audience is the name the launcher issues credentials to.
func New(anchor native.Anchor, audience string, cfg authority.Config) (*State, error) {
	attester, err := native.NewAttester(anchor)
	if err != nil {
		return nil, fmt.Errorf("launcher anchor: %w", err)
	}
	if cfg.Keys == nil && cfg.Signer != nil {
		public, ok := cfg.Signer.Public().(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("the local authority signs with an Ed25519 key")
		}
		cfg.Keys = keySet{cfg.KeyID: public}
	}
	store := memstore.New()
	var state *State
	cfg.CheckSession = func(ctx context.Context, id string) error {
		state.mu.RLock()
		defer state.mu.RUnlock()
		if session, known := state.sessions[id]; known && (session.Ended || !state.svc.Now().Before(session.ExpiresAt)) {
			return fmt.Errorf("%w: session ended or expired", ErrUnauthenticated)
		}
		return nil
	}
	// An uninstall forgets the installation's access grants in its own
	// transaction: the store carries both, and a reinstall revives none.
	cfg.Journal = access.Journal(cfg.Journal)
	svc, err := authority.New(store, cfg)
	if err != nil {
		return nil, err
	}
	// The access service reads through a reader that only a test ever holds
	// behind the store (FreezeAccessReads); the store is the newest state,
	// which serves every revision minimum the reader has not reached.
	lag := memstore.Lagging(store)
	grants, err := access.New(svc, lag, access.Config{Clock: svc.Now, MinRevisions: true, Primary: store})
	if err != nil {
		return nil, err
	}
	state = &State{store: store, svc: svc, access: grants, accessLag: lag, attester: attester, audience: audience, trustDomain: runTrustDomain(anchor),
		orgs: map[string]string{}, people: map[string]Person{}, byToken: map[string]string{}, roles: map[string]Role{},
		sessions: map[string]Session{}, deliveries: map[string]*appliedDelivery{}, Approvals: &MemoryApprovals{}}
	return state, nil
}

// Service is the core this host issues and decides through.
func (s *State) Service() *authority.Service { return s.svc }

// Access is the access service (codefly.dev/access) over the same core and
// the same in-memory store: grants on a collection, a document or a version.
func (s *State) Access() *access.Service { return s.access }

// FreezeAccessReads holds the access service's reader at the grants as they
// stand now, as a replica that stopped replaying would, until the function it
// answers is called. It exists for the conformance cases that prove a
// decision asked with a revision minimum is never read from an earlier state;
// nothing in a running authority calls it.
func (s *State) FreezeAccessReads() (catchUp func()) {
	s.accessLag.Freeze()
	return s.accessLag.CatchUp
}

// OnInstall sets the install step the host runs for a solution installation.
func (s *State) OnInstall(step InstallStep) { s.installStep = step }

// RunInstallStep runs the host's install step for inst, if one is set.
func (s *State) RunInstallStep(ctx context.Context, inst Installation) error {
	if s.installStep == nil {
		return nil
	}
	return s.installStep(ctx, inst)
}

func (s *State) read(fn func(authority.Tx) error) error {
	return s.store.Read(context.Background(), fn)
}

func (s *State) write(fn func(authority.Tx) error) error {
	return s.store.Write(context.Background(), fn)
}

// LoadFixture seeds organisations, roles, people and delegations, and
// performs the fixture's installations through the install path.
func (s *State) LoadFixture(ctx context.Context, data []byte) error {
	var f fixtureFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("fixture: %w", err)
	}
	s.mu.Lock()
	for _, o := range f.Organizations {
		s.orgs[o.ID] = o.Name
		s.store.PutOrganization(domain.Organization{ID: o.ID, Name: o.Name})
	}
	for _, team := range f.Teams {
		if _, ok := s.orgs[team.Organization]; !ok || team.ID == "" {
			s.mu.Unlock()
			return fmt.Errorf("fixture: team %q names no id or an unknown organization %q", team.ID, team.Organization)
		}
		s.store.PutTeam(team.Organization, team.ID)
	}
	for _, r := range f.Roles {
		if r.Generated || len(r.Scopes.Content) > 0 {
			s.mu.Unlock()
			return fmt.Errorf("fixture: role %s/%s states what it grants (scopes, or generated): an organisation role decides administration only and grants nothing at a module; a person reaches a module through a role on an installation (installations: members)", r.Organization, r.Name)
		}
		s.roles[r.Organization+"/"+r.Name] = Role{Organization: r.Organization, Name: r.Name}
	}
	for _, p := range f.People {
		if _, ok := s.orgs[p.Organization]; !ok {
			s.mu.Unlock()
			return fmt.Errorf("fixture: person %q names unknown organization %q", p.ID, p.Organization)
		}
		for _, role := range p.Roles {
			if _, ok := s.roles[p.Organization+"/"+role]; !ok {
				s.mu.Unlock()
				return fmt.Errorf("fixture: person %q holds unknown role %q", p.ID, role)
			}
		}
		if _, seen := s.people[p.ID]; !seen {
			s.order = append(s.order, p.ID)
		}
		s.people[p.ID] = p
		s.byToken[p.FixtureToken] = p.ID
		s.store.PutPerson(domain.Person{ID: p.ID, Organization: p.Organization, Roles: slices.Clone(p.Roles), Teams: slices.Clone(p.Teams)})
		// The fixture is this host's team directory: a team it seats a person
		// in exists, and teams: lists the ones nobody belongs to yet.
		for _, team := range p.Teams {
			s.store.PutTeam(p.Organization, team)
		}
	}
	s.mu.Unlock()
	for _, d := range f.Delegations {
		if d.ID == "" || d.Grantor == "" || d.Module == "" || d.Organization == "" {
			return fmt.Errorf("delegation %q names no id, grantor, module or organization", d.ID)
		}
		var scopes []*basev0.WorkScopeV1
		for _, sc := range d.Scopes {
			scopes = append(scopes, &basev0.WorkScopeV1{ResourceKind: sc.Kind, Actions: slices.Clone(sc.Actions), ResourceIds: slices.Clone(sc.ResourceIDs)})
		}
		stored := domain.Delegation{ID: d.ID, Organization: d.Organization, Grantor: d.Grantor, Module: d.Module, Purpose: d.Purpose, Scopes: Normalize(scopes)}
		if err := s.write(func(tx authority.Tx) error { return tx.PutDelegation(stored) }); err != nil {
			return err
		}
	}
	// A module composed before its organisations arrived gets its
	// installation at each of them now: delivery order never decides use.
	if err := s.ensureModuleInstallations(); err != nil {
		return err
	}
	for _, i := range f.Installations {
		s.mu.Lock()
		err := s.keepStandingLocked(i)
		s.mu.Unlock()
		if err != nil {
			return err
		}
		if i.Target == EveryTarget {
			continue // installs and seats through SeatRoleTeams, below
		}
		if _, composed := s.Module(i.Target); !composed {
			s.mu.Lock()
			s.pendingInstalls = append(s.pendingInstalls, i)
			s.mu.Unlock()
			continue
		}
		if err := s.performInstall(ctx, i, nil); err != nil {
			return err
		}
	}
	for _, fm := range f.Modules {
		if _, composed := s.Module(fm.Module); composed {
			continue
		}
		m := Manifest{Name: fm.Module, Principal: fm.Module, Kind: domain.KindModule, Generation: 1, Bindings: map[string]Binding{}, StandIn: true}
		for _, k := range fm.Kinds {
			m.ResourceKinds = append(m.ResourceKinds, &basev0.WorkScopeV1{ResourceKind: k.Kind, Actions: slices.Clone(k.Actions)})
		}
		if _, err := s.ApplyManifest(m); err != nil {
			return fmt.Errorf("fixture module %s: %w", m.Name, err)
		}
	}
	_, err := s.SeatRoleTeams(ctx)
	return err
}

// ensureModuleInstallations holds every composed module installed at every
// organisation, through the core.
func (s *State) ensureModuleInstallations() error {
	return s.svc.ReconcileOrganizations(context.Background())
}

// performInstall installs what the fixture names through the core, then
// records its grants: the admin role to its owner, its role to its teams.
// A delivery's intent remembers the revision its first attempt took: a replay
// resumes that attempt, and refuses when the installation was revoked or
// reinstalled since, so a replay never undoes an administrator's act.
func (s *State) performInstall(ctx context.Context, i FixtureInstallation, intent *pendingInstallation) error {
	id := InstallationID(i.Organization, i.Target)
	existing, found := s.Installation(id)
	s.mu.RLock()
	attempted := uint64(0)
	if intent != nil {
		attempted = intent.revision
	}
	s.mu.RUnlock()
	if attempted != 0 && (!found || existing.Status == domain.Revoked || existing.Revision != attempted) {
		return fmt.Errorf("%w: fixture installation attempt %s was revoked or changed", ErrStale, id)
	}
	if !found || existing.Status != domain.Active {
		inst, err := s.svc.InstallAsHost(ctx, i.Organization, i.Target, i.Role, i.Owner, s.installStep)
		if intent != nil && inst.Revision != 0 {
			s.mu.Lock()
			intent.revision = inst.Revision
			s.mu.Unlock()
		}
		if err != nil {
			return fmt.Errorf("fixture installation of %s at %s: %w", i.Target, i.Organization, classify(err))
		}
	}
	// Each grant goes through the core's decision, as an administrator's
	// would: nothing the fixture names is written past it.
	grants := []domain.RoleGrant{{InstallationID: id, Role: AdminRole, PersonID: i.Owner}}
	for _, team := range i.Teams {
		grants = append(grants, domain.RoleGrant{InstallationID: id, Role: i.Role, TeamID: team})
	}
	for _, g := range grants {
		if err := s.grantAsHost(ctx, g); err != nil {
			return fmt.Errorf("fixture installation of %s at %s: %w", i.Target, i.Organization, err)
		}
	}
	return nil
}

// SignIn opens a session for the person holding a fixture token.
func (s *State) SignIn(token string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byToken[token]
	if !ok {
		return Session{}, fmt.Errorf("%w: fixture token", ErrUnknown)
	}
	p := s.people[id]
	name := p.Name
	if name == "" {
		name = p.Email
	}
	sess := Session{PersonDisplayName: name, OrganizationDisplayName: s.orgs[p.Organization], ID: uuid.NewString(), Person: p.ID,
		Organization: p.Organization, Roles: slices.Clone(p.Roles), Teams: slices.Clone(p.Teams), ExpiresAt: s.svc.Now().Add(SessionLifetime)}
	s.sessions[sess.ID] = sess
	return sess, nil
}

// OpenRoleView opens a session that acts as roles of installationID which the
// session parent acts as: the core decides and records it, and this host only
// keeps the session it names, listed as the person's own.
func (s *State) OpenRoleView(ctx context.Context, parent, installationID string, roles []string) (Session, error) {
	caller, err := s.Caller(parent)
	if err != nil {
		return Session{}, err
	}
	sess, _ := s.Session(parent)
	id := uuid.NewString()
	view, err := s.svc.OpenRoleView(ctx, caller, authority.RoleViewRequest{Organization: caller.Organization, InstallationID: installationID, SessionID: id, Roles: roles})
	if err != nil {
		return Session{}, err
	}
	sess.ID, sess.RoleView = id, view.Roles
	s.mu.Lock()
	defer s.mu.Unlock()
	// A parent that ended while the core decided opens no session of its own.
	return s.keepChildLocked(parent, sess)
}

// OpenTeamCast opens a session that acts as a member of team and of nothing
// else. The core decides (a person acts as a team whose roles they could
// grant) and records it; this host only keeps the session it names, which
// holds no role of the person's and no other team of theirs.
func (s *State) OpenTeamCast(ctx context.Context, parent, team string) (Session, error) {
	caller, err := s.Caller(parent)
	if err != nil {
		return Session{}, err
	}
	sess, _ := s.Session(parent)
	id := uuid.NewString()
	cast, err := s.svc.OpenTeamCast(ctx, caller, authority.TeamCastRequest{Organization: caller.Organization, Team: team, SessionID: id})
	if err != nil {
		return Session{}, err
	}
	sess.ID, sess.RoleView, sess.CastTeam, sess.Roles, sess.Teams = id, cast.Roles, cast.Team, nil, []string{cast.Team}
	s.mu.Lock()
	defer s.mu.Unlock()
	// A parent that ended while the core decided opens no session of its own.
	return s.keepChildLocked(parent, sess)
}

// CastableTeams is the teams the session may act as now, with what each
// holds: the core lists them by OpenTeamCast's own rule.
func (s *State) CastableTeams(ctx context.Context, session string) ([]authority.CastableTeam, error) {
	caller, err := s.Caller(session)
	if err != nil {
		return nil, err
	}
	return s.svc.CastableTeams(ctx, caller, caller.Organization)
}

// FixturePeople is every fixture person, in the fixture's order.
func (s *State) FixturePeople() []Person {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Person, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.people[id])
	}
	return out
}

// OrganizationDisplayName is an organisation's name as the fixture spells it,
// or empty for an organisation the fixture does not define.
func (s *State) OrganizationDisplayName(organization string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.orgs[organization]
}

// Session resolves an open session: one that neither ended nor expired.
func (s *State) Session(id string) (Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.openLocked(id)
	if !ok {
		return Session{}, fmt.Errorf("%w: an open session is required", ErrUnauthenticated)
	}
	return sess, nil
}

// LeaveTeam removes person from team: every capability they hold through a
// grant to that team ends at once (the core moves their person epoch).
func (s *State) LeaveTeam(ctx context.Context, person, team string) error {
	s.mu.Lock()
	p, ok := s.people[person]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("%w: person %q", ErrUnknown, person)
	}
	p.Teams = slices.DeleteFunc(slices.Clone(p.Teams), func(t string) bool { return t == team })
	s.people[person] = p
	s.store.PutPerson(domain.Person{ID: p.ID, Organization: p.Organization, Roles: slices.Clone(p.Roles), Teams: slices.Clone(p.Teams)})
	s.mu.Unlock()
	return s.svc.PersonChanged(ctx, person)
}

// JoinTeam puts person in team, a team of their organisation's directory:
// they hold what the team is granted from the next decision (the core moves
// their person epoch). A person already in it is left as they are.
func (s *State) JoinTeam(ctx context.Context, person, team string) error {
	s.mu.RLock()
	p, ok := s.people[person]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: person %q", ErrUnknown, person)
	}
	var exists bool
	if err := s.read(func(tx authority.Tx) (err error) { exists, err = tx.TeamExists(p.Organization, team); return err }); err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: team %q", ErrUnknown, team)
	}
	s.mu.Lock()
	p, ok = s.people[person]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("%w: person %q", ErrUnknown, person)
	}
	if slices.Contains(p.Teams, team) {
		s.mu.Unlock()
		return nil
	}
	p.Teams = append(slices.Clone(p.Teams), team)
	s.people[person] = p
	s.store.PutPerson(domain.Person{ID: p.ID, Organization: p.Organization, Roles: slices.Clone(p.Roles), Teams: slices.Clone(p.Teams)})
	s.mu.Unlock()
	return s.svc.PersonChanged(ctx, person)
}

// ChangeFixtureTeam is the session interface's membership change, for a run
// on its fixture: the person the open session administrator authenticates
// puts person in team (join) or takes them out, in the organisation they are
// signed into. The session is the person's own, never a cast or a role view,
// and they administer the organisation; the person named is a person of it.
func (s *State) ChangeFixtureTeam(ctx context.Context, administrator, team, person string, join bool) error {
	sess, err := s.Session(administrator)
	if err != nil {
		return err
	}
	if sess.Parent != "" || sess.CastTeam != "" || len(sess.RoleView) > 0 {
		return fmt.Errorf("%w: a team's members are changed on a person's own session, never a cast or a role view", ErrForbidden)
	}
	s.mu.RLock()
	caller, signedIn := s.people[sess.Person]
	p, known := s.people[person]
	s.mu.RUnlock()
	// The person's roles now, not the session's snapshot of them.
	if !signedIn || caller.Organization != sess.Organization || !slices.Contains(caller.Roles, AdminRole) {
		return fmt.Errorf("%w: %s does not administer %s", ErrForbidden, sess.Person, sess.Organization)
	}
	if team == "" || person == "" {
		return fmt.Errorf("%w: the call names a team and a person", ErrUnknown)
	}
	// Another organisation's person is as unknown here as one who does not exist.
	if !known || p.Organization != sess.Organization {
		return fmt.Errorf("%w: person %q of %s", ErrUnknown, person, sess.Organization)
	}
	if join {
		return s.JoinTeam(ctx, person, team)
	}
	return s.LeaveTeam(ctx, person, team)
}

// DeleteTeam removes team from organization's directory and from every
// member: what its grants gave ends at once (the core moves each member's
// person epoch), and it is granted nothing more. Its grants stay listed and
// revocable.
func (s *State) DeleteTeam(ctx context.Context, organization, team string) error {
	s.mu.Lock()
	var members []string
	for _, id := range s.order {
		p := s.people[id]
		if p.Organization != organization || !slices.Contains(p.Teams, team) {
			continue
		}
		p.Teams = slices.DeleteFunc(slices.Clone(p.Teams), func(t string) bool { return t == team })
		s.people[id] = p
		s.store.PutPerson(domain.Person{ID: p.ID, Organization: p.Organization, Roles: slices.Clone(p.Roles), Teams: slices.Clone(p.Teams)})
		members = append(members, id)
	}
	s.store.DeleteTeam(organization, team)
	s.mu.Unlock()
	for _, id := range members {
		if err := s.svc.PersonChanged(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// LeaveOrganization removes person: they sign in no more, and every
// capability they hold ends at once.
func (s *State) LeaveOrganization(ctx context.Context, person string) error {
	s.mu.Lock()
	p, ok := s.people[person]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("%w: person %q", ErrUnknown, person)
	}
	delete(s.people, person)
	delete(s.byToken, p.FixtureToken)
	s.order = slices.DeleteFunc(s.order, func(id string) bool { return id == person })
	for id, sess := range s.sessions {
		if sess.Person == person {
			delete(s.sessions, id)
		}
	}
	s.store.DeletePerson(person)
	s.mu.Unlock()
	return s.svc.PersonChanged(ctx, person)
}

// Caller is the person an open session authenticates, as the core takes it.
func (s *State) Caller(sessionID string) (authority.Person, error) {
	sess, err := s.Session(sessionID)
	if err != nil {
		return authority.Person{}, err
	}
	return authority.Person{ID: sess.Person, Organization: sess.Organization, SessionID: sess.ID, ExpiresAt: sess.ExpiresAt, Teams: slices.Clone(sess.Teams)}, nil
}

// ApplyManifest is trusted host fixture setup, never a public request path.
// It records one module instance through the core at a newer generation.
// A module owned by a signed delivery is never replaced by a fixture.
func (s *State) ApplyManifest(m Manifest) ([]string, error) {
	s.mu.Lock()
	for _, record := range s.deliveries {
		held, _ := record.carrier.Manifest()
		if held.Alias == m.Name {
			s.mu.Unlock()
			return nil, fmt.Errorf("%w: %s is owned by signed binding %s; a sketch cannot replace it", ErrForbidden, m.Name, held.Binding)
		}
	}
	ids, pending, err := s.applyManifestLocked(m)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	for _, i := range pending {
		if err := s.performInstall(context.Background(), i, nil); err != nil {
			return nil, err
		}
	}
	if _, err := s.SeatRoleTeams(context.Background()); err != nil {
		return nil, err
	}
	return ids, nil
}

// applyManifestLocked applies m through the core, which refuses an owner
// anywhere in it and joins what its methods require to what it serves.
// Caller holds mu.
func (s *State) applyManifestLocked(m Manifest) ([]string, []FixtureInstallation, error) {
	ids, err := s.svc.ApplyModule(context.Background(), m)
	if err != nil {
		return nil, nil, classify(err)
	}
	return ids, s.takePendingInstalls(m.Name), nil
}

// takePendingInstalls removes and returns the fixture installations waiting
// for target. Caller holds mu.
func (s *State) takePendingInstalls(target string) []FixtureInstallation {
	var mine, keep []FixtureInstallation
	for _, i := range s.pendingInstalls {
		if i.Target == target {
			mine = append(mine, i)
		} else {
			keep = append(keep, i)
		}
	}
	s.pendingInstalls = keep
	return mine
}

// Module returns a composed module by name.
func (s *State) Module(name string) (Manifest, bool) {
	var m Manifest
	err := s.read(func(tx authority.Tx) error {
		var err error
		m, err = tx.ModuleNamed(name)
		return err
	})
	return m, err == nil
}

// ModuleByPrincipal returns the module a principal names.
func (s *State) ModuleByPrincipal(principal string) (Manifest, error) {
	var m Manifest
	err := s.read(func(tx authority.Tx) error {
		var err error
		m, err = tx.Module(principal)
		return err
	})
	if errors.Is(err, domain.ErrNotFound) {
		return m, fmt.Errorf("%w: audience %q is not composed", ErrUnknown, principal)
	}
	return m, err
}

// Installation returns one installation.
func (s *State) Installation(id string) (Installation, bool) {
	var inst Installation
	err := s.read(func(tx authority.Tx) error {
		var err error
		inst, err = tx.Installation(id)
		return err
	})
	return inst, err == nil
}

// InstallAsHost installs a solution as trusted host setup: the
// fixture's path, and a test's.
func (s *State) InstallAsHost(ctx context.Context, org, target, role, owner string) (Installation, error) {
	inst, err := s.svc.InstallAsHost(ctx, org, target, role, owner, s.installStep)
	return inst, classify(err)
}

// classify keeps the core's refusal (its code still answers domain.CodeOf)
// and names its family as this host's callers test it.
func classify(err error) error {
	code, ok := domain.CodeOf(err)
	switch {
	case !ok:
		return err
	case code == domain.Denied:
		return fmt.Errorf("%w: %w", ErrForbidden, err)
	case code == domain.NotFound:
		return fmt.Errorf("%w: %w", ErrUnknown, err)
	case code == domain.Precondition:
		return fmt.Errorf("%w: %w", ErrStale, err)
	}
	return err
}

// UninstallAsHost disables an installation and its principal for trusted host
// teardown: a test's, and the conformance driver's.
func (s *State) UninstallAsHost(id string) error {
	inst, ok := s.Installation(id)
	if !ok {
		return fmt.Errorf("%w: installation %q", ErrUnknown, id)
	}
	return s.svc.UninstallAsHost(context.Background(), inst.Organization, id)
}

// GrantRole grants a role as the host's own setup (no caller): a test's. It
// is decided as every grant is (grantAsHost).
func (s *State) GrantRole(g domain.RoleGrant) error {
	return s.grantAsHost(context.Background(), g)
}

// grantAsHost grants a role with no caller, through the core's one grant
// decision (authority.GrantRoleAsHost), the organization's administrator
// standing as the caller: the installation is installed, the role is one its
// target declares, and the subject is one person or one team of its
// organization. The host writes no grant the decision did not admit, and the
// core journals it as it does an administrator's.
func (s *State) grantAsHost(ctx context.Context, g domain.RoleGrant) error {
	inst, ok := s.Installation(g.InstallationID)
	if !ok {
		return fmt.Errorf("%w: installation %q", ErrUnknown, g.InstallationID)
	}
	_, err := s.svc.GrantRoleAsHost(ctx, authority.RoleRequest{Organization: inst.Organization, InstallationID: g.InstallationID, Role: g.Role, PersonID: g.PersonID, TeamID: g.TeamID})
	return classify(err)
}

// runTrustDomain is the one trust domain every workload anchor declares is
// in: a run's launcher vouches under its environment's host trust domain, so
// it is the host's. Empty when the anchor declares none or more than one.
func runTrustDomain(anchor native.Anchor) string {
	domain := ""
	for _, subject := range anchor.Subjects {
		switch {
		case subject.TrustDomain == "":
			return ""
		case domain == "":
			domain = subject.TrustDomain
		case subject.TrustDomain != domain:
			return ""
		}
	}
	return domain
}

// TrustDomain is the host's trust domain, as the run's anchor declared it
// when the host started; empty when it named no single one.
func (s *State) TrustDomain() string { return s.trustDomain }

// Audience is what this host attests workload credentials for.
func (s *State) Audience() string { return s.audience }

// AttestWorkload attests a native launcher credential with core's attester
// and answers the workload it names, composed module or not: for a caller the
// host knows by workload alone, as the hop registering its admission key.
func (s *State) AttestWorkload(ctx context.Context, credential string) (workloadidentity.Workload, error) {
	attestation, err := s.attester.Attest(ctx, credential, s.audience)
	if err != nil {
		return workloadidentity.Workload{}, fmt.Errorf("%w: workload credential: %v", ErrForbidden, err)
	}
	return attestation.Workload, nil
}

// VerifyWorkload attests a native launcher credential with core's attester
// and resolves the module it names to a composed module; for a signed
// delivery the service must be one of its current declared workloads.
func (s *State) VerifyWorkload(ctx context.Context, credential string) (Manifest, error) {
	attestation, err := s.attester.Attest(ctx, credential, s.audience)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: workload credential: %v", ErrForbidden, err)
	}
	m, ok := s.Module(attestation.Workload.Module)
	if !ok {
		return Manifest{}, fmt.Errorf("%w: module %q is not composed", ErrUnknown, attestation.Workload.Module)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, record := range s.deliveries {
		manifest, err := record.carrier.Manifest()
		if err != nil {
			return Manifest{}, err
		}
		if manifest.Alias != m.Name {
			continue
		}
		if _, listed := manifest.WorkloadNamed(attestation.Workload.Service); !listed || manifest.Removed {
			return Manifest{}, fmt.Errorf("%w: service %q is not a live workload of %s", ErrForbidden, attestation.Workload.Service, m.Name)
		}
	}
	return m, nil
}

// AdmitMethod applies what the module at audience declares for method to the
// scopes a checked call holds: the core's decide.AdmitMethod.
func (s *State) AdmitMethod(audience, method string, held []*basev0.WorkScopeV1) error {
	m, err := s.ModuleByPrincipal(audience)
	if err != nil {
		return err
	}
	return classify(decide.AdmitMethod(m, method, held))
}
