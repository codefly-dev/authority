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
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/memstore"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	resources "github.com/codefly-dev/authority/libraries/resources/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workloadidentity/native"
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

// Scope is one (kind, actions) pair as the fixture spells it, optionally
// narrowed to named resources. With no resources it covers every resource of
// the kind.
type Scope struct {
	Kind      string          `yaml:"kind"`
	Actions   []string        `yaml:"actions"`
	Resources []ResourceMatch `yaml:"resources"`
}

// ResourceMatch is one resource grant as the fixture spells it: exactly one of
// every resource, one id, an id prefix or a pattern (libraries/resources).
type ResourceMatch struct {
	All     bool   `yaml:"all"`
	ID      string `yaml:"id"`
	Prefix  string `yaml:"prefix"`
	Pattern string `yaml:"pattern"`
}

// Grant is the match as the shared library evaluates it.
func (r ResourceMatch) Grant() resources.Grant {
	return resources.Grant{All: r.All, ID: r.ID, Prefix: r.Prefix, Pattern: r.Pattern}
}

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

// Role is a named set of scopes at one organisation.
type Role struct {
	Organization string  `yaml:"organization"`
	Name         string  `yaml:"name"`
	Generated    bool    `yaml:"generated,omitempty"`
	Scopes       []Scope `yaml:"scopes"`
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

// The installation states, the reserved role and the wildcards.
const (
	Pending       = domain.Pending
	Active        = domain.Active
	Revoked       = domain.Revoked
	InstallerRole = domain.InstallerRole
	AnyAction     = scope.AnyAction
	AnyKind       = scope.AnyKind
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
func Namespace(i Installation) string { return i.Organization + "." + i.Target }

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
}

type fixtureFile struct {
	Organizations []struct {
		ID   string `yaml:"id"`
		Name string `yaml:"name"`
	} `yaml:"organizations"`
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
type FixtureModule struct {
	Module string  `yaml:"module"`
	Kinds  []Scope `yaml:"kinds"`
}

// FixtureInstallation is one installation the fixture performs through the
// real install path, once its target is composed: Role is the installation's
// own (its agent's), Owner installed it and is granted the installer role,
// and each of Teams is granted Role.
type FixtureInstallation struct {
	Organization string   `yaml:"organization"`
	Target       string   `yaml:"target"`
	Role         string   `yaml:"role"`
	Owner        string   `yaml:"owner"`
	Teams        []string `yaml:"teams"`
}

// State is the host; every method is safe for concurrent use.
type State struct {
	mu         sync.RWMutex
	store      *memstore.Store
	svc        *authority.Service
	attester   *native.Attester
	audience   string
	orgs       map[string]string // id → display name
	people     map[string]Person
	order      []string // people's ids, in the fixture's order
	byToken    map[string]string
	roles      map[string]Role // org/name, as authored, the generated developer role included
	sessions   map[string]Session
	deliveries map[string]*appliedDelivery // binding → verified record, including withdrawals
	// pendingInstalls are fixture installations whose target was not composed
	// when the fixture loaded; each is performed when its target applies.
	pendingInstalls []FixtureInstallation
	installStep     InstallStep
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
	svc, err := authority.New(store, cfg)
	if err != nil {
		return nil, err
	}
	return &State{store: store, svc: svc, attester: attester, audience: audience,
		orgs: map[string]string{}, people: map[string]Person{}, byToken: map[string]string{}, roles: map[string]Role{},
		sessions: map[string]Session{}, deliveries: map[string]*appliedDelivery{}, Approvals: &MemoryApprovals{}}, nil
}

// Service is the core this host issues and decides through.
func (s *State) Service() *authority.Service { return s.svc }

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
	for _, r := range f.Roles {
		if r.Generated && (r.Name != "developer" || len(r.Scopes) != 0) {
			s.mu.Unlock()
			return fmt.Errorf("fixture: generated role must be developer with no authored scopes")
		}
		if err := compileScopes(r); err != nil {
			s.mu.Unlock()
			return err
		}
		s.roles[r.Organization+"/"+r.Name] = r
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
	}
	s.refreshRolesLocked()
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
	return nil
}

func compileScopes(r Role) error {
	for _, sc := range r.Scopes {
		grants := make([]resources.Grant, 0, len(sc.Resources))
		for _, m := range sc.Resources {
			grants = append(grants, m.Grant())
		}
		if _, err := resources.Compile(grants); err != nil {
			return fmt.Errorf("role %s/%s scope %s: %w", r.Organization, r.Name, sc.Kind, err)
		}
	}
	return nil
}

// ensureModuleInstallations holds a module installation at every organisation.
func (s *State) ensureModuleInstallations() error {
	return s.write(func(tx authority.Tx) error {
		modules, err := tx.Modules()
		if err != nil {
			return err
		}
		orgs, err := tx.Organizations()
		if err != nil {
			return err
		}
		for _, m := range modules {
			if m.Kind == domain.KindSolution {
				continue
			}
			for _, org := range orgs {
				id := InstallationID(org.ID, m.Name)
				if _, err := tx.Installation(id); errors.Is(err, domain.ErrNotFound) {
					if err := tx.PutInstallation(domain.Installation{ID: id, Organization: org.ID, Target: m.Name, Status: domain.Active, Revision: 1}); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

// performInstall installs what the fixture names through the core, then
// records its grants: the installer role to its owner, its role to its teams.
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
	grants := []domain.RoleGrant{{InstallationID: id, Role: InstallerRole, PersonID: i.Owner}}
	for _, team := range i.Teams {
		grants = append(grants, domain.RoleGrant{InstallationID: id, Role: i.Role, TeamID: team})
	}
	return s.write(func(tx authority.Tx) error {
		for _, g := range grants {
			if err := tx.PutRoleGrant(g); err != nil {
				return err
			}
		}
		return nil
	})
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
		Organization: p.Organization, Roles: slices.Clone(p.Roles), Teams: slices.Clone(p.Teams)}
	s.sessions[sess.ID] = sess
	return sess, nil
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

// Session resolves an open session.
func (s *State) Session(id string) (Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
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
	return authority.Person{ID: sess.Person, Organization: sess.Organization, SessionID: sess.ID, Teams: slices.Clone(sess.Teams)}, nil
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
	return ids, nil
}

// applyManifestLocked applies m through the core, what its methods require
// joined to what it serves. Caller holds mu.
func (s *State) applyManifestLocked(m Manifest) ([]string, []FixtureInstallation, error) {
	if err := noOwners(m); err != nil {
		return nil, nil, err
	}
	m.ResourceKinds = Normalize(append(slices.Clone(m.ResourceKinds), servedByMethods(m.Methods)...))
	ids, err := s.svc.ApplyModule(context.Background(), m)
	if err != nil {
		return nil, nil, classify(err)
	}
	s.refreshRolesLocked()
	return ids, s.takePendingInstalls(m.Name), nil
}

// noOwners refuses a delivery naming a resource owner where none belongs: in
// what a module serves, in a binding's scopes, in a role or in a method's
// requirement. An owner is the authority's to select per installation; read
// owner-blind, it would widen to the whole kind, so it is refused by name.
func noOwners(m Manifest) error {
	check := func(where string, scopes []*basev0.WorkScopeV1) error {
		for _, sc := range scopes {
			if sc.GetResourceOwnerId() != "" {
				return fmt.Errorf("%w: %s: %s names resource owner %q; a delivery never selects an owner", ErrForbidden, where, sc.GetResourceKind(), sc.GetResourceOwnerId())
			}
		}
		return nil
	}
	if err := check(m.Name+" serves", m.ResourceKinds); err != nil {
		return err
	}
	for _, id := range slices.Sorted(maps.Keys(m.Bindings)) {
		b := m.Bindings[id]
		for _, scopes := range [][]*basev0.WorkScopeV1{b.InvokeScopes, b.HeadlessScopes, b.LookupScopes} {
			if err := check(m.Name+" binding "+id, scopes); err != nil {
				return err
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(m.Roles)) {
		if err := check(m.Name+" role "+name, m.Roles[name]); err != nil {
			return err
		}
	}
	for _, method := range slices.Sorted(maps.Keys(m.Methods)) {
		if err := check(m.Name+" method "+method, m.Methods[method].Requires); err != nil {
			return err
		}
	}
	return nil
}

// servedByMethods is every (kind, action) a module's methods require of a
// call: what the module serves, read from its own method declarations.
func servedByMethods(methods map[string]MethodPolicy) []*basev0.WorkScopeV1 {
	var served []*basev0.WorkScopeV1
	for _, policy := range methods {
		for _, required := range policy.Requires {
			served = append(served, &basev0.WorkScopeV1{ResourceKind: required.GetResourceKind(), Actions: slices.Clone(required.GetActions())})
		}
	}
	return served
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

// GrantRole grants a role as the host's own setup (no caller): a test's.
func (s *State) GrantRole(g domain.RoleGrant) error {
	return s.write(func(tx authority.Tx) error { return tx.PutRoleGrant(g) })
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
// scopes a checked call holds. A method that declares nothing, or both that it
// requires something and nothing, is refused: an absent or ambiguous
// declaration is never read as permission.
func (s *State) AdmitMethod(audience, method string, held []*basev0.WorkScopeV1) error {
	m, err := s.ModuleByPrincipal(audience)
	if err != nil {
		return err
	}
	return admitMethod(m, audience, method, held)
}

func admitMethod(m Manifest, audience, method string, held []*basev0.WorkScopeV1) error {
	var err error
	if m.Methods == nil {
		return fmt.Errorf("%w: %s's delivery declares no method policy, so %s is refused", ErrForbidden, audience, method)
	}
	p, ok := m.Methods[method]
	if !ok {
		if p, ok, err = routeOf(m.Methods, method); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrForbidden, audience, err)
		}
	}
	switch {
	case !ok:
		return fmt.Errorf("%w: %s serves no method %s", ErrUnknown, audience, method)
	case p.AnyCheckedCaller && len(p.Requires) > 0:
		return fmt.Errorf("%w: %s declares for %s both that it requires scopes and that it requires none", ErrForbidden, audience, method)
	case p.AnyCheckedCaller:
		return nil
	case len(p.Requires) == 0:
		return fmt.Errorf("%w: %s declares no policy for %s", ErrForbidden, audience, method)
	}
	// Method admission checks the kind and action; the module still checks
	// each resource, and its owner, against the unchanged scopes.
	var missing []string
	for _, r := range p.Requires {
		for _, action := range r.GetActions() {
			if !HoldsAction(held, r.GetResourceKind(), action) {
				missing = append(missing, r.GetResourceKind()+":"+action)
			}
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s requires %s for %s, which the call does not hold (it holds %s)",
			ErrForbidden, audience, strings.Join(missing, ", "), method, describe(held))
	}
	return nil
}

// routeOf is the route a module declares that an HTTP request "<VERB> <path>"
// is for; two templates matching one path is an ambiguous declaration,
// refused rather than guessed between.
func routeOf(methods map[string]MethodPolicy, request string) (MethodPolicy, bool, error) {
	verb, path, ok := strings.Cut(request, " ")
	if !ok || !strings.HasPrefix(path, "/") {
		return MethodPolicy{}, false, nil
	}
	var found []string
	for declared := range methods {
		if v, template, ok := strings.Cut(declared, " "); ok && v == verb && routing.RouteMatches(template, path) {
			found = append(found, declared)
		}
	}
	switch len(found) {
	case 0:
		return MethodPolicy{}, false, nil
	case 1:
		return methods[found[0]], true, nil
	}
	slices.Sort(found)
	return MethodPolicy{}, false, fmt.Errorf("%s matches more than one declared route (%s)", request, strings.Join(found, ", "))
}

func describe(held []*basev0.WorkScopeV1) string {
	var out []string
	for _, h := range held {
		for _, a := range h.GetActions() {
			permission := h.GetResourceKind() + ":" + a
			switch {
			case h.GetResourceOwnerId() != "":
				permission += " (owner-selected)"
			case len(h.GetResourceIds()) > 0:
				permission += " (resource-limited)"
			}
			out = append(out, permission)
		}
	}
	if len(out) == 0 {
		return "nothing"
	}
	return strings.Join(out, ", ")
}
