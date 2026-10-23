// Package state is the authority gateway's whole memory: the fixture people and
// roles, the composition as delivered by manifests, the installations and the
// open sessions. It is the seal and revision source core's issuer and verifier
// read, so one struct answers every "is this still true" the authority asks.
package state

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
	"github.com/codefly-dev/core/workloadidentity/native"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// Errors a caller distinguishes.
var (
	ErrUnknown   = errors.New("state: unknown")
	ErrForbidden = errors.New("state: forbidden")
	ErrStale     = errors.New("state: generation is not newer")
)

// Scope is one (kind, actions) pair as the fixture spells it.
type Scope struct {
	Kind    string   `yaml:"kind"`
	Actions []string `yaml:"actions"`
}

// Person is a fixture person.
type Person struct {
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
	Scopes       []Scope `yaml:"scopes"`
}

// Binding is a module's declared call towards another module.
type Binding struct {
	ID             string
	Audience       string
	InvokeScopes   []*basev0.WorkScopeV1
	HeadlessScopes []*basev0.WorkScopeV1
}

// Manifest is what the render delivered for one module instance.
type Manifest struct {
	Module        string
	Principal     string
	Kind          string
	Generation    uint64
	Bindings      map[string]Binding
	ResourceKinds []*basev0.WorkScopeV1
	// Roles are what a solution declares a person may hold on an installation of
	// it, each within what the solution serves. A solution always declares
	// InstallerRole; a module declares none, since a module is installed by
	// composition and a person's access to it is the organisation's roles.
	Roles map[string][]*basev0.WorkScopeV1
	// Methods are what each method the module serves declares a call must hold,
	// from the authority's signed document delivered with the manifest. Nil
	// means the delivery declared no method policy: every check naming one of
	// the module's methods is then refused.
	Methods map[string]MethodPolicy
}

// MethodPolicy is one method's declaration: exactly one of its fields is set.
type MethodPolicy struct {
	Requires         []*basev0.WorkScopeV1
	AnyCheckedCaller bool
}

// AdmitMethod applies what the module at audience declares for method to the
// scopes a checked call holds. A method that declares nothing, or both that it
// requires something and nothing, is refused: an absent or ambiguous
// declaration is never read as permission.
func (s *State) AdmitMethod(audience, method string, held []*basev0.WorkScopeV1) error {
	s.mu.RLock()
	m, err := s.moduleByPrincipal(audience)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	if m.Methods == nil {
		return fmt.Errorf("%w: %s's delivery declares no method policy, so %s is refused", ErrForbidden, audience, method)
	}
	p, ok := m.Methods[method]
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
	var missing []string
	for _, r := range p.Requires {
		for _, action := range r.GetActions() {
			if !holdsAction(held, r.GetResourceKind(), action) {
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

// holdsAction is whether held carries action on kind. A method's requirement is
// on the kind; which resources of it the call may touch is the module's own
// check, against the context it is handed.
func holdsAction(held []*basev0.WorkScopeV1, kind, action string) bool {
	for _, h := range held {
		if h.GetResourceKind() == kind && (slices.Contains(h.GetActions(), action) || slices.Contains(h.GetActions(), AnyAction)) {
			return true
		}
	}
	return false
}

func describe(held []*basev0.WorkScopeV1) string {
	var out []string
	for _, h := range held {
		for _, a := range h.GetActions() {
			out = append(out, h.GetResourceKind()+":"+a)
		}
	}
	if len(out) == 0 {
		return "nothing"
	}
	return strings.Join(out, ", ")
}

// InstallerRole is the role every solution declares: whoever installs it holds
// it on that installation, which is the install-and-configure surface.
const InstallerRole = "installer"

// ErrNoInstallerRole refuses a solution that declares no installer role.
var ErrNoInstallerRole = fmt.Errorf("%w: a solution declares an installer role", ErrForbidden)

// Status is an installation's lifecycle.
type Status string

// The three states.
const (
	Pending Status = "pending"
	Active  Status = "active"
	Revoked Status = "revoked"
)

// Installation is one organisation's installation of one target.
type Installation struct {
	ID           string
	Organization string
	Target       string
	Status       Status
	Revision     uint64
	// Role is the target's role the granted teams hold on this installation.
	Role  string
	Teams []string
	// Owner installed it and holds the target's installer role on it.
	Owner string
}

// AgentPrincipal is the principal an installation acts as for itself.
func (i Installation) AgentPrincipal() string { return i.ID + "/agent" }

// Session is an open sign-in.
type Session struct {
	ID           string
	Person       string
	Organization string
	Roles        []string
	Teams        []string
}

// InstallStep is what the host calls once per installation; it must converge.
type InstallStep func(ctx context.Context, installation Installation) error

type fixtureFile struct {
	Organizations []struct {
		ID   string `yaml:"id"`
		Name string `yaml:"name"`
	} `yaml:"organizations"`
	Roles         []Role                `yaml:"roles"`
	People        []Person              `yaml:"people"`
	Installations []FixtureInstallation `yaml:"installations"`
	// Modules are modules a local run supervises itself rather than composing
	// them through Codefly (a bridge process a playground starts, say), declared
	// so they can be an audience. A delivered manifest of the same module
	// supersedes it; one already composed is left as delivered.
	Modules []FixtureModule `yaml:"modules"`
}

// FixtureModule is one module the fixture composes: its name, which is its
// principal, and the kinds and actions it serves.
type FixtureModule struct {
	Module string  `yaml:"module"`
	Kinds  []Scope `yaml:"kinds"`
}

// FixtureInstallation is one installation the fixture performs through the real
// install path, once its target is composed.
type FixtureInstallation struct {
	Organization string   `yaml:"organization"`
	Target       string   `yaml:"target"`
	Role         string   `yaml:"role"`
	Owner        string   `yaml:"owner"`
	Teams        []string `yaml:"teams"`
}

// State holds everything; every method is safe for concurrent use.
type State struct {
	mu            sync.RWMutex
	orgs          map[string]string
	people        map[string]Person
	byToken       map[string]string
	roles         map[string]Role // org/name
	modules       map[string]Manifest
	principals    map[string]string // principal → module
	installations map[string]Installation
	sessions      map[string]Session
	revisions     map[string]uint64
	attester      *native.Attester
	audience      string
	installStep   InstallStep
	// pendingInstalls are fixture installations whose target was not composed
	// when the fixture loaded; each is performed when its target's manifest applies.
	pendingInstalls []FixtureInstallation
}

// New returns an empty state that attests workloads against one launcher anchor:
// core's native anchor, the issuer name, its public key and the subjects it
// declared, handed to the host as configuration. audience is the name the
// launcher issues credentials to, this host.
func New(anchor native.Anchor, audience string) (*State, error) {
	attester, err := native.NewAttester(anchor)
	if err != nil {
		return nil, fmt.Errorf("launcher anchor: %w", err)
	}
	return &State{
		orgs: map[string]string{}, people: map[string]Person{}, byToken: map[string]string{},
		roles: map[string]Role{}, modules: map[string]Manifest{}, principals: map[string]string{},
		installations: map[string]Installation{}, sessions: map[string]Session{}, revisions: map[string]uint64{},
		attester: attester, audience: audience,
	}, nil
}

// OnInstall sets the install step the host runs for a solution installation.
// Nil acknowledges immediately, which is what a module installation does.
func (s *State) OnInstall(step InstallStep) { s.installStep = step }

// LoadFixture seeds organisations, roles, people and installations from YAML.
// Installations in the fixture are performed through Install, never written.
func (s *State) LoadFixture(ctx context.Context, data []byte) error {
	var f fixtureFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("fixture: %w", err)
	}
	s.mu.Lock()
	for _, o := range f.Organizations {
		s.orgs[o.ID] = o.Name
	}
	// A module composed before its organisations arrived gets its installation
	// at each of them now; order of delivery must not decide what is usable.
	for _, m := range s.modules {
		s.ensureModuleInstallations(m)
	}
	for _, r := range f.Roles {
		s.roles[r.Organization+"/"+r.Name] = r
	}
	var fixtureModules []Manifest
	for _, fm := range f.Modules {
		if _, composed := s.modules[fm.Module]; composed {
			continue
		}
		m := Manifest{Module: fm.Module, Principal: fm.Module, Kind: "module", Generation: 1, Bindings: map[string]Binding{}}
		for _, k := range fm.Kinds {
			m.ResourceKinds = append(m.ResourceKinds, &basev0.WorkScopeV1{ResourceKind: k.Kind, Actions: append([]string(nil), k.Actions...)})
		}
		fixtureModules = append(fixtureModules, m)
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
		s.people[p.ID] = p
		s.byToken[p.FixtureToken] = p.ID
	}
	s.mu.Unlock()
	for _, i := range f.Installations {
		if _, composed := s.modules[i.Target]; !composed {
			// On a running service composition arrives by delivery after the
			// fixture loads; the installation waits for its target's manifest.
			s.pendingInstalls = append(s.pendingInstalls, i)
			continue
		}
		inst, err := s.Install(ctx, i.Organization, i.Target, i.Role, i.Owner)
		if err != nil {
			return err
		}
		for _, team := range i.Teams {
			if _, err := s.GrantToTeam(ctx, i.Organization, inst.ID, team); err != nil {
				return err
			}
		}
	}
	for _, m := range fixtureModules {
		if _, err := s.ApplyManifest(m); err != nil {
			return fmt.Errorf("fixture module %s: %w", m.Module, err)
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
	sess := Session{ID: uuid.NewString(), Person: p.ID, Organization: p.Organization, Roles: append([]string(nil), p.Roles...), Teams: append([]string(nil), p.Teams...)}
	s.sessions[sess.ID] = sess
	return sess, nil
}

// Session resolves an open session.
func (s *State) Session(id string) (Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok {
		return Session{}, fmt.Errorf("%w: session", ErrUnknown)
	}
	return sess, nil
}

// PersonScopes is what a person holds at one module: the union of their roles'
// scopes intersected with the module's declared resource kinds.
func (s *State) PersonScopes(person, audience string) ([]*basev0.WorkScopeV1, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.people[person]
	if !ok {
		return nil, fmt.Errorf("%w: person", ErrUnknown)
	}
	m, err := s.moduleByPrincipal(audience)
	if err != nil {
		return nil, err
	}
	var held []*basev0.WorkScopeV1
	if m.Kind == "solution" {
		// A person's access to a solution is the role its installation grants
		// her: the installer role as its owner, the installation's role through
		// a granted team. Nothing from the organisation's roles.
		for _, i := range s.entitled(p) {
			if i.Target != m.Module {
				continue
			}
			if i.Owner == person {
				held = append(held, m.Roles[InstallerRole]...)
			}
			for _, t := range i.Teams {
				if slices.Contains(p.Teams, t) {
					held = append(held, m.Roles[i.Role]...)
				}
			}
		}
		return Intersect(Normalize(held), m.ResourceKinds), nil
	}
	for _, name := range p.Roles {
		for _, sc := range s.roles[p.Organization+"/"+name].Scopes {
			if sc.Kind == AnyKind {
				for _, kind := range m.ResourceKinds {
					held = append(held, &basev0.WorkScopeV1{ResourceKind: kind.GetResourceKind(), Actions: append([]string(nil), sc.Actions...)})
				}
				continue
			}
			held = append(held, &basev0.WorkScopeV1{ResourceKind: sc.Kind, Actions: append([]string(nil), sc.Actions...)})
		}
	}
	return Intersect(Normalize(held), m.ResourceKinds), nil
}

// ApplyManifest records one module instance at a newer generation and holds a
// module installation at every organisation, so a module is usable without a
// click. A lower or equal generation is refused.
func (s *State) ApplyManifest(m Manifest) ([]string, error) {
	if err := validateRoles(m); err != nil {
		return nil, err
	}
	if m.Module == "" || m.Principal == "" || m.Generation == 0 {
		return nil, fmt.Errorf("%w: a manifest names its module, its principal and a generation", ErrForbidden)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.modules[m.Module]; ok && prev.Generation >= m.Generation {
		return nil, fmt.Errorf("%w: %s is at %d, got %d", ErrStale, m.Module, prev.Generation, m.Generation)
	}
	if other, ok := s.principals[m.Principal]; ok && other != m.Module {
		return nil, fmt.Errorf("%w: principal %q already belongs to %s", ErrForbidden, m.Principal, other)
	}
	for id, b := range m.Bindings {
		if !Attenuates(b.HeadlessScopes, b.InvokeScopes) {
			return nil, fmt.Errorf("%w: binding %s: headless scopes exceed invoke scopes", ErrForbidden, id)
		}
	}
	m.ResourceKinds = Normalize(m.ResourceKinds)
	s.modules[m.Module] = m
	s.principals[m.Principal] = m.Module
	ids := s.ensureModuleInstallations(m)
	pending := s.takePendingInstalls(m.Module)
	s.mu.Unlock()
	defer s.mu.Lock()
	if err := s.performPendingInstalls(pending); err != nil {
		return nil, err
	}
	return ids, nil
}

// takePendingInstalls removes and returns the fixture installations waiting for
// this target; the caller holds the lock.
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

// performPendingInstalls installs what the fixture asked for a target that has
// just composed, through the real install path and its team grants; the caller
// holds no lock.
func (s *State) performPendingInstalls(pending []FixtureInstallation) error {
	for _, i := range pending {
		inst, err := s.Install(context.Background(), i.Organization, i.Target, i.Role, i.Owner)
		if err != nil {
			return fmt.Errorf("fixture installation of %s at %s: %w", i.Target, i.Organization, err)
		}
		for _, team := range i.Teams {
			if _, err := s.GrantToTeam(context.Background(), i.Organization, inst.ID, team); err != nil {
				return fmt.Errorf("fixture grant of %s to %s: %w", inst.ID, team, err)
			}
		}
	}
	return nil
}

// ensureModuleInstallations holds a module installation at every organisation;
// a solution is installed explicitly. Caller holds the lock.
func (s *State) ensureModuleInstallations(m Manifest) []string {
	if m.Kind == "solution" {
		return nil
	}
	var ids []string
	for org := range s.orgs {
		id := org + "/" + m.Module
		if _, ok := s.installations[id]; !ok {
			s.installations[id] = Installation{ID: id, Organization: org, Target: m.Module, Status: Active, Revision: 1}
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Module returns a composed module by name.
func (s *State) Module(name string) (Manifest, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.modules[name]
	return m, ok
}

// ModuleByPrincipal returns the module a principal names.
func (s *State) ModuleByPrincipal(principal string) (Manifest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.moduleByPrincipal(principal)
}

func (s *State) moduleByPrincipal(principal string) (Manifest, error) {
	name, ok := s.principals[principal]
	if !ok {
		return Manifest{}, fmt.Errorf("%w: audience %q is not composed", ErrUnknown, principal)
	}
	return s.modules[name], nil
}

// Install composes an installation: pending until the install step is acknowledged.
func (s *State) Install(ctx context.Context, org, target, role, owner string) (Installation, error) {
	s.mu.Lock()
	if _, ok := s.orgs[org]; !ok {
		s.mu.Unlock()
		return Installation{}, fmt.Errorf("%w: organization %q", ErrUnknown, org)
	}
	target_, ok := s.modules[target]
	if !ok || target_.Kind != "solution" {
		s.mu.Unlock()
		return Installation{}, fmt.Errorf("%w: %q is not a composed solution; a module is installed by composition", ErrUnknown, target)
	}
	if _, ok := target_.Roles[role]; !ok {
		s.mu.Unlock()
		return Installation{}, fmt.Errorf("%w: role %q is not one %s declares", ErrUnknown, role, target)
	}
	if p, ok := s.people[owner]; !ok || p.Organization != org {
		s.mu.Unlock()
		return Installation{}, fmt.Errorf("%w: owner %q is not a member of %s", ErrForbidden, owner, org)
	}
	id := org + "/" + target
	if existing, ok := s.installations[id]; ok && existing.Status != Revoked {
		s.mu.Unlock()
		return Installation{}, fmt.Errorf("%w: %s is already installed at %s", ErrForbidden, target, org)
	}
	inst := Installation{ID: id, Organization: org, Target: target, Status: Pending, Revision: 1, Role: role, Owner: owner}
	s.installations[id] = inst
	s.revisions[org]++
	step := s.installStep
	s.mu.Unlock()
	if step == nil {
		return s.Acknowledge(id)
	}
	if err := step(ctx, inst); err != nil {
		return inst, fmt.Errorf("install step for %s: %w", id, err)
	}
	return s.Acknowledge(id)
}

// Acknowledge records that the target's install step completed.
func (s *State) Acknowledge(id string) (Installation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inst, ok := s.installations[id]
	if !ok {
		return Installation{}, fmt.Errorf("%w: installation %q", ErrUnknown, id)
	}
	if inst.Status == Pending {
		inst.Status = Active
		s.installations[id] = inst
	}
	return inst, nil
}

// GrantToTeam exposes an installation to a team; the authorization revision moves.
// org, when given, must be the installation's own: a grant names the
// organisation it is made in, as an administrator's act does.
func (s *State) GrantToTeam(_ context.Context, org, id, team string) (Installation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inst, ok := s.installations[id]
	if !ok || inst.Status == Revoked {
		return Installation{}, fmt.Errorf("%w: installation %q", ErrUnknown, id)
	}
	if org != "" && org != inst.Organization {
		return Installation{}, fmt.Errorf("%w: installation %s is not at organization %q", ErrForbidden, id, org)
	}
	for _, t := range inst.Teams {
		if t == team {
			return inst, nil
		}
	}
	inst.Teams = append(inst.Teams, team)
	inst.Revision++
	s.installations[id] = inst
	s.revisions[inst.Organization]++
	return inst, nil
}

// Revoke uninstalls; every capability sealed to the installation is refused next check.
func (s *State) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	inst, ok := s.installations[id]
	if !ok {
		return fmt.Errorf("%w: installation %q", ErrUnknown, id)
	}
	inst.Status = Revoked
	inst.Revision++
	s.installations[id] = inst
	s.revisions[inst.Organization]++
	return nil
}

// Installation returns one installation.
func (s *State) Installation(id string) (Installation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i, ok := s.installations[id]
	return i, ok
}

// List answers what one organisation has installed, sorted by id.
func (s *State) List(org string) []Installation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Installation
	for _, i := range s.installations {
		if i.Organization == org {
			out = append(out, i)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out
}

// Entitled lists the active solution installations a person may use: those
// granted to a team they belong to. This is the navigation.
func (s *State) Entitled(person string) []Installation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.people[person]
	if !ok {
		return nil
	}
	return s.entitled(p)
}

func (s *State) entitled(p Person) []Installation {
	person := p.ID
	var out []Installation
	for _, i := range s.installations {
		if i.Organization != p.Organization || i.Status != Active || i.Role == "" {
			continue
		}
		if i.Owner == person {
			out = append(out, i)
			continue
		}
		for _, t := range i.Teams {
			for _, mine := range p.Teams {
				if t == mine {
					out = append(out, i)
					goto next
				}
			}
		}
	next:
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out
}

// RoleScopes is what a role grants, as scopes.
func (s *State) RoleScopes(org, role string) []*basev0.WorkScopeV1 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*basev0.WorkScopeV1
	for _, sc := range s.roles[org+"/"+role].Scopes {
		out = append(out, &basev0.WorkScopeV1{ResourceKind: sc.Kind, Actions: append([]string(nil), sc.Actions...)})
	}
	return Normalize(out)
}

// VerifyWorkload attests a native launcher credential with core's attester and
// resolves the module it names to a composed module. The credential format, the
// signature check, the audience and the window are core's, the same the host
// runs; this state adds only "is that module composed here".
func (s *State) VerifyWorkload(ctx context.Context, credential string) (Manifest, error) {
	attestation, err := s.attester.Attest(ctx, credential, s.audience)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: workload credential: %v", ErrForbidden, err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.modules[attestation.Workload.Module]
	if !ok {
		return Manifest{}, fmt.Errorf("%w: module %q is not composed", ErrUnknown, attestation.Workload.Module)
	}
	return m, nil
}

// --- core's seal and revision sources ---------------------------------------

// Seal answers for a principal's use of an installation: the installation must
// be active and the principal must be a member of its organisation, a composed
// module, or the installation's own agent.
func (s *State) Seal(_ context.Context, principalID, installationID string) (workcontext.Seal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inst, ok := s.installations[installationID]
	if !ok || inst.Status != Active {
		return workcontext.Seal{}, workcontext.ErrNoSeal
	}
	switch {
	case principalID == inst.AgentPrincipal():
	case s.isModulePrincipal(principalID):
	case s.isMember(principalID, inst.Organization):
	default:
		return workcontext.Seal{}, workcontext.ErrNoSeal
	}
	return workcontext.Seal{InstallationID: inst.ID, InstallationRevision: inst.Revision}, nil
}

// PrincipalEpoch is a module's generation, and 1 for a person or an agent.
func (s *State) PrincipalEpoch(_ context.Context, principalID string) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if name, ok := s.principals[principalID]; ok {
		return s.modules[name].Generation, nil
	}
	if _, ok := s.people[principalID]; ok {
		return 1, nil
	}
	if id, ok := strings.CutSuffix(principalID, "/agent"); ok {
		if inst, ok := s.installations[id]; ok && inst.Status == Active {
			return 1, nil
		}
	}
	return 0, fmt.Errorf("%w: principal %q", ErrUnknown, principalID)
}

// OperationBinding resolves "<org>/<module>/<binding>" from the manifests.
func (s *State) OperationBinding(_ context.Context, bindingID string) (workcontext.OperationBinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	parts := strings.SplitN(bindingID, "/", 3)
	if len(parts) != 3 {
		return workcontext.OperationBinding{}, workcontext.ErrNoBinding
	}
	m, ok := s.modules[parts[1]]
	if !ok {
		return workcontext.OperationBinding{}, workcontext.ErrNoBinding
	}
	if _, ok := m.Bindings[parts[2]]; !ok {
		return workcontext.OperationBinding{}, workcontext.ErrNoBinding
	}
	inst, ok := s.installations[parts[0]+"/"+parts[1]]
	if !ok {
		return workcontext.OperationBinding{}, workcontext.ErrNoBinding
	}
	return workcontext.OperationBinding{
		ID: bindingID, PrincipalID: m.Principal, InstallationID: inst.ID,
		Revision: m.Generation, Incarnation: 1, Revoked: inst.Status == Revoked,
	}, nil
}

// Grant answers core's grant source: the authority gateway issues no approval grants,
// so every grant capability is refused by name rather than skipped.
func (s *State) Grant(_ context.Context, grantID string) (*workcontext.Grant, error) {
	return nil, fmt.Errorf("%w: grant %q (the authority gateway issues no approval grants)", ErrUnknown, grantID)
}

// AuthorizationRevision is per organisation and moves on every grant change.
func (s *State) AuthorizationRevision(_ context.Context, tenantID string) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.orgs[tenantID]; !ok {
		return 0, fmt.Errorf("%w: organization %q", ErrUnknown, tenantID)
	}
	return s.revisions[tenantID] + 1, nil
}

func (s *State) isModulePrincipal(p string) bool { _, ok := s.principals[p]; return ok }
func (s *State) isMember(p, org string) bool {
	person, ok := s.people[p]
	return ok && person.Organization == org
}

// --- scope algebra ------------------------------------------------------------

// Normalize merges duplicate kinds and sorts actions, the shape core requires.
func Normalize(in []*basev0.WorkScopeV1) []*basev0.WorkScopeV1 {
	byKind := map[string]map[string]bool{}
	for _, sc := range in {
		if sc == nil || sc.GetResourceKind() == "" {
			continue
		}
		if byKind[sc.GetResourceKind()] == nil {
			byKind[sc.GetResourceKind()] = map[string]bool{}
		}
		for _, a := range sc.GetActions() {
			byKind[sc.GetResourceKind()][a] = true
		}
	}
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	out := make([]*basev0.WorkScopeV1, 0, len(kinds))
	for _, k := range kinds {
		actions := make([]string, 0, len(byKind[k]))
		for a := range byKind[k] {
			actions = append(actions, a)
		}
		sort.Strings(actions)
		out = append(out, &basev0.WorkScopeV1{ResourceKind: k, Actions: actions})
	}
	return out
}

// Intersect keeps, per kind, the actions present in both.
// AnyAction, on a module's declared resource kind, serves whatever actions the
// roles grant on that kind: core's manifest names kinds and not actions. On a
// role's scope it grants every action the audience serves on that kind.
const AnyAction = "*"

// AnyKind, on a role's scope, grants its actions on every kind the audience
// module serves: a local developer's role, written without naming any module.
const AnyKind = "*"

func Intersect(a, b []*basev0.WorkScopeV1) []*basev0.WorkScopeV1 {
	allowed := map[string]map[string]bool{}
	for _, sc := range Normalize(b) {
		allowed[sc.GetResourceKind()] = map[string]bool{}
		for _, act := range sc.GetActions() {
			allowed[sc.GetResourceKind()][act] = true
		}
	}
	var out []*basev0.WorkScopeV1
	for _, sc := range Normalize(a) {
		var actions []string
		for _, act := range sc.GetActions() {
			if allowed[sc.GetResourceKind()][act] || allowed[sc.GetResourceKind()][AnyAction] {
				actions = append(actions, act)
			} else if act == AnyAction {
				// a role granting every action holds what the audience serves
				for served := range allowed[sc.GetResourceKind()] {
					actions = append(actions, served)
				}
			}
		}
		if len(actions) > 0 {
			out = append(out, &basev0.WorkScopeV1{ResourceKind: sc.GetResourceKind(), Actions: actions})
		}
	}
	return out
}

// Attenuates reports whether every scope in narrow is within wide.
func Attenuates(narrow, wide []*basev0.WorkScopeV1) bool {
	n := Normalize(narrow)
	return len(Intersect(n, wide)) == len(n) && sameActions(Intersect(n, wide), n)
}

func sameActions(a, b []*basev0.WorkScopeV1) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].GetResourceKind() != b[i].GetResourceKind() || strings.Join(a[i].GetActions(), ",") != strings.Join(b[i].GetActions(), ",") {
			return false
		}
	}
	return true
}

// validateRoles holds a solution to its role contract: it declares an installer
// role, and every role stays within what the solution serves. A module declares
// no roles.
func validateRoles(m Manifest) error {
	if m.Kind != "solution" {
		if len(m.Roles) > 0 {
			return fmt.Errorf("%w: module %q declares roles; a module's access is the organisation's roles", ErrForbidden, m.Module)
		}
		return nil
	}
	if _, ok := m.Roles[InstallerRole]; !ok {
		return fmt.Errorf("%w: %s declares %d role(s) and none is %q", ErrNoInstallerRole, m.Module, len(m.Roles), InstallerRole)
	}
	for name, scopes := range m.Roles {
		if len(scopes) == 0 {
			return fmt.Errorf("%w: role %q of %s grants nothing", ErrForbidden, name, m.Module)
		}
		if !Attenuates(scopes, m.ResourceKinds) {
			return fmt.Errorf("%w: role %q of %s grants beyond what %s serves", ErrForbidden, name, m.Module, m.Module)
		}
	}
	return nil
}
