// Package state is the authority gateway's whole memory: the fixture people and
// roles, the composition as delivered by manifests, the installations and the
// open sessions. It is the seal and revision source core's issuer and verifier
// read, so one struct answers every "is this still true" the authority asks.
package state

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	delivery "github.com/codefly-dev/authority/libraries/delivery/go"
	resources "github.com/codefly-dev/authority/libraries/resources/go"
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

// Binding is a module's declared call towards another module.
type Binding struct {
	ID             string
	Audience       string
	InvokeScopes   []*basev0.WorkScopeV1
	HeadlessScopes []*basev0.WorkScopeV1
	// LookupScopes are what a receipt lookup through the binding may read.
	LookupScopes []*basev0.WorkScopeV1
}

// DelegationScope preserves the exact resource ceiling of a WorkScope.
// Role matchers are a separate contract; a delegation names IDs, not patterns.
type DelegationScope struct {
	Kind        string   `yaml:"kind"`
	Actions     []string `yaml:"actions"`
	ResourceIDs []string `yaml:"resource_ids,omitempty"`
}

// Refuse role-matcher syntax instead of silently decoding a restricted grant
// as an unrestricted one. Fixture decoding otherwise permits unknown fields.
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

// Delegation is a person's grant to a module to act for them beyond any
// session, on scopes they hold. Every capability issued from it is the
// grantor's, re-checked against what the grantor holds at the time.
type Delegation struct {
	ID           string            `yaml:"id"`
	Organization string            `yaml:"organization"`
	Grantor      string            `yaml:"grantor"`
	Module       string            `yaml:"module"`
	Purpose      string            `yaml:"purpose"`
	Scopes       []DelegationScope `yaml:"scopes"`
	Revoked      bool              `yaml:"-"`
}

// WorkScopes is the delegation's scopes as core spells them.
func (d Delegation) WorkScopes() []*basev0.WorkScopeV1 {
	var out []*basev0.WorkScopeV1
	for _, sc := range d.Scopes {
		out = append(out, &basev0.WorkScopeV1{
			ResourceKind: sc.Kind, Actions: append([]string(nil), sc.Actions...),
			ResourceIds: append([]string(nil), sc.ResourceIDs...),
		})
	}
	return Normalize(out)
}

// Manifest is what the render delivered for one module instance.
type Manifest struct {
	Module     string
	Principal  string
	Kind       string
	Generation uint64
	// StandIn marks a module the fixture declares for a run that supervises it
	// itself: what it serves, until the module's own delivery replaces it.
	StandIn       bool
	Bindings      map[string]Binding
	ResourceKinds []*basev0.WorkScopeV1
	// Roles are what a solution declares a person may hold on an installation of
	// it, each within what the solution serves or explicitly consumes through
	// invoke/lookup bindings. A solution always declares
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

// servedByMethods is every (kind, action) a module's methods require of a call:
// what the module serves, read from its own method declarations rather than
// from any summary of them. A person's or an installation's grant at the module
// is cut to what it serves, so a kind a method requires is never one nobody can
// be granted.
func servedByMethods(methods map[string]MethodPolicy) []*basev0.WorkScopeV1 {
	var served []*basev0.WorkScopeV1
	for _, policy := range methods {
		for _, required := range policy.Requires {
			served = append(served, &basev0.WorkScopeV1{ResourceKind: required.GetResourceKind(), Actions: append([]string(nil), required.GetActions()...)})
		}
	}
	return served
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
	// Method requirements name whole kinds, not selected resources. Keep the
	// existing action matcher, but only whole-kind holdings can satisfy it.
	var wholeKindHeld []*basev0.WorkScopeV1
	for _, scope := range held {
		if len(scope.GetResourceIds()) == 0 {
			wholeKindHeld = append(wholeKindHeld, scope)
		}
	}
	var missing []string
	for _, r := range p.Requires {
		for _, action := range r.GetActions() {
			if !holdsAction(wholeKindHeld, r.GetResourceKind(), action) {
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
// is for: a declared "<VERB> <template>" whose template matches the path, a
// "{name}" in it standing for one path segment's text and a "{name=**}" ending
// it for the rest of the path. Two templates matching one path is an ambiguous
// declaration, refused rather than guessed between. A Connect call is an HTTP
// POST whose path is the gRPC method's full name: it is admitted under that
// method.
func routeOf(methods map[string]MethodPolicy, request string) (MethodPolicy, bool, error) {
	verb, path, ok := strings.Cut(request, " ")
	if !ok || !strings.HasPrefix(path, "/") {
		return MethodPolicy{}, false, nil
	}
	if p, ok := methods[path]; ok && verb == "POST" {
		return p, true, nil
	}
	var found []string
	for declared := range methods {
		if v, template, ok := strings.Cut(declared, " "); ok && v == verb && routeMatches(template, path) {
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

// routeMatches is whether path is an instance of template, segment by segment;
// a last segment holding "{name=**}" takes the rest of the path, at least one
// character of at least one segment, between the literal text around it (a
// custom verb such as ":settle" after it).
func routeMatches(template, path string) bool {
	want, got := strings.Split(template, "/"), strings.Split(path, "/")
	if last := want[len(want)-1]; strings.Contains(last, "=**}") {
		if len(got) < len(want) {
			return false
		}
		open := strings.Index(last, "{")
		prefix, suffix := last[:open], last[strings.Index(last, "=**}")+4:]
		rest := strings.Join(got[len(want)-1:], "/")
		if !strings.HasPrefix(rest, prefix) || !strings.HasSuffix(rest, suffix) || len(rest) <= len(prefix)+len(suffix) {
			return false
		}
		want, got = want[:len(want)-1], got[:len(want)-1]
	}
	if len(want) != len(got) {
		return false
	}
	for i, segment := range want {
		if !segmentMatches(segment, got[i]) {
			return false
		}
	}
	return true
}

// segmentMatches matches one segment: literal text, with each "{name}" standing
// for at least one character of the segment, such as "{match_id}:settle".
func segmentMatches(template, segment string) bool {
	open := strings.IndexByte(template, '{')
	if open < 0 {
		return template == segment
	}
	end := strings.IndexByte(template[open:], '}')
	if end < 0 || !strings.HasPrefix(segment, template[:open]) {
		return false
	}
	rest, tail := segment[open:], template[open+end+1:]
	for i := 1; i <= len(rest); i++ {
		if segmentMatches(tail, rest[i:]) {
			return true
		}
	}
	return false
}

// holdsAction reports whether held carries action on any resource of kind.
// It is a vocabulary/presence check, not whole-kind method admission.
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
			permission := h.GetResourceKind() + ":" + a
			if len(h.GetResourceIds()) > 0 {
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

// installationNamespace names installations: InstallationID's UUIDs are
// version-5 names under it.
var installationNamespace = uuid.MustParse("6f1c2b0e-3a52-5d7c-9a1e-0c0de0a07b1a")

// InstallationID is the id of org's installation of target: a canonical UUID,
// as the host issues, so a module keys installations the same under either.
// It is named by organisation and target rather than drawn, so a module's
// stored rows (robin's conversations, its intent store) still name the
// installation after the authority restarts with its fixture.
func InstallationID(org, target string) string {
	return uuid.NewSHA1(installationNamespace, []byte(org+"\x00"+target)).String()
}

// Namespace is the source the installation's own authored content belongs
// to, named by the host so a module never chooses it: "<organization>.<target>".
func (i Installation) Namespace() string { return i.Organization + "." + i.Target }

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

// InstallStep converges one installation. Delivery replay may retry the same
// Pending attempt after a failed call; external effects must be idempotent.
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
	// Delegations a fixture person has already granted.
	Delegations []Delegation `yaml:"delegations"`
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
	deliveries    map[string]*appliedDelivery // binding → verified record, including withdrawals
	orgs          map[string]string
	people        map[string]Person
	order         []string // people's ids, in the fixture's order
	byToken       map[string]string
	roles         map[string]Role // org/name
	modules       map[string]Manifest
	principals    map[string]string // principal → module
	installations map[string]Installation
	delegations   map[string]Delegation
	sessions      map[string]Session
	revisions     map[string]uint64
	attester      *native.Attester
	audience      string
	installStep   InstallStep
	// pendingInstalls are fixture installations whose target was not composed
	// when the fixture loaded; each is performed when its target's manifest applies.
	pendingInstalls []FixtureInstallation
	// Approvals are the artifacts people have consented to (the artifact
	// interface): in memory until the run that composes the store swaps in its
	// Postgres (work.go approvalsFor), before any listener starts.
	Approvals Approvals
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
		deliveries: map[string]*appliedDelivery{}, roles: map[string]Role{}, modules: map[string]Manifest{}, principals: map[string]string{},
		installations: map[string]Installation{}, delegations: map[string]Delegation{}, sessions: map[string]Session{}, revisions: map[string]uint64{},
		attester: attester, audience: audience, Approvals: &MemoryApprovals{},
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
		if r.Generated && (r.Name != "developer" || len(r.Scopes) != 0) {
			s.mu.Unlock()
			return fmt.Errorf("fixture: generated role must be developer with no authored scopes")
		}
		for _, sc := range r.Scopes {
			grants := make([]resources.Grant, 0, len(sc.Resources))
			for _, m := range sc.Resources {
				grants = append(grants, m.Grant())
			}
			if _, err := resources.Compile(grants); err != nil {
				s.mu.Unlock()
				return fmt.Errorf("role %s/%s scope %s: %w", r.Organization, r.Name, sc.Kind, err)
			}
		}
		s.roles[r.Organization+"/"+r.Name] = r
	}
	s.refreshDeveloperRoles()
	var fixtureModules []Manifest
	for _, d := range f.Delegations {
		if d.ID == "" || d.Grantor == "" || d.Module == "" || d.Organization == "" {
			s.mu.Unlock()
			return fmt.Errorf("delegation %q names no id, grantor, module or organization", d.ID)
		}
		s.delegations[d.ID] = d
	}
	for _, fm := range f.Modules {
		if _, composed := s.modules[fm.Module]; composed {
			continue
		}
		m := Manifest{Module: fm.Module, Principal: fm.Module, Kind: "module", Generation: 1, Bindings: map[string]Binding{}, StandIn: true}
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
		if _, seen := s.people[p.ID]; !seen {
			s.order = append(s.order, p.ID)
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

// Delegate records person's grant to module of scopes, each of which the
// person must hold at the module or at an audience one of its bindings
// addresses.
func (s *State) Delegate(person, module string, scopes []*basev0.WorkScopeV1, purpose string) (Delegation, error) {
	s.mu.RLock()
	p, ok := s.people[person]
	m, err := s.moduleByPrincipal(module)
	s.mu.RUnlock()
	if !ok {
		return Delegation{}, fmt.Errorf("%w: person", ErrUnknown)
	}
	if err != nil {
		return Delegation{}, err
	}
	if len(scopes) == 0 {
		return Delegation{}, fmt.Errorf("%w: a delegation names what it grants", ErrForbidden)
	}
	audiences := []string{m.Principal}
	for _, b := range m.Bindings {
		audiences = append(audiences, b.Audience)
	}
	var holds []*basev0.WorkScopeV1
	for _, audience := range audiences {
		if there, err := s.PersonScopes(person, audience); err == nil {
			holds = append(holds, there...)
		}
	}
	if !Attenuates(scopes, holds) {
		return Delegation{}, fmt.Errorf("%w: %s delegates what they do not hold", ErrForbidden, person)
	}
	d := Delegation{ID: newDelegationID(), Organization: p.Organization, Grantor: person, Module: m.Module, Purpose: purpose}
	for _, sc := range Normalize(scopes) {
		d.Scopes = append(d.Scopes, DelegationScope{
			Kind: sc.GetResourceKind(), Actions: append([]string(nil), sc.GetActions()...),
			ResourceIDs: append([]string(nil), sc.GetResourceIds()...),
		})
	}
	s.mu.Lock()
	s.delegations[d.ID] = d
	s.mu.Unlock()
	return d, nil
}

// RevokeDelegation ends a delegation; only its grantor may.
func (s *State) RevokeDelegation(person, id string) (Delegation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.delegations[id]
	if !ok {
		return Delegation{}, fmt.Errorf("%w: delegation %q", ErrUnknown, id)
	}
	if d.Grantor != person {
		return Delegation{}, fmt.Errorf("%w: only the grantor of %s may revoke it", ErrForbidden, id)
	}
	if d.Revoked {
		return d, nil
	}
	d.Revoked = true
	s.delegations[id] = d
	// Core checks this revision on every effect-time verification. Revoking
	// the grant must also invalidate capabilities already issued from it.
	s.revisions[d.Organization]++
	return d, nil
}

// DelegationByID answers a delegation as it stands.
func (s *State) DelegationByID(id string) (Delegation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.delegations[id]
	if !ok {
		return Delegation{}, fmt.Errorf("%w: delegation %q", ErrUnknown, id)
	}
	return d, nil
}

// newDelegationID is a random UUID, the shape the host issues a delegation
// under: a module that holds one as a grant reference checks that shape.
func newDelegationID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// ResourceGrants answers which resources of kind a person may act on with
// action at audience: the resource grants of every role scope that holds the
// action on the kind, and every resource for a scope that names none. A person
// whose roles hold no such scope is answered with no grant.
func (s *State) ResourceGrants(person, audience, kind, action string) ([]resources.Grant, error) {
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
	served := false
	for _, k := range m.ResourceKinds {
		if k.GetResourceKind() == kind {
			served = true
		}
	}
	if !served {
		return nil, fmt.Errorf("%w: %s serves no resource kind %q", ErrUnknown, audience, kind)
	}
	var grants []resources.Grant
	for _, name := range p.Roles {
		for _, sc := range s.roles[p.Organization+"/"+name].Scopes {
			if (sc.Kind != kind && sc.Kind != AnyKind) || (!slices.Contains(sc.Actions, action) && !slices.Contains(sc.Actions, AnyAction)) {
				continue
			}
			if len(sc.Resources) == 0 {
				return []resources.Grant{{All: true}}, nil
			}
			for _, r := range sc.Resources {
				grants = append(grants, r.Grant())
			}
		}
	}
	return grants, nil
}

// ApplyManifest records one module instance at a newer generation and holds a
// module installation at every organisation, so a module is usable without a
// click. A lower or equal generation is refused.
func (s *State) ApplyManifest(m Manifest) ([]string, error) {
	s.mu.Lock()
	for _, record := range s.deliveries {
		held, _ := record.carrier.Manifest()
		if held.Alias == m.Module {
			s.mu.Unlock()
			return nil, fmt.Errorf("%w: %s is owned by signed binding %s; a sketch cannot replace it", ErrForbidden, m.Module, held.Binding)
		}
	}
	ids, pending, err := s.applyManifestLocked(m)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := s.performPendingInstalls(pending); err != nil {
		return nil, err
	}
	return ids, nil
}

// applyManifestLocked validates before replacing the live projection. Caller holds mu.
func (s *State) applyManifestLocked(m Manifest) ([]string, []FixtureInstallation, error) {
	if err := validateManifest(m); err != nil {
		return nil, nil, err
	}
	if prev, ok := s.modules[m.Module]; ok && !prev.StandIn && prev.Generation >= m.Generation {
		return nil, nil, fmt.Errorf("%w: %s is at %d, got %d", ErrStale, m.Module, prev.Generation, m.Generation)
	}
	if other, ok := s.principals[m.Principal]; ok && other != m.Module {
		return nil, nil, fmt.Errorf("%w: principal %q already belongs to %s", ErrForbidden, m.Principal, other)
	}
	m.ResourceKinds = Normalize(append(m.ResourceKinds, servedByMethods(m.Methods)...))
	s.invalidateNarrowedAuthority(m)
	if previous, ok := s.modules[m.Module]; ok {
		delete(s.principals, previous.Principal)
	}
	s.modules[m.Module] = m
	s.refreshDeveloperRoles()
	s.principals[m.Principal] = m.Module
	return s.ensureModuleInstallations(m), s.takePendingInstalls(m.Module), nil
}

func validateManifest(m Manifest) error {
	for method, policy := range m.Methods {
		requires := map[string][]string{}
		for _, scope := range policy.Requires {
			if len(scope.GetResourceIds()) > 0 {
				return fmt.Errorf("%w: %s: %s: method requirements name whole resource kinds; resource IDs are not supported", ErrForbidden, m.Module, method)
			}
			requires[scope.GetResourceKind()] = append(requires[scope.GetResourceKind()], scope.GetActions()...)
		}
		if err := delivery.ValidateMethodPolicy(method, policy.AnyCheckedCaller, requires, false); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrForbidden, m.Module, err)
		}
	}
	if err := validateRoles(m); err != nil {
		return err
	}
	if m.Module == "" || m.Principal == "" || m.Generation == 0 {
		return fmt.Errorf("%w: a manifest names its module, its principal and a generation", ErrForbidden)
	}
	for id, b := range m.Bindings {
		lookupCeiling := b.InvokeScopes
		if len(lookupCeiling) == 0 {
			lookupCeiling = b.HeadlessScopes
		}
		if len(b.LookupScopes) > 0 && !Attenuates(b.LookupScopes, lookupCeiling) {
			return fmt.Errorf("%w: binding %s: lookup scopes exceed what the binding may do", ErrForbidden, id)
		}
		if len(b.InvokeScopes) > 0 && !Attenuates(b.HeadlessScopes, b.InvokeScopes) {
			return fmt.Errorf("%w: binding %s: headless scopes exceed invoke scopes", ErrForbidden, id)
		}
	}
	return nil
}

// invalidateNarrowedAuthority advances the existing live revisions when delivery
// removes role or binding authority. Person roots can carry binding scopes for a
// later module hop without that module's epoch, so generation alone is not enough.
// Caller holds mu; expansion does not advance these revisions.
func (s *State) invalidateNarrowedAuthority(next Manifest) {
	previous, ok := s.modules[next.Module]
	if !ok {
		return
	}
	bindingsNarrowed := false
	for id, old := range previous.Bindings {
		binding, exists := next.Bindings[id]
		if !exists || old.Audience != binding.Audience ||
			!Attenuates(old.InvokeScopes, binding.InvokeScopes) ||
			!Attenuates(old.HeadlessScopes, binding.HeadlessScopes) ||
			!Attenuates(old.LookupScopes, binding.LookupScopes) {
			bindingsNarrowed = true
			break
		}
	}
	changed := map[string]bool{}
	for id, inst := range s.installations {
		if inst.Target != next.Module || inst.Status != Active {
			continue
		}
		rolesNarrowed := previous.Kind == "solution" &&
			(!Attenuates(previous.Roles[inst.Role], next.Roles[inst.Role]) ||
				!Attenuates(previous.Roles[InstallerRole], next.Roles[InstallerRole]))
		if !bindingsNarrowed && !rolesNarrowed {
			continue
		}
		inst.Revision++
		s.installations[id] = inst
		changed[inst.Organization] = true
	}
	for org := range changed {
		s.revisions[org]++
	}
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
		id := InstallationID(org, m.Module)
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
	return s.install(ctx, org, target, role, owner, 0, nil)
}

// generation is nonzero only when resuming a committed delivery's fixture intent.
func (s *State) install(ctx context.Context, org, target, role, owner string, generation uint64, intent *pendingInstallation) (Installation, error) {
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
	if generation != 0 && target_.Generation != generation {
		s.mu.Unlock()
		return Installation{}, fmt.Errorf("%w: installation delivery was superseded", ErrStale)
	}
	if _, ok := target_.Roles[role]; !ok {
		s.mu.Unlock()
		return Installation{}, fmt.Errorf("%w: role %q is not one %s declares", ErrUnknown, role, target)
	}
	if p, ok := s.people[owner]; !ok || p.Organization != org {
		s.mu.Unlock()
		return Installation{}, fmt.Errorf("%w: owner %q is not a member of %s", ErrForbidden, owner, org)
	}
	id := InstallationID(org, target)
	existing, exists := s.installations[id]
	if intent != nil && exists && (existing.Status == Revoked || (intent.revision == 0 || existing.Revision != intent.revision)) {
		s.mu.Unlock()
		return Installation{}, fmt.Errorf("%w: fixture installation attempt %s was revoked or changed", ErrStale, id)
	}
	if exists && existing.Status != Revoked {
		if generation == 0 || existing.Role != role || existing.Owner != owner {
			s.mu.Unlock()
			return Installation{}, fmt.Errorf("%w: %s is already installed at %s", ErrForbidden, target, org)
		}
		if existing.Status == Active {
			s.mu.Unlock()
			return existing, nil
		}
	} else {
		existing = Installation{ID: id, Organization: org, Target: target, Status: Pending, Revision: existing.Revision + 1, Role: role, Owner: owner}
		s.installations[id] = existing
		s.revisions[org]++
	}
	if intent != nil {
		intent.revision = existing.Revision
	}
	step := s.installStep
	s.mu.Unlock()
	if step != nil {
		if err := step(ctx, existing); err != nil {
			return existing, fmt.Errorf("install step for %s: %w", id, err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.installations[id]
	live, composed := s.modules[target]
	if !composed || live.Generation != target_.Generation || current.Status != Pending || current.Revision != existing.Revision {
		return current, fmt.Errorf("%w: installation attempt %s changed before acknowledgement", ErrStale, id)
	}
	current.Status = Active
	s.installations[id] = current
	return current, nil
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

// InstallationScopes resolves the selected role in the installed solution's
// declaration, never in the organisation's independent role catalogue. The
// installation, role, audience and authorization revision share one snapshot.
// Issuance must not stamp these scopes with a different revision.
func (s *State) InstallationScopes(id, audience string) (Installation, []*basev0.WorkScopeV1, uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inst, ok := s.installations[id]
	if !ok {
		return Installation{}, nil, 0, fmt.Errorf("%w: installation %q", ErrUnknown, id)
	}
	if inst.Status != Active {
		return Installation{}, nil, 0, fmt.Errorf("%w: installation %s is %s", workcontext.ErrNoSeal, id, inst.Status)
	}
	target, ok := s.modules[inst.Target]
	if !ok || target.Kind != "solution" {
		return Installation{}, nil, 0, fmt.Errorf("%w: installation target is not a delivered solution", ErrUnknown)
	}
	held, ok := target.Roles[inst.Role]
	if !ok {
		return Installation{}, nil, 0, fmt.Errorf("%w: role %q is no longer declared by %s", ErrUnknown, inst.Role, inst.Target)
	}
	served, err := s.moduleByPrincipal(audience)
	if err != nil {
		return Installation{}, nil, 0, err
	}
	return inst, Intersect(held, served.ResourceKinds), s.revisions[inst.Organization] + 1, nil
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
// runs. This state also requires a composed module and, for signed deliveries,
// membership in its current declared workloads.
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
	for _, record := range s.deliveries {
		manifest, err := record.carrier.Manifest()
		if err != nil {
			return Manifest{}, err
		}
		if manifest.Alias != m.Module {
			continue
		}
		if _, listed := manifest.WorkloadNamed(attestation.Workload.Service); !listed || manifest.Removed {
			return Manifest{}, fmt.Errorf("%w: service %q is not a live workload of %s", ErrForbidden, attestation.Workload.Service, m.Module)
		}
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
	inst, ok := s.installations[InstallationID(parts[0], parts[1])]
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

// A scope covers either the whole of a kind (no resource ids) or the resources
// it names. Every operation below keeps that distinction: an id-limited scope
// is never widened to its kind, and an intersection keeps the narrower side.

// AnyAction, on a module's declared resource kind, serves whatever actions the
// roles grant on that kind: core's manifest names kinds and not actions. On a
// role's scope it grants every action the audience serves on that kind.
const AnyAction = "*"

// AnyKind, on a role's scope, grants its actions on every kind the audience
// module serves: a local developer's role, written without naming any module.
const AnyKind = "*"

// coverage is kind -> action -> ids, where a nil set is the whole kind.
type coverage map[string]map[string]map[string]bool

func coverageOf(in []*basev0.WorkScopeV1) coverage {
	c := coverage{}
	for _, sc := range in {
		if sc == nil || sc.GetResourceKind() == "" {
			continue
		}
		kind := sc.GetResourceKind()
		if c[kind] == nil {
			c[kind] = map[string]map[string]bool{}
		}
		for _, act := range sc.GetActions() {
			current, seen := c[kind][act]
			switch {
			case len(sc.GetResourceIds()) == 0:
				c[kind][act] = nil
			case seen && current == nil:
				// already the whole kind
			default:
				if current == nil {
					current = map[string]bool{}
				}
				for _, id := range sc.GetResourceIds() {
					current[id] = true
				}
				c[kind][act] = current
			}
		}
	}
	return c
}

// scopes renders coverage in the shape core requires: kinds sorted, actions
// sorted, one scope per kind and id set.
func (c coverage) scopes() []*basev0.WorkScopeV1 {
	kinds := make([]string, 0, len(c))
	for k := range c {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	var out []*basev0.WorkScopeV1
	for _, kind := range kinds {
		bySet := map[string][]string{}
		sets := map[string][]string{}
		for act, ids := range c[kind] {
			key := ""
			var list []string
			if ids != nil {
				for id := range ids {
					list = append(list, id)
				}
				sort.Strings(list)
				key = "\x00" + strings.Join(list, "\x00")
			}
			bySet[key] = append(bySet[key], act)
			sets[key] = list
		}
		keys := make([]string, 0, len(bySet))
		for k := range bySet {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			actions := bySet[k]
			sort.Strings(actions)
			out = append(out, &basev0.WorkScopeV1{ResourceKind: kind, Actions: actions, ResourceIds: sets[k]})
		}
	}
	return out
}

// Normalize merges duplicate kinds and sorts actions, the shape core requires.
func Normalize(in []*basev0.WorkScopeV1) []*basev0.WorkScopeV1 {
	return coverageOf(in).scopes()
}

// Intersect keeps what a holds that b allows, the narrower side winning: a
// whole kind meets named ids as those ids, and two id sets meet as their
// common ids. AnyAction in b allows every action of a's kind; AnyAction in a
// takes every action b allows on that kind.
func Intersect(a, b []*basev0.WorkScopeV1) []*basev0.WorkScopeV1 {
	allowed := coverageOf(b)
	asked := coverageOf(a)
	out := coverage{}
	put := func(kind, act string, ids map[string]bool) {
		if ids != nil && len(ids) == 0 {
			return
		}
		if out[kind] == nil {
			out[kind] = map[string]map[string]bool{}
		}
		out[kind][act] = ids
	}
	for kind, acts := range asked {
		for act, ids := range acts {
			if act == AnyAction {
				for served, allowedIDs := range allowed[kind] {
					put(kind, served, meet(ids, allowedIDs))
				}
				continue
			}
			allowedIDs, ok := allowed[kind][act]
			if !ok {
				allowedIDs, ok = allowed[kind][AnyAction]
			}
			if ok {
				put(kind, act, meet(ids, allowedIDs))
			}
		}
	}
	return out.scopes()
}

// meet is two coverages of one kind and action: nil is the whole kind.
func meet(a, b map[string]bool) map[string]bool {
	switch {
	case a == nil && b == nil:
		return nil
	case a == nil:
		return b
	case b == nil:
		return a
	}
	common := map[string]bool{}
	for id := range a {
		if b[id] {
			common[id] = true
		}
	}
	return common
}

// Attenuates reports whether every scope in narrow is within wide.
func Attenuates(narrow, wide []*basev0.WorkScopeV1) bool {
	n := Normalize(narrow)
	return sameScopes(Intersect(n, wide), n)
}

func sameScopes(a, b []*basev0.WorkScopeV1) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].GetResourceKind() != b[i].GetResourceKind() || strings.Join(a[i].GetActions(), ",") != strings.Join(b[i].GetActions(), ",") ||
			strings.Join(a[i].GetResourceIds(), "\x00") != strings.Join(b[i].GetResourceIds(), "\x00") {
			return false
		}
	}
	return true
}

// validateRoles holds a solution to its role contract: it declares an installer
// role, and every role stays within what the solution serves or explicitly
// consumes through invoke/lookup bindings. Headless authority belongs to the
// workload and cannot supply a role grant. A module declares no roles.
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
	grantable := slices.Clone(m.ResourceKinds)
	for _, binding := range m.Bindings {
		grantable = append(grantable, binding.InvokeScopes...)
		grantable = append(grantable, binding.LookupScopes...)
	}
	for name, scopes := range m.Roles {
		if len(scopes) == 0 {
			return fmt.Errorf("%w: role %q of %s grants nothing", ErrForbidden, name, m.Module)
		}
		if !Attenuates(scopes, grantable) {
			return fmt.Errorf("%w: role %q of %s grants beyond what %s serves or explicitly consumes through invoke/lookup bindings", ErrForbidden, name, m.Module, m.Module)
		}
	}
	return nil
}
