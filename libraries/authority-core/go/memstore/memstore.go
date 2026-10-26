// Package memstore is an in-memory authority.Store: one lock, and a deep copy
// of every record handed in or out, so a transaction's snapshot never changes
// under a reader. It backs the core's tests and the local authority.
package memstore

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"sync"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/protobuf/proto"
)

// Store is the in-memory store.
type Store struct {
	mu            sync.RWMutex
	orgs          map[string]domain.Organization
	people        map[string]domain.Person
	roles         map[string]domain.OrgRole // organization/name
	modules       map[string]domain.Module  // name
	installations map[string]domain.Installation
	grants        map[string][]domain.RoleGrant
	revisions     map[string]uint64
	personEpochs  map[string]uint64
	grantEpochs   map[string]uint64
	ownerAware    map[string]uint64
	delegations   map[string]domain.Delegation
	tombstones    map[string]domain.Tombstone
}

// New is an empty store.
func New() *Store {
	return &Store{
		orgs: map[string]domain.Organization{}, people: map[string]domain.Person{}, roles: map[string]domain.OrgRole{},
		modules: map[string]domain.Module{}, installations: map[string]domain.Installation{}, grants: map[string][]domain.RoleGrant{},
		revisions: map[string]uint64{}, personEpochs: map[string]uint64{}, grantEpochs: map[string]uint64{},
		ownerAware: map[string]uint64{}, delegations: map[string]domain.Delegation{}, tombstones: map[string]domain.Tombstone{},
	}
}

var _ authority.Store = (*Store)(nil)

// Read runs fn under the read lock.
func (s *Store) Read(_ context.Context, fn func(authority.Tx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fn(tx{s: s})
}

// Write runs fn under the write lock, as one transaction: when fn fails or
// panics, every write it made is undone.
func (s *Store) Write(_ context.Context, fn func(authority.Tx) error) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, committed := s.snapshot(), false
	defer func() {
		if !committed {
			s.restore(before)
		}
	}()
	if err = fn(tx{s: s, write: true}); err != nil {
		return err
	}
	committed = true
	return nil
}

// state is every map the authority writes; identity (organizations, people,
// roles) is the host's and changes only through the seeding methods.
type state struct {
	modules       map[string]domain.Module
	installations map[string]domain.Installation
	grants        map[string][]domain.RoleGrant
	revisions     map[string]uint64
	personEpochs  map[string]uint64
	grantEpochs   map[string]uint64
	ownerAware    map[string]uint64
	delegations   map[string]domain.Delegation
	tombstones    map[string]domain.Tombstone
}

func (s *Store) snapshot() state {
	grants := make(map[string][]domain.RoleGrant, len(s.grants))
	for id, g := range s.grants {
		grants[id] = slices.Clone(g)
	}
	return state{modules: maps.Clone(s.modules), installations: maps.Clone(s.installations), grants: grants,
		revisions: maps.Clone(s.revisions), personEpochs: maps.Clone(s.personEpochs), grantEpochs: maps.Clone(s.grantEpochs),
		ownerAware: maps.Clone(s.ownerAware), delegations: maps.Clone(s.delegations), tombstones: maps.Clone(s.tombstones)}
}

func (s *Store) restore(b state) {
	s.modules, s.installations, s.grants, s.revisions = b.modules, b.installations, b.grants, b.revisions
	s.personEpochs, s.grantEpochs, s.ownerAware, s.delegations = b.personEpochs, b.grantEpochs, b.ownerAware, b.delegations
	s.tombstones = b.tombstones
}

// PutOrganization, PutPerson, DeletePerson and PutOrgRole seed and change
// identity, the host's own data.
func (s *Store) PutOrganization(o domain.Organization) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orgs[o.ID] = o
}

// PutPerson records a person.
func (s *Store) PutPerson(p domain.Person) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.people[p.ID] = clonePerson(p)
}

// DeletePerson removes a person.
func (s *Store) DeletePerson(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.people, id)
}

// PutOrgRole records an organization role.
func (s *Store) PutOrgRole(r domain.OrgRole) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[r.Organization+"/"+r.Name] = r
}

type tx struct {
	s     *Store
	write bool
}

func missing(what, id string) error { return fmt.Errorf("%s %q: %w", what, id, domain.ErrNotFound) }

func (t tx) mustWrite() {
	if !t.write {
		panic("memstore: a write inside Read")
	}
}

func (t tx) Organizations() ([]domain.Organization, error) {
	var out []domain.Organization
	for _, o := range t.s.orgs {
		out = append(out, o)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, nil
}

func (t tx) Organization(id string) (domain.Organization, error) {
	o, ok := t.s.orgs[id]
	if !ok {
		return o, missing("organization", id)
	}
	return o, nil
}

func (t tx) Person(id string) (domain.Person, error) {
	p, ok := t.s.people[id]
	if !ok {
		return p, missing("person", id)
	}
	return clonePerson(p), nil
}

func (t tx) People(org string) ([]domain.Person, error) {
	var out []domain.Person
	for _, p := range t.s.people {
		if p.Organization == org {
			out = append(out, clonePerson(p))
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, nil
}

func (t tx) OrgRole(org, name string) (domain.OrgRole, error) {
	r, ok := t.s.roles[org+"/"+name]
	if !ok {
		return r, missing("role", org+"/"+name)
	}
	return r, nil
}

func (t tx) Module(principal string) (domain.Module, error) {
	for _, m := range t.s.modules {
		if m.Principal == principal {
			return cloneModule(m), nil
		}
	}
	return domain.Module{}, missing("audience", principal)
}

func (t tx) ModuleNamed(name string) (domain.Module, error) {
	m, ok := t.s.modules[name]
	if !ok {
		return m, missing("module", name)
	}
	return cloneModule(m), nil
}

func (t tx) Modules() ([]domain.Module, error) {
	var out []domain.Module
	for _, m := range t.s.modules {
		out = append(out, cloneModule(m))
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

func (t tx) PutModule(m domain.Module) error {
	t.mustWrite()
	t.s.modules[m.Name] = cloneModule(m)
	return nil
}

func (t tx) DeleteModule(name string) error {
	t.mustWrite()
	delete(t.s.modules, name)
	return nil
}

func (t tx) Tombstone(name string) (domain.Tombstone, error) {
	tomb, ok := t.s.tombstones[name]
	if !ok {
		return tomb, missing("tombstone", name)
	}
	return tomb, nil
}

func (t tx) TombstoneByPrincipal(principal string) (domain.Tombstone, error) {
	for _, tomb := range t.s.tombstones {
		if tomb.Principal == principal {
			return tomb, nil
		}
	}
	return domain.Tombstone{}, missing("tombstone of principal", principal)
}

func (t tx) PutTombstone(tomb domain.Tombstone) error {
	t.mustWrite()
	t.s.tombstones[tomb.Name] = tomb
	return nil
}

func (t tx) Installation(id string) (domain.Installation, error) {
	i, ok := t.s.installations[id]
	if !ok {
		return i, missing("installation", id)
	}
	return i, nil
}

func (t tx) InstallationByPrincipal(principal string) (domain.Installation, error) {
	for _, i := range t.s.installations {
		if principal != "" && i.PrincipalID == principal {
			return i, nil
		}
	}
	return domain.Installation{}, missing("principal", principal)
}

func (t tx) Installations(org string) ([]domain.Installation, error) {
	var out []domain.Installation
	for _, i := range t.s.installations {
		if org == "" || i.Organization == org {
			out = append(out, i)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, nil
}

func (t tx) PutInstallation(i domain.Installation) error {
	t.mustWrite()
	t.s.installations[i.ID] = i
	return nil
}

func (t tx) RoleGrants(id string) ([]domain.RoleGrant, error) {
	return slices.Clone(t.s.grants[id]), nil
}

func (t tx) PutRoleGrant(g domain.RoleGrant) error {
	t.mustWrite()
	if !slices.Contains(t.s.grants[g.InstallationID], g) {
		t.s.grants[g.InstallationID] = append(slices.Clone(t.s.grants[g.InstallationID]), g)
	}
	return nil
}

func (t tx) DeleteRoleGrant(g domain.RoleGrant) error {
	t.mustWrite()
	t.s.grants[g.InstallationID] = slices.DeleteFunc(slices.Clone(t.s.grants[g.InstallationID]), func(h domain.RoleGrant) bool { return h == g })
	return nil
}

func (t tx) DeleteRoleGrants(id string) error {
	t.mustWrite()
	delete(t.s.grants, id)
	return nil
}

func (t tx) AuthorizationRevision(org string) (uint64, error) {
	if _, ok := t.s.orgs[org]; !ok {
		return 0, missing("organization", org)
	}
	return t.s.revisions[org] + 1, nil
}

func (t tx) BumpAuthorizationRevision(org string) error {
	t.mustWrite()
	t.s.revisions[org]++
	return nil
}

func (t tx) PersonEpoch(p string) (uint64, error) { return t.s.personEpochs[p] + 1, nil }
func (t tx) BumpPersonEpoch(p string) error {
	t.mustWrite()
	t.s.personEpochs[p]++
	return nil
}

func (t tx) GrantEpoch(p, inst string) (uint64, error) { return t.s.grantEpochs[p+"\x00"+inst], nil }
func (t tx) BumpGrantEpoch(p, inst string) error {
	t.mustWrite()
	t.s.grantEpochs[p+"\x00"+inst]++
	return nil
}

func (t tx) OwnerAwareRevision(audience string) (uint64, error) { return t.s.ownerAware[audience], nil }
func (t tx) BumpOwnerAwareRevision(audience string) error {
	t.mustWrite()
	t.s.ownerAware[audience]++
	return nil
}

func (t tx) Delegation(id string) (domain.Delegation, error) {
	d, ok := t.s.delegations[id]
	if !ok {
		return d, missing("delegation", id)
	}
	d.Scopes = cloneScopes(d.Scopes)
	return d, nil
}

func (t tx) Delegations() ([]domain.Delegation, error) {
	var out []domain.Delegation
	for _, d := range t.s.delegations {
		d.Scopes = cloneScopes(d.Scopes)
		out = append(out, d)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, nil
}

func (t tx) PutDelegation(d domain.Delegation) error {
	t.mustWrite()
	d.Scopes = cloneScopes(d.Scopes)
	t.s.delegations[d.ID] = d
	return nil
}

func clonePerson(p domain.Person) domain.Person {
	p.Roles, p.Teams = slices.Clone(p.Roles), slices.Clone(p.Teams)
	return p
}

func cloneScopes(in []*basev0.WorkScopeV1) []*basev0.WorkScopeV1 {
	if in == nil {
		return nil
	}
	out := make([]*basev0.WorkScopeV1, len(in))
	for i, s := range in {
		out[i] = proto.CloneOf(s)
	}
	return out
}

func cloneModule(m domain.Module) domain.Module {
	m.ResourceKinds = cloneScopes(m.ResourceKinds)
	bindings := make(map[string]domain.Binding, len(m.Bindings))
	for id, b := range m.Bindings {
		b.InvokeScopes, b.HeadlessScopes, b.LookupScopes = cloneScopes(b.InvokeScopes), cloneScopes(b.HeadlessScopes), cloneScopes(b.LookupScopes)
		bindings[id] = b
	}
	m.Bindings = bindings
	if m.Roles != nil {
		roles := make(map[string][]*basev0.WorkScopeV1, len(m.Roles))
		for name, scopes := range m.Roles {
			roles[name] = cloneScopes(scopes)
		}
		m.Roles = roles
	}
	return m
}
