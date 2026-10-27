// Package storetest is the contract every authority.Store must meet, run
// against the in-memory store here and against each host's own store there
// (the accounts Postgres store, the local authority's): one transaction is all
// or nothing, a missing record wraps domain.ErrNotFound, every record reads
// back as written, grants are idempotent, every revision and epoch only grows,
// and identity reads answer what the host seeded.
//
// Every id a run uses is fresh, so a host may run it against a store other
// tests share.
package storetest

import (
	"context"
	"errors"
	"slices"
	"sort"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	resources "github.com/codefly-dev/authority/libraries/resources/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/google/uuid"
)

// Identity is what a host seeds before its store is opened: organizations and
// their members. Identity is the host's own data; the store only reads it.
type Identity struct {
	Organizations []domain.Organization
	Members       []Member
}

// Member is one person's membership of one organization: an administrator
// or not, their teams there, and the organization-role scopes they hold
// there. A person may be a member of several organizations.
type Member struct {
	Organization, Person string
	Administrator        bool
	Teams                []string
	Scopes               []domain.RoleScope
}

// Open seeds id into a store and opens it.
type Open func(t *testing.T, id Identity) authority.Store

// Run proves the contract against the stores open opens.
func Run(t *testing.T, open Open) {
	t.Helper()
	ctx := context.Background()
	f := newFixture()
	store := open(t, f.identity)
	read := func(t *testing.T, fn func(authority.Tx) error) {
		t.Helper()
		if err := store.Read(ctx, fn); err != nil {
			t.Fatal(err)
		}
	}
	write := func(t *testing.T, fn func(authority.Tx) error) {
		t.Helper()
		if err := store.Write(ctx, fn); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("identity reads answer what the host seeded", func(t *testing.T) {
		read(t, func(tx authority.Tx) error {
			all, err := tx.Organizations()
			if err != nil {
				return err
			}
			for _, want := range f.identity.Organizations {
				got, err := tx.Organization(want.ID)
				if err != nil || got.ID != want.ID || got.Name != want.Name {
					t.Errorf("organization %s: %+v %v", want.ID, got, err)
				}
				if !slices.ContainsFunc(all, func(o domain.Organization) bool { return o.ID == want.ID }) {
					t.Errorf("Organizations omits %s", want.ID)
				}
			}
			for _, m := range f.identity.Members {
				p, err := tx.Member(m.Organization, m.Person)
				if err != nil {
					t.Errorf("member %s of %s: %v", m.Person, m.Organization, err)
					continue
				}
				if p.ID != m.Person || p.Organization != m.Organization || decide.IsAdministrator(p) != m.Administrator || !sameSet(p.Teams, m.Teams) {
					t.Errorf("member %s of %s reads %+v, want %+v", m.Person, m.Organization, p, m)
				}
				if !m.Administrator {
					held, err := heldScopes(tx, p)
					if err != nil {
						return err
					}
					if want := points(m.Scopes); !samePoints(held, want) {
						t.Errorf("member %s of %s holds %v, want %v", m.Person, m.Organization, held, want)
					}
				}
				if _, err := tx.Person(m.Person); err != nil {
					t.Errorf("person %s: %v", m.Person, err)
				}
			}
			for _, org := range f.identity.Organizations {
				people, err := tx.People(org.ID)
				if err != nil {
					return err
				}
				var got, want []string
				for _, p := range people {
					got = append(got, p.ID)
					if p.Organization != org.ID {
						t.Errorf("People(%s) answered %s as a member of %s", org.ID, p.ID, p.Organization)
					}
				}
				for _, m := range f.identity.Members {
					if m.Organization == org.ID {
						want = append(want, m.Person)
					}
				}
				if !sameSet(got, want) {
					t.Errorf("People(%s) = %v, want %v", org.ID, got, want)
				}
			}
			if _, err := tx.Member(f.orgB, f.onlyA); !errors.Is(err, domain.ErrNotFound) {
				t.Errorf("a person is no member of an organization they do not belong to: %v", err)
			}
			return nil
		})
	})

	t.Run("a missing record wraps ErrNotFound", func(t *testing.T) {
		absent := "storetest-absent-" + uuid.NewString()
		read(t, func(tx authority.Tx) error {
			for name, err := range map[string]error{
				"organization":    second(tx.Organization(uuid.NewString())),
				"person":          second(tx.Person(uuid.NewString())),
				"member":          second(tx.Member(f.orgA, uuid.NewString())),
				"module":          second(tx.Module(absent)),
				"module by name":  second(tx.ModuleNamed(absent)),
				"tombstone":       second(tx.Tombstone(absent)),
				"tomb principal":  second(tx.TombstoneByPrincipal(absent)),
				"installation":    second(tx.Installation(uuid.NewString())),
				"by principal":    second(tx.InstallationByPrincipal(uuid.NewString())),
				"empty principal": second(tx.InstallationByPrincipal("")),
				"delegation":      second(tx.Delegation(uuid.NewString())),
			} {
				if !errors.Is(err, domain.ErrNotFound) {
					t.Errorf("%s: %v", name, err)
				}
			}
			return nil
		})
	})

	t.Run("a module reads back as written, by name and by principal", func(t *testing.T) {
		m := f.module("solution")
		write(t, func(tx authority.Tx) error { return tx.PutModule(m) })
		read(t, func(tx authority.Tx) error {
			byName, err := tx.ModuleNamed(m.Name)
			if err != nil {
				return err
			}
			byPrincipal, err := tx.Module(m.Principal)
			if err != nil {
				return err
			}
			sameModule(t, byName, m)
			sameModule(t, byPrincipal, m)
			all, err := tx.Modules()
			if err != nil {
				return err
			}
			if !slices.ContainsFunc(all, func(x domain.Module) bool { return x.Name == m.Name }) ||
				!sort.SliceIsSorted(all, func(a, b int) bool { return all[a].Name < all[b].Name }) {
				t.Errorf("Modules omits %s or is not sorted by name", m.Name)
			}
			return nil
		})
		m.Generation = 2
		m.OwnerAware = false
		write(t, func(tx authority.Tx) error { return tx.PutModule(m) })
		read(t, func(tx authority.Tx) error {
			got, err := tx.ModuleNamed(m.Name)
			sameModule(t, got, m)
			return err
		})
		write(t, func(tx authority.Tx) error { return tx.DeleteModule(m.Name) })
		read(t, func(tx authority.Tx) error {
			if _, err := tx.ModuleNamed(m.Name); !errors.Is(err, domain.ErrNotFound) {
				t.Errorf("a deleted module still reads: %v", err)
			}
			return nil
		})
	})

	t.Run("a tombstone reads back by name and by principal", func(t *testing.T) {
		tomb := domain.Tombstone{Name: f.name("withdrawn"), Principal: f.name("withdrawn-principal"), Generation: 7}
		write(t, func(tx authority.Tx) error { return tx.PutTombstone(tomb) })
		read(t, func(tx authority.Tx) error {
			a, err := tx.Tombstone(tomb.Name)
			if err != nil {
				return err
			}
			b, err := tx.TombstoneByPrincipal(tomb.Principal)
			if err != nil {
				return err
			}
			if a != tomb || b != tomb {
				t.Errorf("tombstone %+v %+v, want %+v", a, b, tomb)
			}
			return nil
		})
	})

	t.Run("an installation reads back as written", func(t *testing.T) {
		inst := domain.Installation{ID: uuid.NewString(), Organization: f.orgA, Target: f.name("target"), Status: domain.Pending, Revision: 3,
			AgentRole: "viewer", PrincipalID: uuid.NewString(), InstalledBy: f.onlyA,
			Consent: domain.ConsentReceipt{OperationID: uuid.NewString(), Intent: "intent", Revision: 3},
			Owned:   map[string][]string{"store.item": {"a", "b"}}}
		module := domain.Installation{ID: uuid.NewString(), Organization: f.orgB, Target: f.name("module"), Status: domain.Active, Revision: 1}
		write(t, func(tx authority.Tx) error {
			if err := tx.PutInstallation(inst); err != nil {
				return err
			}
			return tx.PutInstallation(module)
		})
		read(t, func(tx authority.Tx) error {
			got, err := tx.Installation(inst.ID)
			if err != nil {
				return err
			}
			sameInstallation(t, got, inst)
			byPrincipal, err := tx.InstallationByPrincipal(inst.PrincipalID)
			if err != nil {
				return err
			}
			sameInstallation(t, byPrincipal, inst)
			got, err = tx.Installation(module.ID)
			if err != nil {
				return err
			}
			sameInstallation(t, got, module)
			ofA, err := tx.Installations(f.orgA)
			if err != nil {
				return err
			}
			if !slices.ContainsFunc(ofA, func(i domain.Installation) bool { return i.ID == inst.ID }) || slices.ContainsFunc(ofA, func(i domain.Installation) bool { return i.ID == module.ID }) {
				t.Errorf("Installations(%s) answers another organization's or omits its own: %v", f.orgA, ofA)
			}
			every, err := tx.Installations("")
			if err != nil {
				return err
			}
			if !slices.ContainsFunc(every, func(i domain.Installation) bool { return i.ID == inst.ID }) || !slices.ContainsFunc(every, func(i domain.Installation) bool { return i.ID == module.ID }) ||
				!sort.SliceIsSorted(every, func(a, b int) bool { return every[a].ID < every[b].ID }) {
				t.Error("Installations(\"\") omits one or is not sorted by id")
			}
			return nil
		})
		inst.Status, inst.Revision, inst.Owned = domain.Revoked, 4, nil
		write(t, func(tx authority.Tx) error { return tx.PutInstallation(inst) })
		read(t, func(tx authority.Tx) error {
			got, err := tx.Installation(inst.ID)
			sameInstallation(t, got, inst)
			return err
		})
	})

	t.Run("role grants are idempotent and kept per installation", func(t *testing.T) {
		a, b := uuid.NewString(), uuid.NewString()
		person := domain.RoleGrant{InstallationID: a, Role: "viewer", PersonID: f.onlyA}
		team := domain.RoleGrant{InstallationID: a, Role: "viewer", TeamID: f.team}
		other := domain.RoleGrant{InstallationID: b, Role: "editor", PersonID: f.onlyA}
		write(t, func(tx authority.Tx) error {
			for _, g := range []domain.RoleGrant{person, person, team, other} {
				if err := tx.PutRoleGrant(g); err != nil {
					return err
				}
			}
			return nil
		})
		grants := func(id string) []domain.RoleGrant {
			var out []domain.RoleGrant
			read(t, func(tx authority.Tx) (err error) { out, err = tx.RoleGrants(id); return err })
			return out
		}
		if got := grants(a); len(got) != 2 || !slices.Contains(got, person) || !slices.Contains(got, team) {
			t.Fatalf("grants of a: %v", got)
		}
		write(t, func(tx authority.Tx) error {
			if err := tx.DeleteRoleGrant(person); err != nil {
				return err
			}
			return tx.DeleteRoleGrant(person)
		})
		if got := grants(a); len(got) != 1 || got[0] != team {
			t.Fatalf("after revoking the person: %v", got)
		}
		write(t, func(tx authority.Tx) error { return tx.DeleteRoleGrants(a) })
		if got := grants(a); len(got) != 0 {
			t.Fatalf("after clearing a: %v", got)
		}
		if got := grants(b); len(got) != 1 || got[0] != other {
			t.Fatalf("clearing a touched b: %v", got)
		}
	})

	t.Run("every revision and epoch only grows, each keyed as it is named", func(t *testing.T) {
		inst := uuid.NewString()
		audience := f.name("audience")
		type counters struct{ org, otherOrg, person, otherPerson, grant, otherGrant, aware uint64 }
		now := func() (c counters) {
			read(t, func(tx authority.Tx) error {
				var err error
				for _, v := range []struct {
					dst *uint64
					get func() (uint64, error)
				}{
					{&c.org, func() (uint64, error) { return tx.AuthorizationRevision(f.orgA) }},
					{&c.otherOrg, func() (uint64, error) { return tx.AuthorizationRevision(f.orgB) }},
					{&c.person, func() (uint64, error) { return tx.PersonEpoch(f.onlyA) }},
					{&c.otherPerson, func() (uint64, error) { return tx.PersonEpoch(f.both) }},
					{&c.grant, func() (uint64, error) { return tx.GrantEpoch(f.onlyA, inst) }},
					{&c.otherGrant, func() (uint64, error) { return tx.GrantEpoch(f.both, inst) }},
					{&c.aware, func() (uint64, error) { return tx.OwnerAwareRevision(audience) }},
				} {
					if *v.dst, err = v.get(); err != nil {
						return err
					}
				}
				return nil
			})
			return c
		}
		before := now()
		if before.org == 0 {
			t.Error("an organization's authorization revision starts above zero")
		}
		write(t, func(tx authority.Tx) error {
			for _, bump := range []func() error{
				func() error { return tx.BumpAuthorizationRevision(f.orgA) },
				func() error { return tx.BumpPersonEpoch(f.onlyA) },
				func() error { return tx.BumpGrantEpoch(f.onlyA, inst) },
				func() error { return tx.BumpOwnerAwareRevision(audience) },
			} {
				if err := bump(); err != nil {
					return err
				}
			}
			return nil
		})
		after := now()
		if after.org <= before.org || after.person <= before.person || after.grant <= before.grant || after.aware <= before.aware {
			t.Errorf("a bump did not grow its counter: before %+v after %+v", before, after)
		}
		if after.otherOrg != before.otherOrg || after.otherPerson != before.otherPerson || after.otherGrant != before.otherGrant {
			t.Errorf("a bump moved another key's counter: before %+v after %+v", before, after)
		}
		read(t, func(tx authority.Tx) error {
			if _, err := tx.AuthorizationRevision(uuid.NewString()); !errors.Is(err, domain.ErrNotFound) {
				t.Errorf("an absent organization has no revision: %v", err)
			}
			return nil
		})
	})

	t.Run("a delegation reads back as written", func(t *testing.T) {
		d := domain.Delegation{ID: uuid.NewString(), Organization: f.orgA, Grantor: f.onlyA, Module: f.name("module"), Purpose: "a purpose",
			Scopes: []*basev0.WorkScopeV1{{ResourceKind: "k", Actions: []string{"read"}, ResourceIds: []string{"a"}}}}
		write(t, func(tx authority.Tx) error { return tx.PutDelegation(d) })
		d.Revoked = true
		write(t, func(tx authority.Tx) error { return tx.PutDelegation(d) })
		read(t, func(tx authority.Tx) error {
			got, err := tx.Delegation(d.ID)
			if err != nil {
				return err
			}
			if got.ID != d.ID || got.Organization != d.Organization || got.Grantor != d.Grantor || got.Module != d.Module || got.Purpose != d.Purpose ||
				!got.Revoked || !scope.Same(got.Scopes, d.Scopes) {
				t.Errorf("delegation %+v, want %+v", got, d)
			}
			all, err := tx.Delegations()
			if err != nil {
				return err
			}
			if !slices.ContainsFunc(all, func(x domain.Delegation) bool { return x.ID == d.ID }) ||
				!sort.SliceIsSorted(all, func(a, b int) bool { return all[a].ID < all[b].ID }) {
				t.Error("Delegations omits it or is not sorted by id")
			}
			return nil
		})
	})

	t.Run("a failed transaction leaves nothing behind", func(t *testing.T) {
		m := f.module("module")
		inst := domain.Installation{ID: uuid.NewString(), Organization: f.orgA, Target: m.Name, Status: domain.Active, Revision: 1}
		var before uint64
		read(t, func(tx authority.Tx) (err error) { before, err = tx.AuthorizationRevision(f.orgA); return err })
		failure := errors.New("the decision refused")
		err := store.Write(ctx, func(tx authority.Tx) error {
			if err := tx.PutModule(m); err != nil {
				return err
			}
			if err := tx.PutInstallation(inst); err != nil {
				return err
			}
			if err := tx.PutRoleGrant(domain.RoleGrant{InstallationID: inst.ID, Role: "viewer", PersonID: f.onlyA}); err != nil {
				return err
			}
			if err := tx.BumpAuthorizationRevision(f.orgA); err != nil {
				return err
			}
			// What a transaction wrote, it reads.
			if _, err := tx.ModuleNamed(m.Name); err != nil {
				return err
			}
			return failure
		})
		if !errors.Is(err, failure) {
			t.Fatalf("the transaction's own error is returned: %v", err)
		}
		read(t, func(tx authority.Tx) error {
			if _, err := tx.ModuleNamed(m.Name); !errors.Is(err, domain.ErrNotFound) {
				t.Errorf("the module survived: %v", err)
			}
			if _, err := tx.Installation(inst.ID); !errors.Is(err, domain.ErrNotFound) {
				t.Errorf("the installation survived: %v", err)
			}
			if grants, err := tx.RoleGrants(inst.ID); err != nil || len(grants) != 0 {
				t.Errorf("the grant survived: %v %v", grants, err)
			}
			if after, err := tx.AuthorizationRevision(f.orgA); err != nil || after != before {
				t.Errorf("the revision moved: %d → %d %v", before, after, err)
			}
			return nil
		})
	})
}

type fixture struct {
	identity                Identity
	run                     string
	orgA, orgB, onlyA, both string
	team                    string
}

func newFixture() *fixture {
	f := &fixture{run: uuid.NewString()[:8], orgA: uuid.NewString(), orgB: uuid.NewString(), onlyA: uuid.NewString(), both: uuid.NewString(), team: uuid.NewString()}
	reader := []domain.RoleScope{{Kind: "storetest.item", Actions: []string{"read"}}, {Kind: "storetest.note", Actions: []string{"write"}, Resources: []resources.Grant{{ID: "note-1"}}}}
	f.identity = Identity{
		Organizations: []domain.Organization{{ID: f.orgA, Name: "Storetest A " + f.run}, {ID: f.orgB, Name: "Storetest B " + f.run}},
		Members: []Member{
			{Organization: f.orgA, Person: f.onlyA, Teams: []string{f.team}, Scopes: reader},
			{Organization: f.orgA, Person: f.both, Administrator: true},
			{Organization: f.orgB, Person: f.both, Scopes: []domain.RoleScope{{Kind: "storetest.item", Actions: []string{"write"}}}},
		},
	}
	return f
}

func (f *fixture) name(what string) string { return "storetest-" + what + "-" + f.run }

func (f *fixture) module(kind string) domain.Module {
	read := []*basev0.WorkScopeV1{{ResourceKind: "storetest.item", Actions: []string{"read"}}}
	m := domain.Module{Name: f.name(kind), Principal: f.name(kind + "-principal"), Kind: kind, Generation: 1, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{{ResourceKind: "storetest.item", Actions: []string{"read", "write"}}},
		Bindings:      map[string]domain.Binding{"store": {ID: "store", Audience: "store", InvokeScopes: read, HeadlessScopes: read, LookupScopes: read}},
		Methods:       map[string]domain.MethodPolicy{"/s.S/Read": {Requires: read}, "GET /open": {AnyCheckedCaller: true}}}
	if kind == domain.KindSolution {
		m.Roles = map[string][]*basev0.WorkScopeV1{domain.InstallerRole: read, "viewer": read}
		m.OwnedRoles = map[string][]*basev0.WorkScopeV1{"viewer": {{ResourceKind: "store.item", Actions: []string{"read"}}}}
	}
	return m
}

func second[T any](_ T, err error) error { return err }

func sameSet(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(slices.Clone(a))), slices.Sorted(slices.Values(slices.Clone(b))))
}

func sameScopes(a, b []*basev0.WorkScopeV1) bool {
	return scope.Same(scope.Normalize(a), scope.Normalize(b))
}

func sameModule(t *testing.T, got, want domain.Module) {
	t.Helper()
	ok := got.Name == want.Name && got.Principal == want.Principal && got.Kind == want.Kind && got.Generation == want.Generation &&
		got.StandIn == want.StandIn && got.OwnerAware == want.OwnerAware && sameScopes(got.ResourceKinds, want.ResourceKinds) &&
		len(got.Bindings) == len(want.Bindings) && len(got.Roles) == len(want.Roles) && len(got.OwnedRoles) == len(want.OwnedRoles) && len(got.Methods) == len(want.Methods)
	for id, b := range want.Bindings {
		g := got.Bindings[id]
		ok = ok && g.ID == b.ID && g.Audience == b.Audience && sameScopes(g.InvokeScopes, b.InvokeScopes) && sameScopes(g.HeadlessScopes, b.HeadlessScopes) && sameScopes(g.LookupScopes, b.LookupScopes)
	}
	for name, scopes := range want.Roles {
		ok = ok && sameScopes(got.Roles[name], scopes)
	}
	for name, scopes := range want.OwnedRoles {
		ok = ok && sameScopes(got.OwnedRoles[name], scopes)
	}
	for method, p := range want.Methods {
		g := got.Methods[method]
		ok = ok && g.AnyCheckedCaller == p.AnyCheckedCaller && sameScopes(g.Requires, p.Requires)
	}
	if !ok {
		t.Errorf("module reads %+v, want %+v", got, want)
	}
}

func sameInstallation(t *testing.T, got, want domain.Installation) {
	t.Helper()
	ok := got.ID == want.ID && got.Organization == want.Organization && got.Target == want.Target && got.Status == want.Status &&
		got.Revision == want.Revision && got.AgentRole == want.AgentRole && got.PrincipalID == want.PrincipalID &&
		got.InstalledBy == want.InstalledBy && got.Consent == want.Consent && len(got.Owned) == len(nonEmpty(want.Owned))
	for k, ids := range nonEmpty(want.Owned) {
		ok = ok && slices.Equal(got.Owned[k], ids)
	}
	if !ok {
		t.Errorf("installation reads %+v, want %+v", got, want)
	}
}

func nonEmpty(m map[string][]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range m {
		if len(v) > 0 {
			out[k] = v
		}
	}
	return out
}

// point is one (kind, action, resource matcher) an organization role grants.
type point struct{ kind, action, resource string }

func points(scopes []domain.RoleScope) map[point]bool {
	out := map[point]bool{}
	for _, sc := range scopes {
		for _, a := range sc.Actions {
			if len(sc.Resources) == 0 {
				out[point{sc.Kind, a, ""}] = true
			}
			for _, r := range sc.Resources {
				out[point{sc.Kind, a, r.ID + "|" + r.Prefix + "|" + r.Pattern}] = true
			}
		}
	}
	return out
}

func heldScopes(tx authority.Tx, p domain.Person) (map[point]bool, error) {
	var all []domain.RoleScope
	for _, name := range p.Roles {
		r, err := tx.OrgRole(p.Organization, name)
		if errors.Is(err, domain.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		all = append(all, r.Scopes...)
	}
	return points(all), nil
}

func samePoints(a, b map[point]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
