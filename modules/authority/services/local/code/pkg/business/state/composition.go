package state

import (
	"context"
	"fmt"
	"slices"

	fixturecomposition "github.com/codefly-dev/authority/libraries/fixture-composition/go"
	"gopkg.in/yaml.v3"
)

// CompositionDocument is the workspace configuration document through which
// a composition adds its part to the fixture: what the fixture's
// organisation roles hold at the modules it composes, the installations of
// the solutions it composes, and the modules it supervises itself. The
// fixture says who exists and which roles they hold, in the authority's own
// vocabulary; each module states its own grants in a fragment next to its
// code, the composition states only what is its own, and the run merges the
// fragments into this document (libraries/fixture-composition).
const CompositionDocument = fixturecomposition.Name

// CompositionSchema versions the document. Its sections and the fixture's
// organisation, role and person ids it names are a contract with every
// composing repository: a breaking change is a new schema, never an edit.
const CompositionSchema = fixturecomposition.Schema

// ApplyComposition adds a composition's document to the loaded fixture. Roles
// entries add scopes to roles the fixture defines (a composition grants; it
// never creates a role or a person, and never touches the generated developer
// role). Installations and modules take the fixture's own path: an
// installation is performed when its target is composed, a module stands in
// until its own delivery replaces it. The document is read by the library's
// one parser, which holds every rule that does not depend on the fixture;
// this checks it against the fixture. Nothing is applied unless the whole
// document is valid. It returns one line per effect, for the boot log.
func (s *State) ApplyComposition(ctx context.Context, data []byte) ([]string, error) {
	doc, err := fixturecomposition.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", CompositionDocument, err)
	}
	roles, lines, err := s.composedRoles(doc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", CompositionDocument, err)
	}
	more, err := s.checkComposedSetup(doc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", CompositionDocument, err)
	}
	s.mu.Lock()
	for key, role := range roles {
		s.roles[key] = role
	}
	s.refreshRolesLocked()
	s.mu.Unlock()
	if len(doc.Installations) > 0 || len(doc.Modules) > 0 {
		setup, err := yaml.Marshal(fixtureFile{Installations: doc.Installations, Modules: doc.Modules})
		if err != nil {
			return nil, err
		}
		if err := s.LoadFixture(ctx, setup); err != nil {
			return nil, fmt.Errorf("%s: %w", CompositionDocument, err)
		}
	}
	return append(lines, more...), nil
}

// composedRoles is the fixture's roles with the document's grants added.
func (s *State) composedRoles(doc fixturecomposition.Document) (map[string]Role, []string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	granted := map[string]Role{}
	var lines []string
	for _, r := range doc.Roles {
		key := r.Key()
		role, ok := granted[key]
		if !ok {
			role, ok = s.roles[key]
			role.Scopes = slices.Clone(role.Scopes)
		}
		switch {
		case !ok:
			return nil, nil, fmt.Errorf("%s is not a role the fixture defines", key)
		case role.Generated:
			return nil, nil, fmt.Errorf("%s is derived from the delivered catalog and takes no grant", key)
		}
		for _, sc := range r.Scopes {
			role.Scopes = append(role.Scopes, sc)
			lines = append(lines, fmt.Sprintf("grants %s: %s:%v", key, sc.Kind, sc.Actions))
		}
		granted[key] = role
	}
	return granted, lines, nil
}

// checkComposedSetup checks the document's installations against the fixture
// before anything is applied, and names each stand-in module.
func (s *State) checkComposedSetup(doc fixturecomposition.Document) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var lines []string
	for _, i := range doc.Installations {
		owner, ok := s.people[i.Owner]
		_, known := s.orgs[i.Organization]
		switch {
		case !known:
			return nil, fmt.Errorf("installation of %s: %q is not an organisation the fixture defines", i.Target, i.Organization)
		case !ok || owner.Organization != i.Organization:
			return nil, fmt.Errorf("installation of %s: %q is not a person of %s in the fixture", i.Target, i.Owner, i.Organization)
		}
		lines = append(lines, fmt.Sprintf("installs %s at %s as %s, granting %s the installer role and %v the role %s", i.Target, i.Organization, i.Role, i.Owner, i.Teams, i.Role))
	}
	for _, m := range doc.Modules {
		lines = append(lines, fmt.Sprintf("stands in for module %s until its delivery", m.Module))
	}
	return lines, nil
}
