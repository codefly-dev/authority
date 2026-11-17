package state

import (
	"context"
	"fmt"

	fixturecomposition "github.com/codefly-dev/authority/libraries/fixture-composition/go"
	"gopkg.in/yaml.v3"
)

// CompositionDocument is the workspace configuration document through which
// a composition adds its part to the fixture: the installations of the
// solutions it composes, who is seated on its role-gated targets, and the
// modules it supervises itself. The fixture says who exists, in the
// authority's own vocabulary; each module states its part in a fragment next
// to its code, the composition states only what is its own, and the run
// merges the fragments into this document (libraries/fixture-composition).
const CompositionDocument = fixturecomposition.Name

// CompositionSchema versions the document. Its sections and the fixture's
// organisation and person ids it names are a contract with every composing
// repository: a breaking change is a new schema, never an edit.
const CompositionSchema = fixturecomposition.Schema

// ApplyComposition adds a composition's document to the loaded fixture.
// Installations and modules take the fixture's own path: an installation is
// performed when its target is composed and its members are seated on its
// role teams, a module stands in until its own delivery replaces it. The
// document grants no organisation role anything: a person reaches a module
// through a role on an installation, and the library's one parser refuses a
// document that says otherwise. This checks the document against the fixture;
// nothing is applied unless the whole document is valid. It returns one line
// per effect, for the boot log.
func (s *State) ApplyComposition(ctx context.Context, data []byte) ([]string, error) {
	doc, err := fixturecomposition.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", CompositionDocument, err)
	}
	lines, err := s.checkComposedSetup(doc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", CompositionDocument, err)
	}
	if len(doc.Installations) > 0 || len(doc.Modules) > 0 {
		setup, err := yaml.Marshal(fixtureFile{Installations: doc.Installations, Modules: doc.Modules})
		if err != nil {
			return nil, err
		}
		if err := s.LoadFixture(ctx, setup); err != nil {
			return nil, fmt.Errorf("%s: %w", CompositionDocument, err)
		}
	}
	seated, err := s.SeatRoleTeams(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", CompositionDocument, err)
	}
	return append(lines, seated...), nil
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
		if i.Target == EveryTarget {
			lines = append(lines, fmt.Sprintf("seats on every role-gated target at %s, for %s: %v", i.Organization, i.Owner, i.Members))
			continue
		}
		lines = append(lines, fmt.Sprintf("installs %s at %s as %s, granting %s the admin role and %v the role %s", i.Target, i.Organization, i.Role, i.Owner, i.Teams, i.Role))
	}
	for _, m := range doc.Modules {
		lines = append(lines, fmt.Sprintf("stands in for module %s until its delivery", m.Module))
	}
	return lines, nil
}
