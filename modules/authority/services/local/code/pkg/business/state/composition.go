package state

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"

	resources "github.com/codefly-dev/authority/libraries/resources/go"
	"gopkg.in/yaml.v3"
)

// CompositionDocument is the workspace configuration document through which
// a composition adds its own part to the fixture: what the fixture's
// organisation roles hold at the modules it composes, the installations of
// the solutions it composes, and the modules it supervises itself. The
// fixture says who exists and which roles they hold, in the authority's own
// vocabulary; every module's and solution's vocabulary belongs to the
// composition that composes it, never to this repository. The authority
// module ships an empty default, so a composition that supplies none boots
// on the fixture alone.
const CompositionDocument = "fixture-composition"

// CompositionSchema versions the document. Its sections and the fixture's
// organisation, role and person ids it names are a contract with every
// composing repository: a breaking change is a new schema, never an edit.
const CompositionSchema = "codefly.dev/authority/fixture-composition/v1"

// A kind is dot-separated lowercase segments ("ledger.entry"); an action one
// lowercase word ("read", "read_config"). A wildcard is neither.
var (
	kindGrammar   = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$`)
	actionGrammar = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
)

type compositionFile struct {
	Schema        string                `yaml:"schema"`
	Roles         []Role                `yaml:"roles"`
	Installations []FixtureInstallation `yaml:"installations"`
	Modules       []FixtureModule       `yaml:"modules"`
}

// ApplyComposition adds a composition's document to the loaded fixture. Roles
// entries add scopes to roles the fixture defines (a composition grants; it
// never creates a role or a person, and never touches the generated developer
// role). Installations and modules take the fixture's own path: an
// installation is performed when its target is composed, a module stands in
// until its own delivery replaces it. Nothing is applied unless the whole
// document is valid. It returns one line per effect, for the boot log.
func (s *State) ApplyComposition(ctx context.Context, data []byte) ([]string, error) {
	doc, err := decodeComposition(data)
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

// decodeComposition reads exactly one versioned mapping. An empty or null
// document, a section spelled null and an unknown field are each refused, so
// a mistake never reads as "grants nothing".
func decodeComposition(data []byte) (compositionFile, error) {
	var doc compositionFile
	var node yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&node); err != nil {
		if errors.Is(err, io.EOF) {
			return doc, errors.New("the document is empty")
		}
		return doc, err
	}
	if len(node.Content) != 1 || node.Content[0].Kind != yaml.MappingNode {
		return doc, errors.New("the document is not a mapping")
	}
	mapping := node.Content[0]
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i+1].Tag == "!!null" {
			return doc, fmt.Errorf("%s is null: omit it, or give a list", mapping.Content[i].Value)
		}
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil {
		return doc, err
	}
	if doc.Schema != CompositionSchema {
		return doc, fmt.Errorf("schema is %q; this authority reads %s", doc.Schema, CompositionSchema)
	}
	return doc, nil
}

// composedRoles is the fixture's roles with the document's grants added.
func (s *State) composedRoles(doc compositionFile) (map[string]Role, []string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	granted := map[string]Role{}
	var lines []string
	for _, r := range doc.Roles {
		key := r.Organization + "/" + r.Name
		role, ok := granted[key]
		if !ok {
			role, ok = s.roles[key]
			role.Scopes = slices.Clone(role.Scopes)
		}
		switch {
		case !ok:
			return nil, nil, fmt.Errorf("%s is not a role the fixture defines", key)
		case r.Generated || role.Generated:
			return nil, nil, fmt.Errorf("%s is derived from the delivered catalog and takes no grant", key)
		case len(r.Scopes) == 0:
			return nil, nil, fmt.Errorf("%s names no scope", key)
		}
		for _, sc := range r.Scopes {
			if err := checkScope(sc.Kind, sc.Actions); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", key, err)
			}
			grants := make([]resources.Grant, 0, len(sc.Resources))
			for _, m := range sc.Resources {
				grants = append(grants, m.Grant())
			}
			if _, err := resources.Compile(grants); err != nil {
				return nil, nil, fmt.Errorf("%s scope %s: %w", key, sc.Kind, err)
			}
			role.Scopes = append(role.Scopes, sc)
			lines = append(lines, fmt.Sprintf("grants %s: %s:%v", key, sc.Kind, sc.Actions))
		}
		granted[key] = role
	}
	return granted, lines, nil
}

// checkScope refuses a wildcard by name, then anything outside the grammar
// (whitespace included). A composition grants the concrete permissions its
// modules serve: a wildcard on a business role would erase the difference
// between viewer, editor and administrator, which the generated developer
// role never carries either.
func checkScope(kind string, actions []string) error {
	if kind == AnyKind {
		return errors.New("a composition grants concrete kinds; the wildcard kind \"*\" is refused")
	}
	if !kindGrammar.MatchString(kind) {
		return fmt.Errorf("kind %q is not a kind (dot-separated lowercase segments)", kind)
	}
	if len(actions) == 0 {
		return fmt.Errorf("scope %s names no action", kind)
	}
	for _, action := range actions {
		if action == AnyAction {
			return fmt.Errorf("a composition grants concrete actions; the wildcard action \"*\" on %s is refused", kind)
		}
		if !actionGrammar.MatchString(action) {
			return fmt.Errorf("action %q on %s is not an action (one lowercase word)", action, kind)
		}
	}
	return nil
}

// checkComposedSetup checks the document's installations and stand-in modules
// against the fixture before anything is applied.
func (s *State) checkComposedSetup(doc compositionFile) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var lines []string
	for _, i := range doc.Installations {
		owner, ok := s.people[i.Owner]
		_, known := s.orgs[i.Organization]
		switch {
		case i.Target == "" || i.Role == "":
			return nil, fmt.Errorf("an installation names no target or no role")
		case !known:
			return nil, fmt.Errorf("installation of %s: %q is not an organisation the fixture defines", i.Target, i.Organization)
		case !ok || owner.Organization != i.Organization:
			return nil, fmt.Errorf("installation of %s: %q is not a person of %s in the fixture", i.Target, i.Owner, i.Organization)
		}
		lines = append(lines, fmt.Sprintf("installs %s at %s as %s, granting %s the installer role and %v the role %s", i.Target, i.Organization, i.Role, i.Owner, i.Teams, i.Role))
	}
	for _, m := range doc.Modules {
		if !kindGrammar.MatchString(m.Module) || len(m.Kinds) == 0 {
			return nil, fmt.Errorf("stand-in module %q names no valid module or no kind", m.Module)
		}
		for _, k := range m.Kinds {
			if err := checkScope(k.Kind, k.Actions); err != nil {
				return nil, fmt.Errorf("stand-in module %s: %w", m.Module, err)
			}
		}
		lines = append(lines, fmt.Sprintf("stands in for module %s until its delivery", m.Module))
	}
	return lines, nil
}
