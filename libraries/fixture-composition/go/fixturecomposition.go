// Package fixturecomposition is the local authority's fixture-composition
// document: what the modules a run composes, and the composition itself, add
// to the local authority's fixture. It is the one parser of the document and
// the one place its merge rules live.
//
// The fixture says who exists and which organisation roles they hold, in the
// authority's own vocabulary. What those roles may do at a module is the
// module's to say: each module ships a fragment of this document next to its
// code (configurations/<profile>/fixture-composition.yaml in the module), and
// a composition ships one more for what is truly its own (a seeded
// collection's id). The run merges every fragment into the document the local
// authority reads (Merge); the local authority then checks the result against
// its fixture.
package fixturecomposition

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	resources "github.com/codefly-dev/authority/libraries/resources/go"
	"gopkg.in/yaml.v3"
)

// Name is the workspace configuration document the local authority reads.
const Name = "fixture-composition"

// Schema versions the document. Its sections and the fixture's organisation,
// role and person ids it names are a contract with every composing
// repository: a breaking change is a new schema, never an edit.
const Schema = "codefly.dev/authority/fixture-composition/v1"

// The wildcards a composition never grants: a wildcard on a business role
// would erase the difference between viewer, editor and administrator.
const (
	anyKind   = "*"
	anyAction = "*"
)

// A kind is dot-separated lowercase segments ("ledger.entry"); an action one
// lowercase word ("read", "read_config"). A wildcard is neither.
var (
	kindGrammar   = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$`)
	actionGrammar = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
)

// ErrConflict is two sources stating the same thing: the same role's grant on
// one kind, the same installation, or the same stand-in module.
var ErrConflict = errors.New("fixture-composition: two sources state the same grant")

// Document is one fixture-composition document.
type Document struct {
	Schema string `yaml:"schema"`
	// Roles adds grants to roles the fixture defines.
	Roles []Role `yaml:"roles,omitempty"`
	// Installations are installations of a solution the run composes, taking
	// the fixture's own path.
	Installations []Installation `yaml:"installations,omitempty"`
	// Modules are modules the run supervises itself, until their own delivery.
	Modules []Module `yaml:"modules,omitempty"`
}

// Role is grants added to one role the fixture defines.
type Role struct {
	Organization string  `yaml:"organization"`
	Name         string  `yaml:"name"`
	Scopes       []Scope `yaml:"scopes"`
}

// Key is the role as the fixture names it, organisation/name.
func (r Role) Key() string { return r.Organization + "/" + r.Name }

// Scope is one (kind, actions) pair, optionally narrowed to named resources.
// With no resources it covers every resource of the kind.
type Scope struct {
	Kind      string          `yaml:"kind"`
	Actions   []string        `yaml:"actions,flow"`
	Resources []ResourceMatch `yaml:"resources,omitempty"`
}

// ResourceMatch is one resource grant: exactly one of every resource, one id,
// an id prefix or a pattern (libraries/resources).
type ResourceMatch struct {
	All     bool   `yaml:"all,omitempty"`
	ID      string `yaml:"id,omitempty"`
	Prefix  string `yaml:"prefix,omitempty"`
	Pattern string `yaml:"pattern,omitempty"`
}

// Grant is the match as the shared library evaluates it.
func (r ResourceMatch) Grant() resources.Grant {
	return resources.Grant{All: r.All, ID: r.ID, Prefix: r.Prefix, Pattern: r.Pattern}
}

// Installation is one installation performed through the real install path
// once its target is composed: Role is the installation's own (its agent's),
// Owner installed it and is granted the installer role, and each of Teams is
// granted Role.
type Installation struct {
	Organization string   `yaml:"organization"`
	Target       string   `yaml:"target"`
	Role         string   `yaml:"role"`
	Owner        string   `yaml:"owner"`
	Teams        []string `yaml:"teams,omitempty,flow"`
}

// Module is a module the run stands in for: its name, which is its principal,
// and the kinds and actions it serves.
type Module struct {
	Module string  `yaml:"module"`
	Kinds  []Scope `yaml:"kinds"`
}

// Decode reads exactly one versioned mapping and checks everything that does
// not depend on the fixture. An empty or null document, a section spelled
// null and an unknown field are each refused, so a mistake never reads as
// "grants nothing"; so are a wildcard, a kind or action outside the grammar,
// a malformed resource matcher, a role or stand-in module with no scope, and
// an installation with no target or role.
func Decode(data []byte) (Document, error) {
	var doc Document
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
	if doc.Schema != Schema {
		return doc, fmt.Errorf("schema is %q; this authority reads %s", doc.Schema, Schema)
	}
	return doc, doc.validate()
}

func (d Document) validate() error {
	for _, r := range d.Roles {
		key := r.Key()
		switch {
		case r.Organization == "" || r.Name == "":
			return fmt.Errorf("a role names no organization or no name (%q)", key)
		case len(r.Scopes) == 0:
			return fmt.Errorf("%s names no scope", key)
		}
		for _, sc := range r.Scopes {
			if err := CheckScope(sc.Kind, sc.Actions); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
			grants := make([]resources.Grant, 0, len(sc.Resources))
			for _, m := range sc.Resources {
				grants = append(grants, m.Grant())
			}
			if _, err := resources.Compile(grants); err != nil {
				return fmt.Errorf("%s scope %s: %w", key, sc.Kind, err)
			}
		}
	}
	for _, i := range d.Installations {
		if i.Target == "" || i.Role == "" {
			return errors.New("an installation names no target or no role")
		}
	}
	for _, m := range d.Modules {
		if !kindGrammar.MatchString(m.Module) || len(m.Kinds) == 0 {
			return fmt.Errorf("stand-in module %q names no valid module or no kind", m.Module)
		}
		for _, k := range m.Kinds {
			if err := CheckScope(k.Kind, k.Actions); err != nil {
				return fmt.Errorf("stand-in module %s: %w", m.Module, err)
			}
		}
	}
	return nil
}

// CheckScope refuses a wildcard by name, then anything outside the grammar
// (whitespace included). A composition grants the concrete permissions its
// modules serve.
func CheckScope(kind string, actions []string) error {
	if kind == anyKind {
		return errors.New("a composition grants concrete kinds; the wildcard kind \"*\" is refused")
	}
	if !kindGrammar.MatchString(kind) {
		return fmt.Errorf("kind %q is not a kind (dot-separated lowercase segments)", kind)
	}
	if len(actions) == 0 {
		return fmt.Errorf("scope %s names no action", kind)
	}
	for _, action := range actions {
		if action == anyAction {
			return fmt.Errorf("a composition grants concrete actions; the wildcard action \"*\" on %s is refused", kind)
		}
		if !actionGrammar.MatchString(action) {
			return fmt.Errorf("action %q on %s is not an action (one lowercase word)", action, kind)
		}
	}
	return nil
}

// Source is one fragment and where it came from, in the words a person fixes
// it by: "module documents (modules/documents/configurations/local/...)".
type Source struct {
	Name string
	Data []byte
}

// Merge combines fragments into the one document the local authority reads.
//
// Every statement has exactly one source: a role's grant on one kind (the
// organisation, the role and the kind together), one installation (its
// organisation and target), one stand-in module. Two sources stating the same
// one is refused naming both, even when they agree, because the fragment that
// owns it is the one a reader goes to: a composition narrowing a module's grant
// to a seeded resource must not be silently widened by the module's, and a
// module's grant copied into a composition is the drift this exists to end.
// Within one source the document reads as it does alone.
//
// The result does not depend on the order the sources are given in: they are
// merged in the order of their names, and two sources of one name are refused.
func Merge(sources []Source) (Document, error) {
	sorted := slices.Clone(sources)
	slices.SortFunc(sorted, func(a, b Source) int { return strings.Compare(a.Name, b.Name) })
	merged := Document{Schema: Schema}
	grants := map[string]string{}
	installations := map[string]string{}
	modules := map[string]string{}
	for i, source := range sorted {
		if source.Name == "" {
			return Document{}, errors.New("a fixture-composition fragment has no source name")
		}
		if i > 0 && sorted[i-1].Name == source.Name {
			return Document{}, fmt.Errorf("two fixture-composition fragments are both named %s", source.Name)
		}
		doc, err := Decode(source.Data)
		if err != nil {
			return Document{}, fmt.Errorf("%s: %w", source.Name, err)
		}
		for _, r := range doc.Roles {
			for _, sc := range r.Scopes {
				key := r.Key() + " " + sc.Kind
				if owner, ok := grants[key]; ok && owner != source.Name {
					return Document{}, fmt.Errorf("%w: %s's grant on %s is stated by %s and by %s; state it in one of them",
						ErrConflict, r.Key(), sc.Kind, owner, source.Name)
				}
				grants[key] = source.Name
			}
		}
		for _, in := range doc.Installations {
			key := in.Organization + "/" + in.Target
			if owner, ok := installations[key]; ok && owner != source.Name {
				return Document{}, fmt.Errorf("%w: the installation of %s at %s is stated by %s and by %s; state it in one of them",
					ErrConflict, in.Target, in.Organization, owner, source.Name)
			}
			installations[key] = source.Name
		}
		for _, m := range doc.Modules {
			if owner, ok := modules[m.Module]; ok && owner != source.Name {
				return Document{}, fmt.Errorf("%w: stand-in module %s is stated by %s and by %s; state it in one of them",
					ErrConflict, m.Module, owner, source.Name)
			}
			modules[m.Module] = source.Name
		}
		merged.Roles = append(merged.Roles, doc.Roles...)
		merged.Installations = append(merged.Installations, doc.Installations...)
		merged.Modules = append(merged.Modules, doc.Modules...)
	}
	return merged, nil
}

// Encode writes the document as YAML that Decode reads back unchanged.
func Encode(doc Document) ([]byte, error) {
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(doc); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
