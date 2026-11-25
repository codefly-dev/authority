// Package fixturecomposition is the local authority's fixture-composition
// document: what the modules a run composes, and the composition itself, add
// to the local authority's fixture. It is the one parser of the document and
// the one place its merge rules live.
//
// The fixture says who exists, in the authority's own vocabulary. A
// composition adds what is its own: the installations of the solutions it
// composes and who is seated on them, and the modules the run supervises
// itself. Each module ships a fragment of this document next to its code
// (configurations/<profile>/fixture-composition.yaml in the module), and a
// composition ships one more for what is truly its own. The run merges every
// fragment into the document the local authority reads (Merge); the local
// authority then checks the result against its fixture.
//
// The document grants no organisation role anything. Organisation roles
// decide administration only, and a person reaches a module through a role
// (admin, user) on an installation: a fixture person who is to reach a module
// is seated on a team of an installation that reaches it (Installation.Members).
package fixturecomposition

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Name is the workspace configuration document the local authority reads.
const Name = "fixture-composition"

// Schema names the document. There is one schema: its sections and the
// fixture's organisation and person ids it names are a contract with every
// composing repository. A document stating any other is refused (Decode).
const Schema = "codefly.dev/authority/fixture-composition/v1"

// noRoles is what a document that still tries to grant an organisation role
// is told.
const noRoles = "organisation roles decide administration only, and a person reaches a module through a role on an installation: seat each person who is to reach a module on a team of an installation that reaches it (installations: members), and remove the roles section"

// The wildcards a stand-in module never serves: it declares the concrete
// kinds and actions the module it stands in for serves.
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

// ErrConflict is the same thing stated twice — the same installation, the
// same stand-in module — whether by two sources (Merge) or twice within one
// document (Decode).
var ErrConflict = errors.New("fixture-composition: one statement, stated twice")

// Document is one fixture-composition document.
type Document struct {
	Schema string `yaml:"schema"`
	// Installations are installations of a solution the run composes, taking
	// the fixture's own path, and who is seated on a role-gated target.
	Installations []Installation `yaml:"installations,omitempty"`
	// Modules are modules the run supervises itself, until their own delivery.
	Modules []Module `yaml:"modules,omitempty"`
}

// Scope is one (kind, actions) pair a stand-in module serves.
type Scope struct {
	Kind    string   `yaml:"kind"`
	Actions []string `yaml:"actions,flow"`
}

// Installation is one installation performed through the real install path
// once its target is composed: Role is the installation's own (its agent's),
// Owner installed it and is granted the admin role, and each of Teams is
// granted Role.
//
// A row whose Target is EveryTarget stands for every role-gated target the
// run composes (a solution, a module page declaring roles), whatever the
// composition is: each declared role of each such target goes to its
// conventional `<target>-<role>` team, and each person under Members joins
// the team of the role named, where the target declares that role. It names
// no role and no teams, since those are one target's, and installs nothing:
// a module page is installed by composition, a solution by a row naming it
// or by an administrator, and each is seated once it is active. Owner is the
// administrator the row stands for, a member of the organisation.
type Installation struct {
	Organization string   `yaml:"organization"`
	Target       string   `yaml:"target"`
	Role         string   `yaml:"role,omitempty"`
	Owner        string   `yaml:"owner"`
	Teams        []string `yaml:"teams,omitempty,flow"`
	// Members are, by declared role, the people who join the conventional
	// `<target>-<role>` team holding that role on the installation.
	Members map[string][]string `yaml:"members,omitempty"`
}

// EveryTarget is the target of a row standing for every role-gated target
// the run composes.
const EveryTarget = "*"

// Module is a module the run stands in for: its name, which is its principal,
// and the kinds and actions it serves.
type Module struct {
	Module string  `yaml:"module"`
	Kinds  []Scope `yaml:"kinds"`
}

// Decode reads exactly one mapping stating the schema and checks everything that does
// not depend on the fixture. An empty or null document, a section spelled
// null and an unknown field are each refused, so a mistake never reads as
// "states nothing"; so are a wildcard, a kind or action outside the grammar,
// a stand-in module with no kind, and an installation with no target. A roles
// section is refused, whatever schema the document states, saying where a
// person's reach is stated now: a document that granted an organisation role
// a module's kinds is never read as one that grants nothing. A document
// stating another schema is refused telling its author to state Schema.
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
	// A roles section first, whatever schema the document states: a document
	// that granted an organisation role a module's kinds is refused saying
	// so, never for its label alone.
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == "roles" {
			return doc, fmt.Errorf("roles: a composition grants no organisation role a module's kinds: %s", noRoles)
		}
	}
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
		return doc, fmt.Errorf("schema is %q, which is unknown; this authority reads %s and no other: state the schema as %s", doc.Schema, Schema, Schema)
	}
	return doc, doc.validate()
}

// validate holds one document — a single fragment, or a merged one — to the
// rules that do not depend on the fixture, the one-statement-one-source rule
// included: the same installation and the same stand-in module are each
// stated once in a document, as they are stated by one source across
// documents (Merge). Whoever reads the first statement has no reason to look
// for a second further down the file.
func (d Document) validate() error {
	installations := map[string]bool{}
	for _, i := range d.Installations {
		switch {
		case i.Target == "":
			return errors.New("an installation names no target")
		case i.Target != EveryTarget && i.Role == "" && len(i.Teams) > 0:
			// A row's teams take its role. A row naming none installs with the
			// role the target declares (installation_role), and the authority
			// refuses a role that overrides that declaration, so a target
			// declaring `installation_role: none` is installed by a row with no
			// role and no teams; an undeclared target still needs one, which
			// the authority asks for by name.
			return errors.New("an installation grants teams and names no role for them")
		case i.Target == EveryTarget && (i.Role != "" || len(i.Teams) > 0):
			return errors.New("a row standing for every target names only its owner and members: a role and teams are one target's")
		}
		for role, people := range i.Members {
			if role == "" || len(people) == 0 {
				return fmt.Errorf("the installation of %s at %s: members name a role and the people who take it", i.Target, i.Organization)
			}
		}
		key := i.Organization + "/" + i.Target
		if installations[key] {
			return fmt.Errorf("%w: the installation of %s at %s is stated twice in one document; state it once",
				ErrConflict, i.Target, i.Organization)
		}
		installations[key] = true
	}
	modules := map[string]bool{}
	for _, m := range d.Modules {
		if !kindGrammar.MatchString(m.Module) || len(m.Kinds) == 0 {
			return fmt.Errorf("stand-in module %q names no valid module or no kind", m.Module)
		}
		if modules[m.Module] {
			return fmt.Errorf("%w: stand-in module %s is stated twice in one document; state it once, with every kind it serves",
				ErrConflict, m.Module)
		}
		modules[m.Module] = true
		for _, k := range m.Kinds {
			if err := CheckScope(k.Kind, k.Actions); err != nil {
				return fmt.Errorf("stand-in module %s: %w", m.Module, err)
			}
		}
	}
	return nil
}

// CheckScope refuses a wildcard by name, then anything outside the grammar
// (whitespace included). A stand-in module serves concrete kinds and actions.
func CheckScope(kind string, actions []string) error {
	if kind == anyKind {
		return errors.New("a stand-in module serves concrete kinds; the wildcard kind \"*\" is refused")
	}
	if !kindGrammar.MatchString(kind) {
		return fmt.Errorf("kind %q is not a kind (dot-separated lowercase segments)", kind)
	}
	if len(actions) == 0 {
		return fmt.Errorf("scope %s names no action", kind)
	}
	for _, action := range actions {
		if action == anyAction {
			return fmt.Errorf("a stand-in module serves concrete actions; the wildcard action \"*\" on %s is refused", kind)
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
// Every statement has exactly one source: one installation (its organisation
// and target), one stand-in module. Two sources stating the same one is
// refused naming both, even when they agree, because the fragment that owns
// it is the one a reader goes to. Within ONE source the same rule holds,
// which Decode refuses (validate).
//
// The result does not depend on the order the sources are given in: they are
// merged in the order of their names, and two sources of one name are refused.
func Merge(sources []Source) (Document, error) {
	sorted := slices.Clone(sources)
	slices.SortFunc(sorted, func(a, b Source) int { return strings.Compare(a.Name, b.Name) })
	merged := Document{Schema: Schema}
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
