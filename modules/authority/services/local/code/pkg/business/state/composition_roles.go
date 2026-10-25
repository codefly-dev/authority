package state

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	resources "github.com/codefly-dev/authority/libraries/resources/go"
	"gopkg.in/yaml.v3"
)

// CompositionRolesDocument is the workspace configuration document a
// composition supplies to grant the fixture's organisation roles what its
// modules serve. The fixture says who exists and which roles they hold; a
// module's permissions belong to the module's own composition (its
// playground), so this repository need not name them.
const CompositionRolesDocument = "fixture-roles"

// GrantCompositionRoles adds a composition's grants to the fixture's roles.
// The document spells roles as the fixture does (`roles:` entries naming an
// organisation, a role and its scopes). Each entry must name a role the
// fixture defines: a composition grants, it never creates a role or a person.
// The generated developer role is refused, being derived from the delivered
// catalog. It returns one line per grant, for the boot log.
func (s *State) GrantCompositionRoles(data []byte) ([]string, error) {
	var doc *struct {
		Roles []Role `yaml:"roles"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", CompositionRolesDocument, err)
	}
	if doc == nil {
		return nil, fmt.Errorf("%s: expected a roles document, got empty or null", CompositionRolesDocument)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: expected exactly one roles document", CompositionRolesDocument)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
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
			return nil, fmt.Errorf("%s: %s is not a role the fixture defines", CompositionRolesDocument, key)
		case r.Generated || role.Generated:
			return nil, fmt.Errorf("%s: %s is derived from the delivered catalog and takes no grant", CompositionRolesDocument, key)
		case len(r.Scopes) == 0:
			return nil, fmt.Errorf("%s: %s names no scope", CompositionRolesDocument, key)
		}
		for _, sc := range r.Scopes {
			if strings.TrimSpace(sc.Kind) == "" || len(sc.Actions) == 0 {
				return nil, fmt.Errorf("%s: %s grants a scope with no kind or no action", CompositionRolesDocument, key)
			}
			for _, action := range sc.Actions {
				if strings.TrimSpace(action) == "" {
					return nil, fmt.Errorf("%s: %s scope %s has an empty action", CompositionRolesDocument, key, sc.Kind)
				}
			}
			grants := make([]resources.Grant, 0, len(sc.Resources))
			for _, m := range sc.Resources {
				grants = append(grants, m.Grant())
			}
			if _, err := resources.Compile(grants); err != nil {
				return nil, fmt.Errorf("%s: %s scope %s: %w", CompositionRolesDocument, key, sc.Kind, err)
			}
			role.Scopes = append(role.Scopes, sc)
			lines = append(lines, fmt.Sprintf("%s: %s:%v", key, sc.Kind, sc.Actions))
		}
		granted[key] = role
	}
	// Applied only once every entry is valid: a refused document leaves the
	// fixture's roles as they were.
	for key, role := range granted {
		s.roles[key] = role
	}
	return lines, nil
}
