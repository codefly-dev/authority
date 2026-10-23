// Package resources is how a grant the authority answers is evaluated, the same
// way everywhere: by the authority gateway when it validates a role, by the
// conformance suite when it holds an implementation to its answers, and by a
// module when it decides which of its resources a caller may touch.
//
// A grant names covered resources by one of four matches: every resource of
// the kind, one id, an id prefix, or a pattern. A resource is covered when any
// grant matches its id.
package resources

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// MaxPattern bounds a pattern's length. Patterns are RE2, so matching is linear
// in the id; the bound keeps compiled programs small.
const MaxPattern = 256

// Grant is one match. Exactly one field is set.
type Grant struct {
	All     bool
	ID      string
	Prefix  string
	Pattern string
}

// Matcher answers whether a resource id is covered by a set of grants.
type Matcher struct {
	all      bool
	ids      map[string]bool
	prefixes []string
	patterns []*regexp.Regexp
}

// ErrInvalid is a grant that names nothing, more than one thing, or a pattern
// that does not compile within the bound.
var ErrInvalid = errors.New("resources: invalid grant")

// Compile validates grants and returns their matcher. No grant covers nothing.
func Compile(grants []Grant) (*Matcher, error) {
	m := &Matcher{ids: map[string]bool{}}
	for i, g := range grants {
		set := 0
		for _, present := range []bool{g.All, g.ID != "", g.Prefix != "", g.Pattern != ""} {
			if present {
				set++
			}
		}
		if set != 1 {
			return nil, fmt.Errorf("%w: grant %d sets %d matches, exactly one is required", ErrInvalid, i, set)
		}
		switch {
		case g.All:
			m.all = true
		case g.ID != "":
			m.ids[g.ID] = true
		case g.Prefix != "":
			m.prefixes = append(m.prefixes, g.Prefix)
		default:
			if len(g.Pattern) > MaxPattern {
				return nil, fmt.Errorf("%w: grant %d pattern is %d bytes, at most %d", ErrInvalid, i, len(g.Pattern), MaxPattern)
			}
			re, err := regexp.Compile(`^(?:` + g.Pattern + `)$`)
			if err != nil {
				return nil, fmt.Errorf("%w: grant %d pattern: %v", ErrInvalid, i, err)
			}
			m.patterns = append(m.patterns, re)
		}
	}
	return m, nil
}

// All reports whether every resource of the kind is covered.
func (m *Matcher) All() bool { return m != nil && m.all }

// Matches reports whether id is covered. An empty id never is.
func (m *Matcher) Matches(id string) bool {
	if m == nil || id == "" {
		return false
	}
	if m.all || m.ids[id] {
		return true
	}
	for _, p := range m.prefixes {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	for _, re := range m.patterns {
		if re.MatchString(id) {
			return true
		}
	}
	return false
}
