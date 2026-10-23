package resources

import (
	"errors"
	"strings"
	"testing"
)

func TestAResourceIsCoveredWhenAnyGrantMatchesItsWholeID(t *testing.T) {
	m, err := Compile([]Grant{{ID: "board"}, {Prefix: "directory/"}, {Pattern: "shared-[a-z]+"}})
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{
		"board": true, "board2": false,
		"directory/2026": true, "directory": false, "x/directory/": false,
		"shared-finance": true, "shared-": false, "shared-Finance": false, "my-shared-finance": false, "shared-finance-2": false,
		"": false,
	} {
		if got := m.Matches(id); got != want {
			t.Errorf("%q: got %v, want %v", id, got, want)
		}
	}
	if m.All() {
		t.Error("no grant names every resource")
	}
}

func TestAllCoversEveryResourceAndNoGrantCoversNone(t *testing.T) {
	all, _ := Compile([]Grant{{All: true}})
	if !all.All() || !all.Matches("anything") {
		t.Fatal("all covers every resource")
	}
	none, _ := Compile(nil)
	if none.All() || none.Matches("anything") {
		t.Fatal("no grant covers nothing")
	}
}

func TestAnInvalidGrantIsRefusedByName(t *testing.T) {
	for name, g := range map[string]Grant{
		"names nothing":             {},
		"names two things":          {ID: "a", Prefix: "b"},
		"a pattern that is not RE2": {Pattern: "(a"},
		"a pattern past the bound":  {Pattern: strings.Repeat("a", MaxPattern+1)},
		"a backreference":           {Pattern: `(a)\1`},
	} {
		if _, err := Compile([]Grant{g}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
