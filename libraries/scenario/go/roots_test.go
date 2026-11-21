package scenario

import (
	"slices"
	"testing"
	"time"

	"github.com/codefly-dev/core/sdk/dependencies"
)

// session is the dependency session the options ask for, as the SDK reads it.
func session(options Options) dependencies.Option {
	var o dependencies.Option
	for _, apply := range sessionOptions("/anchor", "scenario", time.Minute, options) {
		apply(&o)
	}
	return o
}

// The roots a composition names reach the dependency session as its co-roots,
// in the order named, beside what the run leaves out: a worker nothing calls
// is started because the options say so, and for no other reason.
func TestRootsAreTheSessionsCoRoots(t *testing.T) {
	o := session(Options{
		Roots:   []string{"runtime/worker", "runtime/dispatcher"},
		Without: []string{"documents/store"},
	})
	if want := []string{"runtime/worker", "runtime/dispatcher"}; !slices.Equal(o.CoRoots, want) {
		t.Fatalf("co-roots = %v, want %v", o.CoRoots, want)
	}
	if want := []string{"documents/store"}; !slices.Equal(o.ExcludedDependencies, want) {
		t.Fatalf("excluded dependencies = %v, want %v", o.ExcludedDependencies, want)
	}
	if o.Directory != "/anchor" || o.NamingScope != "scenario" || !o.CommandScopedEnvironment {
		t.Fatalf("the session is not the anchor's: directory %q, scope %q, command-scoped %v", o.Directory, o.NamingScope, o.CommandScopedEnvironment)
	}
}

// A composition that names no root asks for none: the run is the anchor's
// dependencies, as it was before Roots existed.
func TestNoRootsAsksForNoCoRoot(t *testing.T) {
	if o := session(Options{Without: []string{"documents/store"}}); len(o.CoRoots) != 0 {
		t.Fatalf("co-roots = %v, want none", o.CoRoots)
	}
}
