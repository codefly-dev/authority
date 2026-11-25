package registry_test

import (
	"testing"
	"time"

	conformance "github.com/codefly-dev/authority/libraries/conformance/go"
)

// TestTheLocalAuthorityPassesTheSuiteOnOneSharedHost drives every case, in
// order, against one host: the way a host that cannot build a fresh one per
// case runs the suite. A case that leans on state another case left behind,
// or leaves behind what a later case trips on, passes RunParallel's fresh
// hosts and is red only here.
func TestTheLocalAuthorityPassesTheSuiteOnOneSharedHost(t *testing.T) {
	// A host of its own, on a clock of its own: it runs beside the other
	// suites of this package, which each build theirs.
	t.Parallel()
	clock := conformance.NewClock(time.Now().UTC())
	conn, descriptors, fixture := localConformanceFixture(t, clock)
	fixture.Clock = clock
	conformance.Run(t, conn, descriptors, fixture)
}
