package conformance

import "time"

// RaceFactor is how many times longer a host may let the suite run in a
// binary built with the race detector. The detector slows the suite's own
// work and the host's several-fold: the local authority's shared-host run
// (TestTheLocalAuthorityPassesTheSuiteOnOneSharedHost) measured 1.9 s and
// 4.2 s without it against 23 s and 28 s with it on one machine, between six
// and twelve times, and a host whose ceiling of 25 minutes was calibrated at
// about 300 s without it was stopped at that ceiling with it.
const RaceFactor = 8

// Ceiling is the most a host lets its run of the suite take, given the
// ceiling it calibrated without the race detector: that ceiling as it is in
// an ordinary build, and RaceFactor times it in a build that carries the
// detector (RaceDetector). A host bounds its run with this rather than
// raising its ceiling for every build, so an ordinary run that is slow still
// fails by name at the calibrated bound:
//
//	ctx, cancel := context.WithTimeout(ctx, conformance.Ceiling(25*time.Minute))
//
// It bounds nothing itself, and a test binary's own deadline (go test
// -timeout) still applies: a run under the detector needs that raised too.
func Ceiling(calibrated time.Duration) time.Duration {
	if RaceDetector {
		return calibrated * RaceFactor
	}
	return calibrated
}
