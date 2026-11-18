//go:build !race

package conformance

// RaceDetector reports whether this binary was built with the race detector
// (go test -race).
const RaceDetector = false
