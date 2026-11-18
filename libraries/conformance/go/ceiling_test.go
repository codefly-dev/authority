package conformance

import (
	"runtime/debug"
	"testing"
	"time"
)

// builtWithRace is whether this test binary was built with -race, read from
// the binary's own build settings rather than from the constant under test.
func builtWithRace(t *testing.T) bool {
	t.Helper()
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("the test binary carries no build information")
	}
	for _, setting := range info.Settings {
		if setting.Key == "-race" {
			return setting.Value == "true"
		}
	}
	return false
}

// A ceiling calibrated without the race detector stands as it is in an
// ordinary build, and is scaled only in a build that carries the detector.
func TestACeilingScalesOnlyUnderTheRaceDetector(t *testing.T) {
	const calibrated = 25 * time.Minute
	race := builtWithRace(t)
	if RaceDetector != race {
		t.Fatalf("RaceDetector is %v in a binary built with -race=%v", RaceDetector, race)
	}
	got := Ceiling(calibrated)
	if !race {
		if got != calibrated {
			t.Fatalf("without the race detector the ceiling is %v, want the calibrated %v", got, calibrated)
		}
		return
	}
	if RaceFactor < 2 {
		t.Fatalf("RaceFactor is %d: the detector slows a run at least twofold", RaceFactor)
	}
	if want := calibrated * RaceFactor; got != want {
		t.Fatalf("under the race detector the ceiling is %v, want %v (%d times the calibrated %v)", got, want, RaceFactor, calibrated)
	}
}
