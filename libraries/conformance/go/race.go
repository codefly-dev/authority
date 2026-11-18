package conformance

import "runtime/debug"

// RaceDetector reports whether this binary was built with the race detector.
// Read the binary's build settings so every source file is checked by the
// repository's no-proxy gate, independent of build-tag selection.
var RaceDetector = raceDetectorEnabled()

func raceDetectorEnabled() bool {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, setting := range info.Settings {
		if setting.Key == "-race" {
			return setting.Value == "true"
		}
	}
	return false
}
