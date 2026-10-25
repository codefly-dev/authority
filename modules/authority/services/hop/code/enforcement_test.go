package main

import "testing"

func TestEnforcementRequiresLocalEnvironment(t *testing.T) {
	for _, local := range []bool{false, true} {
		for _, mode := range []string{"", "enforce", "warn", "invalid"} {
			warn, err := enforcementMode(mode, local)
			denied := mode == "invalid" || mode == "warn" && !local
			if (err != nil) != denied || warn != (mode == "warn" && local) {
				t.Fatalf("mode %q local %v: warn %v, error %v", mode, local, warn, err)
			}
		}
	}
}
