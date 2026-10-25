package main

import (
	"strings"
	"testing"
)

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

func TestMissingRoutingNamesTheRequiredCLIProducer(t *testing.T) {
	for _, raw := range []string{"", "{}", `{"schema":"older"}`} {
		if _, err := requiredRoutes(raw, nil); err == nil || !strings.Contains(err.Error(), RouteProducerVersion) {
			t.Fatalf("missing CLI requirement: %v", err)
		}
	}
}
