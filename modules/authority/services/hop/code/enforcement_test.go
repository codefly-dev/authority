package main

import (
	"strings"
	"testing"
)

func TestSignedAdmissionRequiresEnforcementInEveryEnvironment(t *testing.T) {
	for _, mode := range []string{"", "enforce", "warn", "invalid"} {
		if err := requireEnforcement(mode); (err != nil) != (mode == "warn" || mode == "invalid") {
			t.Fatalf("mode %q: %v", mode, err)
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
