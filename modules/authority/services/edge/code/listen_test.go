package main

import (
	"testing"
)

// The edge listens where the run resolved its own endpoint, which on a
// developer's machine is loopback: the sign-in page it serves lists the
// fixture's sign-in tokens, so it is never bound to every interface there. A
// container keeps its wildcard bind, since its ingress is the container's
// own; so does nothing else.
func TestTheEdgeBindsItsResolvedHostUnlessItRunsInAContainer(t *testing.T) {
	for name, tc := range map[string]struct {
		runtime, hostname, want string
		refused                 bool
	}{
		"native":                   {"native", "127.0.0.1", "127.0.0.1:8080", false},
		"nix":                      {"nix", "localhost", "localhost:8080", false},
		"no runtime context named": {"", "127.0.0.1", "127.0.0.1:8080", false},
		"a container":              {"container", "edge.internal", ":8080", false},
		"kubernetes":               {"kubernetes", "edge.svc", ":8080", false},
		"native, no host resolved": {"native", " ", "", true},
		"unnamed, no host":         {"", "", "", true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("CODEFLY__RUNTIME_CONTEXT", tc.runtime)
			got, err := listenAddress(tc.hostname, 8080)
			if tc.refused {
				if err == nil {
					t.Fatalf("listening at %q with no host resolved", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("listening at %q (%v), want %q", got, err, tc.want)
			}
		})
	}
}
