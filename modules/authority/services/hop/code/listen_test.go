package main

import "testing"

// The hop's HTTP face is bound as its generated listeners are: to the host
// the run resolved in a native run, to the wildcard only in a container.
func TestTheHTTPFaceBindsAsTheGeneratedListenersDo(t *testing.T) {
	for runtime, want := range map[string]string{"native": "127.0.0.1:8080", "nix": "127.0.0.1:8080", "container": ":8080"} {
		t.Setenv("CODEFLY__RUNTIME_CONTEXT", runtime)
		if got := httpListenAddress("127.0.0.1", 8080); got != want {
			t.Errorf("runtime %s: the HTTP face listens at %q, want %q", runtime, got, want)
		}
	}
}
