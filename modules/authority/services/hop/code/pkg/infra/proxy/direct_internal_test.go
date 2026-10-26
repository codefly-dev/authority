package proxy

import "testing"

// The hop's request to a module never follows a proxy from the environment: the
// transport names none, so HTTP_PROXY and HTTPS_PROXY are never consulted.
func TestTheHopReachesModulesWithoutAnEnvironmentProxy(t *testing.T) {
	if direct.Proxy != nil {
		t.Fatal("the hop's transport to a module consults a proxy")
	}
}
