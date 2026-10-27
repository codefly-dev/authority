package state_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/codefly-dev/core/workloadidentity"
	"github.com/codefly-dev/core/workloadidentity/native"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
)

// The host's trust domain is the run's: the one the launcher's anchor
// declares every workload under. An anchor naming several, or none, gives the
// host none, so no hop is ever matched against a guess.
func TestTheHostsTrustDomainIsTheOneTheAnchorDeclares(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	build := func(domains ...string) string {
		launcher, err := native.NewIssuer()
		if err != nil {
			t.Fatal(err)
		}
		for n, domain := range domains {
			launcher.Declare(workloadidentity.Workload{TrustDomain: domain, Module: "m" + string(rune('a'+n)), Service: "api"})
		}
		st, err := state.New(launcher.Anchor(), testkit.Audience, issuer.Config(testkit.Audience, "k", key, time.Now))
		if err != nil {
			t.Fatal(err)
		}
		return st.TrustDomain()
	}
	for want, domains := range map[string][]string{
		"run.test": {"run.test", "run.test"},
		"":         {"run.test", "elsewhere.test"},
	} {
		if got := build(domains...); got != want {
			t.Errorf("an anchor declaring %v gives the host trust domain %q, want %q", domains, got, want)
		}
	}
	if got := build(); got != "" {
		t.Errorf("an anchor declaring nothing gives the host trust domain %q", got)
	}
}
