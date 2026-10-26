package main

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"github.com/codefly-dev/core/resources"
)

// Review r3 B1: the local authority publishes the hop's admission key in Keys,
// derived in code from the hop's own Codefly-generated seed (the variable the
// hop reads), so no consumer is configured with a hand-copied public key.
func TestTheHopsAdmissionKeyIsDerivedFromItsSeedAndPublished(t *testing.T) {
	t.Setenv(resources.ModulePrefix, "authority")
	t.Setenv(resources.ServicePrefix, "local")
	seed := strings.Repeat("07", 32)
	t.Setenv(resources.ServiceSecretConfigurationPrefix+"__AUTHORITY__HOP__HOP_SIGNING__SEED", seed)
	keys, err := hopAdmissionKey(context.Background())
	if err != nil || len(keys) != 1 {
		t.Fatalf("published %v: %v", keys, err)
	}
	hop, _ := stamp.NewSigner(seed)
	if got := keys[0]; hex.EncodeToString(got.GetPublicKey()) != hop.PublicKey() || got.GetPurpose() != stamp.Purpose || got.GetKeyId() != keyID(hop) {
		t.Fatalf("published %v, not the public half of the hop's seed", got)
	}
}

func keyID(s *stamp.Signer) string {
	id, _ := s.Admission()
	return id
}

// A seed that is not one refuses to boot, as the hop refuses it.
func TestAMalformedHopSeedRefusesToBoot(t *testing.T) {
	t.Setenv(resources.ModulePrefix, "authority")
	t.Setenv(resources.ServicePrefix, "local")
	t.Setenv(resources.ServiceSecretConfigurationPrefix+"__AUTHORITY__HOP__HOP_SIGNING__SEED", "not-a-seed")
	if _, err := hopAdmissionKey(context.Background()); err == nil {
		t.Fatal("a malformed hop seed was published")
	}
}
