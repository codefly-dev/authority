package main

import (
	"bytes"
	"os"
	"testing"
)

// The hop's copy of the authority's policy option is the stopgap
// proto/authority/VENDORED.md describes; it must not drift from its source.
func TestTheVendoredPolicyIsItsSource(t *testing.T) {
	copied, err := os.ReadFile("../proto/authority/hop/v1/policy.proto")
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("../../../../../libraries/hop/proto/authority/hop/v1/policy.proto")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copied, source) {
		t.Fatal("proto/authority/hop/v1/policy.proto drifted from libraries/hop/proto; copy it again")
	}
}
