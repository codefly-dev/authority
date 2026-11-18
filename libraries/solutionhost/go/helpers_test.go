package solutionhost_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/codefly-dev/authority/libraries/solutionhost/go"
	"github.com/stretchr/testify/require"
)

const (
	testCoordinate = "obin/local/dev"
	testDomain     = "obin"
	testKeyID      = "release"
)

// validYAML is the manifest the spec shows, as a renderer would write it.
const validYAML = `schema: codefly/module-manifest/v1
binding: acme.local.wiki
alias: wiki
kind: module
generation: 7
host: {coordinate: obin/local/dev, domain: obin}
release: {publisher: obin, name: wiki, version: 0.1.0}
frontend:
  title: Wiki
  order: 10
  exposed_module: ./Page
  host_contract: 1
  payload:
    artifact: wiki-frontend
    digest: sha256:0000000000000000000000000000000000000000000000000000000000000001
    media_type: application/gzip
workloads:
  - service: backend
    container: backend
  - service: indexer
    container: indexer
endpoints:
  - {name: rest, service: backend, api: rest, address: "http://localhost:5123"}
  - {name: grpc, service: indexer, api: grpc, address: "localhost:5124"}
authority:
  principal: wiki
  bindings:
    - id: model
      audience: modelservice
      operations:
        invoke: [modelservice.profiles:invoke, modelservice.profiles:read]
        headless: [modelservice.profiles:invoke]
  queues: [wiki.index]
  namespaces: [wiki]
  resource_kinds: [wiki.pages]
`

// valid parses validYAML, so every test starts from what a renderer writes.
func valid(t *testing.T) *solutionhost.ModuleManifest {
	t.Helper()
	manifest, err := solutionhost.Parse([]byte(validYAML))
	require.NoError(t, err)
	return manifest
}

// removed is the withdrawal of valid at the next generation.
func removed(t *testing.T) *solutionhost.ModuleManifest {
	t.Helper()
	live := valid(t)
	return &solutionhost.ModuleManifest{
		Schema: live.Schema, Binding: live.Binding, Alias: live.Alias, Kind: live.Kind,
		Generation: live.Generation + 1, Removed: true, Host: live.Host, Release: live.Release,
	}
}

// signerFor derives a deterministic Ed25519 signer from its key ID, so two
// calls with one ID are one key and two IDs are two keys.
func signerFor(t *testing.T, id string) *solutionhost.InMemorySigner {
	t.Helper()
	seed := sha256.Sum256([]byte("solutionhost test key " + id))
	signer, err := solutionhost.NewInMemorySigner(id, ed25519.NewKeyFromSeed(seed[:]))
	require.NoError(t, err)
	return signer
}

// differentKey is a signer carrying id but holding another private key.
func differentKey(t *testing.T, id string) *solutionhost.InMemorySigner {
	t.Helper()
	seed := sha256.Sum256([]byte("another key for " + id))
	signer, err := solutionhost.NewInMemorySigner(id, ed25519.NewKeyFromSeed(seed[:]))
	require.NoError(t, err)
	return signer
}

func pinFor(t *testing.T, signer solutionhost.Signer, kind solutionhost.KeyKind, domains ...string) solutionhost.PinnedKey {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	require.NoError(t, err)
	return solutionhost.PinnedKey{
		KeyID: signer.KeyID(), Kind: kind, OwnershipDomains: domains,
		PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
	}
}

func verifierFor(t *testing.T, pins ...solutionhost.PinnedKey) *solutionhost.Verifier {
	t.Helper()
	keys, err := solutionhost.NewPinnedKeySet(pins...)
	require.NoError(t, err)
	verifier, err := solutionhost.NewVerifier(keys)
	require.NoError(t, err)
	return verifier
}

// testVerifier pins the test release key for the test domain.
func testVerifier(t *testing.T) *solutionhost.Verifier {
	t.Helper()
	return verifierFor(t, pinFor(t, signerFor(t, testKeyID), solutionhost.KeyKindRelease, testDomain))
}

// signedValid is valid, signed by the test release key and read back through
// the carrier's own parser.
func signedValid(t *testing.T) *solutionhost.Signed {
	t.Helper()
	payload, err := solutionhost.SignedPayload(valid(t))
	require.NoError(t, err)
	return signedWith(t, payload, signerFor(t, testKeyID))
}
