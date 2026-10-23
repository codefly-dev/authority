// Package delivery reads what a run writes for its host to verify deliveries by:
// the verification policy naming the signers it admits, bound to the run's
// native anchor. The shape is the one every host reads; nothing here is typed.
package delivery

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/codefly-dev/core/solutionhost"
)

// TrustAnchorEnvironment names the directory the run writes the policy into.
const TrustAnchorEnvironment = "SOLUTION_HOST_LOCAL_TRUST_ANCHOR"

const policyFileName = "verification_policy.json"

type policy struct {
	Local   *localBinding `json:"local,omitempty"`
	Signers []signer      `json:"signers"`
}

type localBinding struct {
	ClusterCertificateAuthoritySha256 string `json:"clusterCertificateAuthoritySha256,omitempty"`
	NativeAnchorSha256                string `json:"nativeAnchorSha256,omitempty"`
}

type signer struct {
	Name      string               `json:"name"`
	Kind      solutionhost.KeyKind `json:"kind"`
	KeyID     string               `json:"keyId"`
	PublicKey string               `json:"publicKey"`
	Domains   []string             `json:"domains"`
}

// VerifierFromDirectory reads the policy the run wrote and pins its signers:
// as core's verifier for the manifest, and by key id for the authority's own
// document delivered with it.
func VerifierFromDirectory(directory string) (*solutionhost.Verifier, map[string]crypto.PublicKey, error) {
	verifier, err := coreVerifier(directory)
	if err != nil {
		return nil, nil, err
	}
	keys, err := keysFromDirectory(directory)
	if err != nil {
		return nil, nil, err
	}
	return verifier, keys, nil
}

func keysFromDirectory(directory string) (map[string]crypto.PublicKey, error) {
	p, err := read(directory)
	if err != nil {
		return nil, err
	}
	keys := make(map[string]crypto.PublicKey, len(p.Signers))
	for _, s := range p.Signers {
		block, _ := pem.Decode([]byte(s.PublicKey))
		if block == nil {
			return nil, fmt.Errorf("signer %q's public key is not PEM", s.Name)
		}
		public, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("signer %q's public key does not parse: %w", s.Name, err)
		}
		keys[s.KeyID] = public
	}
	return keys, nil
}

func coreVerifier(directory string) (*solutionhost.Verifier, error) {
	p, err := read(directory)
	if err != nil {
		return nil, err
	}
	if len(p.Signers) == 0 {
		return nil, errors.New("the verification policy admits no signer")
	}
	pins := make([]solutionhost.PinnedKey, 0, len(p.Signers))
	for i, s := range p.Signers {
		if strings.TrimSpace(s.Name) == "" || s.KeyID == "" {
			return nil, fmt.Errorf("verification policy signer %d names no name or key", i)
		}
		if s.Kind == solutionhost.KeyKindPerson && p.Local == nil {
			return nil, fmt.Errorf("signer %q is a person, admitted only by a policy that declares itself local", s.Name)
		}
		pins = append(pins, solutionhost.PinnedKey{KeyID: s.KeyID, PublicKeyPEM: s.PublicKey, Kind: s.Kind, OwnershipDomains: s.Domains})
	}
	keys, err := solutionhost.NewPinnedKeySet(pins...)
	if err != nil {
		return nil, err
	}
	return solutionhost.NewVerifier(keys)
}

func read(directory string) (policy, error) {
	data, err := os.ReadFile(filepath.Join(directory, policyFileName))
	if err != nil {
		return policy{}, fmt.Errorf("read %s from %q: %w", policyFileName, directory, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var p policy
	if err := decoder.Decode(&p); err != nil {
		return policy{}, fmt.Errorf("%s does not decode: %w", policyFileName, err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return policy{}, fmt.Errorf("%s must contain exactly one policy document", policyFileName)
	}
	return p, nil
}
