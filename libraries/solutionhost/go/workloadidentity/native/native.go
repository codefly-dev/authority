// Package native is the workload identity of a process a native `codefly run`
// started on a laptop.
//
// The CLI starts every process, so it is the one party that knows which
// declared workload a process is and which executable it launched. It holds
// an Issuer — a key made for the run — and hands each process a credential
// file it rewrites before the credential lapses. A host holds the run's
// Anchor and verifies each credential with an Attester.
//
// Nothing here imitates a cluster. A native credential is its own token type
// (header typ NativeTokenType, claims under NativeClaim), so it can never be
// mistaken for a projected ServiceAccount token, and a cluster's token can
// never be verified here.
//
// The mechanism is a laptop's and nothing else's: LoadAttester refuses inside
// a pod, so a composition that points a deployed host at an anchor of its own
// making is refused at boot instead of having its signatures believed.
package native

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/codefly-dev/authority/libraries/solutionhost/go/workloadidentity"
)

// TokenLifetime is a credential's validity: the 600 s a cell asks the kubelet
// for, the longest a host admits, so a credential copied off a laptop is
// replayable for no longer than one copied off a pod.
const TokenLifetime = 600 * time.Second

// RefreshInterval is how often an issuer rewrites a credential: at 80% of its
// lifetime, as a kubelet rotates a projected token.
const RefreshInterval = TokenLifetime * 4 / 5

// NativeTokenType is the JOSE header typ of a native credential.
const NativeTokenType = "codefly-native+jwt"

// NativeClaim is the claim holding what the launcher vouches for.
const NativeClaim = "codefly.dev/native"

// AnchorEnvironment names the absolute path of the run's anchor file, set by
// the CLI on a process that verifies native credentials (the host).
const AnchorEnvironment = "CODEFLY_NATIVE_IDENTITY_ANCHOR"

// clockSkew tolerates an issued-at slightly ahead of the verifier's clock.
const clockSkew = 30 * time.Second

// ErrInPod refuses the native mechanism inside a cluster's pod.
var ErrInPod = errors.New("a pod proves its identity through its cluster, never through a native anchor")

// Subject is what the launcher vouches for about one process.
type Subject struct {
	// Workload is the declaration the launcher started — trust domain, module,
	// service — and the one instance of it. It is the whole identity.
	Workload workloadidentity.Workload `json:"workload"`
	// Container is the declared container the process is, when the subject is
	// a workload's container rather than a carrier identity.
	Container string `json:"container,omitempty"`
}

func (s Subject) validate() error {
	if err := s.Workload.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(s.Workload.Instance) == "" {
		return fmt.Errorf("native subject names no instance")
	}
	return nil
}

// Anchor is what a verifier trusts: the issuer's name and public key.
type Anchor struct {
	Issuer    string `json:"issuer"`
	PublicKey string `json:"public_key"` // base64url, unpadded Ed25519
	// Subjects are the declared workloads this launcher vouches for: the
	// identity workloads it started, their delivery carriers, and the applied
	// observer. A credential naming any other workload is refused under this
	// anchor, so a launcher's key is never authority over a module it did not
	// launch.
	Subjects []workloadidentity.Workload `json:"subjects"`
}

// Vouches reports whether the anchor declares workload (instance ignored).
func (a Anchor) Vouches(workload workloadidentity.Workload) bool {
	declared := workload.Declared()
	for _, subject := range a.Subjects {
		if subject.Declared() == declared {
			return true
		}
	}
	return false
}

// Fingerprint is the lowercase hex SHA-256 of the anchor's public key: what a
// local trust profile pins.
func (a Anchor) Fingerprint() string {
	key, _ := base64.RawURLEncoding.DecodeString(a.PublicKey)
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

func (a Anchor) key() (ed25519.PublicKey, error) {
	if !strings.HasPrefix(a.Issuer, "codefly-native/") {
		return nil, fmt.Errorf("anchor issuer %q is not a native issuer", a.Issuer)
	}
	key, err := base64.RawURLEncoding.DecodeString(a.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("anchor public key is not an Ed25519 key")
	}
	return key, nil
}

// WriteFile writes the anchor owner-only and atomically.
func (a Anchor) WriteFile(path string) error {
	content, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return writePrivate(path, content)
}

// ReadAnchor reads an anchor file and checks it names a native Ed25519 key.
func ReadAnchor(path string) (Anchor, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Anchor{}, err
	}
	var anchor Anchor
	if err := json.Unmarshal(content, &anchor); err != nil {
		return Anchor{}, fmt.Errorf("unreadable native anchor: %w", err)
	}
	if _, err := anchor.key(); err != nil {
		return Anchor{}, err
	}
	return anchor, nil
}

// Issuer signs credentials for one run. Its key never leaves the CLI.
type Issuer struct {
	name     string
	key      ed25519.PrivateKey
	now      func() time.Time
	subjects []workloadidentity.Workload
}

// Declare adds workloads this launcher vouches for. Each is recorded once,
// without its instance; the anchor written after a Declare carries it.
func (i *Issuer) Declare(workloads ...workloadidentity.Workload) {
	for _, workload := range workloads {
		declared := workload.Declared()
		if !i.Anchor().Vouches(declared) {
			i.subjects = append(i.subjects, declared)
		}
	}
}

// NewIssuer makes a fresh key for a run.
func NewIssuer() (*Issuer, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Issuer{name: "codefly-native/" + randomID(), key: key, now: time.Now}, nil
}

// Anchor is the issuer's public half, for verifiers.
func (i *Issuer) Anchor() Anchor {
	public, _ := i.key.Public().(ed25519.PublicKey)
	return Anchor{Issuer: i.name, PublicKey: base64.RawURLEncoding.EncodeToString(public), Subjects: append([]workloadidentity.Workload(nil), i.subjects...)}
}

type claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	Expires   int64    `json:"exp"`
	ID        string   `json:"jti"`
	Native    *Subject `json:"codefly.dev/native"`
}

// Issue signs a credential for subject, for one audience, valid TokenLifetime.
func (i *Issuer) Issue(subject Subject, audience string) (string, error) {
	if err := subject.validate(); err != nil {
		return "", err
	}
	if audience == "" {
		return "", errors.New("a native credential names an audience")
	}
	if !i.Anchor().Vouches(subject.Workload) {
		return "", fmt.Errorf("this launcher did not declare %s, so it issues no credential for it", subject.Workload.Unique())
	}
	now := i.now()
	body := claims{
		Issuer:    i.name,
		Subject:   "native:" + subject.Workload.String(),
		Audience:  []string{audience},
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		Expires:   now.Add(TokenLifetime).Unix(),
		ID:        randomID(),
		Native:    &subject,
	}
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": NativeTokenType})
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(i.key, []byte(input))), nil
}

// WriteCredential issues a credential and writes it owner-only and atomically
// at path, so a reader never sees half a token.
func (i *Issuer) WriteCredential(path string, subject Subject, audience string) error {
	token, err := i.Issue(subject, audience)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writePrivate(path, []byte(token))
}

// Attester verifies native credentials against one anchor.
type Attester struct {
	anchor Anchor
	key    ed25519.PublicKey
	now    func() time.Time
	// path is the anchor file this attester was loaded from, when it was: the
	// launcher rewrites it as it declares workloads admitted after the host
	// booted, and the attester re-reads it under the same issuer and key.
	path    string
	mu      sync.Mutex
	modTime time.Time
	size    int64
}

var _ workloadidentity.Attester = (*Attester)(nil)

// NewAttester verifies against anchor.
func NewAttester(anchor Anchor) (*Attester, error) {
	key, err := anchor.key()
	if err != nil {
		return nil, err
	}
	return &Attester{anchor: anchor, key: key, now: time.Now}, nil
}

// LoadAttester builds the attester from the anchor the CLI named in
// AnchorEnvironment. It answers (nil, nil) when none is named, and refuses
// inside a pod whatever is named.
func LoadAttester() (*Attester, error) {
	path := os.Getenv(AnchorEnvironment)
	if path == "" {
		return nil, nil
	}
	if InPod() {
		return nil, fmt.Errorf("%w: %s is set in a pod", ErrInPod, AnchorEnvironment)
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%s must be an absolute path, got %q", AnchorEnvironment, path)
	}
	anchor, err := ReadAnchor(path)
	if err != nil {
		return nil, err
	}
	attester, err := NewAttester(anchor)
	if err != nil {
		return nil, err
	}
	attester.path = path
	if info, statErr := os.Stat(path); statErr == nil {
		attester.modTime, attester.size = info.ModTime(), info.Size()
	}
	return attester, nil
}

// current is the anchor as the launcher last wrote it. A rewrite that changes
// the issuer or the key is not a rewrite of this anchor, and is refused rather
// than followed: the host trusts the run it was started under, not whatever
// is at the path now.
func (a *Attester) current() (Anchor, error) {
	if a.path == "" {
		return a.anchor, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	info, err := os.Stat(a.path)
	if err != nil || (info.ModTime().Equal(a.modTime) && info.Size() == a.size) {
		return a.anchor, nil
	}
	anchor, err := ReadAnchor(a.path)
	if err != nil {
		return Anchor{}, fmt.Errorf("the native anchor at %s was rewritten and is unreadable: %w", a.path, err)
	}
	if anchor.Issuer != a.anchor.Issuer || anchor.PublicKey != a.anchor.PublicKey {
		return Anchor{}, fmt.Errorf("the native anchor at %s now names issuer %q, and this host trusts %q; a host follows its run's declarations, never another run", a.path, anchor.Issuer, a.anchor.Issuer)
	}
	a.anchor, a.modTime, a.size = anchor, info.ModTime(), info.Size()
	return a.anchor, nil
}

// InPod reports whether this process carries what a kubelet puts in a pod.
func InPod() bool {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	_, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token")
	return err == nil
}

// Anchor is the anchor this attester verifies against.
func (a *Attester) Anchor() Anchor {
	anchor, err := a.current()
	if err != nil {
		return a.anchor
	}
	return anchor
}

// Mechanism is workloadidentity.Native.
func (a *Attester) Mechanism() workloadidentity.Mechanism { return workloadidentity.Native }

// Authenticate verifies a native credential for audience and reports its
// account and instance.
func (a *Attester) Authenticate(ctx context.Context, credential, audience string) (*workloadidentity.Attestation, error) {
	attested, err := a.Attest(ctx, credential, audience)
	if err != nil {
		return nil, err
	}
	attested.Facts = nil
	return attested, nil
}

// Attest verifies a native credential for audience.
func (a *Attester) Attest(_ context.Context, credential, audience string) (*workloadidentity.Attestation, error) {
	reject := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", workloadidentity.ErrRejected, fmt.Sprintf(format, args...))
	}
	anchor, err := a.current()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", workloadidentity.ErrUnavailable, err)
	}
	parts := strings.Split(strings.TrimSpace(credential), ".")
	if len(parts) != 3 {
		return nil, reject("not a compact JWS")
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, reject("unreadable header")
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil || header.Algorithm != "EdDSA" || header.Type != NativeTokenType {
		return nil, reject("not a native credential")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(a.key, []byte(parts[0]+"."+parts[1]), signature) {
		return nil, reject("signature does not verify under the run's anchor")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, reject("unreadable payload")
	}
	var body claims
	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, reject("unreadable claims")
	}
	if body.Issuer != anchor.Issuer {
		return nil, reject("issued by %q, not this run", body.Issuer)
	}
	if !contains(body.Audience, audience) {
		return nil, reject("not issued for audience %q", audience)
	}
	now := a.now()
	issued, expires := time.Unix(body.IssuedAt, 0), time.Unix(body.Expires, 0)
	switch {
	case body.ID == "":
		return nil, reject("carries no credential id")
	case !expires.After(now):
		return nil, reject("expired")
	case issued.After(now.Add(clockSkew)) || time.Unix(body.NotBefore, 0).After(now.Add(clockSkew)):
		return nil, reject("not yet valid")
	case !expires.After(issued):
		return nil, reject("expires before it is issued")
	case body.Native == nil:
		return nil, reject("names no subject")
	}
	subject := *body.Native
	if err := subject.validate(); err != nil {
		return nil, reject("%v", err)
	}
	if !anchor.Vouches(subject.Workload) {
		return nil, reject("names %s, which the launcher behind this anchor never declared", subject.Workload.Unique())
	}
	return &workloadidentity.Attestation{
		Mechanism:  workloadidentity.Native,
		Workload:   subject.Workload,
		Credential: workloadidentity.Credential{ID: body.ID, IssuedAt: issued, ExpiresAt: expires},
		// The launcher issues only while the process it started runs, so the
		// instance is running; nothing else about it is invented. The
		// credential's own id is the incarnation: a restart is a new one.
		Facts: &workloadidentity.Facts{InstanceUID: body.ID, Phase: workloadidentity.PhaseRunning, Containers: containersOf(subject)},
	}, nil
}

func containersOf(subject Subject) []workloadidentity.Container {
	if subject.Container == "" {
		return nil
	}
	return []workloadidentity.Container{{
		Name:  subject.Container,
		Kind:  workloadidentity.ContainerRegular,
		State: workloadidentity.ContainerRunning,
	}}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func randomID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func writePrivate(path string, content []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
