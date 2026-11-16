// Package workloadidentity is how a host learns which declared workload is
// calling it, whatever proved it.
//
// A workload's identity is the composition's declaration: the module and
// service it was composed as — the same CODEFLY__MODULE and CODEFLY__SERVICE
// every process is started with — and the one instance of it that is running.
// That is the identity a host keys on, the identity a manifest names, and the
// identity every mechanism attests. No environment's vocabulary is the
// identity: a namespace, a ServiceAccount or a pod is how one environment
// proves which declared workload a process is, and it is carried as that
// environment's facts, never read as who the caller is.
//
// A workload presents a credential: a token it reads from a file it was handed
// and re-reads before every use, so rotation needs nothing from it. A host
// hands the credential to an Attester, which answers with one Attestation:
// the declared workload the credential proves, the credential's lifetime, and
// the facts the mechanism can vouch for about the instance. Policy — which
// principal that workload belongs to, how long a credential may live — stays
// with the host. This package only establishes facts.
//
// There is one Attester per mechanism, and the mechanism is the environment's,
// never the caller's:
//
//   - kubernetes: a projected ServiceAccount token, reviewed by the cluster's
//     API server (TokenReview), and the pod it names, read from that server.
//     The pair (namespace, ServiceAccount) the review yields is resolved to the
//     declared workload through the Declaration the render made — a pair the
//     render never declared is refused — and the pod becomes Facts.
//     Implemented where the cluster client lives.
//   - native: a token the CLI signs for a process it started on a laptop,
//     verified against the run's anchor (package native). The launcher is the
//     one party that knows which declared workload it started, so the
//     credential names the declaration directly. Nothing is invented: no
//     namespace, no account, no pod, no UID.
//
// Both answer the same Attestation, so the host's checks run unchanged under
// either, and a gap in one mechanism cannot hide behind the other's shape.
package workloadidentity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Mechanism names how a credential is proven.
type Mechanism string

const (
	// Kubernetes proves a credential through the cluster that issued it.
	Kubernetes Mechanism = "kubernetes"
	// Native proves a credential through the run that issued it.
	Native Mechanism = "native"
)

// ErrRejected is the attester's answer to a credential it would not accept:
// the host refuses the caller. The wrapped reason names what failed.
var ErrRejected = errors.New("workload credential rejected")

// ErrUnavailable means nothing was decided: the mechanism could not be
// consulted. The host must not read it as a refusal.
var ErrUnavailable = errors.New("workload attestation unavailable")

// Attester proves credentials under one mechanism.
type Attester interface {
	Mechanism() Mechanism
	// Authenticate establishes who signed the credential and for whom, without
	// reading what the instance runs: it answers an Attestation with nil Facts.
	Authenticate(ctx context.Context, credential, audience string) (*Attestation, error)
	// Attest is Authenticate plus what the mechanism can vouch for about the
	// instance: its Facts.
	Attest(ctx context.Context, credential, audience string) (*Attestation, error)
}

// Workload is a declared workload: the identity every mechanism attests and
// every host keys on. TrustDomain is the composition's; Module and Service are
// as the composition declares them; Instance names the one running copy a
// credential was issued to, and is empty where only the declaration is named
// (a manifest declares a service, not a copy of it).
type Workload struct {
	TrustDomain string `json:"trust_domain"`
	Module      string `json:"module"`
	Service     string `json:"service"`
	Instance    string `json:"instance,omitempty"`
}

// Validate refuses a declaration that names less than a workload: a host
// cannot key authority on a blank. The instance is validated by whoever needs
// one (an attestation does; a manifest does not).
func (w Workload) Validate() error {
	for name, value := range map[string]string{"trust domain": w.TrustDomain, "module": w.Module, "service": w.Service} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("workload names no %s", name)
		}
	}
	return nil
}

// Unique is the declared identity without its instance, as the composition
// spells a service: module/service. Every instance of one declared service
// shares it; "one declared workload, one principal" keys on it.
func (w Workload) Unique() string { return w.Module + "/" + w.Service }

// A cell spells a workload with the same two words: its pod runs in the
// namespace named after the module, as the ServiceAccount named after the
// service. That is a rule, never a declaration — nothing writes a namespace
// or an account down, and a reviewed pair reads straight back to the workload.

// KubernetesNamespace is the namespace a cell runs this workload in.
func (w Workload) KubernetesNamespace() string { return w.Module }

// KubernetesAccount is the ServiceAccount a cell runs this workload as.
func (w Workload) KubernetesAccount() string { return w.Service }

// SPIFFEID is the mesh identity a cell issues this workload.
func (w Workload) SPIFFEID() string {
	return "spiffe://" + w.TrustDomain + "/ns/" + w.Module + "/sa/" + w.Service
}

// FromKubernetes is the workload a reviewed (namespace, account) pair is, by
// the rule above. It validates nothing: the caller decides whether that
// workload is one it knows.
func FromKubernetes(trustDomain, namespace, account string) Workload {
	return Workload{TrustDomain: trustDomain, Module: namespace, Service: account}
}

// Declared is the workload with its instance removed: the declaration a
// credential's attestation is matched against.
func (w Workload) Declared() Workload { w.Instance = ""; return w }

// String is the whole identity, instance included when there is one.
func (w Workload) String() string {
	if w.Instance == "" {
		return w.Unique()
	}
	return w.Unique() + "@" + w.Instance
}

// Declaration resolves what a Kubernetes environment proves — the namespace
// and ServiceAccount a reviewed token names — to the declared workload the
// render gave that pair to. A pair the render never declared resolves to
// nothing, and a mechanism must refuse it: a token for an account nothing
// declared is not a workload of the composition.
// DeliveryService is the declared service of a module's delivery carrier: the
// workload {module, delivery} delivers that module's manifests. A launcher
// signs a credential naming it; a cell runs it as the delivery account of the
// module's namespace, which the host's declaration resolves back to it.
const DeliveryService = "delivery"

// AppliedObserver is the declared workload of the protected applied-state
// observer, the host's own. It is named here, once, so a launcher and a host
// agree on it without either spelling the other's environment.
var AppliedObserver = Workload{Module: "solution-host", Service: "applied-observer"}

type Declaration interface {
	WorkloadFor(namespace, account string) (Workload, bool)
}

// Credential is what the attester can say about the token itself.
type Credential struct {
	// ID is the credential's own identifier, unique per issued token.
	ID        string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Attestation is one mechanism's proof of one declared workload.
type Attestation struct {
	Mechanism  Mechanism
	Workload   Workload
	Credential Credential
	// Facts is what the mechanism can vouch for about the instance beyond its
	// identity: nil when Authenticate was asked. A host reads Facts to bind an
	// execution to one instance and for audit, never for who the caller is.
	Facts *Facts
}

// Facts is the mechanism's own vocabulary for the running instance. Under
// kubernetes they are the pod's; under native they are what the launcher
// vouched for. None of them is identity.
type Facts struct {
	// Namespace and Account are the Kubernetes pair the credential proved,
	// kept for audit; the Declaration already turned them into the Workload.
	Namespace string
	Account   string
	// InstanceUID distinguishes one incarnation of the instance from a later
	// one under the same name.
	InstanceUID string
	// Phase and Terminating are the instance's lifecycle as the mechanism
	// reports it. Native reports PhaseRunning: the launcher started it.
	Phase       string
	Terminating bool
	Containers  []Container
}

// PhaseRunning is the one phase a workload may act in.
const PhaseRunning = "Running"

// ContainerKind is why a container is in the instance.
type ContainerKind string

const (
	ContainerRegular   ContainerKind = "regular"
	ContainerInit      ContainerKind = "init"
	ContainerEphemeral ContainerKind = "ephemeral"
)

// ContainerState is where the container is in its own lifecycle.
type ContainerState string

const (
	ContainerRunning      ContainerState = "running"
	ContainerWaiting      ContainerState = "waiting"
	ContainerTerminated   ContainerState = "terminated"
	ContainerStateUnknown ContainerState = "unknown"
)

// Container is one container of the instance, as the mechanism saw it. It
// reports no image: what runs is not attested, by decision.
type Container struct {
	Name  string
	Kind  ContainerKind
	State ContainerState
	// Restartable says the container may be restarted in place.
	Restartable bool
}
