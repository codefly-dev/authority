// Package solutionhost defines the two signed documents a host is delivered:
// the module manifest, which says a module or solution instance is present on
// a host, which workloads run as it, where its endpoints live, and what
// authority it asks for; and the module envelope, the authority grants the
// composition holds that host to, per module principal.
//
// A module is present on a host because a signed manifest declared it, never
// because its process announced itself. The manifest is desired state and
// nothing else: it carries no observation, no health, no credential and no
// build approval. "Only approved images run" is deploy-time admission, outside
// this package; a host mints for a workload because the attested account
// matches a workload this manifest lists and an organisation has installed the
// module, not because a digest matched.
//
// What the package owns:
//
//   - ModuleManifest, its strict reader (Parse), its writer (Marshal), its
//     rules (Validate) and its canonical encoding (CanonicalBytes, Digest);
//   - the DSSE signature over those canonical bytes, verified offline against
//     pinned keys whose policy also says which ownership domain each signer may
//     deliver under (VerifyDelivered);
//   - the monotonic-generation decision a host makes when a manifest arrives
//     for a binding it may already hold (Admit), and the route-alias rules a
//     host holds a candidate alias to (CheckAlias);
//   - ModuleEnvelope, its canonical encoding and the same DSSE signature
//     under the same pins, admitted only from a release key
//     (VerifyDeliveredEnvelope), at a revision that only rises per host
//     (AdmitEnvelope). The grants inside it are the host's contract; this
//     package reads each one only as a JSON object.
//
// Nothing here renders, reconciles, mints or observes. Signing authority
// belongs to the delivery pipeline: a Signer is supplied by the caller.
package solutionhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/codefly-dev/authority/libraries/solutionhost/go/workloadidentity"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"

	modulecontract "github.com/codefly-dev/core/contracts/module"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/wire"
)

const (
	// SchemaModuleManifestV1 is the only schema this package reads. It is part
	// of the signed canonical encoding, so a signature is bound to the document
	// type as well as its contents.
	SchemaModuleManifestV1 = "codefly/module-manifest/v1"

	// FileName is the conventional name of a rendered manifest.
	FileName = "module-manifest.codefly.yaml"

	// ManifestMaxBytes bounds one manifest before it is decoded. A manifest
	// declares a module instance; the largest block it carries, the frontend,
	// is bounded to FrontendMaxBytes on its own.
	ManifestMaxBytes = 1 << 20

	// EndpointAddressMaxBytes bounds one endpoint address.
	EndpointAddressMaxBytes = 4096
)

var (
	// ErrSchema means a document does not declare the schema this package
	// reads: a version skew, not a malformed record. A document of the family
	// the manifest replaced is reported with the remedy (re-render it).
	ErrSchema = errors.New("module manifest schema is not supported")

	// ErrInvalid means a document violates the manifest's rules.
	ErrInvalid = errors.New("module manifest is invalid")
)

// Kind is what a manifest declares the presence of. Both are delivered and
// reconciled the same way; they differ in what may install them and in the
// surface a host routes them under, so a host never infers it.
type Kind string

const (
	// KindModule is one module instance.
	KindModule Kind = "module"
	// KindSolution is a composed solution instance.
	KindSolution Kind = "solution"
)

var kinds = []Kind{KindModule, KindSolution}

var (
	// bindingPattern admits a ULID, a UUID or a readable instance id such as
	// "acme.local.wiki", and nothing that needs escaping in a path or a label.
	bindingPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,126}[A-Za-z0-9]$`)

	// namePattern is a lowercase dotted or slashed name: a host coordinate, an
	// ownership domain, a reserved route namespace.
	namePattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)

	// segmentPattern is one lowercase segment, never a path: a route alias, a
	// release publisher or name, a service, a container, an endpoint, an API.
	// Release.Identity joins publisher and name with "/", so a "/" inside
	// either would let two releases render one identity.
	segmentPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)

	// opaqueIDPattern is a principal or an operation binding id: compared,
	// never parsed or subset.
	opaqueIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}[A-Za-z0-9]$`)

	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// reservedOwner is composition.ValidateCollisions' sentinel owner, exempt from
// reserved namespaces. Route claims are owned by binding ids, so a binding
// called "base" would inherit the exemption; it is refused instead.
const reservedOwner = "base"

// ModuleManifest is one module (or solution) instance on one host, at a
// generation. It replaces the presence, authority and endpoint-delivery
// documents: one document, one signature, one generation.
type ModuleManifest struct {
	// Schema is SchemaModuleManifestV1, checked first and signed.
	Schema string `yaml:"schema" json:"schema"`

	// Binding is the stable instance id (workspace.environment.instance). A
	// second instance gets its own binding and inherits nothing from this one.
	Binding string `yaml:"binding" json:"binding"`

	// Alias is the route alias: one lowercase path segment, unique among the
	// live manifests on its host (CheckAlias).
	Alias string `yaml:"alias" json:"alias"`

	// Kind is module or solution.
	Kind Kind `yaml:"kind" json:"kind"`

	// Generation is strictly monotonic per binding, set by the publisher, and
	// starts at 1. See Admit.
	Generation uint64 `yaml:"generation" json:"generation"`

	// Removed marks a withdrawal. A withdrawn manifest carries only its
	// identity — schema, binding, alias, kind, generation, host, release — and
	// is terminal: no later generation brings the binding back.
	Removed bool `yaml:"removed,omitempty" json:"removed,omitempty"`

	// Host is where the instance runs and the ownership domain the manifest
	// speaks for. The signer must be pinned for that domain.
	Host HostTarget `yaml:"host" json:"host"`

	// Release is the release this generation deploys.
	Release Release `yaml:"release" json:"release"`

	// Group is the presentation group a solution is organised under.
	// Solutions only, optional.
	Group *SolutionGroup `yaml:"group,omitempty" json:"group,omitempty"`

	// Frontend is the page and client surfaces the instance contributes,
	// including the generated payload identity. Optional.
	Frontend *Frontend `yaml:"frontend,omitempty" json:"frontend,omitempty"`

	// Workloads are every workload that runs as the module's principal. At
	// least one for a live manifest; each account appears once.
	Workloads []Workload `yaml:"workloads,omitempty" json:"workloads,omitempty"`

	// Endpoints are what a host or gateway may route to, with their address.
	// Each names a declared workload's service.
	Endpoints []Endpoint `yaml:"endpoints,omitempty" json:"endpoints,omitempty"`

	// Authority is what the module asks for. Absent asks for nothing. It is a
	// request: a host grants the intersection of it with the administrator's
	// approval, never more.
	Authority *Authority `yaml:"authority,omitempty" json:"authority,omitempty"`
}

// HostTarget is the host a manifest targets and the ownership domain it
// speaks for.
type HostTarget struct {
	// Coordinate names the host. A host refuses a manifest naming another.
	Coordinate string `yaml:"coordinate" json:"coordinate"`
	// Domain is the ownership domain. A binding keeps the domain its first
	// applied generation declared, and only a signer pinned for it delivers.
	Domain string `yaml:"domain" json:"domain"`
}

// Release identifies the release a generation deploys.
type Release struct {
	Publisher string `yaml:"publisher" json:"publisher"`
	Name      string `yaml:"name" json:"name"`
	Version   string `yaml:"version" json:"version"`
}

// Identity is publisher/name@version. Publisher and name are single segments,
// so the string maps back to exactly one release.
func (release Release) Identity() string {
	return release.Publisher + "/" + release.Name + "@" + release.Version
}

// Workload is one workload that runs as the module's principal.
type Workload struct {
	// Service is the workload's service name, and the key an endpoint routes
	// to.
	Service string `yaml:"service" json:"service"`

	// Container is the one container that authenticates, so a sidecar in the
	// same instance never holds the workload's authority.
	Container string `yaml:"container" json:"container"`
}

// Declared is the workload's identity: the module the manifest is for and
// the service, as the composition declares them.
func (workload Workload) Declared(trustDomain, module string) workloadidentity.Workload {
	return workloadidentity.Workload{TrustDomain: trustDomain, Module: module, Service: workload.Service}
}

// Endpoint is one endpoint a host or gateway may route to.
type Endpoint struct {
	Name    string `yaml:"name" json:"name"`
	Service string `yaml:"service" json:"service"`
	API     string `yaml:"api" json:"api"`
	// Address is where the endpoint is reached: resolved at render in a cell,
	// at delivery natively.
	Address string `yaml:"address" json:"address"`
}

// Authority is what a module asks to be granted. Every list is a request; an
// empty one asks for nothing on that axis. Installation declarations express
// machine-role selection and edge presence, and confer no authority themselves.
type Authority struct {
	// Principal is the module's principal: its name. Opaque here.
	Principal string `yaml:"principal" json:"principal"`

	// InstallationRole is the Core-validated selector, carried verbatim: empty
	// is undeclared; "none" declares no standing grant; otherwise a role name.
	InstallationRole string `yaml:"installation_role,omitempty" json:"installation_role,omitempty"`
	// EdgeDependencies preserve declaration order and grant no authority.
	// Their identities are resolved by the host, never inferred from bindings.
	EdgeDependencies []modulecontract.EdgeDependency `yaml:"edge_dependencies,omitempty" json:"edge_dependencies,omitempty"`
	// SourceGovernance are the scopes, each "<resource kind>:<action>" of one
	// of ResourceKinds, whose holders on an installation govern the data
	// sources tied to it (modulecontract.SourceGovernance). Absent, the module
	// governs no source. It grants nothing by itself: a host still asks
	// whether the person is issued the scope there.
	SourceGovernance []string `yaml:"source_governance,omitempty" json:"source_governance,omitempty"`

	// Bindings are the operation bindings the module asks to redeem.
	Bindings []AuthorityBinding `yaml:"bindings,omitempty" json:"bindings,omitempty"`

	// Queues are the queues the module owns.
	Queues []string `yaml:"queues,omitempty" json:"queues,omitempty"`

	// Namespaces are the audit namespaces the module emits under.
	Namespaces []string `yaml:"namespaces,omitempty" json:"namespaces,omitempty"`

	// ResourceKinds are the module's own resource kinds.
	ResourceKinds []string `yaml:"resource_kinds,omitempty" json:"resource_kinds,omitempty"`
}

// AuthorityBinding is one requested operation binding: an audience, and per
// operation (invoke, lookup, headless) the scopes asked for, each written
// "<resource kind>:<action>".
type AuthorityBinding struct {
	ID         string              `yaml:"id" json:"id"`
	Audience   string              `yaml:"audience" json:"audience"`
	Operations map[string][]string `yaml:"operations" json:"operations"`
}

// Operations a binding may request, as the module contract names them.
var operations = []string{modulecontract.OperationInvoke, modulecontract.OperationLookup, modulecontract.OperationHeadless}

// Parse decodes and validates one manifest. Decoding is strict: an unknown
// field, a repeated key, a merge key, an explicit null, a fraction or a second
// document is refused rather than repaired. YAML is a superset of JSON, so the
// canonical JSON form parses here too.
func Parse(data []byte) (*ModuleManifest, error) {
	if len(data) > ManifestMaxBytes {
		return nil, fmt.Errorf("%w: the document is %d bytes, more than the %d a manifest may hold", ErrInvalid, len(data), ManifestMaxBytes)
	}
	manifest, err := decodeStrict[ModuleManifest](data, "module manifest", SchemaModuleManifestV1, checkSectionNodes)
	if err != nil {
		return nil, err
	}
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return manifest, nil
}

// Marshal is the one way to write a manifest: validate, encode, and read the
// bytes back through Parse, returning them only when they read back as the
// same document. A renderer never writes a manifest its reader refuses.
func Marshal(manifest *ModuleManifest) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	encoded, err := yaml.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("%w: the manifest cannot be encoded: %v", ErrInvalid, err)
	}
	again, err := Parse(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: the encoded manifest is refused by its own reader: %v", ErrInvalid, err)
	}
	if want, got := mustCanonical(manifest), mustCanonical(again); !bytes.Equal(want, got) {
		return nil, fmt.Errorf("%w: the encoded manifest reads back as a different document", ErrInvalid)
	}
	return encoded, nil
}

func mustCanonical(manifest *ModuleManifest) []byte {
	encoded, err := manifest.CanonicalBytes()
	if err != nil {
		return nil
	}
	return encoded
}

// replacedFamilies are the documents the manifest replaced. A document of any
// version of them is refused with the remedy, never read as a manifest.
var replacedFamilies = []string{
	"codefly/solution-host-binding",
	"codefly/solution-authority",
	"codefly/endpoint-delivery",
}

func replacedFamily(declared string) bool {
	family := declared
	if cut := strings.LastIndex(declared, "/"); cut >= 0 {
		family = declared[:cut]
	}
	return slices.Contains(replacedFamilies, family)
}

func schemaRefusal(declared, accepted string) error {
	if replacedFamily(declared) {
		return fmt.Errorf("%w: %q is a presence, authority or endpoint-delivery document, which the module manifest (%q) replaced; re-render it with a current Codefly CLI",
			ErrSchema, declared, accepted)
	}
	return fmt.Errorf("%w: %q (this Core reads %q)", ErrSchema, declared, accepted)
}

// decodeStrict decodes exactly one YAML document into T. The schema is read
// first, leniently, so a document of another schema is told so rather than
// refused for a field it legitimately has; schema "" skips that step. Then
// the tree is checked before any typed field exists (internal/wire): one key
// once per mapping with aliases resolved, no merge key, no explicit null, no
// fractional number, every key a name — each of which the typed decoder would
// otherwise repair silently. nodes is the caller's own check over the tree.
func decodeStrict[T any](data []byte, label, schema string, nodes func(tree *yaml.Node) error) (*T, error) {
	if schema != "" {
		var header struct {
			Schema string `yaml:"schema"`
		}
		if err := yaml.Unmarshal(data, &header); err != nil {
			return nil, fmt.Errorf("%w: decode %s: not a YAML document: %v", ErrInvalid, label, err)
		}
		if header.Schema != schema {
			return nil, schemaRefusal(header.Schema, schema)
		}
	}
	var tree yaml.Node
	if err := yaml.Unmarshal(data, &tree); err != nil {
		return nil, fmt.Errorf("%w: decode %s: not a YAML document: %v", ErrInvalid, label, err)
	}
	// Every document this package reads is a mapping. Anything else is refused
	// here, by what it is, rather than decoded into an empty value whose first
	// missing field would be reported as the defect.
	if root := &tree; root.Kind == yaml.DocumentNode && len(root.Content) == 1 && root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w: decode %s: the document is not a mapping", ErrInvalid, label)
	}
	switch defect := wire.Check(&tree); defect.Kind {
	case wire.DuplicateKey:
		return nil, fmt.Errorf("%w: the mapping at %s names the key %q twice; a repeated key makes the decoded document depend on order",
			ErrInvalid, defect.Path, defect.Detail)
	case wire.MergeKey:
		return nil, fmt.Errorf("%w: the mapping at %s uses the merge key <<, which yaml applies after every check has run",
			ErrInvalid, defect.Path)
	case wire.NullNode:
		return nil, fmt.Errorf("%w: the document carries an explicit null at %s %s; an absent field is absent, and an empty list is written []",
			ErrInvalid, defect.Path, defect.Detail)
	case wire.FractionalNumber:
		return nil, fmt.Errorf("%w: the number %s at %s is not a whole number; yaml would truncate it before any rule saw it",
			ErrInvalid, defect.Detail, defect.Path)
	case wire.KeyNotAName:
		return nil, fmt.Errorf("%w: the mapping at %s carries a key that is not a name (%q)", ErrInvalid, defect.Path, defect.Detail)
	}
	if nodes != nil {
		if err := nodes(&tree); err != nil {
			return nil, err
		}
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var value T
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("%w: decode %s: a field no %s declares, or a value of the wrong shape: %v", ErrInvalid, label, label, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%w: decode %s: the file holds more than one document", ErrInvalid, label)
		}
		return nil, fmt.Errorf("%w: decode %s: trailing input after the document: %v", ErrInvalid, label, err)
	}
	return &value, nil
}

// Validate checks everything a manifest can be checked against on its own.
// Whether a generation may be applied over what a host holds is Admit's;
// whether its alias is free on the host is CheckAlias'.
func (manifest *ModuleManifest) Validate() error {
	if manifest == nil {
		return fmt.Errorf("%w: a manifest is required", ErrInvalid)
	}
	if manifest.Schema != SchemaModuleManifestV1 {
		return schemaRefusal(manifest.Schema, SchemaModuleManifestV1)
	}
	if err := manifest.validateIdentity(); err != nil {
		return err
	}
	if manifest.Removed {
		// A withdrawal that still describes what it withdraws leaves a host
		// deciding which half meant it.
		for _, declared := range []struct {
			field   string
			present bool
		}{
			{"workloads", len(manifest.Workloads) != 0}, {"endpoints", len(manifest.Endpoints) != 0},
			{"authority", manifest.Authority != nil}, {"frontend", manifest.Frontend != nil},
			{"group", manifest.Group != nil},
		} {
			if declared.present {
				return fmt.Errorf("%w: binding %q is removed and declares %s; a withdrawal carries only its identity", ErrInvalid, manifest.Binding, declared.field)
			}
		}
		return nil
	}
	if err := manifest.validateWorkloads(); err != nil {
		return err
	}
	if err := manifest.validateEndpoints(); err != nil {
		return err
	}
	if err := validateSections(manifest); err != nil {
		return err
	}
	if manifest.Authority != nil {
		if err := manifest.Authority.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (manifest *ModuleManifest) validateIdentity() error {
	switch {
	case !bindingPattern.MatchString(manifest.Binding) || manifest.Binding == reservedOwner:
		return fmt.Errorf("%w: binding %q is not a valid instance id", ErrInvalid, manifest.Binding)
	case !segmentPattern.MatchString(manifest.Alias):
		return fmt.Errorf("%w: alias %q is not one lowercase path segment", ErrInvalid, manifest.Alias)
	case !slices.Contains(kinds, manifest.Kind):
		return fmt.Errorf("%w: kind %q is not one of %v", ErrInvalid, manifest.Kind, kinds)
	case manifest.Generation == 0:
		return fmt.Errorf("%w: generation starts at 1", ErrInvalid)
	case !namePattern.MatchString(manifest.Host.Coordinate):
		return fmt.Errorf("%w: host coordinate %q is invalid", ErrInvalid, manifest.Host.Coordinate)
	case !namePattern.MatchString(manifest.Host.Domain):
		return fmt.Errorf("%w: host domain %q is invalid", ErrInvalid, manifest.Host.Domain)
	case !segmentPattern.MatchString(manifest.Release.Publisher):
		return fmt.Errorf("%w: release publisher %q is not one lowercase segment", ErrInvalid, manifest.Release.Publisher)
	case !segmentPattern.MatchString(manifest.Release.Name):
		return fmt.Errorf("%w: release name %q is not one lowercase segment", ErrInvalid, manifest.Release.Name)
	}
	if _, err := semver.StrictNewVersion(manifest.Release.Version); err != nil {
		return fmt.Errorf("%w: release version %q is not semantic: %v", ErrInvalid, manifest.Release.Version, err)
	}
	return nil
}

func (manifest *ModuleManifest) validateWorkloads() error {
	if len(manifest.Workloads) == 0 {
		return fmt.Errorf("%w: binding %q is live and declares no workload; a module with no workload has nothing that can act as it", ErrInvalid, manifest.Binding)
	}
	services := map[string]bool{}
	for _, workload := range manifest.Workloads {
		if !segmentPattern.MatchString(workload.Service) {
			return fmt.Errorf("%w: workload service %q is invalid", ErrInvalid, workload.Service)
		}
		if services[workload.Service] {
			return fmt.Errorf("%w: workload service %q is declared twice", ErrInvalid, workload.Service)
		}
		services[workload.Service] = true
		if !segmentPattern.MatchString(workload.Container) {
			return fmt.Errorf("%w: workload %q container %q is invalid", ErrInvalid, workload.Service, workload.Container)
		}
	}
	return nil
}

func (manifest *ModuleManifest) validateEndpoints() error {
	services := map[string]bool{}
	for _, workload := range manifest.Workloads {
		services[workload.Service] = true
	}
	seen := map[string]bool{}
	for _, endpoint := range manifest.Endpoints {
		switch {
		case !segmentPattern.MatchString(endpoint.Name):
			return fmt.Errorf("%w: endpoint name %q is invalid", ErrInvalid, endpoint.Name)
		case !segmentPattern.MatchString(endpoint.API):
			return fmt.Errorf("%w: endpoint %q api %q is invalid", ErrInvalid, endpoint.Name, endpoint.API)
		case !services[endpoint.Service]:
			// A host routes an endpoint only to a workload that runs as the
			// module; an endpoint of anything else is a route to nobody's code.
			return fmt.Errorf("%w: endpoint %q names service %q, which is no declared workload's", ErrInvalid, endpoint.Name, endpoint.Service)
		case endpoint.Address == "" || len(endpoint.Address) > EndpointAddressMaxBytes || !singleLine(endpoint.Address):
			return fmt.Errorf("%w: endpoint %q address must be one line of at most %d bytes", ErrInvalid, endpoint.Name, EndpointAddressMaxBytes)
		}
		if _, err := resources.ParseAddress(endpoint.Address); err != nil {
			return fmt.Errorf("%w: endpoint %q address %q is malformed: %v", ErrInvalid, endpoint.Name, endpoint.Address, err)
		}
		key := endpoint.Service + "\x00" + endpoint.Name
		if seen[key] {
			return fmt.Errorf("%w: endpoint %q of service %q is declared twice", ErrInvalid, endpoint.Name, endpoint.Service)
		}
		seen[key] = true
	}
	return nil
}

func (authority *Authority) validate() error {
	if !opaqueIDPattern.MatchString(authority.Principal) {
		return fmt.Errorf("%w: authority principal %q is invalid", ErrInvalid, authority.Principal)
	}
	ids := map[string]bool{}
	for _, binding := range authority.Bindings {
		if !opaqueIDPattern.MatchString(binding.ID) {
			return fmt.Errorf("%w: authority binding id %q is invalid", ErrInvalid, binding.ID)
		}
		if ids[binding.ID] {
			return fmt.Errorf("%w: authority binding %q is declared twice", ErrInvalid, binding.ID)
		}
		ids[binding.ID] = true
		if binding.Audience == "" || !singleLine(binding.Audience) {
			return fmt.Errorf("%w: authority binding %q audience must be one line", ErrInvalid, binding.ID)
		}
		if len(binding.Operations) == 0 {
			return fmt.Errorf("%w: authority binding %q requests no operation", ErrInvalid, binding.ID)
		}
		for operation, scopes := range binding.Operations {
			if !slices.Contains(operations, operation) {
				return fmt.Errorf("%w: authority binding %q requests operation %q, which is none of %v", ErrInvalid, binding.ID, operation, operations)
			}
			// An operation with no scope cannot be minted; asking for it is
			// asking for nothing under a name that reads as something.
			if len(scopes) == 0 {
				return fmt.Errorf("%w: authority binding %q operation %q requests no scope", ErrInvalid, binding.ID, operation)
			}
			for index, scope := range scopes {
				kind, action, found := strings.Cut(scope, ":")
				if !found || kind == "" || action == "" || strings.Contains(action, ":") || !singleLine(scope) {
					return fmt.Errorf("%w: authority binding %q operation %q scope %q is not <resource kind>:<action>", ErrInvalid, binding.ID, operation, scope)
				}
				if slices.Contains(scopes[:index], scope) {
					return fmt.Errorf("%w: authority binding %q operation %q requests scope %q twice", ErrInvalid, binding.ID, operation, scope)
				}
			}
		}
	}
	// A DELIVERED edge dependency carries the one presence the environment's
	// class resolved (modulecontract.ResolveEdgeDependencies), never the
	// per-class declaration it was resolved from. A manifest carrying both
	// would say two things about one edge and let a host pick, which is the
	// whole point of resolving at delivery; a host never learns what an
	// environment class is.
	for _, edge := range authority.EdgeDependencies {
		switch {
		case len(edge.PresenceByClass) > 0:
			return fmt.Errorf("%w: authority edge dependency %q carries a per-environment-class presence; a delivered manifest carries the presence the environment's class resolved to, and the deliverer resolves it", ErrInvalid, edge.Module)
		case edge.Presence != modulecontract.PresenceRequired && edge.Presence != modulecontract.PresenceOptional:
			return fmt.Errorf("%w: authority edge dependency %q presence %q must be %s or %s", ErrInvalid, edge.Module, edge.Presence, modulecontract.PresenceRequired, modulecontract.PresenceOptional)
		}
	}
	// A governing scope is one of the module's own kinds: a host decides it
	// where the module is installed, and a kind it does not declare is one no
	// installation of it holds.
	for index, governing := range authority.SourceGovernance {
		kind, action, found := strings.Cut(governing, ":")
		if !found || kind == "" || action == "" || strings.Contains(action, ":") || !singleLine(governing) {
			return fmt.Errorf("%w: authority source governance scope %q is not <resource kind>:<action>", ErrInvalid, governing)
		}
		if !slices.Contains(authority.ResourceKinds, kind) {
			return fmt.Errorf("%w: authority source governance scope %q names a kind the module does not declare", ErrInvalid, governing)
		}
		if slices.Contains(authority.SourceGovernance[:index], governing) {
			return fmt.Errorf("%w: authority declares source governance scope %q twice", ErrInvalid, governing)
		}
	}
	for _, list := range []struct {
		label  string
		values []string
	}{{"queue", authority.Queues}, {"namespace", authority.Namespaces}, {"resource kind", authority.ResourceKinds}} {
		for index, value := range list.values {
			if value == "" || !singleLine(value) {
				return fmt.Errorf("%w: authority %s %q must be one line", ErrInvalid, list.label, value)
			}
			if slices.Contains(list.values[:index], value) {
				return fmt.Errorf("%w: authority declares %s %q twice", ErrInvalid, list.label, value)
			}
		}
	}
	return nil
}

// singleLine reports a printable, whitespace-free value: the shape of a name,
// never of a PEM block or a pasted credential.
func singleLine(value string) bool {
	return !strings.ContainsFunc(value, func(r rune) bool { return r <= ' ' || r == 0x7f })
}

// CanonicalBytes is the deterministic JSON encoding of a valid manifest:
// object keys in name order at every depth, every set in sorted order, every
// number its exact literal. It is what a signature covers and what Digest
// hashes, so it must move only when the manifest does.
func (manifest *ModuleManifest) CanonicalBytes() ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	normalized := *manifest
	normalized.Workloads = slices.Clone(manifest.Workloads)
	sort.Slice(normalized.Workloads, func(i, j int) bool { return normalized.Workloads[i].Service < normalized.Workloads[j].Service })
	normalized.Endpoints = slices.Clone(manifest.Endpoints)
	sort.Slice(normalized.Endpoints, func(i, j int) bool {
		left, right := normalized.Endpoints[i], normalized.Endpoints[j]
		if left.Service != right.Service {
			return left.Service < right.Service
		}
		return left.Name < right.Name
	})
	if manifest.Frontend != nil {
		normalized.Frontend = manifest.Frontend.canonical()
	}
	if manifest.Authority != nil {
		normalized.Authority = manifest.Authority.canonical()
	}
	return canonicalJSON(normalized)
}

func (authority *Authority) canonical() *Authority {
	normalized := Authority{
		InstallationRole: authority.InstallationRole,
		EdgeDependencies: slices.Clone(authority.EdgeDependencies),
		SourceGovernance: sortedOrNil(authority.SourceGovernance),
		Principal:        authority.Principal,
		Queues:           sortedOrNil(authority.Queues),
		Namespaces:       sortedOrNil(authority.Namespaces),
		ResourceKinds:    sortedOrNil(authority.ResourceKinds),
	}
	for _, binding := range authority.Bindings {
		operations := make(map[string][]string, len(binding.Operations))
		for operation, scopes := range binding.Operations {
			operations[operation] = slices.Sorted(slices.Values(scopes))
		}
		normalized.Bindings = append(normalized.Bindings, AuthorityBinding{ID: binding.ID, Audience: binding.Audience, Operations: operations})
	}
	sort.Slice(normalized.Bindings, func(i, j int) bool { return normalized.Bindings[i].ID < normalized.Bindings[j].ID })
	return &normalized
}

func sortedOrNil(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return slices.Sorted(slices.Values(values))
}

// canonicalJSON encodes a value with object keys in name order at every depth
// and every number kept as its exact literal.
func canonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

// Digest is the SHA-256 of the canonical encoding, "sha256:<hex>". Two
// manifests with one digest are one document.
func (manifest *ModuleManifest) Digest() (string, error) {
	canonical, err := manifest.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// WorkloadNamed answers the workload this manifest declares under service: the
// lookup for a credential that names its declaration.
func (manifest *ModuleManifest) WorkloadNamed(service string) (Workload, bool) {
	for _, workload := range manifest.Workloads {
		if workload.Service == service {
			return workload, true
		}
	}
	return Workload{}, false
}
