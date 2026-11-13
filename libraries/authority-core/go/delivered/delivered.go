// Package delivered reads a verified delivery as the authority's module: core's
// signed module manifest and, beside it, the authority's own document
// (codefly.dev/composition AuthorityManifestV1). Every host composes a module
// from the same two documents, so this is where the reading lives; a host
// verifies the carrier (it holds the release keys) and decodes the document
// from its own generated binding into Document, and nothing else.
package delivered

import (
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	delivery "github.com/codefly-dev/authority/libraries/delivery/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/solutionhost"
)

// Scopes is a scope list.
type Scopes = []*basev0.WorkScopeV1

// Document is the authority's own document delivered with a manifest, as a
// host decodes it.
type Document struct {
	Module             string
	Generation         uint64
	CoreManifestDigest string
	ScopeCeilings      Scopes
	Methods            []Method
	Roles              []Role
	OwnerAware         bool
	// Core validates these declarations; every delivery hop carries them verbatim.
	InstallationRole string
	EdgeDependencies []domain.EdgeDependency
	// SharedKinds are the served kinds the module declares unowned
	// (domain.Module.SharedKinds).
	SharedKinds []string
}

// Method is one method's declaration in the document.
type Method struct {
	Method           string
	Requires         Scopes
	AnyCheckedCaller bool
}

// Role is one of a solution's or a module page's roles: its scopes, and those
// it declares installation-owned (resolved to the ids each installation owns).
type Role struct {
	Name                      string
	Scopes, InstallationOwned Scopes
	// Through are the scopes the role names downstream of each of the
	// module's own bindings, by binding id (domain.Module.Through).
	Through map[string]Scopes
}

// VerifyDocument checks the document's signature against the pinned release
// keys and that the key which signed it is the one that signed the carrier, so
// a delivery cannot pair one release's manifest with another's declarations.
func VerifyDocument(document, envelope []byte, keys map[string]crypto.PublicKey, carrierSigner string) error {
	keyID, err := delivery.Verify(document, envelope, keys)
	if err != nil {
		return domain.Refuse("the authority's document does not verify: %v", err)
	}
	if keyID != carrierSigner {
		return domain.Refuse("the authority's document is signed by %q and the manifest by %q", keyID, carrierSigner)
	}
	return nil
}

// Pair holds a verified document to the carrier it was delivered with: the
// same module, generation, carrier digest and duplicated install declaration.
func Pair(doc Document, carrierDocument []byte, manifest *solutionhost.ModuleManifest) error {
	switch {
	case doc.Module != manifest.Alias:
		return domain.Refuse("the authority's document is for %q, the manifest for %q", doc.Module, manifest.Alias)
	case doc.Generation != manifest.Generation:
		return domain.Refuse("the authority's document is at generation %d, the manifest at %d", doc.Generation, manifest.Generation)
	case doc.CoreManifestDigest != delivery.Digest(carrierDocument):
		return domain.Refuse("the authority's document names another manifest than the one delivered with it")
	}
	return sameInstallationDeclaration(manifest.Authority, &doc)
}

// Source is the digest of a delivery's signed documents, as a host verified
// them: core's manifest (the carrier's document) and the authority's document
// paired with it, nil when none was. Two readings of one generation come from
// the same delivery exactly when their sources are equal: a host that reads
// a field it did not read before reads the same Source differently
// (domain.Module.Source, authority.Service.RereadModule).
func Source(carrierDocument, authorityDocument []byte) string {
	h := sha256.New()
	for _, doc := range [][]byte{carrierDocument, authorityDocument} {
		var size [8]byte // 0 for an absent document, its length plus one otherwise
		if doc != nil {
			binary.BigEndian.PutUint64(size[:], uint64(len(doc))+1)
		}
		h.Write(size[:])
		h.Write(doc)
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

// Module is what a verified delivery composes: core's manifest (FromCore),
// narrowed and completed by the document paired with it, when one was, and a
// module page's standard roles derived when the document declares none. A
// withdrawal carries no live declaration.
func Module(manifest *solutionhost.ModuleManifest, doc *Document) (domain.Module, error) {
	m := FromCore(manifest)
	if err := sameInstallationDeclaration(manifest.Authority, doc); err != nil {
		return m, err
	}
	if doc == nil {
		return m, nil
	}
	if manifest.Removed && (len(doc.Methods) > 0 || len(doc.Roles) > 0 || len(doc.ScopeCeilings) > 0) {
		return m, domain.Malformed("a withdrawal carries no live authority declarations")
	}
	var err error
	if m.Methods, err = methods(doc.Methods); err != nil {
		return m, err
	}
	for _, ceiling := range doc.ScopeCeilings {
		if ceiling.GetResourceOwnerId() != "" {
			return m, domain.Refuse("%s: scope ceiling %s names resource owner %q; a delivery never selects an owner", m.Name, ceiling.GetResourceKind(), ceiling.GetResourceOwnerId())
		}
	}
	if m, err = Ceiled(m, doc.ScopeCeilings); err != nil {
		return m, err
	}
	if m.Roles, m.OwnedRoles, m.Through, err = roles(doc.Roles); err != nil {
		return m, err
	}
	// A module page declaring no roles gets the standard three, derived from
	// what it serves (decide.StandardRoles): every page is gated by its own
	// roles, declared or derived, and only a module without a page is on the
	// organization's. Derived here, where the document is read, so every host
	// composes the same roles from the same delivery.
	if m.Kind != domain.KindSolution && m.Page && len(m.Roles) == 0 {
		m.Roles = decide.StandardRoles(m)
	}
	m.OwnerAware = doc.OwnerAware
	m.InstallationRole = doc.InstallationRole
	m.EdgeDependencies = slices.Clone(doc.EdgeDependencies)
	m.SharedKinds = slices.Clone(doc.SharedKinds)
	return m, nil
}

// sameInstallationDeclaration checks agreement, not declaration validity. Both
// signed carriers are projections of one authored value. Neither wins a conflict;
// a missing carrier supplies only the legacy empty declaration.
func sameInstallationDeclaration(carrier *solutionhost.Authority, doc *Document) error {
	if carrier == nil {
		carrier = &solutionhost.Authority{}
	}
	if doc == nil {
		doc = &Document{}
	}
	if carrier.InstallationRole != doc.InstallationRole {
		return domain.Refuse("installation_role differs between the signed manifest and authority document")
	}
	if len(carrier.EdgeDependencies) != len(doc.EdgeDependencies) {
		return domain.Refuse("edge_dependencies differs between the signed manifest and authority document")
	}
	for i, edge := range carrier.EdgeDependencies {
		if edge.Module != doc.EdgeDependencies[i].Module || edge.Presence != doc.EdgeDependencies[i].Presence {
			return domain.Refuse("edge_dependencies differs between the signed manifest and authority document at entry %d", i)
		}
	}
	return nil
}

// methods reads what each method declares.
func methods(in []Method) (map[string]domain.MethodPolicy, error) {
	out := make(map[string]domain.MethodPolicy, len(in))
	for _, method := range in {
		if _, twice := out[method.Method]; twice || method.Method == "" {
			return nil, domain.Malformed("the authority's document lists method %q twice or unnamed", method.Method)
		}
		out[method.Method] = domain.MethodPolicy{Requires: method.Requires, AnyCheckedCaller: method.AnyCheckedCaller}
	}
	return out, nil
}

// roles reads the roles a solution or a module page declares, by name, the
// scopes of each it declares installation-owned, and those it names through
// each of its bindings, which are part of the role's grant. Core holds them
// to the role contract when the module is applied (decide.ValidateModule).
func roles(in []Role) (map[string]Scopes, map[string]Scopes, map[string]map[string]Scopes, error) {
	owned := map[string]Scopes{}
	if len(in) == 0 {
		return nil, owned, nil, nil
	}
	out := make(map[string]Scopes, len(in))
	var through map[string]map[string]Scopes
	for _, role := range in {
		if _, twice := out[role.Name]; twice || role.Name == "" {
			return nil, nil, nil, domain.Malformed("the authority's document lists role %q twice or unnamed", role.Name)
		}
		grant := slices.Clone(role.Scopes)
		for _, binding := range slices.Sorted(maps.Keys(role.Through)) {
			if binding == "" || len(role.Through[binding]) == 0 {
				return nil, nil, nil, domain.Malformed("role %q names an empty through: a binding and the scopes reached through it", role.Name)
			}
			if through == nil {
				through = map[string]map[string]Scopes{}
			}
			if through[role.Name] == nil {
				through[role.Name] = map[string]Scopes{}
			}
			through[role.Name][binding] = scope.Normalize(role.Through[binding])
			grant = append(grant, role.Through[binding]...)
		}
		out[role.Name] = scope.Normalize(grant)
		if len(role.InstallationOwned) > 0 {
			owned[role.Name] = role.InstallationOwned
		}
	}
	return out, owned, through, nil
}

// Ceiled gives each of the module's own kinds the actions its document
// declares on it, in place of the any-action kind core's manifest leaves it
// with. A ceiling naming a kind core's manifest does not declare is refused:
// the document narrows what core's manifest composes, never adds to it.
func Ceiled(m domain.Module, ceilings Scopes) (domain.Module, error) {
	if len(ceilings) == 0 {
		return m, nil
	}
	declared := map[string]bool{}
	for _, kind := range m.ResourceKinds {
		declared[kind.GetResourceKind()] = true
	}
	ceiled := map[string]bool{}
	for _, ceiling := range ceilings {
		if !declared[ceiling.GetResourceKind()] {
			return m, domain.Malformed("the authority's document ceils %s, which %s's manifest does not declare", ceiling.GetResourceKind(), m.Name)
		}
		if len(ceiling.GetActions()) == 0 {
			return m, domain.Malformed("the authority's document ceils %s with no action", ceiling.GetResourceKind())
		}
		ceiled[ceiling.GetResourceKind()] = true
	}
	kinds := slices.Clone(ceilings)
	for _, kind := range m.ResourceKinds {
		if !ceiled[kind.GetResourceKind()] {
			kinds = append(kinds, kind)
		}
	}
	m.ResourceKinds = scope.Normalize(kinds)
	return m, nil
}

// FromCore reads core's module manifest as the authority's module. Core's
// manifest carries no roles; a solution's or a module page's arrive in the
// document delivered with it, and a manifest declaring a frontend is a page,
// whichever way the host mounts it: a remote it loads or a package it bundles
// (solutionhost.Frontend.Bundled).
// The scopes that govern its sources do ride on it (SourceGovernance), held
// to those roles when the module is applied (decide.ValidateModule).
// The manifest is the ceiling here: a resource kind declared with no actions
// serves whatever the roles grant on it, a binding's operations are its
// scopes, each "<resource kind>:<action>" as core's manifest writes them.
func FromCore(in *solutionhost.ModuleManifest) domain.Module {
	m := domain.Module{Name: in.Alias, Principal: in.Alias, Kind: string(in.Kind), Generation: in.Generation, Bindings: map[string]domain.Binding{},
		Page: in.Frontend != nil}
	if in.Authority == nil {
		return m
	}
	m.InstallationRole = in.Authority.InstallationRole
	for _, edge := range in.Authority.EdgeDependencies {
		m.EdgeDependencies = append(m.EdgeDependencies, domain.EdgeDependency{Module: edge.Module, Presence: edge.Presence})
	}
	if in.Authority.Principal != "" {
		m.Principal = in.Authority.Principal
	}
	m.SourceGovernance = scopesOf(in.Authority.SourceGovernance)
	for _, kind := range in.Authority.ResourceKinds {
		m.ResourceKinds = append(m.ResourceKinds, &basev0.WorkScopeV1{ResourceKind: kind, Actions: []string{scope.AnyAction}})
	}
	m.ResourceKinds = scope.Normalize(m.ResourceKinds)
	for _, b := range in.Authority.Bindings {
		m.Bindings[b.ID] = domain.Binding{ID: b.ID, Audience: b.Audience, InvokeScopes: scopesOf(b.Operations["invoke"]),
			HeadlessScopes: scopesOf(b.Operations["headless"]), LookupScopes: scopesOf(b.Operations["lookup"])}
	}
	return m
}

// scopesOf reads one operation's scopes, grouped by kind. An entry without a
// colon names nothing and is skipped; the manifest's own validation refuses it.
func scopesOf(entries []string) Scopes {
	byKind := map[string][]string{}
	var kinds []string
	for _, entry := range entries {
		kind, action, ok := strings.Cut(entry, ":")
		if !ok || kind == "" || action == "" {
			continue
		}
		if _, seen := byKind[kind]; !seen {
			kinds = append(kinds, kind)
		}
		byKind[kind] = append(byKind[kind], action)
	}
	var out Scopes
	for _, kind := range kinds {
		out = append(out, &basev0.WorkScopeV1{ResourceKind: kind, Actions: byKind[kind]})
	}
	return scope.Normalize(out)
}
