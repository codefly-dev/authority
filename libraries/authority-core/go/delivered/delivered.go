// Package delivered reads a verified delivery as the authority's module: core's
// signed module manifest and, beside it, the authority's own document
// (codefly.dev/composition AuthorityManifestV1). Every host composes a module
// from the same two documents, so this is where the reading lives; a host
// verifies the carrier (it holds the release keys) and decodes the document
// from its own generated binding into Document, and nothing else.
package delivered

import (
	"crypto"
	"slices"
	"strings"

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
}

// Method is one method's declaration in the document.
type Method struct {
	Method           string
	Requires         Scopes
	AnyCheckedCaller bool
}

// Role is one of a solution's roles: its scopes, and those it declares
// installation-owned (resolved to the ids each installation owns).
type Role struct {
	Name                      string
	Scopes, InstallationOwned Scopes
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
// same module, the same generation, and the carrier's own digest.
func Pair(doc Document, carrierDocument []byte, manifest *solutionhost.ModuleManifest) error {
	switch {
	case doc.Module != manifest.Alias:
		return domain.Refuse("the authority's document is for %q, the manifest for %q", doc.Module, manifest.Alias)
	case doc.Generation != manifest.Generation:
		return domain.Refuse("the authority's document is at generation %d, the manifest at %d", doc.Generation, manifest.Generation)
	case doc.CoreManifestDigest != delivery.Digest(carrierDocument):
		return domain.Refuse("the authority's document names another manifest than the one delivered with it")
	}
	return nil
}

// Module is what a verified delivery composes: core's manifest (FromCore),
// narrowed and completed by the document paired with it, when one was. A
// withdrawal carries no live declaration.
func Module(manifest *solutionhost.ModuleManifest, doc *Document) (domain.Module, error) {
	m := FromCore(manifest)
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
	if m.Roles, m.OwnedRoles, err = roles(doc.Roles); err != nil {
		return m, err
	}
	m.OwnerAware = doc.OwnerAware
	m.InstallationRole = doc.InstallationRole
	m.EdgeDependencies = slices.Clone(doc.EdgeDependencies)
	return m, nil
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

// roles reads the roles a solution declares, by name, and the scopes of each
// it declares installation-owned. Core holds them to the role contract when
// the module is applied (decide.ValidateModule).
func roles(in []Role) (map[string]Scopes, map[string]Scopes, error) {
	owned := map[string]Scopes{}
	if len(in) == 0 {
		return nil, owned, nil
	}
	out := make(map[string]Scopes, len(in))
	for _, role := range in {
		if _, twice := out[role.Name]; twice || role.Name == "" {
			return nil, nil, domain.Malformed("the authority's document lists role %q twice or unnamed", role.Name)
		}
		out[role.Name] = scope.Normalize(role.Scopes)
		if len(role.InstallationOwned) > 0 {
			owned[role.Name] = role.InstallationOwned
		}
	}
	return out, owned, nil
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
// manifest carries no roles; a solution's arrive in the document delivered
// with it. The manifest is the ceiling here: a resource kind declared with no
// actions serves whatever the roles grant on it, a binding's operations are
// its scopes, each "<resource kind>:<action>" as core's manifest writes them.
func FromCore(in *solutionhost.ModuleManifest) domain.Module {
	m := domain.Module{Name: in.Alias, Principal: in.Alias, Kind: string(in.Kind), Generation: in.Generation, Bindings: map[string]domain.Binding{}}
	if in.Authority == nil {
		return m
	}
	if in.Authority.Principal != "" {
		m.Principal = in.Authority.Principal
	}
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
