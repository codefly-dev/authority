package solutionhost

import (
	"gopkg.in/yaml.v3"

	"github.com/codefly-dev/core/wire"
)

// A rule is one refusal over an optional block of the manifest — the frontend
// or the group. A NODE rule runs over the block's node of the YAML tree before
// the typed decoder sees it, because yaml repairs what it cannot represent (a
// number in another base, an absent field read as zero); a MODEL rule runs
// over the decoded manifest. A rule runs only when its block is present.
type rule struct {
	name    string
	section string
	node    func(section *yaml.Node) error
	check   func(manifest *ModuleManifest) error
}

// The blocks a rule reads, by the key each is written under.
const (
	sectionFrontend = "frontend"
	sectionGroup    = "group"
)

func rules() []rule {
	all := append(frontendNodeRules(), groupNodeRules()...)
	all = append(all, frontendModelRules()...)
	return append(all, groupModelRules()...)
}

// checkSectionNodes runs every node rule over its block of a parsed tree.
func checkSectionNodes(tree *yaml.Node) error {
	for _, r := range rules() {
		if r.node == nil {
			continue
		}
		if section := sectionNode(tree, r.section); section != nil {
			if err := r.node(section); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateSections runs every model rule whose block the manifest carries.
func validateSections(manifest *ModuleManifest) error {
	for _, r := range rules() {
		if r.check == nil {
			continue
		}
		if (r.section == sectionFrontend && manifest.Frontend == nil) || (r.section == sectionGroup && manifest.Group == nil) {
			continue
		}
		if err := r.check(manifest); err != nil {
			return err
		}
	}
	return nil
}

// sectionNode finds the named value of the document's top-level mapping,
// aliases resolved, or nil when the document carries none.
func sectionNode(tree *yaml.Node, section string) *yaml.Node {
	root := wire.Resolve(tree)
	if root != nil && root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = wire.Resolve(root.Content[0])
	}
	return mappingValue(root, section)
}

// mappingValue returns the value a mapping holds under key, aliases resolved,
// or nil. It matches the key's written text, which is sound because the shared
// wire check has already refused every key that is not a plain name.
func mappingValue(node *yaml.Node, key string) *yaml.Node {
	node = wire.Resolve(node)
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		name := wire.Resolve(node.Content[index])
		if name != nil && name.Kind == yaml.ScalarNode && name.Value == key {
			return wire.Resolve(node.Content[index+1])
		}
	}
	return nil
}

// countField is one field a block declares, by the path a refusal names and
// the node carrying it — nil when the field is absent.
type countField struct {
	path string
	node *yaml.Node
}
