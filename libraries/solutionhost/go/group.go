package solutionhost

import (
	"fmt"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/codefly-dev/core/resources"
)

// SolutionGroup is the presentation group a solution is organised under on
// its host — in the navigation, after the host's own entitlement filter, and
// in the administrative catalogue, where a headless solution is organised
// too, which is why it is a block of the document and not of the frontend.
// It is GENERATED: the renderer projects it from the composing product's
// solution groups (resources.SolutionGroup, through Workspace.SolutionGroupOf)
// and an author writes it nowhere else. It grants nothing and installs
// nothing: a group is a heading, where it sorts, and the id the solutions
// under it share, and a solution's own identity is unchanged by it. Solutions
// only — a module is grouped by nothing — and a withdrawal declares none.
//
// The block is OPTIONAL, and one that carries it is held to every group rule.
type SolutionGroup struct {
	// ID is the group's id as the composing workspace spells it: lowercase
	// letters and digits, dash-separated (resources.ValidateSolutionGroupID).
	ID string `yaml:"id" json:"id"`

	// Title is what the host labels the group with: one non-blank line, no
	// control characters (resources.ValidateSolutionGroupTitle).
	Title string `yaml:"title" json:"title"`

	// Order is where the group sorts among groups. Declared, zero included:
	// an omitted order would decode as zero and read as a choice. The field
	// is wide; the admitted range is a signed 32-bit integer
	// (resources.ValidateSolutionGroupOrder), held on the written number
	// before it is typed, so a host's int32 wire and a client's number
	// represent every admitted value exactly and nothing casts.
	Order int64 `yaml:"order" json:"order"`
}

// GroupTextMaxBytes bounds a group's id and title, in UTF-8 bytes: the bound
// the group is authored within (resources.SolutionGroupTextMaxBytes), which
// is also the frontend text bound, since a host persists and projects both
// the same way.
const GroupTextMaxBytes = resources.SolutionGroupTextMaxBytes

// The group rules, by name; see rule.
const (
	ruleGroupFieldsDeclared = "group-fields-declared"
	ruleGroupOrderDecimal   = "group-order-decimal"
	ruleGroupOrderFits      = "group-order-fits"
	ruleGroupSolutionOnly   = "group-solution-only"
	ruleGroupTextBounded    = "group-text-bounded"
	ruleGroupID             = "group-id"
	ruleGroupTitle          = "group-title"
)

// groupNodeRules run over the group node before it is typed, and
// groupModelRules over the decoded block; both are rows of the one table in
// rules(), which fixes their order among the other rules.
func groupNodeRules() []rule {
	return []rule{
		{name: ruleGroupFieldsDeclared, section: sectionGroup, node: checkGroupFieldsDeclared},
		{name: ruleGroupOrderDecimal, section: sectionGroup, node: checkGroupOrderDecimal},
		{name: ruleGroupOrderFits, section: sectionGroup, node: checkGroupOrderFits},
	}
}

func groupModelRules() []rule {
	return []rule{
		{name: ruleGroupSolutionOnly, section: sectionGroup, check: checkGroupSolutionOnly},
		{name: ruleGroupTextBounded, section: sectionGroup, check: checkGroupTextBounded},
		{name: ruleGroupID, section: sectionGroup, check: checkGroupID},
		{name: ruleGroupTitle, section: sectionGroup, check: checkGroupTitle},
	}
}

// groupFields lists the fields of the block by the path a refusal names, the
// order apart as its one number, which is signed. A block that is not a
// mapping is left to the typed decoder, which refuses its shape.
func groupFields(section *yaml.Node) (order countField, others []countField) {
	for _, name := range []string{"id", "title"} {
		others = append(others, countField{path: "group." + name, node: mappingValue(section, name)})
	}
	return countField{path: "group.order", node: mappingValue(section, "order")}, others
}

func checkGroupFieldsDeclared(section *yaml.Node) error {
	order, others := groupFields(section)
	for _, field := range append(others, order) {
		if field.node == nil {
			return fmt.Errorf("%w: %s must be declared; an absent field decodes as zero or empty, and a value nobody wrote would be signed as a choice", ErrInvalid, field.path)
		}
	}
	return nil
}

func checkGroupOrderDecimal(section *yaml.Node) error {
	if order, _ := groupFields(section); order.node != nil && !isDecimalInteger(order.node, true) {
		return fmt.Errorf("%w: %s is %q, not a whole number written in decimal digits; a number has one spelling here, and yaml would otherwise read a base prefix, a leading zero, a plus sign or a string into a number nobody wrote", ErrInvalid, order.path, order.node.Value)
	}
	return nil
}

// fitsGroupOrder reports whether a decimal order scalar is within the range
// the group is authored within, read as the number it is written as.
func fitsGroupOrder(node *yaml.Node) bool {
	value, err := strconv.ParseInt(node.Value, 10, 64)
	return err == nil && resources.ValidateSolutionGroupOrder(value) == nil
}

func checkGroupOrderFits(section *yaml.Node) error {
	if order, _ := groupFields(section); order.node != nil && isDecimalInteger(order.node, true) && !fitsGroupOrder(order.node) {
		return fmt.Errorf("%w: %s is %s, outside %d..%d, the range every host represents exactly", ErrInvalid, order.path, order.node.Value, resources.SolutionGroupOrderMin, resources.SolutionGroupOrderMax)
	}
	return nil
}

func checkGroupSolutionOnly(document *ModuleManifest) error {
	if document.Kind != KindSolution {
		return fmt.Errorf("%w: group is declared on a %q; a group organises solutions, and a module is grouped by nothing", ErrInvalid, document.Kind)
	}
	return nil
}

func (group *SolutionGroup) texts() []frontendText {
	return []frontendText{{path: "group.id", value: group.ID}, {path: "group.title", value: group.Title}}
}

func checkGroupTextBounded(document *ModuleManifest) error {
	for _, text := range document.Group.texts() {
		if len(text.value) > GroupTextMaxBytes {
			return fmt.Errorf("%w: group text exceeds %d bytes at %s", ErrInvalid, GroupTextMaxBytes, text.path)
		}
	}
	return nil
}

func checkGroupID(document *ModuleManifest) error {
	if err := resources.ValidateSolutionGroupID(document.Group.ID); err != nil {
		return fmt.Errorf("%w: group.id %q is invalid: %v", ErrInvalid, document.Group.ID, err)
	}
	return nil
}

func checkGroupTitle(document *ModuleManifest) error {
	if err := resources.ValidateSolutionGroupTitle(document.Group.Title); err != nil {
		return fmt.Errorf("%w: group.title must be a non-blank single-line text: %v", ErrInvalid, err)
	}
	return nil
}
