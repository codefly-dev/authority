// Package scope is the authority's scope algebra: what a set of Work Context
// scopes covers, their intersection and attenuation, and the per-kind limits a
// parent capability imposes on every later hop. It is owner-aware: a scope
// naming a resource owner covers only that owner's resources, and an
// intersection keeps the narrower side, so an owner is added but never dropped.
package scope

import (
	"errors"
	"slices"
	"sort"
	"strings"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/protobuf/proto"
)

// AnyAction on a served kind serves whatever actions a role grants on it; on
// a role's scope it grants every action the audience serves on that kind.
const AnyAction = "*"

// AnyKind on a role's scope grants its actions on every kind the audience serves.
const AnyKind = "*"

// key is one kind as one owner holds it ("" selects no owner).
type key struct{ kind, owner string }

// coverage is (kind, owner) -> action -> ids, where a nil id set is every
// resource the row selects.
type coverage map[key]map[string]map[string]bool

func coverageOf(in []*basev0.WorkScopeV1) coverage {
	c := coverage{}
	for _, sc := range in {
		if sc == nil || sc.GetResourceKind() == "" {
			continue
		}
		k := key{sc.GetResourceKind(), sc.GetResourceOwnerId()}
		if c[k] == nil {
			c[k] = map[string]map[string]bool{}
		}
		for _, act := range sc.GetActions() {
			current, seen := c[k][act]
			switch {
			case len(sc.GetResourceIds()) == 0:
				c[k][act] = nil
			case seen && current == nil:
			default:
				if current == nil {
					current = map[string]bool{}
				}
				for _, id := range sc.GetResourceIds() {
					current[id] = true
				}
				c[k][act] = current
			}
		}
	}
	return c
}

// scopes renders coverage sorted: kinds, then owners, then id sets.
func (c coverage) scopes() []*basev0.WorkScopeV1 {
	keys := make([]key, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(a, b int) bool {
		if keys[a].kind != keys[b].kind {
			return keys[a].kind < keys[b].kind
		}
		return keys[a].owner < keys[b].owner
	})
	var out []*basev0.WorkScopeV1
	for _, k := range keys {
		bySet := map[string][]string{}
		sets := map[string][]string{}
		for act, ids := range c[k] {
			set := ""
			var list []string
			if ids != nil {
				for id := range ids {
					list = append(list, id)
				}
				sort.Strings(list)
				set = "\x00" + strings.Join(list, "\x00")
			}
			bySet[set] = append(bySet[set], act)
			sets[set] = list
		}
		names := make([]string, 0, len(bySet))
		for set := range bySet {
			names = append(names, set)
		}
		sort.Strings(names)
		for _, set := range names {
			actions := bySet[set]
			sort.Strings(actions)
			out = append(out, &basev0.WorkScopeV1{ResourceKind: k.kind, Actions: actions, ResourceIds: sets[set], ResourceOwnerId: k.owner})
		}
	}
	return out
}

// Normalize merges duplicate rows and sorts actions, the shape core requires.
func Normalize(in []*basev0.WorkScopeV1) []*basev0.WorkScopeV1 { return coverageOf(in).scopes() }

// Intersect keeps what a holds that b allows, the narrower side winning: a
// whole kind meets named ids as those ids, two id sets meet as their common
// ids, a row naming no owner meets an owner's row as that owner's, and two
// different owners meet as nothing. AnyAction in b allows every action of a's
// kind; AnyAction in a takes every action b allows on that kind. Where several
// rows of b allow the same (kind, owner, action), the result is the union of
// what each allows: a repeated row adds to the answer, never replaces it.
func Intersect(a, b []*basev0.WorkScopeV1) []*basev0.WorkScopeV1 {
	allowed, asked := coverageOf(b), coverageOf(a)
	out := coverage{}
	put := func(k key, act string, ids map[string]bool) {
		if ids != nil && len(ids) == 0 {
			return
		}
		if out[k] == nil {
			out[k] = map[string]map[string]bool{}
		}
		if current, seen := out[k][act]; seen {
			ids = union(current, ids)
		}
		out[k][act] = ids
	}
	for ka, acts := range asked {
		for kb, allowedActs := range allowed {
			if ka.kind != kb.kind || (ka.owner != "" && kb.owner != "" && ka.owner != kb.owner) {
				continue
			}
			k := key{ka.kind, ka.owner}
			if k.owner == "" {
				k.owner = kb.owner
			}
			for act, ids := range acts {
				if act == AnyAction {
					for served, allowedIDs := range allowedActs {
						put(k, served, meet(ids, allowedIDs))
					}
					continue
				}
				// An exact row and an AnyAction row of the same kind both
				// allow act: the result is what either allows, so the exact
				// row never hides a wider AnyAction row.
				if allowedIDs, ok := allowedActs[act]; ok {
					put(k, act, meet(ids, allowedIDs))
				}
				if allowedIDs, ok := allowedActs[AnyAction]; ok {
					put(k, act, meet(ids, allowedIDs))
				}
			}
		}
	}
	return out.scopes()
}

func meet(a, b map[string]bool) map[string]bool {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	common := map[string]bool{}
	for id := range a {
		if b[id] {
			common[id] = true
		}
	}
	return common
}

func union(a, b map[string]bool) map[string]bool {
	if a == nil || b == nil {
		return nil
	}
	out := map[string]bool{}
	for id := range a {
		out[id] = true
	}
	for id := range b {
		out[id] = true
	}
	return out
}

// Attenuates reports whether every scope in narrow is within wide, decided
// per resource rather than by comparing rendered rows: for each (kind, owner,
// action) narrow names, every resource it selects must be selected by some row
// of wide of that kind, holding that action (or AnyAction), and naming the
// same owner or none. A whole kind is within only a whole kind; an owner-blind
// row is within only an owner-blind row; AnyAction in narrow is within only
// AnyAction in wide.
func Attenuates(narrow, wide []*basev0.WorkScopeV1) bool {
	held := coverageOf(wide)
	for k, acts := range coverageOf(narrow) {
		for act, ids := range acts {
			if !covered(held, k, act, ids) {
				return false
			}
		}
	}
	return true
}

// covered: every resource ids selects (nil: the whole kind) is held for act at
// k, by rows naming k's owner or no owner and holding act or AnyAction.
func covered(held coverage, k key, act string, ids map[string]bool) bool {
	owners, actions := []string{""}, []string{AnyAction}
	if k.owner != "" {
		owners = append(owners, k.owner)
	}
	if act != AnyAction {
		actions = append(actions, act)
	}
	var selections []map[string]bool
	for _, owner := range owners {
		for _, a := range actions {
			heldIDs, ok := held[key{k.kind, owner}][a]
			if !ok {
				continue
			}
			if heldIDs == nil {
				return true
			}
			selections = append(selections, heldIDs)
		}
	}
	if ids == nil {
		return false
	}
	for id := range ids {
		if !slices.ContainsFunc(selections, func(s map[string]bool) bool { return s[id] }) {
			return false
		}
	}
	return true
}

// Same reports whether two normalized scope lists are equal row for row,
// owners included: two rows differing only in their owner are not the same.
func Same(a, b []*basev0.WorkScopeV1) bool {
	return slices.EqualFunc(a, b, func(x, y *basev0.WorkScopeV1) bool { return proto.Equal(x, y) })
}

// Owned is scopes selecting only owner's resources: the shape every scope a
// solution's role grants takes, on the data its principal owns. An empty owner
// would select every owner's resources, so it is refused, never rendered.
func Owned(scopes []*basev0.WorkScopeV1, owner string) ([]*basev0.WorkScopeV1, error) {
	if owner == "" {
		return nil, errors.New("scope: an owner-selected scope names its owner; an empty owner would select every owner's resources")
	}
	out := make([]*basev0.WorkScopeV1, 0, len(scopes))
	for _, sc := range scopes {
		c := proto.CloneOf(sc)
		c.ResourceOwnerId = owner
		out = append(out, c)
	}
	return Normalize(out), nil
}

// HoldsAction reports whether held carries action on any resource of kind,
// whatever its ids or owner: a vocabulary check, never resource admission.
func HoldsAction(held []*basev0.WorkScopeV1, kind, action string) bool {
	return slices.ContainsFunc(held, func(h *basev0.WorkScopeV1) bool {
		return h.GetResourceKind() == kind && (slices.Contains(h.GetActions(), action) || slices.Contains(h.GetActions(), AnyAction))
	})
}

// HasOwner reports whether any scope selects a resource owner.
func HasOwner(scopes []*basev0.WorkScopeV1) bool {
	return slices.ContainsFunc(scopes, func(s *basev0.WorkScopeV1) bool { return s.GetResourceOwnerId() != "" })
}

// Unowned is scopes with their owner dropped: what a kind and its actions
// look like whatever owns them, for a vocabulary comparison only.
func Unowned(scopes []*basev0.WorkScopeV1) []*basev0.WorkScopeV1 {
	out := make([]*basev0.WorkScopeV1, 0, len(scopes))
	for _, sc := range scopes {
		out = append(out, &basev0.WorkScopeV1{ResourceKind: sc.GetResourceKind(), Actions: slices.Clone(sc.GetActions())})
	}
	return Normalize(out)
}
