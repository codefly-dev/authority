package scope

import (
	"sort"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/protobuf/proto"
)

// Limits are lasting bounds on visited kinds, read from a parent capability:
// a narrowing is never recovered by a later hop. A zero-action row is an
// explicit denial; an absent kind has not been constrained.
type Limits map[string][]*basev0.WorkScopeV1

// ParentLimits reads every kind the parent's authority and hops constrained.
func ParentLimits(parent *basev0.WorkContextV1) Limits {
	sets := [][]*basev0.WorkScopeV1{parent.GetAuthorityScopes()}
	for _, actor := range parent.GetActorChain() {
		sets = append(sets, actor.GetGrantedScopes())
	}
	limits := Limits{}
	for _, scopes := range sets {
		for kind, rows := range byKind(scopes) {
			if previous, ok := limits[kind]; ok {
				limits[kind] = Intersect(previous, rows)
			} else {
				limits[kind] = rows
			}
		}
	}
	return limits
}

// Constrain cuts each scope of a constrained kind to its limit.
func (limits Limits) Constrain(scopes []*basev0.WorkScopeV1) []*basev0.WorkScopeV1 {
	var out []*basev0.WorkScopeV1
	for _, sc := range scopes {
		if bound, ok := limits[sc.GetResourceKind()]; ok {
			out = append(out, Intersect([]*basev0.WorkScopeV1{sc}, bound)...)
		} else {
			out = append(out, sc)
		}
	}
	return out
}

// Project updates only the current binding's kinds, retaining other audience
// limits; an omitted or disjoint target kind stays explicitly denied.
func (limits Limits) Project(domain, granted []*basev0.WorkScopeV1) []*basev0.WorkScopeV1 {
	for _, sc := range domain {
		limits[sc.GetResourceKind()] = nil
	}
	for kind, rows := range byKind(granted) {
		limits[kind] = rows
	}
	kinds := make([]string, 0, len(limits))
	for kind := range limits {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	out := make([]*basev0.WorkScopeV1, 0, len(limits))
	for _, kind := range kinds {
		rows := Normalize(limits[kind])
		if len(rows) == 0 {
			rows = []*basev0.WorkScopeV1{{ResourceKind: kind}}
		}
		out = append(out, rows...)
	}
	return out
}

// byKind keeps every action/resource row of a kind together; combining their
// actions and ids separately would authorize the cross product.
func byKind(scopes []*basev0.WorkScopeV1) Limits {
	grouped := Limits{}
	for _, sc := range scopes {
		grouped[sc.GetResourceKind()] = append(grouped[sc.GetResourceKind()], proto.CloneOf(sc))
	}
	return grouped
}
