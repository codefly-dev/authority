package issuer

import (
	"sort"

	"gateway/pkg/business/state"
	base "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/protobuf/proto"
)

// scopeLimits are lasting bounds on visited kinds. A zero-action scope is an
// explicit denial; an absent kind has not been constrained. Never normalize the
// entire set through the grant helpers, which intentionally omit empty grants.
type scopeLimits map[string][]*base.WorkScopeV1

func parentScopeLimits(parent *base.WorkContextV1) scopeLimits {
	sets := [][]*base.WorkScopeV1{parent.GetAuthorityScopes()}
	for _, actor := range parent.GetActorChain() {
		sets = append(sets, actor.GetGrantedScopes())
	}
	limits := scopeLimits{}
	for _, scopes := range sets {
		for kind, rows := range scopesByKind(scopes) {
			if previous, ok := limits[kind]; ok {
				limits[kind] = state.Intersect(previous, rows)
			} else {
				limits[kind] = rows
			}
		}
	}
	return limits
}

func (limits scopeLimits) constrain(scopes []*base.WorkScopeV1) []*base.WorkScopeV1 {
	var out []*base.WorkScopeV1
	for _, scope := range scopes {
		if bound, ok := limits[scope.GetResourceKind()]; ok {
			out = append(out, state.Intersect([]*base.WorkScopeV1{scope}, bound)...)
		} else {
			out = append(out, scope)
		}
	}
	return out
}

// project updates only the current binding's kinds, retaining other audience
// caps. An omitted or disjoint target kind stays explicitly denied downstream.
func (limits scopeLimits) project(domain, granted []*base.WorkScopeV1) []*base.WorkScopeV1 {
	for _, scope := range domain {
		limits[scope.GetResourceKind()] = nil
	}
	for kind, rows := range scopesByKind(granted) {
		limits[kind] = rows
	}
	out := make([]*base.WorkScopeV1, 0, len(limits))
	kinds := make([]string, 0, len(limits))
	for kind := range limits {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		rows := state.Normalize(limits[kind])
		if len(rows) == 0 {
			rows = []*base.WorkScopeV1{{ResourceKind: kind}}
		}
		out = append(out, rows...)
	}
	return out
}

// Keep every action/resource row together. Combining their actions and ids
// separately would authorize the cross product; keeping only one loses grants.
func scopesByKind(scopes []*base.WorkScopeV1) scopeLimits {
	grouped := scopeLimits{}
	for _, scope := range scopes {
		kind := scope.GetResourceKind()
		grouped[kind] = append(grouped[kind], proto.CloneOf(scope))
	}
	return grouped
}
