package scope_test

import (
	"math/rand/v2"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The reference model: a scope list is the set of points (kind, owner,
// action, id) it covers. Each dimension's universe holds the values the
// generator draws plus one it never draws (an unseen owner, action and id),
// so a whole kind, an owner-blind row and AnyAction each cover something no
// narrower row does, exactly as they do for real.
var (
	kinds   = []string{"doc", "note"}
	owners  = []string{"u", "v", "unseen-owner"}
	actions = []string{"read", "write", "unseen-action"}
	ids     = []string{"x", "y", "unseen-id"}
)

type point struct{ kind, owner, action, id string }

func points(scopes []*basev0.WorkScopeV1) map[point]bool {
	out := map[point]bool{}
	for _, sc := range scopes {
		for _, owner := range owners {
			if sc.GetResourceOwnerId() != "" && sc.GetResourceOwnerId() != owner {
				continue
			}
			for _, act := range actions {
				holds := false
				for _, a := range sc.GetActions() {
					holds = holds || a == act || a == scope.AnyAction
				}
				if !holds {
					continue
				}
				for _, id := range ids {
					named := len(sc.GetResourceIds()) == 0
					for _, r := range sc.GetResourceIds() {
						named = named || r == id
					}
					if named {
						out[point{sc.GetResourceKind(), owner, act, id}] = true
					}
				}
			}
		}
	}
	return out
}

func within(a, b map[point]bool) bool {
	for p := range a {
		if !b[p] {
			return false
		}
	}
	return true
}

func randomScopes(r *rand.Rand) []*basev0.WorkScopeV1 {
	var out []*basev0.WorkScopeV1
	for range r.IntN(4) {
		sc := &basev0.WorkScopeV1{ResourceKind: kinds[r.IntN(len(kinds))]}
		if r.IntN(2) == 0 {
			sc.ResourceOwnerId = owners[r.IntN(2)]
		}
		for _, a := range []string{"read", "write", scope.AnyAction} {
			if r.IntN(3) == 0 {
				sc.Actions = append(sc.Actions, a)
			}
		}
		if len(sc.Actions) == 0 {
			sc.Actions = []string{"read"}
		}
		if r.IntN(2) == 0 {
			for _, id := range []string{"x", "y"} {
				if r.IntN(2) == 0 {
					sc.ResourceIds = append(sc.ResourceIds, id)
				}
			}
		}
		out = append(out, sc)
	}
	return out
}

// Attenuates answers exactly what the model answers, owned and owner-blind
// rows mixed, AnyAction included: no false yes (a widening) and no false no
// (a legitimate ask refused).
func TestAttenuatesMatchesTheReferenceModel(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for n := range 200000 {
		narrow, wide := randomScopes(r), randomScopes(r)
		want := within(points(narrow), points(wide))
		if got := scope.Attenuates(narrow, wide); got != want {
			t.Fatalf("case %d: Attenuates(%v, %v) = %v, the model says %v", n, narrow, wide, got, want)
		}
	}
}

// Intersect covers exactly the points both sides cover, so an exact row never
// hides an AnyAction row and a repeated row adds to the answer.
func TestIntersectMatchesTheReferenceModel(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for n := range 200000 {
		a, b := randomScopes(r), randomScopes(r)
		got, inA, inB := points(scope.Intersect(a, b)), points(a), points(b)
		for p := range got {
			if !inA[p] || !inB[p] {
				t.Fatalf("case %d: Intersect(%v, %v) covers %v, outside one side", n, a, b, p)
			}
		}
		for p := range inA {
			if inB[p] && !got[p] && p.action != "unseen-action" {
				t.Fatalf("case %d: Intersect(%v, %v) drops %v, which both sides cover", n, a, b, p)
			}
		}
	}
}

func TestTheCasesTheModelFound(t *testing.T) {
	read := []string{"read"}
	// The ask equals one held row beside an owned row of the same kind.
	if !scope.Attenuates([]*basev0.WorkScopeV1{sc("doc", "", read)}, []*basev0.WorkScopeV1{sc("doc", "", read), sc("doc", "u", read)}) {
		t.Fatal("an ask equal to a held row is refused")
	}
	// An exact row does not hide a wider AnyAction row of the same kind.
	got := scope.Intersect([]*basev0.WorkScopeV1{sc("doc", "", read)}, []*basev0.WorkScopeV1{sc("doc", "", read, "x"), sc("doc", "", []string{scope.AnyAction})})
	if len(got) != 1 || len(got[0].GetResourceIds()) != 0 {
		t.Fatalf("the exact row hid AnyAction: %v", got)
	}
	// A repeated row adds to the answer: ids x and y from two rows.
	got = scope.Intersect([]*basev0.WorkScopeV1{sc("doc", "", read)}, []*basev0.WorkScopeV1{sc("doc", "", read, "x"), sc("doc", "", read, "y")})
	if len(got) != 1 || len(got[0].GetResourceIds()) != 2 {
		t.Fatalf("repeated rows met as %v, want their union", got)
	}
	// Same compares owners: one row owned by u and one by v are not the same.
	if scope.Same([]*basev0.WorkScopeV1{sc("doc", "u", read)}, []*basev0.WorkScopeV1{sc("doc", "v", read)}) {
		t.Fatal("two owners are the same")
	}
	if !scope.Same([]*basev0.WorkScopeV1{sc("doc", "u", read)}, []*basev0.WorkScopeV1{sc("doc", "u", read)}) {
		t.Fatal("one owner is not the same as itself")
	}
}
