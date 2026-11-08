package decide_test

import (
	"fmt"
	"maps"
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// denseComposition is the review's synthetic shape: a solution and
// modules-1 modules over kinds kinds, each serving most of them, five
// operations per module, two roles, and about half of every possible
// binding, cycles and self-bindings included.
func denseComposition(seed int64, modules, kinds int) (domain.Module, []domain.Module) {
	r := rand.New(rand.NewSource(seed))
	actions := []string{"read", "write", "admin"}
	some := func() []*basev0.WorkScopeV1 {
		var out []*basev0.WorkScopeV1
		for k := 0; k < kinds; k++ {
			var acts []string
			for _, a := range actions {
				if r.Intn(2) == 0 {
					acts = append(acts, a)
				}
			}
			if len(acts) > 0 && r.Intn(4) > 0 {
				out = append(out, rs(fmt.Sprintf("data.k%d", k), acts...))
			}
		}
		if len(out) == 0 {
			out = append(out, rs("data.k0", "read"))
		}
		return out
	}
	var out []domain.Module
	for i := 0; i < modules; i++ {
		name := fmt.Sprintf("m%d", i)
		m := domain.Module{Name: name, Principal: name, Kind: domain.KindModule, ResourceKinds: some(),
			Bindings: map[string]domain.Binding{}, Methods: map[string]domain.MethodPolicy{}}
		for j := 0; j < 5; j++ {
			m.Methods[fmt.Sprintf("/%s.v1.S/Op%d", name, j)] = domain.MethodPolicy{Requires: some()}
		}
		for o := 0; o < modules; o++ {
			if r.Intn(2) == 0 {
				id := fmt.Sprintf("to-m%d", o)
				m.Bindings[id] = domain.Binding{ID: id, Audience: fmt.Sprintf("m%d", o), InvokeScopes: some(), LookupScopes: some()[:1]}
			}
		}
		if i == 0 {
			m.Kind, m.Roles = domain.KindSolution, map[string][]*basev0.WorkScopeV1{"editor": some(), "viewer": some()}
		}
		out = append(out, m)
	}
	return out[0], out
}

func benchmarkReachOf(b *testing.B, modules, kinds int) {
	target, all := denseComposition(1, modules, kinds)
	for b.Loop() {
		if _, err := decide.ReachOf(target, all); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReachOf8Modules5Kinds(b *testing.B)   { benchmarkReachOf(b, 8, 5) }
func BenchmarkReachOf12Modules6Kinds(b *testing.B)  { benchmarkReachOf(b, 12, 6) }
func BenchmarkReachOf16Modules8Kinds(b *testing.B)  { benchmarkReachOf(b, 16, 8) }
func BenchmarkReachOf32Modules10Kinds(b *testing.B) { benchmarkReachOf(b, 32, 10) }

// ReachOf runs inside a delivery's write transaction, a review and an
// install: on dense compositions it stays within milliseconds, whatever
// the seed.
func TestReachOfIsFastOnDenseCompositions(t *testing.T) {
	for _, shape := range [][2]int{{8, 5}, {12, 6}, {16, 8}, {32, 10}} {
		for seed := int64(1); seed <= 5; seed++ {
			target, all := denseComposition(seed, shape[0], shape[1])
			start := time.Now()
			reach, err := decide.ReachOf(target, all)
			if err != nil {
				t.Fatal(err)
			}
			if took := time.Since(start); took > 250*time.Millisecond {
				t.Fatalf("%d modules, %d kinds, seed %d: ReachOf took %v (roles %v)", shape[0], shape[1], seed, took, slices.Sorted(maps.Keys(reach)))
			}
		}
	}
}
