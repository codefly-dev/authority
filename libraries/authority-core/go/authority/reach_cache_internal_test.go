package authority

import (
	"fmt"
	"testing"
)

// The reach cache keeps at most its size, evicting the oldest first; an
// entry put again is not duplicated and keeps its place.
func TestTheReachCacheIsBounded(t *testing.T) {
	c := reachCache{size: 3}
	for i := 0; i < 5; i++ {
		c.put(fmt.Sprint(i), reachIndex{fmt.Sprint(i): nil})
	}
	c.put("4", reachIndex{})
	if len(c.byKey) != 3 || len(c.order) != 3 {
		t.Fatalf("the cache holds %d entries (%d in order), want 3", len(c.byKey), len(c.order))
	}
	for _, evicted := range []string{"0", "1"} {
		if _, ok := c.get(evicted); ok {
			t.Fatalf("%s was not evicted", evicted)
		}
	}
	for _, kept := range []string{"2", "3", "4"} {
		if index, ok := c.get(kept); !ok || index[kept] != nil || len(index) != 1 {
			t.Fatalf("%s is not kept as first put: %v %v", kept, index, ok)
		}
	}
	var unsized reachCache
	for i := 0; i < reachCacheSize+10; i++ {
		unsized.put(fmt.Sprint(i), reachIndex{})
	}
	if len(unsized.byKey) != reachCacheSize {
		t.Fatalf("the default cache holds %d, want %d", len(unsized.byKey), reachCacheSize)
	}
}
