package hop_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hop "github.com/codefly-dev/authority/libraries/hop/go"
)

func TestReplayReservationIsAtomicAcrossInstancesAndSurvivesRestart(t *testing.T) {
	directory := t.TempDir()
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for n := 0; n < 32; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store, err := hop.NewFileReplayStore(directory)
			if err != nil {
				t.Error(err)
				return
			}
			if store.Consume(context.Background(), "same-call", time.Now().Add(time.Minute)) == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d calls, want one", accepted.Load())
	}
	restarted, err := hop.NewFileReplayStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Consume(context.Background(), "same-call", time.Now().Add(time.Minute)) == nil {
		t.Fatal("replayed after restart")
	}
}
