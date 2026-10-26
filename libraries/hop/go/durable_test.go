package hop_test

import (
	"context"
	"errors"
	"testing"

	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"github.com/codefly-dev/authority/libraries/hop/go/replaypg"
	"github.com/codefly-dev/core/resources"
	core "github.com/codefly-dev/core/workcontext"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type insertingPool struct{}

func (insertingPool) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func (insertingPool) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

// Review r164 B1: the contract forbids a per-replica replay store outside a
// local run, but nothing refused one. A hand-written path to per-pod storage,
// or Core's in-memory store, passed and let a captured admission replay once
// per replica inside its window. The verifier refuses it at startup now.
func TestAReplayStoreThatIsNotSharedIsRefusedOutsideALocalRun(t *testing.T) {
	a := hoptest.New(t)
	postgres, err := replaypg.New(insertingPool{})
	if err != nil {
		t.Fatal(err)
	}
	directory, err := hop.NewFileReplayStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mount, err := hop.NewSharedFileReplayStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	build := func(store core.ReplayStore) error {
		_, err := hop.NewVerifier(context.Background(), a.PublishHop(proof), "documents", store)
		return err
	}

	// A laptop and a test keep working with any store, including Core's
	// in-memory one, only under the exact local environment name.
	for _, environment := range []string{"local"} {
		t.Setenv(resources.EnvironmentPrefix, environment)
		for name, store := range map[string]core.ReplayStore{
			"in-memory": hoptest.Replay(), "a directory": directory,
			"a shared mount": mount, "postgres": postgres,
		} {
			if err := build(store); err != nil {
				t.Fatalf("environment %q refused %s: %v", environment, name, err)
			}
		}
	}

	for _, environment := range []string{"", "staging", "production", "local-docker", "local-production", " local", "local "} {
		t.Setenv(resources.EnvironmentPrefix, environment)
		for name, store := range map[string]core.ReplayStore{
			"in-memory": hoptest.Replay(), "a directory not stated to be shared": directory,
		} {
			if err := build(store); !errors.Is(err, hop.ErrReplayStoreNotShared) {
				t.Fatalf("environment %q admitted %s: %v", environment, name, err)
			}
		}
		// A store that states it is the one every replica shares is admitted.
		for name, store := range map[string]core.ReplayStore{
			"postgres": postgres, "a mount stated to be shared": mount,
		} {
			if err := build(store); err != nil {
				t.Fatalf("environment %q refused %s: %v", environment, name, err)
			}
		}
	}
}
