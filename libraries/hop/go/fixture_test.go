package hop

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/metadata"
)

var updateFixture = flag.Bool("update-fixture", false, "rewrite ../testdata/stamped.json")

// The stamp's one contract, for every language a module is written in: the
// headers this hop writes for one call, which the Python reader
// (../python) reads back in its own tests.
func TestTheStampFixtureIsWhatTheHopWrites(t *testing.T) {
	md := metadata.Pairs(WorkContextKey, "eyJ3YyI6ImZpeHR1cmUifQ.c2lnbmF0dXJl")
	Stamp(md, Identity{Owner: "remi", OwnerKind: "human", Tenant: "acme", Actors: []string{"robin"}, Scopes: []string{"modelservice.profiles:read", "modelservice.profiles:invoke"}, Binding: "acme/robin/model"}, "fixture-proof")
	headers := map[string]string{}
	for key, values := range md {
		headers[key] = values[0]
	}
	want, err := json.MarshalIndent(map[string]any{"proof": "fixture-proof", "headers": headers}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	path := filepath.Join("..", "testdata", "stamped.json")
	if *updateFixture {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(want) {
		t.Fatalf("%s is not what the hop writes; regenerate with -update-fixture: %v", path, err)
	}
}
