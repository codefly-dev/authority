package main

import (
	"os"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/hop/go/replaypg"
)

// The console's store carries the table the adapter writes to. Two copies of
// one DDL drift, so this is the one that fails when they do: the migration is
// what the store runs, replaypg.Migration is what a module without a migration
// pipeline embeds, and they must stay the same table.
func TestTheStoreMigrationCarriesTheAdaptersTable(t *testing.T) {
	const path = "../../store/migrations/1_hop_admissions.up.sql"
	migration, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(migration), replaypg.Migration) {
		t.Fatalf("%s no longer carries replaypg.Migration:\n%s", path, replaypg.Migration)
	}
	// The verifier reserves, reads back and collects; it never updates, because
	// a refreshed reservation would let a replay extend its own window.
	grant := "GRANT SELECT, INSERT, DELETE ON hop_admissions TO app_console;"
	if !strings.Contains(string(migration), grant) {
		t.Fatalf("%s does not grant exactly %q", path, grant)
	}
	if strings.Contains(string(migration), "UPDATE ON hop_admissions") {
		t.Fatalf("%s grants UPDATE on the reservations", path)
	}
}
