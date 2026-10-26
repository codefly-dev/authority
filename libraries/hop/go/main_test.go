package hop_test

import (
	"os"
	"testing"
)

// TestMain runs this package's tests in the local run: most stand up a verifier
// on a process-local store, which only the run named exactly "local" may use.
// A test of the startup guard or over Postgres sets its own environment.
func TestMain(m *testing.M) {
	_ = os.Setenv("CODEFLY__ENVIRONMENT", "local")
	os.Exit(m.Run())
}
