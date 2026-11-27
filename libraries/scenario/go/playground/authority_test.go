//go:build composition

package playground_test

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/scenario/go"
)

var composed *scenario.Composition

func TestMain(m *testing.M) {
	os.Exit(scenario.Main(m, &composed, scenario.Options{
		Anchor:                "../../../../playground/modules/authority-playground/services/scenarios",
		Scope:                 "authority-scenarios",
		Seated:                []string{"org-directory"},
		Without:               []string{"documents/docx", "documents/pdf", "documents/libreoffice", "documents/xlsx", "documents/documents"},
		WithoutConfigurations: []string{"document-formats"},
	}))
}

func TestTheEdgeAndHopRespectTheFixtureSeats(t *testing.T) {
	const page = "org-directory"
	read := scenario.Call{Page: page, Procedure: "directory.v1.DirectoryService/GetEmployees"}
	// Directory defines its record types after its listener opens. Wait only
	// for that dependency to serve this read before checking every seat.
	admin := composed.As(t, "dana")
	deadline := time.Now().Add(time.Minute)
	for {
		out := admin.Do(t, read)
		if out.Status != http.StatusServiceUnavailable || out.Code != "unavailable" {
			if out.Verdict != scenario.Allowed {
				t.Fatalf("Directory readiness: %s (%d): %s", out.Code, out.Status, out.Reason)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Directory remained unavailable: %s", out.Reason)
		}
		time.Sleep(250 * time.Millisecond)
	}
	composed.Check(t,
		scenario.Row{Name: "the session lists the page a person holds", Call: scenario.Session,
			Want: scenario.Want{"dana": scenario.Allow.And(scenario.Uses(page)), "carol": scenario.Allow.And(scenario.Uses(page)), "bob": scenario.Allow.And(scenario.UsesNothing)}},
		scenario.Row{Name: "the page may read only for its members", Call: read,
			Want: scenario.Want{"dana": scenario.Allow, "carol": scenario.Allow, "bob": scenario.Deny("holds no role")}},
	)
}
