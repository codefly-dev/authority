package forward

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"github.com/codefly-dev/core/wool"
)

// logged keeps what a wool logger is told.
type logged struct{ lines []*wool.Log }

func (l *logged) Process(line *wool.Log) { l.lines = append(l.lines, line) }

// forwarded is a hop line as the run shows it: the run forwards the hop's
// output through its own logger, which redacts any line whose label (the
// text before its first "=" or ":") reads as a credential's.
func forwarded(t *testing.T, line *wool.Log) string {
	t.Helper()
	run := &logged{}
	wool.Get(context.Background()).WithLogger(run).Info(line.String())
	if len(run.lines) != 1 {
		t.Fatalf("the run logged %d lines", len(run.lines))
	}
	return run.lines[0].Message
}

// Review #28 F4: the registration log names the published key by its id, and
// a refusal by its reason, and both survive the run's redaction; they never
// name the seed. "the authority publishes this hop's admission key
// admission=hop-…" reached the run as "admission=****".
func TestTheRegistrationLogNamesTheKeyIDThroughTheRunsRedaction(t *testing.T) {
	hop := &logged{}
	report := registrationReport(wool.Get(context.Background()).In("hop").WithLogger(hop))
	seed := strings.Repeat("ab", 32)
	signer, err := stamp.NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	id, public := signer.Admission()
	lapses := time.Date(2026, 10, 26, 19, 30, 0, 0, time.UTC)
	report(&authorityv1.PublicKey{KeyId: id, PublicKey: public}, lapses, nil)
	report(nil, time.Time{}, errors.New("rpc error: code = PermissionDenied desc = the registration proof is stale"))
	if len(hop.lines) != 2 {
		t.Fatalf("the hop logged %d lines", len(hop.lines))
	}
	published := forwarded(t, hop.lines[0])
	if !strings.Contains(published, id) || !strings.Contains(published, "2026-10-26T19:30:00Z") || strings.Contains(published, "****") {
		t.Fatalf("the run shows %q, not the key id %s and its lapse", published, id)
	}
	refused := forwarded(t, hop.lines[1])
	if !strings.Contains(refused, "the registration proof is stale") || strings.Contains(refused, "****") {
		t.Fatalf("the run shows %q, not the refusal's reason", refused)
	}
	for _, line := range hop.lines {
		if strings.Contains(line.String(), seed) || strings.Contains(line.String(), signer.PublicKey()) {
			t.Fatalf("the hop logged key material: %s", line.String())
		}
	}
}
