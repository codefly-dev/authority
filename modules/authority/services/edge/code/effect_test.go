package main

import (
	"net/http"
	"testing"

	"github.com/codefly-dev/sdk-go/receipts"
	"github.com/google/uuid"
)

// A module operation that keeps receipts requires an effect id on every call,
// and the edge forwards no x-codefly-* header a browser sent. So the edge
// mints one for each module call: a browser can't name an effect, and so can
// never replay another person's receipt, yet its call still reaches a guarded
// operation.
func TestEachModuleCallCarriesAnEffectIDTheEdgeMinted(t *testing.T) {
	f := newFixture(t)
	cookie := f.signIn(t)
	minted := func(seen http.Header) string {
		t.Helper()
		id := seen.Get(receipts.EffectIDHeaderName)
		if _, err := uuid.Parse(id); err != nil {
			t.Fatalf("the module received effect id %q: %v", id, err)
		}
		return id
	}
	// Idempotency-Key is the SDK's HTTP spelling of the same effect id: left in
	// place beside the minted one, it would be a second effect id, which the SDK
	// refuses before running the operation.
	if res, _ := f.do(t, http.MethodGet, "/v1/records/types", http.Header{"Cookie": {cookie.String()}, "X-Codefly-Effect-Id": {"forged"}, receipts.IdempotencyKeyHeaderName: {"forged"}}); res.StatusCode != http.StatusOK {
		t.Fatalf("answered %d", res.StatusCode)
	}
	seen, _ := f.rest.last()
	first := minted(seen)
	if first == "forged" || seen.Get(receipts.IdempotencyKeyHeaderName) != "" {
		t.Fatalf("the browser named the effect: %v", seen)
	}
	if res, _ := f.do(t, http.MethodGet, "/v1/records/types", http.Header{"Cookie": {cookie.String()}}); res.StatusCode != http.StatusOK {
		t.Fatalf("answered %d", res.StatusCode)
	}
	if seen, _ := f.rest.last(); minted(seen) == first {
		t.Fatal("two calls were minted one effect")
	}
	// The Connect face, by the service its path names.
	if res, _ := f.do(t, http.MethodPost, "/records.v1.RecordsService/Query", http.Header{"Cookie": {cookie.String()}, "Origin": {f.edge.URL}, receipts.IdempotencyKeyHeaderName: {"forged"}}); res.StatusCode != http.StatusOK {
		t.Fatalf("a Connect call answered %d", res.StatusCode)
	}
	if seen, _ := f.connect.last(); minted(seen) == first || seen.Get(receipts.IdempotencyKeyHeaderName) != "" {
		t.Fatalf("the Connect call reused an effect or kept the caller's: %v", seen)
	}
}
