package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"hop/pkg/business/decide"
	"hop/pkg/infra/proxy"
)

// This is a hermetic transport probe, not a replacement module or playground.
// A routing failure may be reported, but a Records request must never go to
// Documents merely because its name sorts first in the hop's module list.
func TestWarnModeDoesNotSendRecordsToDocuments(t *testing.T) {
	var documentsCalls atomic.Int32
	documents := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		documentsCalls.Add(1)
		http.Error(w, "documents does not serve RecordsService", http.StatusNotFound)
	}))
	defer documents.Close()
	records := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"record":{}}`))
	}))
	defer records.Close()
	docsURL, _ := url.Parse(documents.URL)
	recordsURL, _ := url.Parse(records.URL)
	decision := decide.Decider{Permissive: true, Modules: map[string]bool{"documents": true, "records": true}}
	face := proxy.HTTP{Proof: "test-run-proof", Decide: decision.Decide,
		Connect: map[string]*url.URL{"documents": docsURL, "records": recordsURL}}
	req := httptest.NewRequest(http.MethodPost, "/records.v1.RecordsService/ReadRecord", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	face.ServeHTTP(response, req)
	if documentsCalls.Load() != 0 {
		t.Fatalf("Records request reached Documents %d time(s): HTTP %d, body %q", documentsCalls.Load(), response.Code, response.Body.String())
	}
}
