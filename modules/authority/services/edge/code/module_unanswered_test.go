package main

import (
	"bytes"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A module the edge cannot reach did not answer: the caller is told that, and
// not the transport error, which names the module's internal address. The
// edge's log is told the error.
func TestAModuleTheEdgeCannotReachKeepsItsAddressInTheLog(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := closed.Addr().String()
	_ = closed.Close()
	target, _ := url.Parse("http://" + address)

	var logged bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(previous) })

	rec := httptest.NewRecorder()
	proxy(target, "", "", rec, httptest.NewRequest(http.MethodGet, "/v1/documents", nil))
	if rec.Code != http.StatusBadGateway || rec.Body.String() != "{\"error\":\"the module did not answer\"}\n" {
		t.Fatalf("the caller was told %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(logged.String(), address) {
		t.Fatalf("the edge's log was told %q", logged.String())
	}
}
