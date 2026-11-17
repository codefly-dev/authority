package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A call to a procedure no module of the composition serves is nobody's to
// refuse: no person was judged and no permission is missing. A Connect caller
// is answered unimplemented, never permission denied, which its client would
// read as a decision about the person; any other caller keeps the plain 404.
// Nothing is asked of the authority and nothing reaches a module.
func TestACallNoModuleServesIsUnimplementedNotPermissionDenied(t *testing.T) {
	f := newFixture(t)
	cookie := f.signIn(t)
	speaksConnect := http.Header{"Cookie": {cookie.String()}, "Origin": {f.edge.URL}, "Content-Type": {"application/json"}, "Connect-Protocol-Version": {"1"}}
	plain := http.Header{"Cookie": {cookie.String()}, "Origin": {f.edge.URL}}
	const unrouted = "/api/solutions/org-directory/proxy/_browser/nothing.v1.Service/Read"

	res, body := f.do(t, http.MethodPost, unrouted, speaksConnect)
	if res.StatusCode != http.StatusNotImplemented || !strings.Contains(body, `"code":"unimplemented"`) || !strings.Contains(body, "no module serves /nothing.v1.Service/Read") {
		t.Fatalf("a Connect call no module serves answered %d: %s", res.StatusCode, body)
	}
	if strings.Contains(body, "permission_denied") {
		t.Fatalf("a call no module serves was answered as a denial of the person: %s", body)
	}
	if res, body := f.do(t, http.MethodPost, unrouted, plain); res.StatusCode != http.StatusNotFound || !strings.Contains(body, "no module serves /nothing.v1.Service/Read") {
		t.Fatalf("a plain call no module serves answered %d: %s", res.StatusCode, body)
	}
	// A module named for REST alone serves no procedure either.
	if res, body := f.do(t, http.MethodPost, "/api/solutions/org-directory/proxy/_browser/secrets.v1.SecretsService/Read", speaksConnect); res.StatusCode != http.StatusNotImplemented || !strings.Contains(body, `"code":"unimplemented"`) {
		t.Fatalf("a Connect call to a module with no Connect face answered %d: %s", res.StatusCode, body)
	}
	if len(f.authority.issued) != 0 || len(f.connect.path) != 0 || len(f.rest.path) != 0 || len(f.secrets.path) != 0 {
		t.Fatalf("a call no module serves reached the authority (%v) or a module", f.authority.issued)
	}

	// With no frontend to serve what no module claims, the same holds off the
	// page route.
	e := &Edge{Sessions: f.authority, Authority: f.authority, Modules: map[string]Module{"records": {Name: "records", Connect: mustURL(t, f.connect.URL), Services: []string{"records.v1.RecordsService"}}}}
	req := httptest.NewRequest(http.MethodPost, "/nothing.v1.Service/Read", strings.NewReader("{}"))
	for name, values := range speaksConnect {
		req.Header[name] = values
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented || !strings.Contains(rec.Body.String(), `"code":"unimplemented"`) {
		t.Fatalf("with no frontend, a Connect call no module serves answered %d: %s", rec.Code, rec.Body)
	}

	// The refusals that are a decision keep their code.
	if res, body := f.do(t, http.MethodPost, "/records.v1.RecordsService/List", http.Header{"Content-Type": {"application/json"}, "Connect-Protocol-Version": {"1"}}); res.StatusCode != http.StatusUnauthorized || !strings.Contains(body, `"code":"unauthenticated"`) {
		t.Fatalf("a call with no session answered %d: %s", res.StatusCode, body)
	}
}
