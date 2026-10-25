package routing

import (
	"encoding/json"
	"strings"
	"testing"
)

func endpoint(service, transport string, methods ...string) RouteEndpoint {
	return RouteEndpoint{Audience: "module", Service: service, Endpoint: transport,
		Transport: transport, Address: "${endpoint:module/" + service + "/" + transport + "}",
		Package: "owner/module", Version: "v1", Digest: "sha256:contract", Methods: methods}
}

func TestPublishedListenersStayDistinct(t *testing.T) {
	routes := Routing{Schema: RoutingSchema, Endpoints: []RouteEndpoint{
		endpoint("first", "grpc", "/first.Service/Call"),
		endpoint("second", "grpc", "/second.Service/Call"),
		endpoint("first", "connect", "/first.Service/Call"),
		endpoint("web", "http", "GET /first.Service/Call", "POST /ordinary.Service/Call", "POST /items/{id}:publish", "GET /files/{name=**}:read"),
	}}
	if err := routes.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ transport, method, service string }{
		{"grpc", "/first.Service/Call", "first"},
		{"grpc", "/second.Service/Call", "second"},
		{"http", "POST /first.Service/Call", "first"},
		{"http", "GET /first.Service/Call", "web"},
		{"http", "POST /ordinary.Service/Call", "web"},
		{"http", "POST /items/a:publish", "web"},
		{"http", "GET /files/a/b:read", "web"},
	} {
		got, err := routes.Find("module", tc.transport, tc.method)
		if err != nil || got.Service != tc.service {
			t.Fatalf("%s: %+v %v", tc.method, got, err)
		}
	}
	for _, tc := range []struct{ audience, transport, method string }{
		{"other", "grpc", "/first.Service/Call"},
		{"module", "grpc", "/imported.Service/Call"},
		{"module", "http", "POST /second.Service/Call"},
		{"module", "http", "DELETE /items/a:publish"},
		{"module", "http", "POST /items/:publish"},
		{"module", "http", "GET /files/:read"},
	} {
		if got, err := routes.Find(tc.audience, tc.transport, tc.method); err == nil {
			t.Fatalf("unexpected route: %+v", got)
		}
	}
}

func TestAmbiguousPublicationAndTemplatesRefuse(t *testing.T) {
	for _, second := range []RouteEndpoint{
		endpoint("second", "grpc", "/first.Service/Call"),
		endpoint("first", "grpc", "/other.Service/Call"),
	} {
		routes := Routing{Schema: RoutingSchema, Endpoints: []RouteEndpoint{endpoint("first", "grpc", "/first.Service/Call"), second}}
		if err := routes.Validate(); err == nil {
			t.Fatal("ambiguous inventory accepted")
		}
	}
	routes := Routing{Schema: RoutingSchema, Endpoints: []RouteEndpoint{
		endpoint("connect", "connect", "/first.Service/Call"), endpoint("web", "http", "POST /first.Service/Call"),
	}}
	if err := routes.Validate(); err == nil {
		t.Fatal("HTTP/Connect collision accepted")
	}
	routes.Endpoints = []RouteEndpoint{endpoint("first", "http", "GET /items/{id}"), endpoint("second", "http", "GET /items/{name}")}
	if err := routes.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := routes.Find("module", "http", "GET /items/one"); err == nil {
		t.Fatal("overlapping templates selected a listener")
	}
	routes.Endpoints = append(routes.Endpoints, endpoint("literal", "http", "GET /items/one"))
	got, err := routes.Find("module", "http", "GET /items/one")
	if err != nil || got.Service != "literal" {
		t.Fatalf("exact admission precedence: %+v %v", got, err)
	}
}

func TestDecodeAndResolvedAddressRefuseInvalidInput(t *testing.T) {
	routes := Routing{Schema: RoutingSchema, Endpoints: []RouteEndpoint{endpoint("first", "grpc", "/first.Service/Call")}}
	raw, err := json.Marshal(routes)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{string(raw) + " {}", strings.Replace(string(raw), `"schema":`, `"unknown":true,"schema":`, 1), `{}`, `null`} {
		if _, err := DecodeRouting(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	if _, err := DecodeRouting(string(raw)); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"${endpoint:module/first/http}", "ftp://host", "http://user:pass@host", "http://host?override=true", "http://host#fragment", "host"} {
		if _, err := (RouteEndpoint{Address: address}).ResolvedURL(); err == nil {
			t.Fatalf("accepted %s", address)
		}
	}
	if _, err := (RouteEndpoint{Address: "http://resolved.example"}).ResolvedURL(); err != nil {
		t.Fatal(err)
	}
}
