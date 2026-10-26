package routing

import (
	"encoding/json"
	"errors"
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
		endpoint("second", "connect", "/first.Service/Call"),
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

func TestNonCanonicalPathsNeverMatchEvenAnExactInventory(t *testing.T) {
	for _, path := range []string{"/items/../secret", "/items/./x", "/items//x", "/items/%2e%2e/secret"} {
		if RouteMatches("/items/{tail=**}", path) {
			t.Fatalf("matched %s", path)
		}
		r := Routing{Endpoints: []RouteEndpoint{endpoint("web", "http", "GET "+path)}}
		if _, _, err := r.Resolve("module", "http", "GET "+path); err == nil {
			t.Fatalf("exact inventory accepted %s", path)
		}
	}
}

func TestConnectGRPCOverlapRefusesInEitherOrder(t *testing.T) {
	a, b := endpoint("a", "grpc", "/a.Service/Call"), endpoint("b", "connect", "/a.Service/Call")
	for _, endpoints := range [][]RouteEndpoint{{a, b}, {b, a}} {
		r := Routing{Schema: RoutingSchema, Endpoints: endpoints}
		if err := r.Validate(); err == nil {
			t.Fatal("ambiguous protocol publication accepted")
		}
	}
}

// Review r164 B2: a go-grpc service with rest-endpoint: true transcodes its
// REST face into the same listener the hop's verifier guards, so the hop's
// "VERB /path" admission can never match the procedure that listener observes.
// Every REST call behind the hop was refused as stamp_method after the
// authority had admitted it. The composition is refused when the hop starts
// instead, naming the reason.
func TestARESTFaceTranscodedIntoAProceduralListenerIsRefusedAtStartup(t *testing.T) {
	for _, beside := range []string{"grpc", "connect"} {
		t.Run("beside "+beside, func(t *testing.T) {
			routes := &Routing{Schema: RoutingSchema, Endpoints: []RouteEndpoint{
				{Audience: "module", Service: "api", Endpoint: beside, Transport: beside, Address: "a", Package: "p", Version: "1", Digest: "d", Methods: []string{"/pkg.Service/Read"}},
				{Audience: "module", Service: "api", Endpoint: "rest", Transport: "http", Address: "a", Package: "p", Version: "1", Digest: "d", Methods: []string{"GET /read"}},
			}}
			err := routes.Validate()
			if !errors.Is(err, ErrTranscodedREST) {
				t.Fatalf("want ErrTranscodedREST: %v", err)
			}
			if !strings.Contains(err.Error(), "module/api") {
				t.Fatalf("the refusal names the listener: %v", err)
			}
		})
	}
}

// A module serving HTTP natively keeps working: its http face is the only one
// on its service, so the verifier observes the same "VERB /path" the hop signs.
func TestANativeHTTPFaceIsAdmittedBesideOtherServicesProceduralFaces(t *testing.T) {
	routes := &Routing{Schema: RoutingSchema, Endpoints: []RouteEndpoint{
		{Audience: "module", Service: "web", Endpoint: "http", Transport: "http", Address: "a", Package: "p", Version: "1", Digest: "d", Methods: []string{"GET /read"}},
		// Another service of the same module, procedural, is no transcoding.
		{Audience: "module", Service: "api", Endpoint: "grpc", Transport: "grpc", Address: "b", Package: "p", Version: "1", Digest: "d", Methods: []string{"/pkg.Service/Read"}},
	}}
	if err := routes.Validate(); err != nil {
		t.Fatalf("a native HTTP face was refused: %v", err)
	}
}
