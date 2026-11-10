package decide

import (
	"context"
	"strings"
	"testing"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// counted is an authority that admits and counts every Check.
type counted struct{ checks int }

func (c *counted) Check(context.Context, *authorityv1.CheckRequest, ...grpc.CallOption) (*authorityv1.CheckResponse, error) {
	c.checks++
	return &authorityv1.CheckResponse{Context: &authorityv1.WorkContextV1{OwnerPrincipalId: "maya", TenantId: "acme"}}, nil
}

// A Work Context addressed to one fronted module, presented for a method
// another fronted module publishes, is the caller's error: PermissionDenied,
// naming the module the call is for and the one the context is addressed to.
// Only a method no fronted module publishes is NotFound. Neither asks the
// authority, and both hold for gRPC and HTTP alike.
func TestAWrongAudienceIsRefusedByNameAndAnUnknownDestinationIsNotFound(t *testing.T) {
	routes := &routing.Routing{Endpoints: []routing.RouteEndpoint{
		{Audience: "documents", Transport: "grpc", Address: "unused", Methods: []string{"/documents.v1.Service/Get"}},
		{Audience: "documents", Transport: "http", Address: "unused", Methods: []string{"GET /v1/documents/{id}"}},
		{Audience: "records", Transport: "grpc", Address: "unused", Methods: []string{"/records.v1.Service/List"}},
		{Audience: "records", Transport: "http", Address: "unused", Methods: []string{"GET /v1/records"}},
	}}
	for _, tc := range []struct {
		name, method, addressed string
		code                    codes.Code
		says                    []string
	}{
		{"grpc, wrong audience", "/documents.v1.Service/Get", "records", codes.PermissionDenied, []string{`for "documents"`, `addressed to "records"`}},
		{"http, wrong audience", "GET /v1/documents/7", "records", codes.PermissionDenied, []string{`for "documents"`, `addressed to "records"`}},
		{"grpc, unknown destination", "/unknown.v1.Service/Call", "records", codes.NotFound, []string{"0 matching published destinations"}},
		{"http, unknown destination", "GET /v1/unknown", "documents", codes.NotFound, []string{"0 matching published destinations"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authority := &counted{}
			d := Decider{Routes: routes, Authority: authority, Modules: map[string]bool{"documents": true, "records": true},
				AudienceOf: func(string) (string, error) { return tc.addressed, nil }}
			decision, err := d.Decide(context.Background(), tc.method, metadata.Pairs(hop.WorkContextKey, "x"))
			if status.Code(err) != tc.code || decision.Route != nil {
				t.Fatalf("decision=%+v error=%v; want %v", decision, err, tc.code)
			}
			for _, want := range tc.says {
				if !strings.Contains(status.Convert(err).Message(), want) {
					t.Errorf("the refusal %q does not say %s", status.Convert(err).Message(), want)
				}
			}
			if authority.checks != 0 {
				t.Errorf("the authority was asked %d times about a call the hop refuses on its routes", authority.checks)
			}
		})
	}
	// The control: the same context at its own module's method is decided by
	// the authority and routed.
	authority := &counted{}
	d := Decider{Routes: routes, Authority: authority, Modules: map[string]bool{"documents": true, "records": true},
		AudienceOf: func(string) (string, error) { return "records", nil }}
	if decision, err := d.Decide(context.Background(), "/records.v1.Service/List", metadata.Pairs(hop.WorkContextKey, "x")); err != nil || decision.Module != "records" || authority.checks != 1 {
		t.Fatalf("a context at its own module is not routed: %+v %v (checks %d)", decision, err, authority.checks)
	}
}

// A module the hop does not front never names a destination: a method only
// it publishes stays NotFound to a context addressed to a fronted module.
func TestAnUnfrontedPublisherIsNotNamed(t *testing.T) {
	routes := &routing.Routing{Endpoints: []routing.RouteEndpoint{
		{Audience: "documents", Transport: "grpc", Address: "unused", Methods: []string{"/documents.v1.Service/Get"}},
		{Audience: "elsewhere", Transport: "grpc", Address: "unused", Methods: []string{"/elsewhere.v1.Service/Get"}},
	}}
	d := Decider{Routes: routes, Authority: &counted{}, Modules: map[string]bool{"documents": true},
		AudienceOf: func(string) (string, error) { return "documents", nil }}
	_, err := d.Decide(context.Background(), "/elsewhere.v1.Service/Get", metadata.Pairs(hop.WorkContextKey, "x"))
	if status.Code(err) != codes.NotFound || strings.Contains(status.Convert(err).Message(), "elsewhere\"") {
		t.Fatalf("got %v; want NotFound naming no unfronted module", err)
	}
}

// Only the addressed module publishing nothing is a wrong audience. Its own
// ambiguous routes keep their own reason; another module's ambiguous routes
// still make it a publisher; several publishers are named in order; a
// trailing {name=**} template publishes what it matches.
func TestAWrongAudienceIsDecidedOnPublicationAlone(t *testing.T) {
	routes := &routing.Routing{Endpoints: []routing.RouteEndpoint{
		{Audience: "documents", Service: "a", Transport: "http", Address: "unused", Methods: []string{"GET /v1/items/{id}", "GET /v1/{kind}/7", "GET /v1/things/{id}", "GET /v1/{kind}/9"}},
		{Audience: "records", Service: "a", Transport: "http", Address: "unused", Methods: []string{"GET /v1/items/{id}", "GET /v1/shared"}},
		{Audience: "annotations", Service: "a", Transport: "http", Address: "unused", Methods: []string{"GET /v1/shared", "GET /v1/files/{path=**}"}},
		{Audience: "tracing", Service: "a", Transport: "http", Address: "unused", Methods: []string{"GET /v1/spans"}},
	}}
	for _, tc := range []struct {
		name, method, addressed string
		code                    codes.Code
		says                    string
	}{
		{"the addressed module's own routes are ambiguous", "GET /v1/items/7", "documents", codes.NotFound, "documents GET /v1/items/7 has 2 matching published destinations"},
		{"another module publishes it ambiguously", "GET /v1/things/9", "records", codes.PermissionDenied, `is for "documents", but its Work Context is addressed to "records"`},
		{"two other modules publish it", "GET /v1/shared", "tracing", codes.PermissionDenied, `is for "annotations", "records", but`},
		{"a trailing wildcard publishes it", "GET /v1/files/a/b.txt", "tracing", codes.PermissionDenied, `is for "annotations", but`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authority := &counted{}
			d := Decider{Routes: routes, Authority: authority, Modules: map[string]bool{"documents": true, "records": true, "annotations": true, "tracing": true},
				AudienceOf: func(string) (string, error) { return tc.addressed, nil }}
			_, err := d.Decide(context.Background(), tc.method, metadata.Pairs(hop.WorkContextKey, "x"))
			if status.Code(err) != tc.code || !strings.Contains(status.Convert(err).Message(), tc.says) {
				t.Fatalf("got %v; want %v saying %s", err, tc.code, tc.says)
			}
			if authority.checks != 0 {
				t.Errorf("the authority was asked about a call the hop refuses on its routes")
			}
		})
	}
}
