package scenario

import (
	"context"
	"net"
	"strings"
	"testing"

	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"google.golang.org/grpc"
)

// fixtureHost is a host that lists one fixture person, named after itself.
type fixtureHost struct {
	sessionv1.UnimplementedSessionServiceServer
	person string
}

func (h fixtureHost) ListFixturePeople(context.Context, *sessionv1.ListFixturePeopleRequest) (*sessionv1.ListFixturePeopleResponse, error) {
	return &sessionv1.ListFixturePeopleResponse{People: []*sessionv1.FixturePerson{{PersonId: h.person, OrganizationId: "acme", Roles: []string{"admin"}}}}, nil
}

// serveHost serves a fixture host and answers where it listens.
func serveHost(t *testing.T, person string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	sessionv1.RegisterSessionServiceServer(server, fixtureHost{person: person})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return listener.Addr().String()
}

// A run delivers both hosts; the composition reads its people from the one
// the options name, and from the local authority when they name none.
func TestTheHostIsTheOneTheOptionsName(t *testing.T) {
	local, accounts := serveHost(t, "from-the-local-authority"), serveHost(t, "from-accounts")
	delivered := map[string]string{
		"CODEFLY__ENDPOINT__AUTHORITY__LOCAL__GRPC__GRPC":      local,
		"CODEFLY__ENDPOINT__AUTHORITY__EDGE__HTTP__HTTP":       "http://edge.test.invalid",
		"CODEFLY__ENDPOINT__SAAS__ACCOUNTS__CONNECT__CONNECT":  "http://" + accounts,
		"CODEFLY__ENDPOINT__SAAS__AUTH_GATEWAY__HTTP__HTTP":    "http://gateway.test.invalid",
		"CODEFLY__ENDPOINT__SAAS__ACCOUNTS__CONNECTED__GRPC":   "a-longer-name.test.invalid",
		"CODEFLY__ENDPOINT__AUTHORITY__LOCAL__GRPC_OTHER__TCP": "another-endpoint.test.invalid",
	}
	for name, tc := range map[string]struct {
		options        Options
		person, origin string
	}{
		"no host named: the local authority": {Options{}, "from-the-local-authority", "http://edge.test.invalid"},
		"Accounts named":                     {Options{Host: Endpoint{Module: "saas", Service: "accounts", Endpoint: "connect"}}, "from-accounts", "http://edge.test.invalid"},
		"Accounts and its own edge": {Options{Host: Endpoint{Module: "saas", Service: "accounts", Endpoint: "connect"},
			Edge: Endpoint{Module: "saas", Service: "auth-gateway", Endpoint: "http"}}, "from-accounts", "http://gateway.test.invalid"},
	} {
		t.Run(name, func(t *testing.T) {
			c := &Composition{delivered: func() map[string]string { return delivered }, signed: map[string]*Person{}}
			if err := c.connect(context.Background(), tc.options); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.conn.Close() })
			if len(c.people) != 1 || c.people[tc.person] == nil {
				t.Fatalf("the people were read from another host: %v", c.people)
			}
			if c.origin != tc.origin || c.home != "acme" {
				t.Fatalf("origin %q, home %q", c.origin, c.home)
			}
		})
	}
	for name, tc := range map[string]struct {
		options Options
		reason  string
	}{
		"a host the run did not deliver":  {Options{Host: Endpoint{Module: "saas", Service: "accounts", Endpoint: "grpc"}}, "delivered no address of saas/accounts/grpc"},
		"an edge the run did not deliver": {Options{Edge: Endpoint{Module: "saas", Service: "edge", Endpoint: "http"}}, "delivered no address of saas/edge/http"},
		"a host half named":               {Options{Host: Endpoint{Module: "saas", Service: "accounts"}}, "each name a module, a service and an endpoint"},
	} {
		t.Run(name, func(t *testing.T) {
			c := &Composition{delivered: func() map[string]string { return delivered }, signed: map[string]*Person{}}
			err := c.connect(context.Background(), tc.options)
			if c.conn != nil {
				_ = c.conn.Close()
			}
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("want a refusal naming %q, got %v", tc.reason, err)
			}
		})
	}
}

// Address answers what the run delivered for an endpoint, host and port, and
// refuses one it did not deliver rather than guessing it.
func TestAddressIsWhatTheRunDelivered(t *testing.T) {
	c := &Composition{delivered: func() map[string]string {
		return map[string]string{"CODEFLY__ENDPOINT__DOCUMENT_STORE__API__GRPC__GRPC": "http://documents.test.invalid:8443", "CODEFLY__ENDPOINT__DOCUMENT_STORE__API__REST__HTTP": ""}
	}}
	if got, err := c.Address("document-store", "api", "grpc"); err != nil || got != "documents.test.invalid:8443" {
		t.Fatalf("address %q, %v", got, err)
	}
	for _, missing := range [][3]string{{"document-store", "api", "rest"}, {"document-store", "worker", "grpc"}, {"document", "store-api", "grpc"}} {
		if got, err := c.Address(missing[0], missing[1], missing[2]); err == nil {
			t.Fatalf("%v answered %q", missing, got)
		}
	}
}
