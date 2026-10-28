package main

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"sync"
	"testing"

	"connectrpc.com/connect"
	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// delegationHost is the authority behind the face's two delegation
// procedures. It answers a known session as the core does and records every
// call with the session that sent it; the core's own decisions are proven in
// authority-core (TestADelegationWithALifetimeEndsByItself).
type delegationHost struct {
	mu       sync.Mutex
	calls    []string
	bearers  []string
	requests []*authorityv1.DelegateRequest
}

func (h *delegationHost) record(ctx context.Context, call string) error {
	bearer := bearerIn(ctx)
	h.mu.Lock()
	h.calls, h.bearers = append(h.calls, call), append(h.bearers, bearer)
	h.mu.Unlock()
	if _, ok := hostPeople[bearer]; !ok {
		return status.Error(codes.Unauthenticated, "no session")
	}
	return nil
}

func (h *delegationHost) Delegate(ctx context.Context, in *authorityv1.DelegateRequest, _ ...grpc.CallOption) (*authorityv1.Delegation, error) {
	if err := h.record(ctx, "Delegate"); err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.requests = append(h.requests, in)
	h.mu.Unlock()
	return &authorityv1.Delegation{DelegationId: "d-1", Module: in.GetModule(), Purpose: in.GetPurpose(), Active: true, ExpiresAtUnix: 1793000000}, nil
}

func (h *delegationHost) GetDelegation(ctx context.Context, in *authorityv1.GetDelegationRequest, _ ...grpc.CallOption) (*authorityv1.Delegation, error) {
	if err := h.record(ctx, "GetDelegation"); err != nil {
		return nil, err
	}
	return &authorityv1.Delegation{DelegationId: in.GetDelegationId(), Active: true, ExpiresAtUnix: 1793000000}, nil
}

func (h *delegationHost) sent() ([]string, []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.calls...), append([]string(nil), h.bearers...)
}

func newDelegationFace(t *testing.T) (*httptest.Server, *delegationHost) {
	h := &delegationHost{}
	srv := httptest.NewServer(&Edge{Delegations: h, Modules: map[string]Module{}})
	t.Cleanup(srv.Close)
	return srv, h
}

// A page delegates one run for the signed-in person, for a lifetime, and
// reads it back: each call reaches the authority as that person's own, and
// its answer reaches the page (handbook proposal
// 2026-10-28-a-person-delegates-a-run-from-the-page).
func TestAPageDelegatesARunForItsPersonThroughTheHostFace(t *testing.T) {
	srv, host := newDelegationFace(t)
	ask := &authorityv1.DelegateRequest{Module: "robin", Purpose: "run r-1", TtlSeconds: 3600,
		Scopes: []*authorityv1.WorkScopeV1{{ResourceKind: "documents", Actions: []string{"read"}}}}
	d, err := browser[authorityv1.DelegateRequest, authorityv1.Delegation](t, srv, srv.URL, "maya-session", authorityv1.AuthorityService_Delegate_FullMethodName, ask)
	if err != nil || d.GetDelegationId() != "d-1" || d.GetExpiresAtUnix() != 1793000000 {
		t.Fatalf("delegate answered %+v, %v", d, err)
	}
	if len(host.requests) != 1 || host.requests[0].GetTtlSeconds() != 3600 || host.requests[0].GetModule() != "robin" {
		t.Fatalf("the authority was asked %+v", host.requests)
	}
	read, err := browser[authorityv1.GetDelegationRequest, authorityv1.Delegation](t, srv, srv.URL, "maya-session", authorityv1.AuthorityService_GetDelegation_FullMethodName,
		&authorityv1.GetDelegationRequest{DelegationId: "d-1"})
	if err != nil || !read.GetActive() {
		t.Fatalf("read answered %+v, %v", read, err)
	}
	calls, bearers := host.sent()
	if len(calls) != 2 || bearers[0] != "maya-session" || bearers[1] != "maya-session" {
		t.Fatalf("the authority was sent %v as %v", calls, bearers)
	}
}

// What a page may not ask never reaches the authority: a delegation with no
// lifetime, which would stand after the run; a read naming a module's
// credential, which is the module's own read; and every other authority
// procedure, Issue and RevokeDelegation included.
func TestThePageCannotAskForAStandingDelegationOrAnythingElseOfTheAuthority(t *testing.T) {
	srv, host := newDelegationFace(t)
	_, err := browser[authorityv1.DelegateRequest, authorityv1.Delegation](t, srv, srv.URL, "maya-session", authorityv1.AuthorityService_Delegate_FullMethodName,
		&authorityv1.DelegateRequest{Module: "robin", Purpose: "run r-1"})
	refusedWith(t, err, connect.CodeInvalidArgument, "ttl_seconds")
	_, err = browser[authorityv1.GetDelegationRequest, authorityv1.Delegation](t, srv, srv.URL, "maya-session", authorityv1.AuthorityService_GetDelegation_FullMethodName,
		&authorityv1.GetDelegationRequest{DelegationId: "d-1", Actor: &authorityv1.WorkloadCredential{Credential: "a-module's"}})
	refusedWith(t, err, connect.CodeInvalidArgument, "actor")
	_, err = browser[authorityv1.IssueRequest, authorityv1.IssueResponse](t, srv, srv.URL, "maya-session", authorityv1.AuthorityService_Issue_FullMethodName,
		&authorityv1.IssueRequest{Audience: "robin"})
	if err == nil {
		t.Fatal("a page was served Issue")
	}
	_, err = browser[authorityv1.RevokeDelegationRequest, authorityv1.RevokeDelegationResponse](t, srv, srv.URL, "maya-session", authorityv1.AuthorityService_RevokeDelegation_FullMethodName,
		&authorityv1.RevokeDelegationRequest{DelegationId: "d-1"})
	if err == nil {
		t.Fatal("a page was served RevokeDelegation")
	}
	_, err = browser[authorityv1.DelegateRequest, authorityv1.Delegation](t, srv, "http://elsewhere.test", "maya-session", authorityv1.AuthorityService_Delegate_FullMethodName,
		&authorityv1.DelegateRequest{Module: "robin", TtlSeconds: 3600})
	refusedWith(t, err, connect.CodePermissionDenied, "must come from this origin")
	if calls, _ := host.sent(); len(calls) != 0 {
		t.Fatalf("refused calls reached the authority: %v", calls)
	}
}

// An edge composing no delegation client serves neither procedure.
func TestAnEdgeWithoutTheAuthorityServesNoDelegation(t *testing.T) {
	srv, _ := newHostFace(t)
	_, err := browser[authorityv1.DelegateRequest, authorityv1.Delegation](t, srv, srv.URL, "maya-session", authorityv1.AuthorityService_Delegate_FullMethodName,
		&authorityv1.DelegateRequest{Module: "robin", TtlSeconds: 3600})
	if err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("an edge with no delegation client served Delegate: %v", err)
	}
}

// The edge serves Delegate only in front of a host that enforces a lifetime:
// one implementing authority 0.3.5 or later. An older host (Accounts at 0.3.4)
// drops ttl_seconds as an unknown field and would record a page's one-hour
// delegation as one that never ends, so the edge refuses to be composed with
// it (review of #50).
func TestTheEdgeRequiresAHostThatEnforcesADelegationsLifetime(t *testing.T) {
	raw, err := os.ReadFile("../service.codefly.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*- interface: codefly\.dev/authority@>=(\d+)\.(\d+)\.(\d+) `).FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatal("the edge declares no floor on codefly.dev/authority")
	}
	floor := [3]int{}
	for i := range floor {
		floor[i], _ = strconv.Atoi(m[i+1])
	}
	if floor[0] == 0 && (floor[1] < 3 || floor[1] == 3 && floor[2] < 5) {
		t.Fatalf("the edge admits authority %d.%d.%d, which ignores a delegation's lifetime; it needs >=0.3.5", floor[0], floor[1], floor[2])
	}
}
