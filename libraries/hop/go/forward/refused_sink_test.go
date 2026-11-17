package forward_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/forward"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// A host hands the front door one sink (Config.Refused) and is told every
// refusal either face makes, with its reason and what identifies the call:
// the refusals the hop makes on its own, which the authority never hears of,
// and the authority's, marked as its own so a host that already records the
// authority's decisions does not record them twice.
func TestTheFrontTellsTheHostsSinkEachRefusal(t *testing.T) {
	h := &gateway{authority: &authority{Authority: hoptest.New(t), revoked: map[string]bool{}, refuse: map[string]string{}}}
	verifier, err := hop.NewVerifier(t.Context(), h.PublishHop(proof), "module", hoptest.Replay())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	moduleServer := grpc.NewServer(grpc.UnaryInterceptor(verifier.UnaryServerInterceptor()))
	registerModule(moduleServer, &module{})
	go func() { _ = moduleServer.Serve(listener) }()
	t.Cleanup(moduleServer.Stop)

	var mu sync.Mutex
	var told []forward.Refusal
	front, err := forward.New(t.Context(), forward.Config{
		Signer: hoptest.Signer(proof), Authority: h, Credential: credential, Modules: []string{"module"},
		Routes: rawRoutes(t, routeEndpoint("api", "grpc", "http://"+listener.Addr().String(), versionProcedure)),
		Refused: func(_ context.Context, r forward.Refusal) {
			mu.Lock()
			defer mu.Unlock()
			told = append(told, r)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	conn := serve(t, front.ServerOptions, func(*grpc.Server) {})
	token := h.Issue(t, "module", identityRead)
	carrying := metadata.AppendToOutgoingContext(t.Context(), hop.WorkContextKey, token)
	// one is the single refusal do's call told the sink.
	one := func(t *testing.T, code codes.Code, do func() error) forward.Refusal {
		t.Helper()
		mu.Lock()
		told = nil
		mu.Unlock()
		if err := do(); status.Code(err) != code {
			t.Fatalf("the call was answered %v, want %v", err, code)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(told) != 1 || told[0].Code != code || told[0].Reason == "" {
			t.Fatalf("the sink was told %+v, want one %v refusal with its reason", told, code)
		}
		return told[0]
	}
	claimed := func(t *testing.T, got forward.Refusal) {
		t.Helper()
		if got.Module != "module" || got.Owner != "principal-owner" || got.Organization != "tenant-conformance" || got.Task == "" || !got.Claimed {
			t.Fatalf("the refusal does not identify the call as its Work Context claims it: %+v", got)
		}
	}

	t.Run("an admitted call is no refusal", func(t *testing.T) {
		if _, err := version(carrying, conn); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(told) != 0 {
			t.Fatalf("the sink was told %+v of an admitted call", told)
		}
	})
	t.Run("a call carrying no Work Context", func(t *testing.T) {
		got := one(t, codes.Unauthenticated, func() error { _, err := version(t.Context(), conn); return err })
		if want := (forward.Refusal{Method: versionProcedure, Code: codes.Unauthenticated, Reason: got.Reason}); got != want {
			t.Fatalf("the refusal is %+v, want %+v", got, want)
		}
	})
	t.Run("a method no published route serves", func(t *testing.T) {
		const unrouted = "/" + moduleService + "/Unrouted"
		got := one(t, codes.NotFound, func() error { return conn.Invoke(carrying, unrouted, &emptypb.Empty{}, &emptypb.Empty{}) })
		if got.Method != unrouted || got.ByAuthority {
			t.Fatalf("the hop's own refusal is %+v", got)
		}
		claimed(t, got)
	})
	t.Run("the HTTP face's refusal reaches the same sink", func(t *testing.T) {
		got := one(t, codes.NotFound, func() error {
			req := httptest.NewRequest(http.MethodGet, "/nowhere", nil)
			req.Header.Set(hop.WorkContextKey, token)
			rec := httptest.NewRecorder()
			front.Handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("an unrouted path was answered %d", rec.Code)
			}
			return status.Error(codes.NotFound, "answered 404")
		})
		if got.Method != "GET /nowhere" || got.ByAuthority {
			t.Fatalf("the hop's own refusal is %+v", got)
		}
		claimed(t, got)
	})
	t.Run("the authority's refusal is marked as the authority's", func(t *testing.T) {
		h.refuse[h.methods[0]] = "module requires console.identity:write"
		got := one(t, codes.PermissionDenied, func() error { _, err := version(carrying, conn); return err })
		if !got.ByAuthority || !strings.Contains(got.Reason, "console.identity:write") || got.Method != versionProcedure {
			t.Fatalf("the authority's refusal is %+v", got)
		}
		claimed(t, got)
	})
}
