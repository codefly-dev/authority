package forward_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/decide"
	"github.com/codefly-dev/authority/libraries/hop/go/forward"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const watchProcedure = "/" + moduleService + "/Watch"

// watching serves Watch: a server stream that sends for as long as it is let,
// and records how its context ended. It runs no verifier, so what ends the
// stream in these tests is the hop.
type watching struct {
	sent  atomic.Int64
	ended chan error
}

func (w *watching) register(s grpc.ServiceRegistrar) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: moduleService,
		HandlerType: (*any)(nil),
		Streams: []grpc.StreamDesc{{StreamName: "Watch", ServerStreams: true, Handler: func(_ any, stream grpc.ServerStream) error {
			if err := stream.RecvMsg(new(emptypb.Empty)); err != nil {
				return err
			}
			for {
				select {
				case <-stream.Context().Done():
					w.ended <- stream.Context().Err()
					return stream.Context().Err()
				case <-time.After(50 * time.Millisecond):
					if err := stream.SendMsg(wrapperspb.String("tick")); err != nil {
						w.ended <- err
						return err
					}
					w.sent.Add(1)
				}
			}
		}}},
	}, w)
}

// Issue 3 of the RBAC review: a stream the hop admitted ran for as long as
// both ends kept it open, past the expiry of the Work Context that admitted
// it. The hop ends it at that expiry, and says why.
func TestAStreamTheHopAdmittedEndsWhenItsWorkContextExpires(t *testing.T) {
	a := &authority{Authority: hoptest.New(t), revoked: map[string]bool{}}
	w := &watching{ended: make(chan error, 1)}
	moduleListener := bufconn.Listen(1 << 20)
	moduleServer := grpc.NewServer()
	w.register(moduleServer)
	go func() { _ = moduleServer.Serve(moduleListener) }()
	t.Cleanup(moduleServer.Stop)
	moduleConn := dial(t, moduleListener, grpc.WithDefaultCallOptions(forward.CallOptions()...))
	p := &forward.Proxy{
		Decide:    decide.Decider{Routes: &routing.Routing{Endpoints: []routing.RouteEndpoint{{Audience: "console", Transport: "grpc", Address: "console", Methods: []string{watchProcedure}}}}, Authority: a, Modules: map[string]bool{"console": true}}.Decide,
		Upstreams: map[string]*grpc.ClientConn{"console": moduleConn},
		Signer:    hoptest.Signer(proof), Ready: published(t, hoptest.Signer(proof)),
	}
	through := serve(t, p.ServerOptions(), func(*grpc.Server) {})

	// The caller would keep the stream for a minute; its context lives two seconds.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, hop.WorkContextKey, a.IssueFor(t, "console", 2*time.Second, identityRead))
	started := time.Now()
	stream, err := through.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, watchProcedure)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SendMsg(&emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	_ = stream.CloseSend()
	received := 0
	for {
		if err = stream.RecvMsg(new(wrapperspb.StringValue)); err != nil {
			break
		}
		received++
		if time.Since(started) > 10*time.Second {
			t.Fatalf("the stream is still open %v after its two-second Work Context was issued", time.Since(started))
		}
	}
	if received == 0 {
		t.Fatalf("the admitted stream carried nothing before it ended: %v", err)
	}
	if status.Code(err) != codes.Unauthenticated || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("the stream ended with %v, want Unauthenticated naming the expiry", err)
	}
	select {
	case <-w.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the module's stream was left open after the hop ended the caller's")
	}
}

// The HTTP face is held to the same bound: a response the module streams
// (server-sent events, a Connect stream) ends at the expiry, and a request the
// module has not answered by then is refused as expired, not as a module that
// did not answer.
func TestAnHTTPStreamTheHopAdmittedEndsWhenItsWorkContextExpires(t *testing.T) {
	ended := make(chan struct{}, 2)
	module := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { ended <- struct{}{} }()
		if r.URL.Path == "/v1/model/silent" {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for {
			if _, err := io.WriteString(w, "data: tick\n\n"); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}))
	defer module.Close()
	target, _ := url.Parse(module.URL)
	front := httptest.NewServer(&forward.HTTP{
		Signer: hoptest.Signer(proof), Ready: published(t, hoptest.Signer(proof)),
		Upstreams: map[string]*url.URL{target.String(): target},
		Decide: func(context.Context, string, metadata.MD) (decide.Decision, error) {
			return decide.Decision{Route: &routing.RouteEndpoint{Address: target.String()}, Module: "model",
				Identity: hop.Identity{Expires: time.Now().Add(2 * time.Second).Unix(), Owner: "jane", OwnerKind: "human", Tenant: "acme"}}, nil
		},
	})
	defer front.Close()
	get := func(path string) (*http.Response, time.Time) {
		req, _ := http.NewRequest(http.MethodGet, front.URL+path, nil)
		req.Header.Set(hop.WorkContextKey, "wc-model")
		started := time.Now()
		res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return res, started
	}

	res, started := get("/v1/model/events")
	body, _ := io.ReadAll(res.Body) // ends when the hop ends the stream, or at the client's 15 seconds
	_ = res.Body.Close()
	if elapsed := time.Since(started); elapsed > 8*time.Second {
		t.Fatalf("the stream was still open %v after its two-second Work Context was stamped", elapsed)
	}
	if !strings.Contains(string(body), "data: tick") {
		t.Fatalf("the admitted stream carried nothing: %q", body)
	}

	res, started = get("/v1/model/silent")
	body, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), "expired") || time.Since(started) > 8*time.Second {
		t.Fatalf("a request unanswered at the expiry was answered %d %s after %v", res.StatusCode, body, time.Since(started))
	}
	for range 2 {
		select {
		case <-ended:
		case <-time.After(5 * time.Second):
			t.Fatal("the module's request was left open after the hop ended the caller's")
		}
	}
}
