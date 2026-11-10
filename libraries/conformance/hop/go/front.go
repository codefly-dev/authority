package hopconformance

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	hop "github.com/codefly-dev/authority/libraries/hop/go"
	hopforward "github.com/codefly-dev/authority/libraries/hop/go/forward"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	"github.com/codefly-dev/core/resources"
	core "github.com/codefly-dev/core/workcontext"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// FrontTarget is one host's hop front door: what a host stands when the
// composition names modules for it, given what Codefly hands it.
type FrontTarget struct {
	// Stand stands the host's hop in front of modules, routed by routes (the
	// generated hop-routes/ROUTES, as Codefly delivers it) and deciding every
	// call with authority, which also takes the host's admission key. It
	// returns the face the hop's endpoint serves HTTP and Connect calls on,
	// ready once that key is registered, and how to stop it.
	Stand func(ctx context.Context, authority hopforward.Authority, modules []string, routes string) (face http.Handler, stop func(), err error)
}

// The two modules the front door cases stand in front of, and the Connect
// procedure each publishes.
const (
	FrontModule      = "documents"
	FrontProcedure   = "/documents.v1.Service/Get"
	OtherModule      = "records"
	OtherProcedure   = "/records.v1.Service/List"
	UnknownProcedure = "/unknown.v1.Service/Call"
)

// RunFront drives the front door cases against a host's hop. A refusal names
// its reason, and a refusal of the caller is never reported as a destination
// that does not exist:
//
//   - a Work Context addressed to one fronted module, presented for a
//     procedure another fronted module publishes, is PermissionDenied, and
//     the reason names both modules; the authority is not asked;
//   - a procedure no fronted module publishes is NotFound, whatever the
//     context; the authority is not asked;
//   - the control: the same context at its own module's procedure is checked
//     by the authority and reaches that module.
//
// Run sets the run named exactly "local" for its duration (t.Setenv), so the
// front may forward over the loopback; the calling test cannot be parallel.
func RunFront(t *testing.T, target FrontTarget) {
	t.Helper()
	if target.Stand == nil {
		t.Fatal("hopconformance: the front target stands no hop")
	}
	t.Setenv(resources.EnvironmentPrefix, "local")
	t.Run("a context for another module is refused by name, and only an unknown destination is not found", func(t *testing.T) {
		a := &frontAuthority{Authority: hoptest.New(t)}
		var reached [2]atomic.Int32
		routes := frontRoutes(t,
			frontRoute(t, FrontModule, FrontProcedure, &reached[0]),
			frontRoute(t, OtherModule, OtherProcedure, &reached[1]))
		face, stop, err := target.Stand(t.Context(), a, []string{FrontModule, OtherModule}, routes)
		if err != nil {
			t.Fatalf("the host does not stand its hop: %v", err)
		}
		t.Cleanup(stop)
		web := httptest.NewServer(face)
		t.Cleanup(web.Close)
		elsewhere := a.Issue(t, OtherModule, read)

		// The control: the context reaches the module it is addressed to, so a
		// refusal below is about the address, not a face that serves nothing.
		got := connectCall(t, web.URL, OtherProcedure, elsewhere)
		if got.status != http.StatusOK || reached[1].Load() != 1 || a.checks.Load() != 1 {
			t.Fatalf("the hop does not serve a context at its own module (%s; reached %d, checked %d), so a refusal proves nothing", got, reached[1].Load(), a.checks.Load())
		}

		got = connectCall(t, web.URL, FrontProcedure, elsewhere)
		switch {
		case got.code != codes.PermissionDenied || got.status != http.StatusForbidden:
			t.Errorf("a context addressed to %s, presented for %s's %s, is not refused as PermissionDenied: %s", OtherModule, FrontModule, FrontProcedure, got)
		case !strings.Contains(got.message, FrontModule) || !strings.Contains(got.message, OtherModule):
			t.Errorf("the wrong-audience refusal does not name the module the call is for and the one its context is addressed to: %s", got)
		default:
			t.Logf("wrong audience: %s", got)
		}

		got = connectCall(t, web.URL, UnknownProcedure, elsewhere)
		switch {
		case got.code != codes.NotFound || got.status != http.StatusNotFound:
			t.Errorf("a procedure no fronted module publishes is not NotFound: %s", got)
		case strings.TrimSpace(got.message) == "":
			t.Errorf("the unknown destination is refused without a reason: %s", got)
		default:
			t.Logf("unknown destination: %s", got)
		}

		if reached[0].Load() != 0 || reached[1].Load() != 1 || a.checks.Load() != 1 {
			t.Errorf("a refused call reached a module or asked the authority (reached %d and %d, checked %d)", reached[0].Load(), reached[1].Load(), a.checks.Load())
		}
	})
}

// frontAuthority answers Check as an authority does for the audience a
// context is addressed to, and acknowledges every admission key it is given.
type frontAuthority struct {
	*hoptest.Authority
	checks atomic.Int32
}

func (a *frontAuthority) Check(_ context.Context, in *authorityv1.CheckRequest, _ ...grpc.CallOption) (*authorityv1.CheckResponse, error) {
	a.checks.Add(1)
	decoded, err := core.Decode(in.GetToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "the Work Context does not decode")
	}
	if got := decoded.Context().GetAudience(); got != in.GetAudience() {
		return nil, status.Errorf(codes.PermissionDenied, "the Work Context is addressed to %s, not %s", got, in.GetAudience())
	}
	wire, err := proto.Marshal(decoded.Context())
	if err != nil {
		return nil, err
	}
	wc := &authorityv1.WorkContextV1{}
	if err := proto.Unmarshal(wire, wc); err != nil {
		return nil, err
	}
	return &authorityv1.CheckResponse{Context: wc}, nil
}

func (a *frontAuthority) RegisterAdmissionKey(_ context.Context, in *authorityv1.RegisterAdmissionKeyRequest, _ ...grpc.CallOption) (*authorityv1.RegisterAdmissionKeyResponse, error) {
	return &authorityv1.RegisterAdmissionKeyResponse{
		Key:           &authorityv1.PublicKey{KeyId: stamp.KeyID(in.GetPublicKey()), PublicKey: in.GetPublicKey(), Algorithm: core.Algorithm, Purpose: stamp.Purpose},
		ExpiresAtUnix: time.Now().Add(time.Hour).Unix(),
	}, nil
}

// frontRoute publishes procedure on a Connect listener of module that counts
// the calls reaching it and answers each with an empty message.
func frontRoute(t *testing.T, module, procedure string, reached *atomic.Int32) routing.RouteEndpoint {
	t.Helper()
	backend := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != procedure {
			http.NotFound(w, r)
			return
		}
		reached.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{}")
	}), &http2.Server{}))
	t.Cleanup(backend.Close)
	return routing.RouteEndpoint{Audience: module, Service: "api", Endpoint: "connect", Transport: "connect", Address: backend.URL,
		Package: "owner/" + module, Version: "1.0.0", Digest: "sha256:" + module, Methods: []string{procedure}}
}

func frontRoutes(t *testing.T, endpoints ...routing.RouteEndpoint) string {
	t.Helper()
	raw, err := json.Marshal(routing.Routing{Schema: routing.RoutingSchema, Endpoints: endpoints})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// connectOutcome is a Connect unary call's answer: its HTTP status and, when
// refused, the Connect code and message.
type connectOutcome struct {
	status  int
	code    codes.Code
	message string
}

func (o connectOutcome) String() string {
	return http.StatusText(o.status) + " " + o.code.String() + ": " + o.message
}

// connectCodes are the Connect protocol's error codes, by their wire names.
var connectCodes = map[string]codes.Code{
	"unauthenticated": codes.Unauthenticated, "permission_denied": codes.PermissionDenied,
	"not_found": codes.NotFound, "invalid_argument": codes.InvalidArgument, "unavailable": codes.Unavailable,
	"internal": codes.Internal, "unknown": codes.Unknown,
}

// connectCall makes one Connect unary JSON call presenting token, as a
// generated Connect client does.
func connectCall(t *testing.T, base, procedure, token string) connectOutcome {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+procedure, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	req.Header.Set(hop.WorkContextKey, token)
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s: %v", procedure, err)
	}
	defer resp.Body.Close()
	out := connectOutcome{status: resp.StatusCode, code: codes.OK}
	if resp.StatusCode == http.StatusOK {
		return out
	}
	var refusal struct{ Code, Message string }
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err := json.Unmarshal(body, &refusal); err != nil {
		out.code, out.message = codes.Unknown, string(body)
		return out
	}
	code, ok := connectCodes[refusal.Code]
	if !ok {
		code = codes.Unknown
	}
	out.code, out.message = code, refusal.Message
	return out
}
