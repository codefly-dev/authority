package forward

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/codefly-dev/authority/libraries/authority-client/go/host"
	callstamp "github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// HTTP is the hop's face for a module that serves HTTP rather than gRPC. The
// decision is the gRPC face's, for the method "<VERB> <path>": the authority
// matches the path against the routes the module declares, and a Connect call
// (a POST to the gRPC method's full name) against that method. A decided
// request goes on to the module unchanged, its caller's stamp stripped and the
// hop's written as headers, the same keys a gRPC module reads as metadata.
type HTTP struct {
	Decide    Decide
	Upstreams map[string]*url.URL
	Signer    *callstamp.Signer
	// Refused is told every refusal, so the hop's log names it.
	Refused func(method string, err error)
}

func (h *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	method := r.Method + " " + r.URL.Path
	if err := routing.CanonicalPath(r.URL.Path, r.URL.EscapedPath()); err != nil {
		refusal := status.Error(codes.InvalidArgument, err.Error())
		if h.Refused != nil {
			h.Refused(method, refusal)
		}
		refuse(w, r, refusal)
		return
	}
	md := metadata.MD{}
	for key, values := range r.Header {
		md[strings.ToLower(key)] = values
	}
	decision, err := h.Decide(r.Context(), method, md)
	if err != nil {
		if h.Refused != nil {
			h.Refused(method, err)
		}
		refuse(w, r, err)
		return
	}
	module, id := decision.Module, decision.Identity
	if decision.Route == nil {
		refuse(w, r, status.Error(codes.Internal, "the hop decision names no published route"))
		return
	}
	target, ok := h.Upstreams[decision.Route.Address]
	if !ok {
		refuse(w, r, status.Errorf(codes.Internal, "the hop has no HTTP connection to %s", module))
		return
	}
	stamp := metadata.MD{}
	stamp.Set(hop.WorkContextKey, md.Get(hop.WorkContextKey)...)
	boundMethod := method
	// Connect's server interceptor observes the full procedure, not the HTTP verb.
	if decision.Route.Transport == "connect" {
		boundMethod = r.URL.Path
	}
	if err := hop.Stamp(stamp, id, h.Signer, boundMethod, module, time.Now()); err != nil {
		refuse(w, r, status.Error(codes.Unauthenticated, err.Error()))
		return
	}
	(&httputil.ReverseProxy{
		// Never through a proxy from the environment, which would see the stamp,
		// the run's proof and the forwarded Work Context.
		Transport: host.HTTPTransport(),
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
			for name := range pr.Out.Header {
				if strings.HasPrefix(strings.ToLower(name), hop.StampPrefix) {
					pr.Out.Header.Del(name)
				}
			}
			for key, values := range stamp {
				if strings.HasPrefix(key, hop.StampPrefix) {
					pr.Out.Header[http.CanonicalHeaderKey(key)] = values
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			refuse(w, r, status.Errorf(codes.Unavailable, "the module did not answer: %v", err))
		},
	}).ServeHTTP(w, r)
}

// connectRefusal answers in Connect's (or gRPC's) words only a caller that
// says it speaks the protocol: a Connect-Protocol-Version header, or
// ?connect=v1 on a GET, or a gRPC content type. Without the requirement every
// GET and every POST of an application/* body (a REST or form caller) would
// be taken for Connect, and a reader of {"error"} would lose the reason.
var connectRefusal = connect.NewErrorWriter(connect.WithRequireConnectProtocolHeader())

// refuse answers a refusal in HTTP's words, its reason the decision's own;
// a Connect caller gets Connect's error, so its client keeps the reason.
func refuse(w http.ResponseWriter, r *http.Request, err error) {
	s := status.Convert(err)
	if connectRefusal.IsSupported(r) {
		_ = connectRefusal.Write(w, r, connect.NewError(connect.Code(s.Code()), errors.New(s.Message())))
		return
	}
	code := http.StatusInternalServerError
	switch s.Code() {
	case codes.Unauthenticated:
		code = http.StatusUnauthorized
	case codes.PermissionDenied:
		code = http.StatusForbidden
	case codes.InvalidArgument:
		code = http.StatusBadRequest
	case codes.NotFound:
		code = http.StatusNotFound
	case codes.Unavailable, codes.DeadlineExceeded:
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": s.Message()})
}
