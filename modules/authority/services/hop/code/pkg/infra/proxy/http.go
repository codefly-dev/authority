package proxy

import (
	"encoding/json"
	callstamp "github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/host"
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
		refuse(w, refusal)
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
		refuse(w, err)
		return
	}
	module, id := decision.Module, decision.Identity
	if decision.Route == nil {
		refuse(w, status.Error(codes.Internal, "the hop decision names no published route"))
		return
	}
	target, ok := h.Upstreams[decision.Route.Address]
	if !ok {
		refuse(w, status.Errorf(codes.Internal, "the hop has no HTTP connection to %s", module))
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
		refuse(w, status.Error(codes.Unauthenticated, err.Error()))
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
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			refuse(w, status.Errorf(codes.Unavailable, "the module did not answer: %v", err))
		},
	}).ServeHTTP(w, r)
}

// refuse answers a refusal in HTTP's words, its reason the decision's own.
func refuse(w http.ResponseWriter, err error) {
	s := status.Convert(err)
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
