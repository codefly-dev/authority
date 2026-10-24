package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/codefly-dev/authority/libraries/hop/go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// HTTP is the hop's face for a module that serves HTTP rather than gRPC. The
// decision is the gRPC face's, for the method "<VERB> <path>": the authority
// matches the path against the routes the module declares. A decided request
// goes on to the module unchanged, its caller's stamp stripped and the hop's
// written as headers, the same keys a gRPC module reads as metadata.
type HTTP struct {
	Decide    Decide
	Upstreams map[string]*url.URL
	Proof     string
	// Refused is told every refusal, so the hop's log names it.
	Refused func(method string, err error)
}

func (h *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	method := r.Method + " " + r.URL.Path
	md := metadata.MD{}
	for key, values := range r.Header {
		md[strings.ToLower(key)] = values
	}
	module, id, err := h.Decide(r.Context(), method, md)
	if err != nil {
		if h.Refused != nil {
			h.Refused(method, err)
		}
		refuse(w, err)
		return
	}
	target, ok := h.Upstreams[module]
	if !ok {
		refuse(w, status.Errorf(codes.Internal, "the hop has no HTTP connection to %s", module))
		return
	}
	stamp := metadata.MD{}
	stamp.Set(hop.WorkContextKey, md.Get(hop.WorkContextKey)...)
	hop.Stamp(stamp, id, h.Proof)
	(&httputil.ReverseProxy{
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
