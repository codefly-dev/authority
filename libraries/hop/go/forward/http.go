package forward

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/codefly-dev/authority/libraries/authority-client/go/host"
	callstamp "github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/decide"
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
	// Ready must be this signer's RegistrationLease.Ready; nil refuses. It is
	// publication state, not proof that downstream verifiers know the key.
	Ready func() bool
	// Refused is told every refusal, so the hop's log names it.
	Refused func(method string, err error)
	// Sink, when set, receives every refusal this face makes, beside the
	// log: those Refused is told, and those the log never named (no
	// admission-key publication, an admission that cannot be signed, a
	// decision with no connection behind it). nil records nothing.
	Sink Sink
}

func (h *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	method := r.Method + " " + r.URL.Path
	md := metadata.MD{}
	for key, values := range r.Header {
		md[strings.ToLower(key)] = values
	}
	// The call as it arrived: the sink is told on its context, whatever
	// deadline the hop puts on the forwarded request below.
	arrived := r.Context()
	var decision decide.Decision
	// refusing answers the caller with err and tells the sink, and the log
	// what the log was always told.
	refusing := func(logged bool, err error) {
		refused(arrived, h.Refused, h.Sink, logged, method, md, decision, err)
		refuse(w, r, err)
	}
	if err := requirePublication(h.Ready); err != nil {
		refusing(false, err)
		return
	}
	if err := routing.CanonicalPath(r.URL.Path, r.URL.EscapedPath()); err != nil {
		refusing(true, status.Error(codes.InvalidArgument, err.Error()))
		return
	}
	decision, err := h.Decide(r.Context(), method, md)
	if err != nil {
		refusing(true, err)
		return
	}
	module, id := decision.Module, decision.Identity
	if decision.Route == nil {
		refusing(false, status.Error(codes.Internal, "the hop decision names no published route"))
		return
	}
	target, ok := h.Upstreams[decision.Route.Address]
	if !ok {
		refusing(false, status.Errorf(codes.Internal, "the hop has no HTTP connection to %s", module))
		return
	}
	stamp := metadata.MD{}
	stamp.Set(hop.WorkContextKey, md.Get(hop.WorkContextKey)...)
	boundMethod := method
	// Connect's server interceptor observes the full procedure, not the HTTP verb.
	if decision.Route.Transport == "connect" {
		boundMethod = r.URL.Path
	}
	// The final pre-sign check admits this call; it does not reserve the
	// lease through Stamp or I/O if Close or expiry races after this point.
	if err := requirePublication(h.Ready); err != nil {
		refusing(false, err)
		return
	}
	if err := hop.Stamp(stamp, id, h.Signer, boundMethod, module, time.Now()); err != nil {
		refusing(false, status.Error(codes.Unauthenticated, err.Error()))
		return
	}
	// The request lives no longer than the Work Context that admitted it: a
	// response the module is still streaming at its expiry is cut there, and a
	// request the module has not answered by then is refused as expired.
	bounded, cancel := hop.UntilExpiry(r.Context(), time.Unix(id.Expires, 0))
	defer cancel()
	r = r.WithContext(bounded)
	(&httputil.ReverseProxy{
		// Never through a proxy from the environment, which would see the stamp,
		// the run's proof and the forwarded Work Context.
		Transport: host.HTTPTransport(),
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
			for name := range pr.Out.Header {
				// No stamp of the caller's and no credential of the caller's
				// (hop.CallerCredentials) reaches the module.
				if lower := strings.ToLower(name); strings.HasPrefix(lower, hop.StampPrefix) || slices.Contains(hop.CallerCredentials, lower) {
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
			if hop.Expired(r.Context()) {
				expired := hop.ExpiredStatus()
				refused(arrived, h.Refused, h.Sink, true, method, md, decision, expired)
				refuse(w, r, expired)
				return
			}
			// A caller that ended its request is not a module that did not
			// answer: the module may be healthy.
			if ended := r.Context().Err(); ended != nil {
				refuse(w, r, status.Errorf(status.FromContextError(ended).Code(), "the caller's request ended before the module answered: %v", ended))
				return
			}
			// The transport error can name the module's internal address:
			// the hop's log is told it, the caller is told what happened.
			failed := status.Errorf(codes.Unavailable, "the module did not answer: %v", err)
			if h.Refused == nil {
				slog.Warn("hop: the module did not answer", "method", method, "module", module, "error", err)
			}
			refused(arrived, h.Refused, h.Sink, true, method, md, decision, failed)
			refuse(w, r, status.Error(codes.Unavailable, "the module did not answer"))
		},
	}).ServeHTTP(w, r)
}

// connectRefusal answers in Connect's (or gRPC's) words only a caller that
// says it speaks the protocol: a Connect-Protocol-Version header, or
// ?connect=v1 on a GET, or a gRPC content type. Without the requirement every
// GET and every POST of an application/* body (a REST or form caller) would
// be taken for Connect, and a reader of {"error"} would lose the reason.
var connectRefusal = connect.NewErrorWriter(connect.WithRequireConnectProtocolHeader())

// statusClientClosedRequest is the HTTP status of a request whose caller went
// away before it was answered; nothing else in HTTP means that.
const statusClientClosedRequest = 499

// refuse answers a refusal in HTTP's words, its reason the decision's own;
// a Connect caller gets Connect's error, so its client keeps the reason.
//
// A denial (Unauthenticated, PermissionDenied) is 401 or 403. A decision that
// reached no verdict is answered as the failure it was, never as a denial or
// a server fault: the caller's request ended (Canceled, 499), or its deadline
// passed or the authority did not answer (DeadlineExceeded, Unavailable, 503).
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
	case codes.ResourceExhausted:
		code = http.StatusTooManyRequests
	case codes.NotFound:
		code = http.StatusNotFound
	case codes.Canceled:
		code = statusClientClosedRequest
	case codes.Unavailable, codes.DeadlineExceeded:
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": s.Message()})
}
