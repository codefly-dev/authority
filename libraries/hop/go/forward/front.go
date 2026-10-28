// Package forward is the hop's front door, for any host that stands in front of
// modules: the authority module's hop on a laptop, a gateway on a cell. Every
// call it receives is decided by the authority's Check (decide), stamped with
// the identity the authority returned and the host's admission key (hop.Stamp),
// and forwarded unchanged to the one listener the generated routes publish for
// it: gRPC as opaque frames (Proxy), HTTP and Connect as the request itself
// (HTTP). New builds both faces from what a host is configured with; the host
// keeps its own listeners.
package forward

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/host"
	callstamp "github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"github.com/codefly-dev/core/wool"
	"google.golang.org/grpc"

	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/decide"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
)

// Authority is what the front door asks of the authority interface: Check, for
// every call, and RegisterAdmissionKey, to publish the host's admission key.
// The interface's generated client serves both
// (authorityv1.NewAuthorityServiceClient).
type Authority interface {
	decide.Checker
	hop.Registrar
}

// Config is what a host hands the front door. Every field but Enforcement and
// Log is required.
type Config struct {
	// Signer holds the host's admission key, from the seed Codefly delivers
	// to the host (stamp.NewSigner). The seed never leaves the host.
	Signer *callstamp.Signer
	// Authority is the authority interface's generated client, over the
	// connection the host dialled (host.Dial). The host closes it.
	Authority Authority
	// Credential returns the host's own workload credential, read fresh on
	// every registration of its admission key (hop.RunCredential for a
	// Codefly-run workload).
	Credential func() (string, error)
	// Modules are the modules the host stands in front of, as the composition
	// names them; a call addressed to any other is refused.
	Modules []string
	// Routes is the generated hop-routes/ROUTES view, as Codefly delivered it:
	// every published listener of every module in Modules.
	Routes string
	// Enforcement is the host's configured enforcement mode; only enforce
	// (or nothing) is accepted.
	Enforcement string
	// Log names every refusal and the admission key's registration; nil is
	// the context's logger, in "hop".
	Log *wool.Wool
}

// Front is the host's half of standing in front of modules: the gRPC face,
// installed on the host's gRPC server, and the HTTP/Connect face, served on
// the host's HTTP listener.
type Front struct {
	publication *hop.RegistrationLease
	// ServerOptions make the host's gRPC server answer every method it does
	// not serve itself through the gRPC face.
	ServerOptions []grpc.ServerOption
	// Handler is the HTTP/Connect face. A host serves it even when every
	// route is gRPC, so its declared endpoint answers; it refuses every
	// request no published HTTP or Connect route admits.
	Handler http.Handler
	// Close stops renewing the admission key's registration and closes every
	// connection to a module. It does not close the authority's.
	Close func()
}

// Ready reports only an unexpired publication lease for this front's signer.
// It does not prove that downstream verifiers have learned a newly published
// key; the prepublication overlap contract still applies. Cancellation of New's
// context or Close makes it false. Hosts combine it with their other checks.
func (f *Front) Ready() bool {
	return f != nil && f.publication.Ready()
}

// RouteProducerVersion is the first producer revision; no released version is
// claimed until CLI #1158 ships it. That PR must merge with or before this hop.
const RouteProducerVersion = "Codefly CLI eee37c1117 (hop-routes/v1 producer), shipping via codefly-dev/cli#1158, or a successor containing that producer"

// MissingRoutes is the refusal for a generated hop-routes/ROUTES view a host
// could not read, or read and cannot use: it names the producer it requires.
func MissingRoutes(err error) error {
	return fmt.Errorf("hop: generated hop-routes/ROUTES requires %s: %w", RouteProducerVersion, err)
}

// New validates the routes against the modules, dials each published
// listener over its transport (host.Endpoint, host.DialOptions), refuses any
// enforcement but enforce, and attempts admission-key registration before it
// returns. A registration failure leaves the front unready and both faces
// unavailable while the same registration loop retries. It renews until ctx is
// cancelled or Close is called. Invalid configuration returns an error instead.
func New(ctx context.Context, c Config) (*Front, error) {
	if c.Signer == nil || c.Authority == nil || c.Credential == nil {
		return nil, fmt.Errorf("hop: the front door needs the host's signer, the authority's client and the host's workload credential")
	}
	if len(c.Modules) == 0 {
		return nil, fmt.Errorf("hop: the front door names no module to stand in front of")
	}
	w := c.Log
	if w == nil {
		w = wool.Get(ctx).In("hop")
	}
	routes, err := requiredRoutes(c.Routes)
	if err != nil {
		return nil, err
	}
	modules, upstreams, webs := map[string]bool{}, map[string]*grpc.ClientConn{}, map[string]*url.URL{}
	configured := false
	defer func() {
		if !configured {
			for _, conn := range upstreams {
				_ = conn.Close()
			}
		}
	}()
	for _, name := range c.Modules {
		modules[strings.TrimSpace(name)] = true
	}
	covered := map[string]bool{}
	for _, route := range routes.Endpoints {
		if !modules[route.Audience] {
			return nil, fmt.Errorf("hop routes: undeclared audience %s", route.Audience)
		}
		dialTarget, transport, transportErr := host.Endpoint(ctx, route.Address)
		if transportErr != nil {
			return nil, fmt.Errorf("hop routes: %s/%s: %w", route.Audience, route.Service, transportErr)
		}
		covered[route.Audience] = true
		switch route.Transport {
		case "grpc", "connect":
			if route.Transport == "connect" {
				target, urlErr := route.ResolvedURL()
				if urlErr != nil {
					return nil, urlErr
				}
				webs[route.Address] = target
			}
			if strings.Contains(route.Address, "${") {
				return nil, fmt.Errorf("hop routes: unresolved endpoint for %s/%s", route.Audience, route.Service)
			}
			if upstreams[route.Address] != nil {
				continue
			}
			conn, dialErr := grpc.NewClient(dialTarget, append(host.DialOptions(transport), grpc.WithDefaultCallOptions(CallOptions()...))...)
			if dialErr != nil {
				return nil, dialErr
			}
			upstreams[route.Address] = conn
		default:
			target, urlErr := route.ResolvedURL()
			if urlErr != nil {
				return nil, urlErr
			}
			webs[route.Address] = target
		}
	}
	for module := range modules {
		if !covered[module] {
			return nil, fmt.Errorf("hop routes: no published endpoint for %s", module)
		}
	}
	// Legacy warning mode must not issue an admission for a policy refusal.
	if err := requireEnforcement(c.Enforcement); err != nil {
		return nil, err
	}
	refused := func(method string, err error) {
		w.Warn("refused", wool.Field("method", method), wool.Field("reason", err.Error()))
	}
	// The authority publishes the host's admission key once the host
	// registers it, proving itself with its workload credential and the key's
	// own proof: the seed stays here.
	publication := hop.Registration{Authority: c.Authority, Signer: c.Signer, Credential: c.Credential, Report: registrationReport(w)}.Start(ctx)
	decision := decide.Decider{Routes: routes, Authority: c.Authority, Modules: modules}.Decide
	p := &Proxy{Decide: decision, Upstreams: upstreams, Signer: c.Signer, Refused: refused, Ready: publication.Ready}
	configured = true
	var closeOnce sync.Once
	return &Front{
		publication:   publication,
		ServerOptions: p.ServerOptions(),
		Handler:       &HTTP{Decide: decision, Upstreams: webs, Signer: c.Signer, Refused: refused, Ready: publication.Ready},
		Close: func() {
			closeOnce.Do(func() {
				publication.Close()
				for _, conn := range upstreams {
					_ = conn.Close()
				}
			})
		},
	}, nil
}

// registrationReport logs each change of the registration's outcome: the
// published key's id (never the seed, never the private key) and when it
// lapses, or why an attempt failed. The id and the reason lead each line,
// in no label the run's log redaction reads as a credential's: a line naming
// "authority" and "key" before its first "=" or ":" has everything after it
// masked once the run forwards it, which hid the key id as "admission=****".
func registrationReport(w *wool.Wool) func(*authorityv1.PublicKey, time.Time, error) {
	return func(key *authorityv1.PublicKey, expires time.Time, err error) {
		if err != nil {
			w.Warn("hop admission registration failed; any acknowledged lease lasts only until its expiry; retrying: " + err.Error())
			return
		}
		w.Info(fmt.Sprintf("hop admission %s published, lapsing at %s unless renewed", key.GetKeyId(), expires.UTC().Format(time.RFC3339)))
	}
}

func requiredRoutes(raw string) (*routing.Routing, error) {
	routes, err := routing.DecodeRouting(raw)
	if err != nil {
		return nil, MissingRoutes(err)
	}
	return routes, nil
}

// requireEnforcement refuses legacy permissive configuration in every environment.
func requireEnforcement(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "enforce":
		return nil
	default:
		return fmt.Errorf("hop/ENFORCEMENT must be enforce: signed admissions require enforced method policy")
	}
}
