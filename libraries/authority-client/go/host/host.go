// Package host resolves and securely dials the composed authority host.
package host

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	codefly "github.com/codefly-dev/sdk-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Dial connects to the host the edge calls (the authority, session and
// installation interfaces). The composition names it in the authority group's
// endpoint, the key every module reads for the same host; a composition that
// names none reaches the authority module's local authority, as before.
func Dial(ctx context.Context) (*grpc.ClientConn, string, error) {
	endpoint, _, err := codefly.For(ctx).WorkspaceValueIfSet("authority", "endpoint")
	if err != nil {
		return nil, "", fmt.Errorf("authority/endpoint cannot be read: %w", err)
	}
	target, transport, err := targetFor(ctx, endpoint, func() (string, error) {
		local, err := codefly.For(ctx).Module("authority").Service("local").API("grpc").ResolveNetworkInstance()
		if err != nil || local == nil {
			return "", fmt.Errorf("the composition names no authority/endpoint and the local authority (authority/local) is not resolved: %v", err)
		}
		return local.Host, nil
	})
	if err != nil {
		return nil, "", err
	}
	conn, err := grpc.NewClient(target, DialOptions(transport)...)
	return conn, target, err
}

// DialOptions are how an address Target or Endpoint admitted is dialled: over
// its transport, and never through a proxy from the environment (HTTPS_PROXY,
// HTTP_PROXY), which would see the workload credential and could swap the
// published keys on a plaintext mesh hop. Dial uses them; a caller dialling an
// admitted address itself (the hop's upstreams, a module's own clients) does too.
func DialOptions(transport credentials.TransportCredentials) []grpc.DialOption {
	return []grpc.DialOption{grpc.WithTransportCredentials(transport), grpc.WithNoProxy()}
}

// noProxy is Go's default HTTP transport minus any proxy from the environment,
// held in an unexported field: callers get a RoundTripper they cannot unwrap,
// so no one can turn proxies back on for every caller with one assignment.
type noProxy struct{ transport *http.Transport }

func (n noProxy) RoundTrip(request *http.Request) (*http.Response, error) {
	return n.transport.RoundTrip(request)
}

// httpTransport is shared so its connections are pooled.
var httpTransport = func() noProxy {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return noProxy{transport: transport}
}()

// HTTPTransport is DialOptions for HTTP: the one RoundTripper every HTTP request
// carrying a Work Context, a stamp or the run's proof is sent over (the hop's
// HTTP face, the edge's reverse proxy). It never consults HTTP_PROXY or
// HTTPS_PROXY, and it exposes no *http.Transport to reconfigure. The
// repository's no-proxy gate (tools/noproxygate) type-checks every module and
// refuses requests, dials and subprocesses that bypass this seam or
// DialOptions. Its blind spots, by class: raw sockets, unsafe, go:linkname,
// cgo, reflection, subprocesses started by other means than those it refuses,
// third-party clients, and options built but not used.
func HTTPTransport() http.RoundTripper { return httpTransport }

// Target is the gRPC target and transport for the host at endpoint:
// HTTPS uses verified TLS. Plaintext requires a local loopback or the
// composition's literal mesh assertion and an in-cluster Service address.
// The SDK-resolved fallback follows the same rule.
func Target(endpoint string, fallback func() (string, error)) (string, credentials.TransportCredentials, error) {
	return targetFor(context.Background(), endpoint, fallback)
}

// Endpoint validates an explicit upstream with the same transport rule as Dial.
// It carries the caller's SDK context so mesh/local decisions have one source.
func Endpoint(ctx context.Context, endpoint string) (string, credentials.TransportCredentials, error) {
	return targetFor(ctx, endpoint, nil)
}

func targetFor(ctx context.Context, endpoint string, fallback func() (string, error)) (string, credentials.TransportCredentials, error) {
	mesh, err := meshProtected(codefly.For(ctx).WorkspaceValueIfSet)
	if err != nil {
		return "", nil, err
	}

	// Control characters are refused in the raw value, before any trimming, so
	// Go and Python (whose strip also removes \x1c-\x1f) judge the same bytes.
	if strings.ContainsFunc(endpoint, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", nil, fmt.Errorf("authority/endpoint carries a control character (value not shown: it may carry a credential)")
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		if fallback == nil {
			return "", nil, fmt.Errorf("transport endpoint is empty; supply a resolved endpoint")
		}
		target, err := fallback()
		if err != nil {
			return "", nil, err
		}
		return plaintext(target, codefly.IsLocal(), mesh)
	}
	if !strings.Contains(endpoint, "://") {
		if _, _, err := net.SplitHostPort(endpoint); err != nil {
			return "", nil, fmt.Errorf("authority/endpoint is neither host:port nor a URL (value not shown: it may carry a credential)")
		}
		return plaintext(endpoint, codefly.IsLocal(), mesh)
	}
	u, err := url.Parse(endpoint)
	if err == nil && u.Host != "" && u.Hostname() == "" {
		return "", nil, fmt.Errorf("authority/endpoint %s names no host", hostOnly(u))
	}
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", nil, fmt.Errorf("authority/endpoint %s is not an origin: it must carry no credential, path, query or fragment", hostOnly(u))
	}
	switch u.Scheme {
	case "https":
		if !validPort(withPort(u, "443")) {
			return "", nil, fmt.Errorf("authority/endpoint %s names no port in 1-65535", hostOnly(u))
		}
		return withPort(u, "443"), credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}), nil
	case "http", "grpc", "tcp":
		return plaintext(withPort(u, "80"), codefly.IsLocal(), mesh)
	default:
		return "", nil, fmt.Errorf("authority/endpoint %s names scheme %q; the host is reached over http:// (h2c) or https://", hostOnly(u), u.Scheme)
	}
}

// hostOnly names an endpoint in an error by its host and port alone: never the
// raw value, its userinfo, path or query, which may carry a credential.
func hostOnly(u *url.URL) string {
	if u == nil || u.Host == "" {
		return "(unparseable)"
	}
	return u.Host
}

// validPort reports whether target names a decimal port in 1..65535 written in
// at most five digits: never an empty port (the dialer reads it as 0), a sign,
// a space, a zero-padded longer spelling or an out-of-range one.
func validPort(target string) bool {
	_, port, err := net.SplitHostPort(target)
	if err != nil || port == "" || len(port) > 5 || strings.TrimLeft(port, "0123456789") != "" {
		return false
	}
	number, err := strconv.Atoi(port)
	return err == nil && number >= 1 && number <= 65535
}

func withPort(u *url.URL, port string) string {
	if u.Port() != "" {
		return u.Host
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func plaintext(target string, local, mesh bool) (string, credentials.TransportCredentials, error) {
	hostname, _, err := net.SplitHostPort(target)
	if err != nil {
		return "", nil, fmt.Errorf("authority endpoint must name host:port")
	}
	if !validPort(target) {
		return "", nil, fmt.Errorf("authority endpoint names no port in 1-65535")
	}
	ip := net.ParseIP(hostname)
	loopback := strings.EqualFold(hostname, "localhost") || ip != nil && ip.IsLoopback()
	if !(local && loopback) && !(mesh && clusterServiceHost(hostname)) {
		return "", nil, fmt.Errorf("authority endpoint requires HTTPS, local loopback, or an in-cluster Service address with internal-transport/mesh-protected=true")
	}
	return target, insecure.NewCredentials(), nil
}

func meshProtected(read func(string, string) (string, bool, error)) (bool, error) {
	value, set, err := read("internal-transport", "mesh-protected")
	if err != nil {
		return false, fmt.Errorf("internal-transport/mesh-protected could not be read")
	}
	if !set || value == "" || value == "false" {
		return false, nil
	}
	if value != "true" {
		return false, fmt.Errorf("internal-transport/mesh-protected must be exactly true or false")
	}
	return true, nil
}

// The mesh assertion covers Service DNS names, never arbitrary hosts or IPs.
func clusterServiceHost(hostname string) bool {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(hostname), "."), ".")
	if len(labels) != 3 && len(labels) != 5 {
		return false
	}
	if labels[2] != "svc" || len(labels) == 5 && (labels[3] != "cluster" || labels[4] != "local") {
		return false
	}
	for _, label := range labels[:2] {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
