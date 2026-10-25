// Package host resolves and securely dials the composed authority host.
package host

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
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
	target, transport, err := Target(endpoint, func() (string, error) {
		local, err := codefly.For(ctx).Module("authority").Service("local").API("grpc").ResolveNetworkInstance()
		if err != nil || local == nil {
			return "", fmt.Errorf("the composition names no authority/endpoint and the local authority (authority/local) is not resolved: %v", err)
		}
		return local.Host, nil
	})
	if err != nil {
		return nil, "", err
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(transport))
	return conn, target, err
}

// Target is the gRPC target and transport for the host at endpoint:
// Plaintext is accepted only on loopback; remote hosts require TLS.
// An empty endpoint is the fallback's, subject to the same transport rule.
func Target(endpoint string, fallback func() (string, error)) (string, credentials.TransportCredentials, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		target, err := fallback()
		if err != nil {
			return "", nil, err
		}
		return plaintext(target)
	}
	if !strings.Contains(endpoint, "://") {
		if _, _, err := net.SplitHostPort(endpoint); err != nil {
			return "", nil, fmt.Errorf("authority/endpoint %q is neither host:port nor a URL", endpoint)
		}
		return plaintext(endpoint)
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", nil, fmt.Errorf("authority/endpoint %q is not an origin", endpoint)
	}
	switch u.Scheme {
	case "https":
		return withPort(u, "443"), credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}), nil
	case "http", "grpc", "tcp":
		return plaintext(withPort(u, "80"))
	default:
		return "", nil, fmt.Errorf("authority/endpoint %q names scheme %q; the host is reached over http:// (h2c) or https://", endpoint, u.Scheme)
	}
}

func withPort(u *url.URL, port string) string {
	if u.Port() != "" {
		return u.Host
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func plaintext(target string) (string, credentials.TransportCredentials, error) {
	hostname, _, err := net.SplitHostPort(target)
	if err != nil {
		return "", nil, fmt.Errorf("authority endpoint must name host:port")
	}
	ip := net.ParseIP(hostname)
	if !strings.EqualFold(hostname, "localhost") && (ip == nil || !ip.IsLoopback()) {
		return "", nil, fmt.Errorf("authority endpoint refuses plaintext to non-local host %q; use https", hostname)
	}
	return target, insecure.NewCredentials(), nil
}
