package main

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

// dialHost connects to the host whose authority interface the hop asks. The
// composition names it in the authority group's endpoint, the key every module
// reads for the same host; a composition that names none reaches the authority
// module's local authority, as before.
func dialHost(ctx context.Context) (*grpc.ClientConn, string, error) {
	endpoint, _, err := codefly.For(ctx).WorkspaceValueIfSet("authority", "endpoint")
	if err != nil {
		return nil, "", fmt.Errorf("authority/endpoint cannot be read: %w", err)
	}
	target, transport, err := hostTarget(endpoint, func() (string, error) {
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

// hostTarget is the gRPC target and transport for the host at endpoint:
// host:port or http:// is the run's plaintext transport (h2c; in a cell the
// mesh carries it), https:// is TLS. An empty endpoint is the fallback's.
func hostTarget(endpoint string, fallback func() (string, error)) (string, credentials.TransportCredentials, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		target, err := fallback()
		return target, insecure.NewCredentials(), err
	}
	if !strings.Contains(endpoint, "://") {
		if _, _, err := net.SplitHostPort(endpoint); err != nil {
			return "", nil, fmt.Errorf("authority/endpoint %q is neither host:port nor a URL", endpoint)
		}
		return endpoint, insecure.NewCredentials(), nil
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", nil, fmt.Errorf("authority/endpoint %q is not an origin", endpoint)
	}
	switch u.Scheme {
	case "https":
		return withPort(u, "443"), credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}), nil
	case "http", "grpc", "tcp":
		return withPort(u, "80"), insecure.NewCredentials(), nil
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
