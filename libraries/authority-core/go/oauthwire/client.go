package oauthwire

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ValidateRegistration bounds the public-client metadata accepted by RFC 7591
// registration. Names are untrusted display text, never a verified publisher.
// This profile supports code + refresh with token_endpoint_auth_method=none;
// adapters must reject requests for other grant types or authentication methods.
func ValidateRegistration(name string, redirects []string) error {
	// client_name is optional in RFC 7591; absence does not require manual registration.
	if !utf8.ValidString(name) || len(name) > 128 || strings.IndexFunc(name, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return errors.New("client_name must contain at most 128 bytes of display text")
	}
	if len(redirects) == 0 || len(redirects) > 8 {
		return errors.New("register 1–8 redirect URIs")
	}
	for _, raw := range redirects {
		if _, err := redirectURL(raw); err != nil {
			return err
		}
	}
	return nil
}

func redirectURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Hostname() == "" || u.Opaque != "" || u.User != nil || strings.ContainsAny(raw, "#*\\\"") || strings.HasSuffix(u.Host, ":") || strings.IndexFunc(raw, func(r rune) bool { return r <= 32 || r >= 127 }) >= 0 {
		return nil, errors.New("invalid redirect URI")
	}
	if port := u.Port(); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return nil, errors.New("invalid redirect port")
		}
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback())) {
		return nil, errors.New("redirect requires HTTPS or HTTP loopback")
	}
	return u, nil
}

// AllowsRedirect matches the registered URI exactly, except RFC 8252's port
// variation for an HTTP loopback IP. Scheme, host, path, escaping and query stay
// bound; this never follows a redirect or fetches a client-supplied URI.
func AllowsRedirect(registered []string, candidate string) bool {
	u, err := redirectURL(candidate)
	if err != nil {
		return false
	}
	for _, raw := range registered {
		v, err := redirectURL(raw)
		if err != nil {
			continue
		}
		if raw == candidate {
			return true
		}
		ip := net.ParseIP(v.Hostname())
		if v.Scheme == "http" && ip != nil && ip.IsLoopback() && u.Scheme == v.Scheme && u.Hostname() == v.Hostname() {
			// Replace only the port, retaining all other components verbatim.
			copy := *u
			copy.Host = v.Host
			if copy.String() == raw {
				return true
			}
		}
	}
	return false
}
