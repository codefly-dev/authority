// Package oauthwire supplies stateless MCP acquisition protocol checks. It does
// not register clients, store codes, sign in people, derive grants or mint tokens.
// Hosts must supply those operations and trusted, resolved public URLs before
// publishing discovery. Nothing in this package enables an HTTP endpoint.
package oauthwire

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Discovery names public endpoints supplied by their route owner, never by an
// unauthenticated request's Host or forwarding headers. Resource is the complete
// URL the MCP client dials; none of these strings is normalized or reconstructed.
type Discovery struct {
	Resource, ResourceMetadataURL, Issuer, AuthorizationEndpoint, TokenEndpoint string
	// Set these only when the host actually implements the corresponding flow.
	RegistrationEndpoint    string
	ClientMetadataSupported bool
	Scopes                  []string
	// Local permits HTTP on a loopback host for a local composition.
	Local bool
}

// ProtectedResourceMetadata is RFC 9728's document for one solution.
type ProtectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	BearerMethods        []string `json:"bearer_methods_supported"`
	Scopes               []string `json:"scopes_supported,omitempty"`
}

// AuthorizationServerMetadata describes an authorization-code + PKCE server
// with refresh for public clients. A host must implement these capabilities
// before publishing the document; discovery is not an implementation of them.
type AuthorizationServerMetadata struct {
	Issuer                   string   `json:"issuer"`
	AuthorizationEndpoint    string   `json:"authorization_endpoint"`
	TokenEndpoint            string   `json:"token_endpoint"`
	ResponseTypes            []string `json:"response_types_supported"`
	GrantTypes               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethods     []string `json:"code_challenge_methods_supported"`
	Scopes                   []string `json:"scopes_supported,omitempty"`
	RegistrationEndpoint     string   `json:"registration_endpoint,omitempty"`
	ClientMetadataSupported  bool     `json:"client_id_metadata_document_supported,omitempty"`
}

// Documents validates the supplied route declarations before constructing either
// document. The caller serves JSON at the declared resource metadata URL and at
// the issuer's RFC 8414 well-known location, without requiring authentication.
func (d Discovery) Documents() (ProtectedResourceMetadata, AuthorizationServerMetadata, error) {
	for name, raw := range map[string]string{
		"resource": d.Resource, "resource metadata": d.ResourceMetadataURL,
		"issuer": d.Issuer, "authorization endpoint": d.AuthorizationEndpoint,
		"token endpoint": d.TokenEndpoint,
	} {
		if err := publicURL(raw, d.Local); err != nil {
			return ProtectedResourceMetadata{}, AuthorizationServerMetadata{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	if d.RegistrationEndpoint != "" {
		if err := publicURL(d.RegistrationEndpoint, d.Local); err != nil {
			return ProtectedResourceMetadata{}, AuthorizationServerMetadata{}, fmt.Errorf("registration endpoint: %w", err)
		}
	}
	resource, _ := url.Parse(d.Resource)
	metadata, _ := url.Parse(d.ResourceMetadataURL)
	if resource.Scheme != metadata.Scheme || resource.Host != metadata.Host {
		return ProtectedResourceMetadata{}, AuthorizationServerMetadata{}, errors.New("resource metadata must be on the resource's edge origin")
	}
	for _, s := range d.Scopes {
		// RFC 6749 scope-token: printable ASCII excluding quote and backslash.
		if s == "" || strings.IndexFunc(s, func(c rune) bool { return c < 0x21 || c > 0x7e || c == '"' || c == '\\' }) >= 0 {
			return ProtectedResourceMetadata{}, AuthorizationServerMetadata{}, errors.New("a scope must be one OAuth scope-token")
		}
	}
	return ProtectedResourceMetadata{
		Resource: d.Resource, AuthorizationServers: []string{d.Issuer},
		BearerMethods: []string{"header"}, Scopes: append([]string(nil), d.Scopes...),
	}, AuthorizationServerMetadata{
		Issuer: d.Issuer, AuthorizationEndpoint: d.AuthorizationEndpoint, TokenEndpoint: d.TokenEndpoint,
		ResponseTypes: []string{"code"}, GrantTypes: []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethods: []string{"none"}, CodeChallengeMethods: []string{S256},
		Scopes: append([]string(nil), d.Scopes...), RegistrationEndpoint: d.RegistrationEndpoint,
		ClientMetadataSupported: d.ClientMetadataSupported,
	}, nil
}

// Challenge is the WWW-Authenticate value for an unauthenticated MCP request's
// 401. No error is attached to the initial request without a credential (6750
// section 3.1). Bad credentials may additionally be reported as invalid_token by
// the host. Resource metadata is a URL, not a token or a session identifier.
func (d Discovery) Challenge() (string, error) {
	if _, _, err := d.Documents(); err != nil {
		return "", err
	}
	return `Bearer resource_metadata="` + d.ResourceMetadataURL + `"`, nil
}

func publicURL(raw string, local bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.Opaque != "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") ||
		strings.ContainsAny(raw, "\"\\") || strings.IndexFunc(raw, func(c rune) bool { return c <= 0x20 || c >= 0x7f }) >= 0 {
		return errors.New("a resolved public URL must be absolute, with no userinfo, query, fragment or unsafe characters")
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if local && u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()) {
		return nil
	}
	return errors.New("a public URL requires HTTPS, or HTTP loopback in a local composition")
}
