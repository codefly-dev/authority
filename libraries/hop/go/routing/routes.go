// Package routing shares published route selection between admission and forwarding.
package routing

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
)

// RoutingSchema identifies the Codefly-generated, resolved hop configuration.
const RoutingSchema = "codefly.dev/hop-routes/v1"

// Routing is one immutable composition snapshot. Codefly derives it from the
// published API catalog and resolves its addresses for this hop's visibility.
// It supplies destinations, never authority or evidence that a service is ready.
type Routing struct {
	Schema    string          `json:"schema"`
	Endpoints []RouteEndpoint `json:"endpoints"`
}

// RouteEndpoint retains the published listener identity and its exact inventory.
// Methods are full protobuf procedures for grpc/connect and "VERB /template"
// for http. REST publication is normalized to http by the producer.
type RouteEndpoint struct {
	Audience  string   `json:"audience"`
	Service   string   `json:"service"`
	Endpoint  string   `json:"endpoint"`
	Transport string   `json:"transport"`
	Address   string   `json:"address"`
	Package   string   `json:"package"`
	Version   string   `json:"version"`
	Digest    string   `json:"digest"`
	Methods   []string `json:"methods"`
}

// DecodeRouting refuses malformed snapshots. A refusal must never select an
// older module-wide upstream as a fallback.
func DecodeRouting(raw string) (*Routing, error) {
	var routes Routing
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&routes); err != nil {
		return nil, fmt.Errorf("hop routes: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("hop routes: trailing JSON")
	}
	if err := routes.Validate(); err != nil {
		return nil, err
	}
	return &routes, nil
}

// Validate checks the carrier independently of endpoint resolution. Unresolved
// references are accepted here for Codefly's plan; the hop rejects them at dial.
func (r *Routing) Validate() error {
	if r.Schema != RoutingSchema || len(r.Endpoints) == 0 {
		return fmt.Errorf("hop routes: expected %s and at least one endpoint", RoutingSchema)
	}
	seen, listeners := map[string]RouteEndpoint{}, map[string]bool{}
	for _, e := range r.Endpoints {
		if e.Audience == "" || e.Service == "" || e.Endpoint == "" || e.Address == "" || e.Package == "" || e.Version == "" || e.Digest == "" || len(e.Methods) == 0 {
			return fmt.Errorf("hop routes: incomplete published endpoint identity")
		}
		listener := e.Audience + "/" + e.Service + "/" + e.Endpoint
		if listeners[listener] {
			return fmt.Errorf("hop routes: duplicate endpoint %s", listener)
		}
		listeners[listener] = true
		for _, method := range e.Methods {
			match := method
			switch e.Transport {
			case "grpc", "connect":
				service, operation, ok := strings.Cut(strings.TrimPrefix(method, "/"), "/")
				if !strings.HasPrefix(method, "/") || !ok || service == "" || operation == "" || strings.Contains(operation, "/") {
					return fmt.Errorf("hop routes: invalid procedure %q", method)
				}
				if e.Transport == "connect" {
					match = "POST " + method
				}
			case "http":
				verb, path, ok := strings.Cut(method, " ")
				if !ok || verb == "" || verb != strings.ToUpper(verb) || !strings.HasPrefix(path, "/") {
					return fmt.Errorf("hop routes: invalid HTTP route %q", method)
				}
			default:
				return fmt.Errorf("hop routes: unsupported transport %q", e.Transport)
			}
			transport := e.Transport
			if transport == "connect" {
				transport = "http"
			}
			keys := []string{e.Audience + "\x00" + transport + "\x00" + match}
			if e.Transport == "connect" {
				keys = append(keys, e.Audience+"\x00grpc\x00"+method)
			}
			for _, key := range keys {
				if prior, taken := seen[key]; taken {
					if err := sameDestination(prior, e); err != nil {
						return fmt.Errorf("hop routes: ambiguous destination for %s %s: %w", e.Audience, method, err)
					}
					continue
				}
				seen[key] = e
			}
		}
	}
	return nil
}

// sameDestination accepts one collision only: a service publishing the same
// contract on its gRPC endpoint and on its Connect endpoint, which also serves
// gRPC. That is one destination with one policy; Resolve prefers Connect.
// Anything else claiming a procedure twice is refused by name.
func sameDestination(a, b RouteEndpoint) error {
	name := func(e RouteEndpoint) string {
		return e.Audience + "/" + e.Service + "/" + e.Endpoint + " (" + e.Transport + ")"
	}
	if a.Audience != b.Audience || a.Service != b.Service || a.Transport == b.Transport ||
		(a.Transport != "grpc" && a.Transport != "connect") || (b.Transport != "grpc" && b.Transport != "connect") {
		return fmt.Errorf("published by %s and %s", name(a), name(b))
	}
	if a.Package != b.Package || a.Version != b.Version || a.Digest != b.Digest {
		return fmt.Errorf("%s and %s publish it under different contracts (%s@%s %s, %s@%s %s), so their policies may differ",
			name(a), name(b), a.Package, a.Version, a.Digest, b.Package, b.Version, b.Digest)
	}
	return nil
}

// Find selects a published route after the caller's audience has been checked.
// HTTP includes Connect POSTs, selected from publication, never path heuristics.
// Exact matches win, as in method admission; overlapping templates are refused.
func (r *Routing) Find(audience, transport, method string) (RouteEndpoint, error) {
	endpoint, _, err := r.Resolve(audience, transport, method)
	return endpoint, err
}

// Resolve selects a destination. HTTP admission always uses the concrete request;
// only a published Connect procedure maps to its protobuf method name.
// A gRPC method's existence never supplies policy for a different HTTP listener.
func (r *Routing) Resolve(audience, transport, method string) (RouteEndpoint, string, error) {
	if r == nil {
		return RouteEndpoint{}, "", fmt.Errorf("hop routes: generated routing snapshot is required")
	}
	if transport == "http" {
		_, requestPath, ok := strings.Cut(method, " ")
		if !ok {
			return RouteEndpoint{}, "", fmt.Errorf("hop routes: HTTP request must name method and path")
		}
		if err := CanonicalPath(requestPath, ""); err != nil {
			return RouteEndpoint{}, "", err
		}
	}

	type match struct {
		endpoint RouteEndpoint
		policy   string
	}
	var matched []match
	var exact *match
	for _, endpoint := range r.Endpoints {
		if endpoint.Audience != audience || (endpoint.Transport != transport && !((transport == "http" || transport == "grpc") && endpoint.Transport == "connect")) {
			continue
		}
		for _, declared := range endpoint.Methods {
			policy := method
			if endpoint.Transport == "connect" && transport == "http" {
				policy = declared
				declared = "POST " + declared
			}
			if declared == method {
				if exact == nil {
					exact = &match{endpoint, policy}
					continue
				}
				// Only one service's gRPC and Connect endpoints may share a
				// procedure; Connect serves gRPC too, so it is the destination.
				if err := sameDestination(exact.endpoint, endpoint); err != nil {
					return RouteEndpoint{}, "", fmt.Errorf("hop routes: ambiguous destination for %s %s: %w", audience, method, err)
				}
				if endpoint.Transport == "connect" {
					exact = &match{endpoint, policy}
				}
				continue
			}
			verb, path, ok := strings.Cut(method, " ")
			wantVerb, template, wantOK := strings.Cut(declared, " ")
			if endpoint.Transport == "http" && ok && wantOK && verb == wantVerb && RouteMatches(template, path) {
				matched = append(matched, match{endpoint, policy})
			}
		}
	}
	if exact != nil {
		return exact.endpoint, exact.policy, nil
	}
	if len(matched) == 1 {
		return matched[0].endpoint, matched[0].policy, nil
	}
	return RouteEndpoint{}, "", fmt.Errorf("hop routes: %s %s has %d matching published destinations", audience, method, len(matched))
}

// ResolvedURL validates a resolved HTTP or Connect destination without allowing
// credentials, query rewriting, or unresolved endpoint references into a proxy.
func (e RouteEndpoint) ResolvedURL() (*url.URL, error) {
	u, err := url.Parse(e.Address)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.Contains(e.Address, "${") {
		return nil, fmt.Errorf("hop routes: %s/%s/%s has no resolved HTTP address", e.Audience, e.Service, e.Endpoint)
	}
	return u, nil
}

// RouteMatches is the shared admission/forwarding template matcher. A final
// {name=**} spans at least one character; ordinary variables span one segment.
func RouteMatches(template, path string) bool {
	if CanonicalPath(path, "") != nil {
		return false
	}
	want, got := strings.Split(template, "/"), strings.Split(path, "/")
	if last := want[len(want)-1]; strings.Contains(last, "=**}") {
		if len(got) < len(want) {
			return false
		}
		open := strings.Index(last, "{")
		if open < 0 {
			return false
		}
		prefix, suffix := last[:open], last[strings.Index(last, "=**}")+4:]
		rest := strings.Join(got[len(want)-1:], "/")
		if !strings.HasPrefix(rest, prefix) || !strings.HasSuffix(rest, suffix) || len(rest) <= len(prefix)+len(suffix) {
			return false
		}
		want, got = want[:len(want)-1], got[:len(want)-1]
	}
	if len(want) != len(got) {
		return false
	}
	for i, segment := range want {
		if !segmentMatches(segment, got[i]) {
			return false
		}
	}
	return true
}

func segmentMatches(template, segment string) bool {
	open := strings.IndexByte(template, '{')
	if open < 0 {
		return template == segment
	}
	end := strings.IndexByte(template[open:], '}')
	if end < 0 || !strings.HasPrefix(segment, template[:open]) {
		return false
	}
	rest, tail := segment[open:], template[open+end+1:]
	for i := 1; i <= len(rest); i++ {
		if segmentMatches(tail, rest[i:]) {
			return true
		}
	}
	return false
}

// CanonicalPath rejects paths whose interpretation can change at a later proxy.
// Escaped separators, dot segments and nested escapes are never normalized here.
func CanonicalPath(decoded, escaped string) error {
	bad := decoded == "" || !strings.HasPrefix(decoded, "/") || path.Clean(decoded) != decoded || strings.ContainsAny(decoded, "\\%")
	lower := strings.ToLower(escaped)
	for _, escape := range []string{"%2e", "%2f", "%5c", "%25"} {
		bad = bad || strings.Contains(lower, escape)
	}
	if bad {
		return fmt.Errorf("hop routes: non-canonical request path is refused; use a canonical path without dot segments, repeated or encoded separators")
	}
	return nil
}
