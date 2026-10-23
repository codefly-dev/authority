// Package authority serves codefly.dev/authority: Issue, Check, Keys.
package authority

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"gateway/pkg/framework"
	"gateway/pkg/wiring"
	"net/http"
	"strings"

	"github.com/codefly-dev/core/workcontext"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

// Plugin registers the authority service.
type Plugin struct {
	authorityv1.UnimplementedAuthorityServiceServer
	Issuer *issuer.Issuer
}

// Name is the plugin's identifier.
func (p *Plugin) Name() string { return "authority" }

// RegisterGRPC registers the service.
func (p *Plugin) RegisterGRPC(s *grpc.Server) { authorityv1.RegisterAuthorityServiceServer(s, p) }

// RegisterREST registers nothing; the interface is Connect/gRPC.
func (p *Plugin) RegisterREST(_ context.Context, mux *runtime.ServeMux, _ string, _ []grpc.DialOption) error {
	return mux.HandlePath(http.MethodGet, KeySetPath, func(w http.ResponseWriter, _ *http.Request, _ map[string]string) {
		body, err := KeySet(p.Issuer.Keys())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
}

// KeySetPath is where Keys is published as a JSON Web Key Set, for a consumer
// that reads an authority's keys over HTTP (a work-context group's
// authority-jwks-url). The same keys as Keys, in the standard format.
const KeySetPath = "/.well-known/jwks.json"

// KeySet renders Keys as a JSON Web Key Set: Ed25519 keys as OKP, by key id.
func KeySet(keys *authorityv1.KeysResponse) ([]byte, error) {
	type jwk struct {
		KeyType string `json:"kty"`
		Curve   string `json:"crv"`
		KeyID   string `json:"kid"`
		X       string `json:"x"`
		Use     string `json:"use"`
		Alg     string `json:"alg"`
	}
	set := struct {
		Keys []jwk `json:"keys"`
	}{Keys: []jwk{}}
	for _, k := range keys.GetKeys() {
		if k.GetAlgorithm() != workcontext.Algorithm {
			continue
		}
		set.Keys = append(set.Keys, jwk{KeyType: "OKP", Curve: "Ed25519", KeyID: k.GetKeyId(),
			X: base64.RawURLEncoding.EncodeToString(k.GetPublicKey()), Use: "sig", Alg: "EdDSA"})
	}
	return json.Marshal(set)
}

// Migrations: none; the authority gateway holds state in memory.
func (p *Plugin) Migrations() []string { return nil }

// Issue signs for one owner shape. A person-owned issue is the caller's own: the
// bearer on the call is the session SignIn opened, and nothing in the request
// names a person.
func (p *Plugin) Issue(ctx context.Context, req *authorityv1.IssueRequest) (*authorityv1.IssueResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		for _, value := range md.Get("authorization") {
			if token, found := strings.CutPrefix(value, "Bearer "); found && token != "" {
				ctx = issuer.WithSession(ctx, token)
			}
		}
	}
	out, err := p.Issuer.Issue(ctx, req)
	return out, Status(err)
}

// Check verifies for the audience the caller is.
func (p *Plugin) Check(ctx context.Context, req *authorityv1.CheckRequest) (*authorityv1.CheckResponse, error) {
	out, err := p.Issuer.Check(ctx, req.GetToken(), req.GetAudience())
	return out, Status(err)
}

// Keys returns the issuer and its keys.
func (p *Plugin) Keys(context.Context, *authorityv1.KeysRequest) (*authorityv1.KeysResponse, error) {
	return p.Issuer.Keys(), nil
}

// Status maps a refusal to a gRPC status that names its reason: every refusal
// reaches the caller, none stays only in a log.
func Status(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, state.ErrUnknown), errors.Is(err, workcontext.ErrNoBinding):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, workcontext.ErrRevoked), errors.Is(err, workcontext.ErrNoSeal),
		errors.Is(err, state.ErrForbidden), errors.Is(err, issuer.ErrRefused):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, workcontext.ErrInvalid), errors.Is(err, workcontext.ErrNotACoreToken), errors.Is(err, workcontext.ErrReplayed):
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.Is(err, state.ErrStale):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// New is the registry's constructor: the plugin over what Configure wired.
func New() framework.Plugin { return &Plugin{Issuer: wiring.Issuer()} }
