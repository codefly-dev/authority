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
// RegisterREST serves the key set, and Issue and Check over HTTP for a module
// with no generated client of its own (a Python service): the same methods,
// transcoded to the gRPC service, the caller's Authorization header carried as
// the bearer.
func (p *Plugin) RegisterREST(ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption) error {
	if err := authorityv1.RegisterAuthorityServiceHandlerFromEndpoint(ctx, mux, endpoint, opts); err != nil {
		return err
	}
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

// Migrations: none; the local authority holds state in memory.
func (p *Plugin) Migrations() []string { return nil }

// Issue signs for one owner shape. A person-owned issue is the caller's own: the
// bearer on the call is the session SignIn opened, and nothing in the request
// names a person.
func (p *Plugin) Issue(ctx context.Context, req *authorityv1.IssueRequest) (*authorityv1.IssueResponse, error) {
	out, err := p.Issuer.Issue(withBearer(ctx), req)
	return out, Status(err)
}

// withBearer carries the caller's bearer as the session it names.
func withBearer(ctx context.Context) context.Context {
	if token := Bearer(ctx); token != "" {
		return issuer.WithSession(ctx, token)
	}
	return ctx
}

// Bearer reads the session credential forwarded by the generated transport.
func Bearer(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	for _, value := range md.Get("authorization") {
		if token, found := strings.CutPrefix(value, "Bearer "); found && token != "" {
			return token
		}
	}
	return ""
}

// Delegate records the signed-in person's grant to a module.
func (p *Plugin) Delegate(ctx context.Context, req *authorityv1.DelegateRequest) (*authorityv1.Delegation, error) {
	d, err := p.Issuer.Delegate(withBearer(ctx), req.GetModule(), issuer.FromWire(req.GetScopes()), req.GetPurpose())
	if err != nil {
		return nil, Status(err)
	}
	return delegationOf(d), nil
}

// RevokeDelegation ends one of the signed-in person's delegations.
func (p *Plugin) RevokeDelegation(ctx context.Context, req *authorityv1.RevokeDelegationRequest) (*authorityv1.RevokeDelegationResponse, error) {
	d, err := p.Issuer.RevokeDelegation(withBearer(ctx), req.GetDelegationId())
	if err != nil {
		return nil, Status(err)
	}
	return &authorityv1.RevokeDelegationResponse{Delegation: delegationOf(d)}, nil
}

// GetDelegation reads one delegation for its module or its grantor.
func (p *Plugin) GetDelegation(ctx context.Context, req *authorityv1.GetDelegationRequest) (*authorityv1.Delegation, error) {
	d, err := p.Issuer.GetDelegation(withBearer(ctx), req.GetDelegationId(), req.GetActor().GetCredential())
	if err != nil {
		return nil, Status(err)
	}
	return delegationOf(d), nil
}

func delegationOf(d state.Delegation) *authorityv1.Delegation {
	out := &authorityv1.Delegation{DelegationId: d.ID, OrganizationId: d.Organization, Grantor: d.Grantor, Module: d.Module, Purpose: d.Purpose, Active: !d.Revoked}
	for _, sc := range d.WorkScopes() {
		out.Scopes = append(out.Scopes, &authorityv1.WorkScopeV1{
			ResourceKind: sc.GetResourceKind(), Actions: sc.GetActions(), ResourceIds: sc.GetResourceIds(),
		})
	}
	return out
}

// Check verifies for the audience the caller is.
func (p *Plugin) Check(ctx context.Context, req *authorityv1.CheckRequest) (*authorityv1.CheckResponse, error) {
	if req.GetAdvisory() {
		out, err := p.Issuer.Advise(ctx, req.GetToken(), req.GetAudience(), req.GetMethod())
		return out, Status(err)
	}
	out, err := p.Issuer.Check(ctx, req.GetToken(), req.GetAudience(), req.GetMethod())
	return out, Status(err)
}

// ListResources answers which resources of a kind a capability covers.
func (p *Plugin) ListResources(ctx context.Context, req *authorityv1.ListResourcesRequest) (*authorityv1.ListResourcesResponse, error) {
	grants, err := p.Issuer.ListResources(ctx, req.GetToken(), req.GetAudience(), req.GetResourceKind(), req.GetAction())
	if err != nil {
		return nil, Status(err)
	}
	out := &authorityv1.ListResourcesResponse{}
	for _, g := range grants {
		grant := &authorityv1.ResourceGrant{}
		switch {
		case g.All:
			grant.Match = &authorityv1.ResourceGrant_All{All: true}
		case g.ID != "":
			grant.Match = &authorityv1.ResourceGrant_Id{Id: g.ID}
		case g.Prefix != "":
			grant.Match = &authorityv1.ResourceGrant_Prefix{Prefix: g.Prefix}
		default:
			grant.Match = &authorityv1.ResourceGrant_Pattern{Pattern: g.Pattern}
		}
		out.Grants = append(out.Grants, grant)
	}
	return out, nil
}

// AttachResource records a resource created through the installation the
// presented capability was issued through.
func (p *Plugin) AttachResource(ctx context.Context, req *authorityv1.AttachResourceRequest) (*authorityv1.AttachResourceResponse, error) {
	id, err := p.Issuer.AttachResource(ctx, req.GetToken(), req.GetActor().GetCredential(), req.GetResourceKind(), req.GetResourceId())
	if err != nil {
		return nil, Status(err)
	}
	return &authorityv1.AttachResourceResponse{InstallationId: id}, nil
}

// DetachResource releases a resource its serving module deleted.
func (p *Plugin) DetachResource(ctx context.Context, req *authorityv1.DetachResourceRequest) (*authorityv1.DetachResourceResponse, error) {
	id, err := p.Issuer.DetachResource(ctx, req.GetActor().GetCredential(), req.GetOrganizationId(), req.GetResourceKind(), req.GetResourceId())
	if err != nil {
		return nil, Status(err)
	}
	return &authorityv1.DetachResourceResponse{InstallationId: id}, nil
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
	case errors.Is(err, state.ErrUnauthenticated):
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.Is(err, state.ErrStale), errors.Is(err, state.ErrNotInstalled):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// New is the registry's constructor: the plugin over what Configure wired.
func New() framework.Plugin { return &Plugin{Issuer: wiring.Issuer()} }
