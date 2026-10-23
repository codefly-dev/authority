// Package issuer is the authority interface on top of core's Work Context
// library: Issue for every owner shape, Check for every callee, Keys for every
// verifier. It mints with core's Authority and verifies with core's Verifier,
// so the laptop signs and refuses exactly as a cell does; what it adds is only
// the resolution of an owner shape into core's inputs against the state.
package issuer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"gateway/pkg/business/state"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

// MaxTTL is the ceiling every capability is clamped to.
const MaxTTL = 15 * time.Minute

type sessionKey struct{}

// WithSession records the caller's own session on the context, as the transport
// layer resolved it from the bearer the call carried. A person-owned Issue reads
// nothing else about who is asking.
func WithSession(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, sessionKey{}, sessionID)
}

func sessionOf(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(sessionKey{}).(string)
	return id, ok && id != ""
}

// ErrRefused is the umbrella for a refusal the caller can do nothing about.
var ErrRefused = errors.New("issuer: refused")

// Issuer signs and verifies.
type Issuer struct {
	state     *state.State
	authority *workcontext.Authority
	replay    workcontext.ReplayStore
	public    ed25519.PublicKey
}

// New builds an issuer for one host identity and one signing key.
func New(st *state.State, issuer, keyID string, key ed25519.PrivateKey, now func() time.Time) *Issuer {
	return &Issuer{
		state:  st,
		public: key.Public().(ed25519.PublicKey),
		replay: workcontext.NewMemoryReplayStore(),
		authority: &workcontext.Authority{
			Issuer: issuer, KeyID: keyID, Key: key, Revisions: st, Seals: st, MaxTTL: MaxTTL, Now: now,
		},
	}
}

// Keys is what a verifier pins.
func (i *Issuer) Keys() *authorityv1.KeysResponse {
	return &authorityv1.KeysResponse{Issuer: i.authority.Issuer, Keys: []*authorityv1.PublicKey{{
		KeyId: i.authority.KeyID, Algorithm: workcontext.Algorithm, PublicKey: []byte(i.public),
	}}}
}

func (i *Issuer) verifier(audience string) *workcontext.Verifier {
	return &workcontext.Verifier{
		Issuer: i.authority.Issuer, Audience: audience,
		Keys:      map[string]ed25519.PublicKey{i.authority.KeyID: i.public},
		Revisions: i.state, Replay: i.replay, Seals: i.state, Grants: i.state, Now: i.authority.Now,
	}
}

// Check verifies a capability for the audience the caller is.
func (i *Issuer) Check(ctx context.Context, token, audience string) (*authorityv1.CheckResponse, error) {
	if audience == "" {
		return nil, fmt.Errorf("%w: a check names the audience the caller is", ErrRefused)
	}
	verified, err := i.verifier(audience).Verify(ctx, token)
	if err != nil {
		return nil, err
	}
	wc, err := ToWire(verified.Context())
	if err != nil {
		return nil, err
	}
	revision, err := i.state.AuthorizationRevision(ctx, verified.Context().GetTenantId())
	if err != nil {
		return nil, err
	}
	return &authorityv1.CheckResponse{Context: wc, AuthorizationRevision: revision}, nil
}

// Issue signs a capability for one owner shape.
func (i *Issuer) Issue(ctx context.Context, req *authorityv1.IssueRequest) (*authorityv1.IssueResponse, error) {
	audienceName := req.GetAudience()
	if audienceName == "" && req.GetOperationBindingId() != "" {
		// A caller that names the binding it exercises need not know where the
		// binding points: the audience is the binding's. Resolved from the
		// module acting, a workload by its credential or a hop's actor.
		derived, err := i.audienceOfBinding(ctx, req)
		if err != nil {
			return nil, err
		}
		audienceName = derived
		req.Audience = audienceName
	}
	if req.GetAudience() == "" {
		return nil, fmt.Errorf("%w: an issue names its audience, or the binding whose audience it is", ErrRefused)
	}
	audience, err := i.state.ModuleByPrincipal(req.GetAudience())
	if err != nil {
		return nil, err
	}
	asked := FromWire(req.GetScopes())
	ttl := time.Duration(req.GetTtlSeconds()) * time.Second
	if ttl <= 0 || ttl > MaxTTL {
		ttl = MaxTTL
	}
	var token string
	var wc *basev0.WorkContextV1
	switch as := req.GetAs().(type) {
	case *authorityv1.IssueRequest_Person:
		sessionID, ok := sessionOf(ctx)
		if !ok {
			return nil, fmt.Errorf("%w: a person-owned issue is made by a signed-in person; the call carries no session", ErrRefused)
		}
		token, wc, err = i.forPerson(ctx, sessionID, audience, req.GetOperationBindingId(), asked, ttl)
	case *authorityv1.IssueRequest_Workload:
		token, wc, err = i.forWorkload(ctx, as.Workload.GetCredential(), req.GetOrganizationId(), req.GetOperationBindingId(), audience, asked, ttl)
	case *authorityv1.IssueRequest_Installation:
		token, wc, err = i.forInstallation(ctx, as.Installation.GetInstallationId(), audience, asked, ttl)
	case *authorityv1.IssueRequest_ParentToken:
		token, wc, err = i.child(ctx, as.ParentToken, req.GetActor().GetCredential(), req.GetOperationBindingId(), audience, asked, ttl)
	default:
		return nil, fmt.Errorf("%w: an issue names whom it is for", ErrRefused)
	}
	if err != nil {
		return nil, err
	}
	wire, err := ToWire(wc)
	if err != nil {
		return nil, err
	}
	return &authorityv1.IssueResponse{Token: token, ExpiresAtUnix: wc.GetExpiresAtUnix(), Context: wire}, nil
}

// forPerson: owner = actor = the person; scopes = asked ∩ what their roles hold
// at the audience; sealed to the audience module's installation at their organisation.
func (i *Issuer) forPerson(ctx context.Context, sessionID string, audience state.Manifest, bindingID string, asked []*basev0.WorkScopeV1, ttl time.Duration) (string, *basev0.WorkContextV1, error) {
	sess, err := i.state.Session(sessionID)
	if err != nil {
		return "", nil, err
	}
	held, err := i.state.PersonScopes(sess.Person, audience.Principal)
	if err != nil {
		return "", nil, err
	}
	if bindingID != "" {
		// The person's token names a binding of the audience module, so the
		// module's hop through that binding carries exactly what the person
		// holds at the binding's audience, and nothing is typed per organisation.
		binding, declared := audience.Bindings[bindingID]
		if !declared {
			return "", nil, fmt.Errorf("%w: operation binding %q is not one %s declares", state.ErrUnknown, bindingID, audience.Module)
		}
		there, err := i.state.PersonScopes(sess.Person, binding.Audience)
		if err != nil {
			return "", nil, err
		}
		through := state.Intersect(there, binding.InvokeScopes)
		if len(through) == 0 {
			return "", nil, fmt.Errorf("%w: %s holds nothing under operation binding %q", ErrRefused, sess.Person, bindingID)
		}
		held = state.Normalize(append(held, through...))
	}
	scopes, err := grant(asked, held)
	if err != nil {
		return "", nil, err
	}
	return i.authority.Start(ctx, workcontext.StartInput{
		TenantID: sess.Organization, OrganizationID: sess.Organization,
		OwnerPrincipalID: sess.Person, OwnerPrincipalKind: "human",
		TaskID: uuid.NewString(), SessionID: sess.ID,
		Audience: audience.Principal, AuthorityScopes: scopes, AttributionTeamIDs: sess.Teams,
		InstallationID: sess.Organization + "/" + audience.Module, TTL: ttl,
	})
}

// forWorkload: owner = actor = the module; scopes = the binding's headless
// scopes ∩ asked; the binding names the audience, so the request's must agree.
func (i *Issuer) forWorkload(ctx context.Context, credential, org, bindingID string, audience state.Manifest, asked []*basev0.WorkScopeV1, ttl time.Duration) (string, *basev0.WorkContextV1, error) {
	module, err := i.state.VerifyWorkload(ctx, credential)
	if err != nil {
		return "", nil, err
	}
	if org == "" || bindingID == "" {
		return "", nil, fmt.Errorf("%w: a workload issue names the organization and the binding it exercises", ErrRefused)
	}
	fullID := org + "/" + module.Module + "/" + bindingID
	binding, ok := module.Bindings[bindingID]
	if !ok {
		return "", nil, fmt.Errorf("%w: %s declares no binding %q", workcontext.ErrNoBinding, module.Module, bindingID)
	}
	if binding.Audience != audience.Principal {
		return "", nil, fmt.Errorf("%w: binding %s is addressed to %s, not %s", ErrRefused, bindingID, binding.Audience, audience.Principal)
	}
	scopes, err := grant(asked, binding.HeadlessScopes)
	if err != nil {
		return "", nil, err
	}
	return i.authority.Start(ctx, workcontext.StartInput{
		TenantID: org, OrganizationID: org,
		OwnerPrincipalID: module.Principal, OwnerPrincipalKind: "service",
		TaskID: uuid.NewString(), Audience: audience.Principal, AuthorityScopes: scopes,
		InstallationID: org + "/" + module.Module, OperationBindingID: fullID, TTL: ttl,
	})
}

// forInstallation: owner = actor = the installation's agent; scopes = asked ∩
// the installation's role ∩ the audience's ceiling.
func (i *Issuer) forInstallation(ctx context.Context, id string, audience state.Manifest, asked []*basev0.WorkScopeV1, ttl time.Duration) (string, *basev0.WorkContextV1, error) {
	inst, ok := i.state.Installation(id)
	if !ok {
		return "", nil, fmt.Errorf("%w: installation %q", state.ErrUnknown, id)
	}
	if inst.Status != state.Active {
		return "", nil, fmt.Errorf("%w: installation %s is %s", workcontext.ErrNoSeal, id, inst.Status)
	}
	held := state.Intersect(i.state.RoleScopes(inst.Organization, inst.Role), audience.ResourceKinds)
	scopes, err := grant(asked, held)
	if err != nil {
		return "", nil, err
	}
	return i.authority.Start(ctx, workcontext.StartInput{
		TenantID: inst.Organization, OrganizationID: inst.Organization,
		OwnerPrincipalID: inst.AgentPrincipal(), OwnerPrincipalKind: "agent", OwnerAgentID: inst.Target,
		TaskID: uuid.NewString(), Audience: audience.Principal, AuthorityScopes: scopes,
		InstallationID: inst.ID, TTL: ttl,
	})
}

// child: one more hop. The parent is verified for its own audience; the actor
// is a module proving itself; the scopes must attenuate the parent's.
func (i *Issuer) child(ctx context.Context, parent, actorCredential, bindingID string, audience state.Manifest, asked []*basev0.WorkScopeV1, ttl time.Duration) (string, *basev0.WorkContextV1, error) {
	decoded, err := workcontext.Decode(parent)
	if err != nil {
		return "", nil, err
	}
	verified, err := i.verifier(decoded.Context().GetAudience()).Verify(ctx, parent)
	if err != nil {
		return "", nil, err
	}
	actor, err := i.state.VerifyWorkload(ctx, actorCredential)
	if err != nil {
		return "", nil, fmt.Errorf("a child hop names the module acting: %w", err)
	}
	// A module hops only on a token addressed to it, and names the binding it
	// exercises: the hop is then sealed within the module's own installation and
	// a verifier resolves exactly one binding.
	if verified.Context().GetAudience() != actor.Principal {
		return "", nil, fmt.Errorf("%w: %s hops only on a token addressed to it; this one is addressed to %s", ErrRefused, actor.Module, verified.Context().GetAudience())
	}
	if bindingID == "" {
		return "", nil, fmt.Errorf("%w: a module's hop names the binding it exercises", ErrRefused)
	}
	binding, declared := actor.Bindings[bindingID]
	if !declared {
		return "", nil, fmt.Errorf("%w: operation binding %q is not one %s declares", state.ErrUnknown, bindingID, actor.Module)
	}
	if binding.Audience != audience.Principal {
		return "", nil, fmt.Errorf("%w: binding %q is addressed to %s, not %s", ErrRefused, bindingID, binding.Audience, audience.Principal)
	}
	scopes := asked
	if len(scopes) == 0 {
		scopes = verified.EffectiveScopes()
	}
	if !state.Attenuates(scopes, verified.EffectiveScopes()) {
		return "", nil, fmt.Errorf("%w: a child widens its parent", ErrRefused)
	}
	in := workcontext.ChildInput{
		PrincipalID: actor.Principal, PrincipalKind: "service",
		DelegationID: verified.Context().GetSessionId(), GrantedScopes: state.Normalize(scopes),
		Audience: audience.Principal, TTL: ttl,
	}
	in.OperationBindingID = verified.Context().GetTenantId() + "/" + actor.Module + "/" + bindingID
	return i.authority.Child(ctx, verified, in)
}

// grant is asked ∩ held, or held when nothing was asked; asking beyond held is refused.
func grant(asked, held []*basev0.WorkScopeV1) ([]*basev0.WorkScopeV1, error) {
	if len(asked) == 0 {
		if len(held) == 0 {
			return nil, fmt.Errorf("%w: the owner holds nothing at this audience", ErrRefused)
		}
		for _, sc := range held {
			if slices.Contains(sc.GetActions(), state.AnyAction) {
				return nil, fmt.Errorf("%w: the audience declares %s without its actions; ask for the scopes you need", ErrRefused, sc.GetResourceKind())
			}
		}
		return held, nil
	}
	if !state.Attenuates(asked, held) {
		return nil, fmt.Errorf("%w: asked beyond what the owner holds", ErrRefused)
	}
	return state.Normalize(asked), nil
}

// ToWire converts core's message to the interface's, byte for byte.
func ToWire(in *basev0.WorkContextV1) (*authorityv1.WorkContextV1, error) {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(in)
	if err != nil {
		return nil, err
	}
	out := &authorityv1.WorkContextV1{}
	return out, proto.Unmarshal(raw, out)
}

// FromWire converts interface scopes to core's, byte for byte.
func FromWire(in []*authorityv1.WorkScopeV1) []*basev0.WorkScopeV1 {
	out := make([]*basev0.WorkScopeV1, 0, len(in))
	for _, sc := range in {
		raw, _ := proto.Marshal(sc)
		c := &basev0.WorkScopeV1{}
		_ = proto.Unmarshal(raw, c)
		out = append(out, c)
	}
	return out
}

// audienceOfBinding answers the audience of the binding a workload or a hop
// names, from the module its credential attests.
func (i *Issuer) audienceOfBinding(ctx context.Context, req *authorityv1.IssueRequest) (string, error) {
	var credential string
	switch as := req.GetAs().(type) {
	case *authorityv1.IssueRequest_Workload:
		credential = as.Workload.GetCredential()
	case *authorityv1.IssueRequest_ParentToken:
		credential = req.GetActor().GetCredential()
	default:
		return "", fmt.Errorf("%w: only a workload or a hop names a binding in place of an audience", ErrRefused)
	}
	module, err := i.state.VerifyWorkload(ctx, credential)
	if err != nil {
		return "", err
	}
	binding, declared := module.Bindings[req.GetOperationBindingId()]
	if !declared {
		return "", fmt.Errorf("%w: operation binding %q is not one %s declares", state.ErrUnknown, req.GetOperationBindingId(), module.Module)
	}
	return binding.Audience, nil
}
