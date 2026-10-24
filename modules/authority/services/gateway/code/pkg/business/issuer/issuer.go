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
	resources "github.com/codefly-dev/authority/libraries/resources/go"
	"slices"
	"strings"
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

// ListResources answers which resources of kind a checked capability may act
// on with action, decided now rather than carried in the capability. The
// capability must hold the action on the kind. A person's answer is what her
// roles grant; a module's or an installation's own work is bounded by the
// capability alone. When the capability's chain names resource ids, only those
// the owner's grants cover remain.
func (i *Issuer) ListResources(ctx context.Context, token, audience, kind, action string) ([]resources.Grant, error) {
	if audience == "" || kind == "" || action == "" {
		return nil, fmt.Errorf("%w: a resource question names the audience, a kind and an action", ErrRefused)
	}
	verified, err := i.verifier(audience).Verify(ctx, token)
	if err != nil {
		return nil, err
	}
	held, whole := false, false
	var ids []string
	for _, sc := range verified.EffectiveScopes() {
		if sc.GetResourceKind() != kind || (!slices.Contains(sc.GetActions(), action) && !slices.Contains(sc.GetActions(), state.AnyAction)) {
			continue
		}
		held = true
		if len(sc.GetResourceIds()) == 0 {
			whole = true
		}
		ids = append(ids, sc.GetResourceIds()...)
	}
	if !held {
		return nil, fmt.Errorf("%w: the capability holds no %s:%s", ErrRefused, kind, action)
	}
	wc := verified.Context()
	grants := []resources.Grant{{All: true}}
	if wc.GetOwnerPrincipalKind() == "human" {
		if grants, err = i.state.ResourceGrants(wc.GetOwnerPrincipalId(), audience, kind, action); err != nil {
			return nil, err
		}
	}
	if whole {
		return grants, nil
	}
	covered, err := resources.Compile(grants)
	if err != nil {
		return nil, err
	}
	narrowed := []resources.Grant{}
	for _, id := range ids {
		if covered.Matches(id) {
			narrowed = append(narrowed, resources.Grant{ID: id})
		}
	}
	return narrowed, nil
}

// Check verifies a capability for the audience the caller is and, when method
// is named, applies what the audience module's delivery declares for it.
func (i *Issuer) Check(ctx context.Context, token, audience, method string) (*authorityv1.CheckResponse, error) {
	if audience == "" {
		return nil, fmt.Errorf("%w: a check names the audience the caller is", ErrRefused)
	}
	verified, err := i.verifier(audience).Verify(ctx, token)
	if err != nil {
		return nil, err
	}
	if method != "" {
		if err := i.state.AdmitMethod(audience, method, verified.EffectiveScopes()); err != nil {
			return nil, err
		}
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
		token, wc, err = i.forWorkload(ctx, as.Workload.GetCredential(), req.GetOrganizationId(), req.GetOperationBindingId(), req.GetOperation(), audience, asked, ttl)
	case *authorityv1.IssueRequest_Installation:
		token, wc, err = i.forInstallation(ctx, as.Installation.GetInstallationId(), audience, asked, ttl)
	case *authorityv1.IssueRequest_ParentToken:
		token, wc, err = i.child(ctx, as.ParentToken, req.GetActor().GetCredential(), req.GetOperationBindingId(), req.GetOperation(), audience, asked, ttl)
	case *authorityv1.IssueRequest_Delegation:
		token, wc, err = i.forDelegation(ctx, as.Delegation.GetDelegationId(), req.GetActor().GetCredential(), req.GetOperationBindingId(), req.GetOperation(), audience, asked, ttl)
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
		InstallationID: state.InstallationID(sess.Organization, audience.Module), TTL: ttl,
	})
}

// forWorkload: owner = actor = the module; scopes = the binding's headless
// scopes ∩ asked; the binding names the audience, so the request's must agree.
func (i *Issuer) forWorkload(ctx context.Context, credential, org, bindingID, operation string, audience state.Manifest, asked []*basev0.WorkScopeV1, ttl time.Duration) (string, *basev0.WorkContextV1, error) {
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
	through, err := scopesFor(binding, operation, "headless")
	if err != nil {
		return "", nil, err
	}
	scopes, err := grant(asked, through)
	if err != nil {
		return "", nil, err
	}
	return i.authority.Start(ctx, workcontext.StartInput{
		TenantID: org, OrganizationID: org,
		OwnerPrincipalID: module.Principal, OwnerPrincipalKind: "service",
		TaskID: uuid.NewString(), Audience: audience.Principal, AuthorityScopes: scopes,
		InstallationID: state.InstallationID(org, module.Module), OperationBindingID: fullID, TTL: ttl,
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

// child: one more hop, inherited from the owner. The parent is verified for its
// own audience and must be addressed to the module acting; the actor proves itself
// and names the binding it exercises, addressed to the hop's audience. The child
// is owned by the parent's owner and carries the parent's actors and then this
// one. Its ceiling is the owner's authority twice over: what was already delegated
// down the chain (the parent's scopes), and what the owner holds now at the hop's
// audience through the binding. An ask narrows the ceiling. The second half is
// what lets a delegate chain cross audiences: a module holds nothing of its own,
// it inherits who it acts for.
func (i *Issuer) child(ctx context.Context, parent, actorCredential, bindingID, operation string, audience state.Manifest, asked []*basev0.WorkScopeV1, ttl time.Duration) (string, *basev0.WorkContextV1, error) {
	decoded, err := workcontext.Decode(parent)
	if err != nil {
		return "", nil, err
	}
	verified, err := i.verifier(decoded.Context().GetAudience()).Verify(ctx, parent)
	if err != nil {
		return "", nil, err
	}
	claims := verified.Context()
	actor, err := i.state.VerifyWorkload(ctx, actorCredential)
	if err != nil {
		return "", nil, fmt.Errorf("a child hop names the module acting: %w", err)
	}
	if claims.GetAudience() != actor.Principal {
		return "", nil, fmt.Errorf("%w: %s hops only on a token addressed to it; this one is addressed to %s", ErrRefused, actor.Module, claims.GetAudience())
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
	held, err := i.ownerHolds(claims, audience)
	if err != nil {
		return "", nil, err
	}
	through, err := scopesFor(binding, operation, "invoke")
	if err != nil {
		return "", nil, err
	}
	ceiling := state.Normalize(append(append([]*basev0.WorkScopeV1(nil), verified.EffectiveScopes()...), state.Intersect(held, through)...))
	if operation == "lookup" {
		// A lookup reads a receipt: never more than the binding's lookup scopes,
		// whatever the parent carried.
		ceiling = state.Intersect(ceiling, through)
	}
	if len(ceiling) == 0 {
		return "", nil, fmt.Errorf("%w: %s holds nothing at %s through binding %q", ErrRefused, claims.GetOwnerPrincipalId(), audience.Module, bindingID)
	}
	scopes := ceiling
	if len(asked) > 0 {
		if !state.Attenuates(asked, ceiling) {
			return "", nil, fmt.Errorf("%w: a child widens what its owner holds through binding %q", ErrRefused, bindingID)
		}
		scopes = state.Normalize(asked)
	}
	// The child never outlives its parent, on the authority's own clock.
	now := time.Now()
	if i.authority.Now != nil {
		now = i.authority.Now()
	}
	if remaining := time.Unix(claims.GetExpiresAtUnix(), 0).Sub(now); remaining < ttl {
		ttl = remaining
	}
	if ttl <= 0 {
		return "", nil, fmt.Errorf("%w: the parent has expired", ErrRefused)
	}
	tenant := claims.GetTenantId()
	hops := append([]*basev0.WorkActorV1(nil), claims.GetActorChain()...)
	// The chain is rebuilt for the new audience, and the token the final hop is
	// derived from carries the parent's own session, so the child descends from
	// the context it was asked from (its parent_session_id is that session), as
	// a caller holding the parent checks.
	parentSession := claims.GetSessionId()
	rootSession := ""
	if len(hops) == 0 {
		rootSession = parentSession
	}
	token, _, err := i.authority.Start(ctx, workcontext.StartInput{
		TenantID: tenant, OrganizationID: claims.GetOrganizationId(),
		OwnerPrincipalID: claims.GetOwnerPrincipalId(), OwnerPrincipalKind: claims.GetOwnerPrincipalKind(), OwnerAgentID: claims.GetOwnerAgentId(),
		TaskID: claims.GetTaskId(), Audience: audience.Principal, AuthorityScopes: scopes, AttributionTeamIDs: claims.GetAttributionTeamIds(),
		InstallationID: state.InstallationID(tenant, actor.Module), SessionID: rootSession, TTL: ttl, ReplayPolicy: workcontext.ReplayIdempotent,
	})
	if err != nil {
		return "", nil, err
	}
	for n := 0; n <= len(hops); n++ {
		current, err := i.verifier(audience.Principal).Verify(ctx, token)
		if err != nil {
			return "", nil, fmt.Errorf("verify the hop a child is derived from: %w", err)
		}
		in := workcontext.ChildInput{GrantedScopes: scopes, Audience: audience.Principal, TTL: ttl, ReplayPolicy: workcontext.ReplayIdempotent}
		if n < len(hops) {
			in.PrincipalID, in.PrincipalKind, in.DelegationID = hops[n].GetPrincipalId(), hops[n].GetPrincipalKind(), hops[n].GetDelegationId()
			if n == len(hops)-1 {
				in.SessionID = parentSession
			}
		} else {
			in.PrincipalID, in.PrincipalKind, in.DelegationID = actor.Principal, "service", claims.GetSessionId()
			in.OperationBindingID = tenant + "/" + actor.Module + "/" + bindingID
		}
		var signed *basev0.WorkContextV1
		token, signed, err = i.authority.Child(ctx, current, in)
		if err != nil {
			return "", nil, err
		}
		if n == len(hops) {
			return token, signed, nil
		}
	}
	return "", nil, fmt.Errorf("%w: no hop was derived", ErrRefused)
}

// scopesFor is what a binding may do for one operation: invoke, headless or
// lookup, or def when the request names none.
func scopesFor(b state.Binding, operation, def string) ([]*basev0.WorkScopeV1, error) {
	if operation == "" {
		operation = def
	}
	switch operation {
	case "invoke":
		return b.InvokeScopes, nil
	case "headless":
		return b.HeadlessScopes, nil
	case "lookup":
		return b.LookupScopes, nil
	}
	return nil, fmt.Errorf("%w: operation %q is none of invoke, headless and lookup", ErrRefused, operation)
}

// forDelegation issues for a delegation's grantor through the module it was
// granted to. No live capability is presented: the delegation must stand, the
// actor must be its module, and the scopes are what was delegated, cut to what
// the grantor holds at the audience now and to the binding. The capability is
// the grantor's, with the module as actor and the delegation on its hop.
func (i *Issuer) forDelegation(ctx context.Context, id, actorCredential, bindingID, operation string, audience state.Manifest, asked []*basev0.WorkScopeV1, ttl time.Duration) (string, *basev0.WorkContextV1, error) {
	d, err := i.state.DelegationByID(id)
	if err != nil {
		return "", nil, err
	}
	if d.Revoked {
		return "", nil, fmt.Errorf("%w: delegation %s is revoked", ErrRefused, id)
	}
	actor, err := i.state.VerifyWorkload(ctx, actorCredential)
	if err != nil {
		return "", nil, fmt.Errorf("an issue from a delegation names the module acting: %w", err)
	}
	if actor.Module != d.Module {
		return "", nil, fmt.Errorf("%w: delegation %s is granted to %s, not %s", ErrRefused, id, d.Module, actor.Module)
	}
	if bindingID == "" {
		return "", nil, fmt.Errorf("%w: an issue from a delegation names the binding it exercises", ErrRefused)
	}
	binding, declared := actor.Bindings[bindingID]
	if !declared {
		return "", nil, fmt.Errorf("%w: operation binding %q is not one %s declares", state.ErrUnknown, bindingID, actor.Module)
	}
	if binding.Audience != audience.Principal {
		return "", nil, fmt.Errorf("%w: binding %q is addressed to %s, not %s", ErrRefused, bindingID, binding.Audience, audience.Principal)
	}
	through, err := scopesFor(binding, operation, "invoke")
	if err != nil {
		return "", nil, err
	}
	held, err := i.state.PersonScopes(d.Grantor, audience.Principal)
	if err != nil {
		return "", nil, err
	}
	ceiling := state.Intersect(state.Intersect(d.WorkScopes(), held), through)
	if len(ceiling) == 0 {
		return "", nil, fmt.Errorf("%w: delegation %s grants nothing %s still holds at %s through binding %q", ErrRefused, id, d.Grantor, audience.Module, bindingID)
	}
	scopes, err := grant(asked, ceiling)
	if err != nil {
		return "", nil, err
	}
	token, _, err := i.authority.Start(ctx, workcontext.StartInput{
		TenantID: d.Organization, OrganizationID: d.Organization,
		OwnerPrincipalID: d.Grantor, OwnerPrincipalKind: "human",
		TaskID: uuid.NewString(), Audience: audience.Principal, AuthorityScopes: scopes,
		InstallationID: state.InstallationID(d.Organization, actor.Module), TTL: ttl, ReplayPolicy: workcontext.ReplayIdempotent,
	})
	if err != nil {
		return "", nil, err
	}
	current, err := i.verifier(audience.Principal).Verify(ctx, token)
	if err != nil {
		return "", nil, fmt.Errorf("verify the capability a delegation's hop is derived from: %w", err)
	}
	return i.authority.Child(ctx, current, workcontext.ChildInput{
		PrincipalID: actor.Principal, PrincipalKind: "service", DelegationID: d.ID,
		GrantedScopes: scopes, Audience: audience.Principal, TTL: ttl, ReplayPolicy: workcontext.ReplayIdempotent,
		OperationBindingID: d.Organization + "/" + actor.Module + "/" + bindingID,
	})
}

// Delegate records the signed-in person's grant to a module.
func (i *Issuer) Delegate(ctx context.Context, module string, scopes []*basev0.WorkScopeV1, purpose string) (state.Delegation, error) {
	person, err := i.signedIn(ctx)
	if err != nil {
		return state.Delegation{}, err
	}
	return i.state.Delegate(person, module, scopes, purpose)
}

// GetDelegation reads a delegation for the module it is granted to or for its
// grantor. Anyone else learns nothing, not even that it exists.
func (i *Issuer) GetDelegation(ctx context.Context, id, actorCredential string) (state.Delegation, error) {
	d, err := i.state.DelegationByID(id)
	if err != nil {
		return state.Delegation{}, err
	}
	if actorCredential != "" {
		if actor, err := i.state.VerifyWorkload(ctx, actorCredential); err == nil && actor.Module == d.Module {
			return d, nil
		}
	} else if person, err := i.signedIn(ctx); err == nil && person == d.Grantor {
		return d, nil
	}
	return state.Delegation{}, fmt.Errorf("%w: delegation %q", state.ErrUnknown, id)
}

// RevokeDelegation ends one of the signed-in person's delegations.
func (i *Issuer) RevokeDelegation(ctx context.Context, id string) (state.Delegation, error) {
	person, err := i.signedIn(ctx)
	if err != nil {
		return state.Delegation{}, err
	}
	return i.state.RevokeDelegation(person, id)
}

func (i *Issuer) signedIn(ctx context.Context) (string, error) {
	sessionID, ok := sessionOf(ctx)
	if !ok {
		return "", fmt.Errorf("%w: a delegation is made by a signed-in person; the call carries no session", ErrRefused)
	}
	sess, err := i.state.Session(sessionID)
	if err != nil {
		return "", err
	}
	return sess.Person, nil
}

// ownerHolds is what the owner of a verified context holds at the audience now:
// a person's roles, or an installation's role, each within what the audience
// serves.
func (i *Issuer) ownerHolds(claims *basev0.WorkContextV1, audience state.Manifest) ([]*basev0.WorkScopeV1, error) {
	owner := claims.GetOwnerPrincipalId()
	switch claims.GetOwnerPrincipalKind() {
	case "human":
		return i.state.PersonScopes(owner, audience.Principal)
	case "agent":
		inst, ok := i.state.Installation(strings.TrimSuffix(owner, "/agent"))
		if !ok || inst.Status != state.Active {
			return nil, fmt.Errorf("%w: the installation that owns this context is not active", workcontext.ErrNoSeal)
		}
		return state.Intersect(i.state.RoleScopes(inst.Organization, inst.Role), audience.ResourceKinds), nil
	}
	// A module's own context inherits nothing more at the next audience: its
	// child carries what it was already delegated.
	return nil, nil
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
	case *authorityv1.IssueRequest_ParentToken, *authorityv1.IssueRequest_Delegation:
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
