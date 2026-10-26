// Package issuer is the authority interface over the generic authority core:
// Issue for every owner shape, Check for every callee, Keys for every
// verifier. Every decision and every signature is the core's; what this
// package adds is the wire: a session bearer resolved to the person, a
// workload credential attested to its module, and a method's declared policy
// applied on Check.
package issuer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
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

// ErrRefused is the umbrella for a refusal the caller can do nothing about:
// this wire layer's own, and every refusal the core denies.
var ErrRefused = errors.New("issuer: refused")

// classify keeps the core's refusal (its code still answers domain.CodeOf)
// and names its family as this host's callers test it: a denial is
// ErrRefused, a missing thing state.ErrUnknown.
func classify(err error) error {
	code, ok := domain.CodeOf(err)
	switch {
	case !ok:
		return err
	case code == domain.Denied:
		return fmt.Errorf("%w: %w", ErrRefused, err)
	case code == domain.NotFound:
		return fmt.Errorf("%w: %w", state.ErrUnknown, err)
	}
	return err
}

// Issuer is the wire over one host and its core.
type Issuer struct {
	state  *state.State
	svc    *authority.Service
	issuer string
	keyID  string
	public ed25519.PublicKey
	now    func() time.Time

	mu sync.Mutex
	// admission are the hop admission keys registered and not yet lapsed, by
	// key id (RegisterAdmissionKey).
	admission map[string]admission
	// nonces are the registration proofs accepted and still fresh, each until
	// it is forgotten, so none is accepted twice.
	nonces map[string]time.Time
	// trustDomain is the host's: only a hop attested in it registers a key.
	trustDomain string
}

// New builds the issuer for a host whose core signs as issuer with keyID, its
// public half published by Keys.
func New(st *state.State, issuer, keyID string, public ed25519.PublicKey) *Issuer {
	return &Issuer{state: st, svc: st.Service(), issuer: issuer, keyID: keyID, public: public, now: time.Now,
		admission: map[string]admission{}, nonces: map[string]time.Time{}, trustDomain: st.TrustDomain()}
}

// Config is the core configuration for one signing key: what state.New
// takes. The local authority is one process on a laptop, so its replay store
// is in memory, chosen here by name rather than defaulted.
func Config(issuer, keyID string, key ed25519.PrivateKey, now func() time.Time) authority.Config {
	replay := workcontext.NewMemoryReplayStore()
	replay.Now = now
	return authority.Config{Issuer: issuer, KeyID: keyID, Signer: key, Clock: now, MaxTTL: MaxTTL, Replay: replay}
}

// Keys is what a verifier pins: the Work Context key, and apart from it the
// admission keys the hop registered (RegisterAdmissionKey).
func (i *Issuer) Keys() *authorityv1.KeysResponse {
	return &authorityv1.KeysResponse{Issuer: i.issuer, Keys: []*authorityv1.PublicKey{{
		KeyId: i.keyID, Algorithm: workcontext.Algorithm, PublicKey: []byte(i.public), Purpose: "work-context",
	}}, AdmissionKeys: i.admissionKeys()}
}

// ListResources answers which resources of kind a checked capability may act
// on with action, decided now by the core.
func (i *Issuer) ListResources(ctx context.Context, token, audience, kind, action string) ([]authority.Grant, error) {
	out, err := i.listResources(ctx, token, audience, kind, action)
	return out, classify(err)
}

func (i *Issuer) listResources(ctx context.Context, token, audience, kind, action string) ([]authority.Grant, error) {
	if audience == "" || kind == "" || action == "" {
		return nil, fmt.Errorf("%w: a resource question names the audience, a kind and an action", ErrRefused)
	}
	return i.svc.ListResources(ctx, token, audience, kind, action)
}

// Check verifies a capability for the audience the caller is and, when method
// is named, applies what the audience module's delivery declares for it.
func (i *Issuer) Check(ctx context.Context, token, audience, method string) (*authorityv1.CheckResponse, error) {
	return i.check(ctx, token, audience, method, false)
}

// Advise is Check with the method's policy decided but not enforced: the
// capability is verified and refused when unsound; what the policy would have
// refused is answered in CheckResponse.Refusal beside the verified capability.
func (i *Issuer) Advise(ctx context.Context, token, audience, method string) (*authorityv1.CheckResponse, error) {
	return i.check(ctx, token, audience, method, true)
}

func (i *Issuer) check(ctx context.Context, token, audience, method string, advisory bool) (*authorityv1.CheckResponse, error) {
	out, err := i.checked(ctx, token, audience, method, advisory)
	return out, classify(err)
}

func (i *Issuer) checked(ctx context.Context, token, audience, method string, advisory bool) (*authorityv1.CheckResponse, error) {
	if audience == "" {
		return nil, fmt.Errorf("%w: a check names the audience the caller is", ErrRefused)
	}
	verified, revision, err := i.svc.Check(ctx, token, audience)
	if err != nil {
		return nil, err
	}
	refusal := ""
	if method != "" {
		if err := i.state.AdmitMethod(audience, method, verified.EffectiveScopes()); err != nil {
			if !advisory {
				return nil, err
			}
			refusal = err.Error()
		}
	}
	wc, err := ToWire(verified.Context())
	if err != nil {
		return nil, err
	}
	return &authorityv1.CheckResponse{Context: wc, AuthorizationRevision: revision, Refusal: refusal}, nil
}

// Issue signs a capability for one owner shape, through the core.
func (i *Issuer) Issue(ctx context.Context, req *authorityv1.IssueRequest) (*authorityv1.IssueResponse, error) {
	out, err := i.issue(ctx, req)
	return out, classify(err)
}

func (i *Issuer) issue(ctx context.Context, req *authorityv1.IssueRequest) (*authorityv1.IssueResponse, error) {
	r := authority.IssueRequest{Audience: req.GetAudience(), Binding: req.GetOperationBindingId(), Operation: req.GetOperation(),
		Organization: req.GetOrganizationId(), Scopes: FromWire(req.GetScopes()), TTL: time.Duration(req.GetTtlSeconds()) * time.Second}
	var out authority.Issued
	var err error
	switch as := req.GetAs().(type) {
	case *authorityv1.IssueRequest_Person:
		sessionID, ok := sessionOf(ctx)
		if !ok {
			return nil, fmt.Errorf("%w: a person-owned issue is made by a signed-in person; the call carries no session", ErrRefused)
		}
		person, perr := i.state.Caller(sessionID)
		if perr != nil {
			return nil, perr
		}
		out, err = i.svc.IssueForPerson(ctx, person, r)
	case *authorityv1.IssueRequest_Workload:
		w, werr := i.workload(ctx, as.Workload.GetCredential(), "a workload issue names the module asking")
		if werr != nil {
			return nil, werr
		}
		out, err = i.svc.IssueForWorkload(ctx, w, r)
	case *authorityv1.IssueRequest_Installation:
		w, werr := i.workload(ctx, req.GetActor().GetCredential(), "an installation acts through its solution's workload")
		if werr != nil {
			return nil, werr
		}
		out, err = i.svc.IssueForInstallation(ctx, w, as.Installation.GetInstallationId(), r)
	case *authorityv1.IssueRequest_ParentToken:
		w, werr := i.workload(ctx, req.GetActor().GetCredential(), "a child hop names the module acting")
		if werr != nil {
			return nil, werr
		}
		out, err = i.svc.IssueChild(ctx, as.ParentToken, w, r)
	case *authorityv1.IssueRequest_Delegation:
		w, werr := i.workload(ctx, req.GetActor().GetCredential(), "a delegated issue names the module acting")
		if werr != nil {
			return nil, werr
		}
		out, err = i.svc.IssueForDelegation(ctx, as.Delegation.GetDelegationId(), w, r)
	default:
		return nil, fmt.Errorf("%w: an issue names whom it is for", ErrRefused)
	}
	if err != nil {
		return nil, err
	}
	wire, err := ToWire(out.Context)
	if err != nil {
		return nil, err
	}
	return &authorityv1.IssueResponse{Token: out.Token, ExpiresAtUnix: out.Context.GetExpiresAtUnix(), Context: wire}, nil
}

// workload attests a credential to the composed module it proves.
func (i *Issuer) workload(ctx context.Context, credential, why string) (authority.Workload, error) {
	m, err := i.state.VerifyWorkload(ctx, credential)
	if err != nil {
		return authority.Workload{}, fmt.Errorf("%s: %w", why, err)
	}
	return authority.Workload{Module: m.Name}, nil
}

// AuthorizeTransfer decides whether an existing resource joins a solution
// principal, the store asking with the person's capability.
func (i *Issuer) AuthorizeTransfer(ctx context.Context, req *authorityv1.AuthorizeTransferRequest) (*authorityv1.AuthorizeTransferResponse, error) {
	out, err := i.authorizeTransfer(ctx, req)
	return out, classify(err)
}

func (i *Issuer) authorizeTransfer(ctx context.Context, req *authorityv1.AuthorizeTransferRequest) (*authorityv1.AuthorizeTransferResponse, error) {
	w, err := i.workload(ctx, req.GetActor().GetCredential(), "a transfer is asked by the module serving the kind")
	if err != nil {
		return nil, err
	}
	d, err := i.svc.AuthorizeTransfer(ctx, authority.TransferRequest{Token: req.GetToken(), Store: w, Kind: req.GetResourceKind(),
		ResourceID: req.GetResourceId(), From: req.GetFromOwnerId(), To: req.GetToPrincipalId()})
	if err != nil {
		return nil, err
	}
	return &authorityv1.AuthorizeTransferResponse{PrincipalId: d.PrincipalID, AuthorizedBy: d.AuthorizedBy}, nil
}

// Delegate records the signed-in person's grant to a module.
func (i *Issuer) Delegate(ctx context.Context, module string, scopes []*basev0.WorkScopeV1, purpose string) (state.Delegation, error) {
	out, err := i.delegate(ctx, module, scopes, purpose)
	return out, classify(err)
}

func (i *Issuer) delegate(ctx context.Context, module string, scopes []*basev0.WorkScopeV1, purpose string) (state.Delegation, error) {
	person, err := i.signedIn(ctx)
	if err != nil {
		return state.Delegation{}, err
	}
	return i.svc.Delegate(ctx, person, module, scopes, purpose)
}

// GetDelegation reads a delegation for the module it is granted to or for its
// grantor. Anyone else learns nothing, not even that it exists.
func (i *Issuer) GetDelegation(ctx context.Context, id, actorCredential string) (state.Delegation, error) {
	out, err := i.getDelegation(ctx, id, actorCredential)
	return out, classify(err)
}

func (i *Issuer) getDelegation(ctx context.Context, id, actorCredential string) (state.Delegation, error) {
	if actorCredential != "" {
		w, err := i.workload(ctx, actorCredential, "a delegation is read by its module")
		if err != nil {
			return state.Delegation{}, err
		}
		return i.svc.Delegation(ctx, id, nil, &w)
	}
	person, err := i.signedIn(ctx)
	if err != nil {
		return state.Delegation{}, err
	}
	return i.svc.Delegation(ctx, id, &person, nil)
}

// RevokeDelegation ends one of the signed-in person's delegations.
func (i *Issuer) RevokeDelegation(ctx context.Context, id string) (state.Delegation, error) {
	out, err := i.revokeDelegation(ctx, id)
	return out, classify(err)
}

func (i *Issuer) revokeDelegation(ctx context.Context, id string) (state.Delegation, error) {
	person, err := i.signedIn(ctx)
	if err != nil {
		return state.Delegation{}, err
	}
	return i.svc.RevokeDelegation(ctx, person, id)
}

func (i *Issuer) signedIn(ctx context.Context) (authority.Person, error) {
	sessionID, ok := sessionOf(ctx)
	if !ok {
		return authority.Person{}, fmt.Errorf("%w: a delegation is made by a signed-in person; the call carries no session", ErrRefused)
	}
	return i.state.Caller(sessionID)
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
