package authority

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	modulecontract "github.com/codefly-dev/core/contracts/module"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
)

const setupBindingPrefix = "installation-setup:"

// IssueForInstallationSetup uses callback evidence to grant one reviewed setup
// method. It does not attenuate the callback's delivery scope into data authority.
// The adapter authenticates w with the same workload attestation as ordinary Issue.
func (s *Service) IssueForInstallationSetup(ctx context.Context, w Workload, stepToken, method string, r IssueRequest) (Issued, error) {
	if r.Operation != "" || r.Binding == "" || method == "" {
		return Issued{}, domain.Refuse("setup names a binding and exact method, not an ordinary operation")
	}
	var solution domain.Module
	err := s.store.Read(ctx, func(tx Tx) error { var err error; solution, err = tx.ModuleNamed(w.Module); return err })
	if err != nil {
		return Issued{}, notFound(err)
	}
	step, _, err := s.VerifyInstallationStep(ctx, stepToken, solution.Principal)
	if err != nil {
		return Issued{}, err
	}
	src, err := s.setupSource(ctx, step.Context().GetSeal().GetInstallationId(), r.Binding, method)
	if err != nil {
		return Issued{}, err
	}
	// Source capture must remain bound to the callback we authenticated, not
	// merely to whichever approval now occupies the same installation ID.
	witness := step.Context()
	if witness.GetOperationBinding().GetBindingId() != src.stepSeals.bindingID() ||
		witness.GetOwnerPrincipalId() != src.principal || witness.GetAuthorizationRevision() != src.revision {
		return Issued{}, domain.NotNow("authenticated installation callback attempt changed")
	}
	if src.attempt.Target != w.Module || (r.Audience != "" && r.Audience != src.audience) || (r.Organization != "" && r.Organization != src.attempt.Organization) {
		return Issued{}, domain.Refuse("setup workload, audience and organization must match the reviewed attempt")
	}
	scopes, err := decide.Issue(r.Scopes, src.scopes)
	if err != nil {
		return Issued{}, err
	}
	if err := decide.AdmitMethod(src.destination, method, scopes); err != nil {
		return Issued{}, err
	}
	now := s.cfg.Clock()
	ttl := min(time.Unix(step.Context().GetExpiresAtUnix(), 0).Sub(now), MaxInstallationStepTTL, s.cfg.MaxTTL)
	if r.TTL > 0 {
		ttl = min(ttl, r.TTL)
	}
	if ttl <= 0 {
		return Issued{}, domain.NotNow("setup evidence expired")
	}
	minter := *s.authority
	minter.Seals, minter.Now = src, func() time.Time { return now }
	token, claims, err := minter.Start(ctx, workcontext.StartInput{
		TenantID: src.attempt.Organization, OrganizationID: src.attempt.Organization,
		OwnerPrincipalID: src.principal, OwnerPrincipalKind: "agent", OwnerAgentID: src.attempt.Target,
		TaskID: src.attempt.Consent.OperationID, Audience: src.audience,
		InstallationID: src.attempt.InstallationID, OperationBindingID: src.bindingID(),
		AuthorityScopes: scopes, TTL: ttl, ReplayPolicy: workcontext.ReplayIdempotent,
	})
	if err != nil {
		return Issued{}, err
	}
	if err := src.current(ctx); err != nil {
		return Issued{}, err
	}
	if claims.GetAuthorizationRevision() != src.revision || !s.cfg.Clock().Before(time.Unix(claims.GetExpiresAtUnix(), 0)) {
		return Issued{}, domain.NotNow("setup changed or expired during issuance")
	}
	return Issued{token, claims}, nil
}

// setupSeals supplies pending state only for this exact reviewed operation.
// The opaque binding fingerprints every live destination and consent boundary.
type setupSeals struct {
	stepSeals
	binding, method, audience string
	destination               domain.Module
	destinationInstallation   domain.Installation
	scopes                    Scopes
	ownerAwareRevision        uint64
}

func (s *Service) setupSource(ctx context.Context, installation, binding, method string) (setupSeals, error) {
	step, err := s.stepSource(ctx, installation)
	if err != nil {
		return setupSeals{}, err
	}
	src := setupSeals{stepSeals: step, binding: binding, method: method}
	err = s.store.Read(ctx, func(tx Tx) error {
		m, err := tx.ModuleNamed(step.attempt.Target)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(m.Setup, func(e modulecontract.ResolvedSetup) bool {
			return e.Binding == binding && slices.Contains(e.Methods, method)
		})
		if i < 0 {
			return domain.Refuse("method is not declared for this setup binding")
		}
		b, ok := m.Bindings[binding]
		if !ok || b.Audience == m.Principal {
			return domain.Refuse("setup binding must reach a declared foreign audience")
		}
		inst, err := tx.Installation(installation)
		if err != nil {
			return err
		}
		if inst.Bindings != nil {
			consented, ok := inst.Bindings[binding]
			if !ok || consented.Audience != b.Audience {
				return domain.Refuse("setup binding is not consented")
			}
			b.InvokeScopes = scope.Intersect(b.InvokeScopes, consented.InvokeScopes)
		}
		src.audience = b.Audience
		if src.destination, err = tx.Module(b.Audience); err != nil {
			return err
		}
		if src.destinationInstallation, err = installationOf(tx, inst.Organization, src.destination.Name); err != nil {
			return err
		}
		if src.destinationInstallation.Status != domain.Active {
			return domain.NotNow("setup destination is not active")
		}
		policy, ok := src.destination.Methods[method]
		if !ok || policy.AnyCheckedCaller || len(policy.Requires) == 0 {
			return domain.Refuse("setup requires an explicit served method policy")
		}
		var approved Scopes
		for _, text := range m.Setup[i].Scopes {
			kind, action, ok := strings.Cut(text, ":")
			if !ok {
				return domain.Refuse("setup declaration has malformed scope")
			}
			approved = append(approved, &basev0.WorkScopeV1{ResourceKind: kind, Actions: []string{action}})
		}
		ceiling := scope.Intersect(scope.Intersect(approved, b.InvokeScopes), decide.Served(src.destination))
		if !scope.Attenuates(policy.Requires, ceiling) {
			return domain.Refuse("current setup method exceeds reviewed scope")
		}
		src.scopes = scope.Intersect(policy.Requires, ceiling)
		for _, sc := range src.scopes {
			sc.ResourceOwnerId = step.principal
		}
		if err := decide.OwnerAware(src.destination, src.scopes); err != nil {
			return err
		}
		src.ownerAwareRevision, err = tx.OwnerAwareRevision(src.audience)
		return err
	})
	if err == nil {
		err = step.current(ctx)
	}
	return src, err
}

func (src setupSeals) bindingID() string {
	// These are owner state, not caller-selected fields. Destination digest
	// changes also fence method-policy and owner-awareness changes.
	digest, _ := offerDigest(src.destination)
	raw, _ := json.Marshal(struct {
		Attempt                                      InstallationStepAttempt
		Binding, Method, Audience, DestinationDigest string
		DestinationID                                string
		DestinationRevision, OwnerAwareRevision      uint64
		Scopes                                       Scopes
	}{src.attempt, src.binding, src.method, src.audience, digest, src.destinationInstallation.ID,
		src.destinationInstallation.Revision, src.ownerAwareRevision, src.scopes})
	return fmt.Sprintf("%s%x", setupBindingPrefix, sha256.Sum256(raw))
}

func (src setupSeals) current(ctx context.Context) error {
	next, err := src.s.setupSource(ctx, src.attempt.InstallationID, src.binding, src.method)
	if err != nil {
		return err
	}
	if next.bindingID() != src.bindingID() || next.principal != src.principal || next.revision != src.revision {
		return domain.NotNow("installation setup operation changed")
	}
	return nil
}

func (src setupSeals) OperationBinding(ctx context.Context, id string) (workcontext.OperationBinding, error) {
	if id != src.bindingID() {
		return workcontext.OperationBinding{}, workcontext.ErrNoBinding
	}
	return workcontext.OperationBinding{ID: id, PrincipalID: src.principal, InstallationID: src.attempt.InstallationID,
		Revision: src.attempt.Revision, Incarnation: src.attempt.Generation}, src.current(ctx)
}

func (s *Service) verifyInstallationSetup(ctx context.Context, token, audience, method string) (*workcontext.Verified, uint64, error) {
	if method == "" {
		return nil, 0, domain.Refuse("setup capability requires its exact method")
	}
	v, err := s.verifier(ctx, audience)
	if err != nil {
		return nil, 0, err
	}
	inspector := workcontext.Inspector{Issuer: v.Issuer, Keys: v.Keys, Now: v.Now}
	if _, err := inspector.Inspect(token, audience); err != nil {
		return nil, 0, err
	}
	decoded, err := workcontext.Decode(token)
	if err != nil {
		return nil, 0, err
	}
	wc := decoded.Context()
	step, err := s.stepSource(ctx, wc.GetSeal().GetInstallationId())
	if err != nil {
		return nil, 0, err
	}
	var bindings []string
	err = s.store.Read(ctx, func(tx Tx) error {
		m, err := tx.ModuleNamed(step.attempt.Target)
		if err != nil {
			return err
		}
		for _, entry := range m.Setup {
			if b, ok := m.Bindings[entry.Binding]; ok && b.Audience == audience && slices.Contains(entry.Methods, method) {
				bindings = append(bindings, entry.Binding)
			}
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	for _, binding := range bindings {
		src, err := s.setupSource(ctx, step.attempt.InstallationID, binding, method)
		if err != nil {
			if _, refusal := domain.CodeOf(err); !refusal && !errors.Is(err, domain.ErrNotFound) {
				return nil, 0, err
			}
			// A withdrawn or ineligible declaration cannot match a valid live
			// operation. Another binding to this audience may still be valid.
			continue
		}
		if wc.GetOperationBinding().GetBindingId() != src.bindingID() {
			continue
		}
		if audience != src.audience || wc.GetTenantId() != src.attempt.Organization || wc.GetOrganizationId() != src.attempt.Organization ||
			wc.GetOwnerPrincipalId() != src.principal || wc.GetOwnerPrincipalKind() != "agent" || wc.GetOwnerAgentId() != src.attempt.Target ||
			wc.GetTaskId() != src.attempt.Consent.OperationID || len(wc.GetActorChain()) != 0 || wc.GetReplayPolicy() != workcontext.ReplayIdempotent ||
			!scope.Attenuates(wc.GetAuthorityScopes(), src.scopes) {
			return nil, 0, domain.Refuse("not this installation's setup operation credential")
		}
		v.Seals = src
		verified, err := v.Verify(ctx, token)
		if err != nil {
			return nil, 0, err
		}
		if err := src.current(ctx); err != nil {
			return nil, 0, err
		}
		if now := s.cfg.Clock(); now.Before(time.Unix(wc.GetNotBeforeUnix(), 0)) || !now.Before(time.Unix(wc.GetExpiresAtUnix(), 0)) {
			return nil, 0, domain.NotNow("setup operation is outside its evidence window")
		}
		if err := decide.OwnerAware(src.destination, verified.EffectiveScopes()); err != nil {
			return nil, 0, err
		}
		if err := decide.AdmitMethod(src.destination, method, verified.EffectiveScopes()); err != nil {
			return nil, 0, err
		}
		return verified, src.revision, nil
	}
	return nil, 0, domain.Refuse("setup capability does not select this current exact method")
}

// This only selects the verification path. The path authenticates the token
// before trusting any lookup key; a fabricated prefix grants nothing.
func isSetupOperation(token string) bool {
	decoded, err := workcontext.Decode(token)
	return err == nil && strings.HasPrefix(decoded.Context().GetOperationBinding().GetBindingId(), setupBindingPrefix)
}
