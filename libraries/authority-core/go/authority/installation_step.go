package authority

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
	"google.golang.org/protobuf/proto"
)

// InstallationStepHTTPMethod and InstallationStepRPCMethod are setup-only
// admission points. A receiver supplies the method it serves, never a body field.
const (
	InstallationStepHTTPMethod = "POST /_codefly/installations"
	InstallationStepRPCMethod  = "/host.installation.v1.InstallableService/Install"
	MaxInstallationStepTTL     = time.Minute
)

// InstallationStepAttempt is the canonical pending record and original reviewed
// delivery identity retained by the host's durable job. Target is its composed
// name; TargetID is the delivered principal (not a host release-table UUID).
// This is not a caller's authority request: only the trusted host job claimant
// may ask for issuance, after checking its lease and immutable release binding.
type InstallationStepAttempt struct {
	InstallationID, Organization, Target, TargetID string
	Revision, Generation                           uint64
	Consent                                        domain.ConsentReceipt
	Digest                                         string
}

// PendingInstallationStep snapshots the current attempt for a trusted host's
// synchronous dispatcher. The supplied pending installation must still match;
// this neither reviews nor consents to a changed offer. Durable dispatchers keep
// the reviewed attempt in their job instead. IssueInstallationStep rechecks it.
func (s *Service) PendingInstallationStep(ctx context.Context, expected domain.Installation) (InstallationStepAttempt, error) {
	src, err := s.stepSource(ctx, expected.ID)
	if err != nil {
		return InstallationStepAttempt{}, err
	}
	a := src.attempt
	if expected.Status != domain.Pending || expected.Organization != a.Organization || expected.Target != a.Target || expected.Revision != a.Revision || expected.Consent != a.Consent {
		return InstallationStepAttempt{}, domain.NotNow("installation step attempt changed")
	}
	return a, nil
}

// IssueInstallationStep grants only delivery of this installation's setup, not
// its agent role or any data access. ttl must fit the claimant's remaining lease.
// Queue custody stays with the host; lease loss is not an Authority state change.
// A successful enqueue is not an acknowledgement: InstallStep must still return
// an error until this exact job succeeds, and Install alone activates the record.
func (s *Service) IssueInstallationStep(ctx context.Context, attempt InstallationStepAttempt, ttl time.Duration) (Issued, error) {
	if ttl <= 0 {
		return Issued{}, domain.Refuse("installation step requires a positive remaining lease")
	}
	now := s.cfg.Clock()
	ttl = min(ttl, MaxInstallationStepTTL, s.cfg.MaxTTL)
	src, err := s.stepSource(ctx, attempt.InstallationID)
	if err != nil {
		return Issued{}, err
	}
	if src.attempt != attempt {
		return Issued{}, domain.NotNow("installation step attempt changed")
	}
	minter := *s.authority
	minter.Seals = src
	minter.Now = func() time.Time { return now }
	token, claims, err := minter.Start(ctx, workcontext.StartInput{
		TenantID: attempt.Organization, OrganizationID: attempt.Organization,
		OwnerPrincipalID: src.principal, OwnerPrincipalKind: "service",
		TaskID: attempt.Consent.OperationID, Audience: attempt.TargetID,
		InstallationID: attempt.InstallationID, OperationBindingID: src.bindingID(),
		AuthorityScopes: Scopes{stepScope(attempt.InstallationID)}, TTL: ttl,
		ReplayPolicy: workcontext.ReplayIdempotent,
	})
	if err != nil {
		return Issued{}, err
	}
	if err := src.current(ctx); err != nil {
		return Issued{}, err
	}
	if claims.GetAuthorizationRevision() != src.revision || !s.cfg.Clock().Before(time.Unix(claims.GetExpiresAtUnix(), 0)) {
		return Issued{}, domain.NotNow("installation step changed or expired during issuance")
	}
	return Issued{token, claims}, nil
}

// VerifyInstallationStep is only for an authenticated setup receiver. CheckMethod
// exposes it through the existing Check transport at the two exact setup methods.
// Ordinary Verify, Check, issuance and child exchange never use its seal source.
// The receiver must compare the verified organization, installation and revision
// with the strict request body/carriers before its callback OR cached acknowledgement.
func (s *Service) VerifyInstallationStep(ctx context.Context, token, audience string) (*workcontext.Verified, uint64, error) {
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
	// Inspection authenticates the lookup key but grants nothing. Core's full
	// verifier still checks every live source before anything is returned.
	wc := decoded.Context()
	src, err := s.stepSource(ctx, wc.GetSeal().GetInstallationId())
	if err != nil {
		return nil, 0, err
	}
	a := src.attempt
	if audience == "" || audience != a.TargetID || wc.GetTenantId() != a.Organization || wc.GetOrganizationId() != a.Organization ||
		wc.GetOwnerPrincipalId() != src.principal || wc.GetOwnerPrincipalKind() != "service" || wc.GetTaskId() != a.Consent.OperationID ||
		len(wc.GetActorChain()) != 0 || len(wc.GetAuthorityScopes()) != 1 || !proto.Equal(wc.GetAuthorityScopes()[0], stepScope(a.InstallationID)) ||
		wc.GetOperationBinding().GetBindingId() != src.bindingID() || wc.GetReplayPolicy() != workcontext.ReplayIdempotent {
		return nil, 0, domain.Refuse("not this installation's setup credential")
	}
	v.Seals = src
	verified, err := v.Verify(ctx, token)
	if err != nil {
		return nil, 0, err
	}
	if err := src.current(ctx); err != nil {
		return nil, 0, err
	}
	// The owner is checking its own lease-bounded credential. Core's default
	// network clock tolerance must not extend this setup delivery window.
	if now := s.cfg.Clock(); now.Before(time.Unix(wc.GetNotBeforeUnix(), 0)) || !now.Before(time.Unix(wc.GetExpiresAtUnix(), 0)) {
		return nil, 0, domain.NotNow("installation step credential is outside its delivery window")
	}
	return verified, src.revision, nil
}

func stepScope(id string) *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: "installations", Actions: []string{"install"}, ResourceIds: []string{id}}
}

// stepSeals is private and answers only this pending attempt. Normal seals keep
// their active-only contract. Its opaque binding cannot resolve as a normal
// organization/module/binding, including after activation at the same revision.
type stepSeals struct {
	s         *Service
	attempt   InstallationStepAttempt
	principal string
	revision  uint64
}

func (s *Service) stepSource(ctx context.Context, id string) (stepSeals, error) {
	out := stepSeals{s: s}
	err := s.store.Read(ctx, func(tx Tx) error {
		inst, err := tx.Installation(id)
		if err != nil {
			return notFound(err)
		}
		if inst.Status != domain.Pending || inst.ID == "" || inst.Organization == "" || inst.PrincipalID == "" || inst.Revision == 0 ||
			inst.Consent.OperationID == "" || inst.Consent.Intent == "" || inst.Consent.Revision != inst.Revision {
			return domain.NotNow("installation has no current consented pending attempt")
		}
		m, err := tx.ModuleNamed(inst.Target)
		if err != nil {
			return notFound(err)
		}
		if m.Kind != domain.KindSolution || m.Principal == "" || m.Generation == 0 {
			return domain.Refuse("setup requires a delivered solution")
		}
		digest, err := offerDigest(m)
		if err != nil {
			return err
		}
		out.attempt = InstallationStepAttempt{inst.ID, inst.Organization, inst.Target, m.Principal, inst.Revision, m.Generation, inst.Consent, digest}
		out.principal = inst.PrincipalID
		out.revision, err = tx.AuthorizationRevision(inst.Organization)
		return err
	})
	return out, err
}

func (src stepSeals) bindingID() string {
	raw, _ := json.Marshal(src.attempt) // this value contains only strings and integers
	return fmt.Sprintf("installation-step:%x", sha256.Sum256(raw))
}

func (src stepSeals) current(ctx context.Context) error {
	now, err := src.s.stepSource(ctx, src.attempt.InstallationID)
	if err != nil {
		return err
	}
	if now.attempt != src.attempt || now.principal != src.principal || now.revision != src.revision {
		return domain.NotNow("installation step attempt changed")
	}
	return nil
}

func (src stepSeals) Seal(ctx context.Context, principal, id string) (workcontext.Seal, error) {
	if principal != src.principal || id != src.attempt.InstallationID {
		return workcontext.Seal{}, workcontext.ErrNoSeal
	}
	return workcontext.Seal{InstallationID: id, InstallationRevision: src.attempt.Revision}, src.current(ctx)
}

func (src stepSeals) PrincipalEpoch(ctx context.Context, principal string) (uint64, error) {
	if principal != src.principal {
		return 0, workcontext.ErrNoSeal
	}
	return src.attempt.Revision, src.current(ctx)
}

func (src stepSeals) OperationBinding(ctx context.Context, id string) (workcontext.OperationBinding, error) {
	if id != src.bindingID() {
		return workcontext.OperationBinding{}, workcontext.ErrNoBinding
	}
	return workcontext.OperationBinding{ID: id, PrincipalID: src.principal, InstallationID: src.attempt.InstallationID,
		Revision: src.attempt.Revision, Incarnation: src.attempt.Generation}, src.current(ctx)
}
