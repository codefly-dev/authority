package issuer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
	"google.golang.org/protobuf/proto"

	"gateway/pkg/business/state"
	artifactv1 "gateway/pkg/gen/host/artifact/v1"
)

// The artifact interface: a person's consent to an exact authored artifact a
// module runs, for one installation, under one policy. A policy is a resource
// kind at the module: approving and revoking need its `activate` action, held
// by the person present; a run needs its `run` action, which a delegated
// context may carry. What a person may approve is therefore what their roles
// grant at the module, and the authority keeps no second permission table.
// Consent is durable: state.Approvals keeps it in the module's store when one
// is composed, so a restart of this process still answers a run.

// Artifact answers Approve or Authorize (action "activate" or "run").
func (i *Issuer) Artifact(ctx context.Context, action string, req *artifactv1.ArtifactRequest) (*artifactv1.Approval, error) {
	if req.GetIdentity() == nil || req.GetIdentity().GetSchema() == "" || req.GetIdentity().GetSource() == "" || len(req.GetIdentity().GetSubject()) == 0 {
		return nil, fmt.Errorf("%w: an artifact names its schema, source and subject", ErrRefused)
	}
	inst, err := i.artifactCaller(ctx, req.GetParentToken(), req.GetActorCredential(), req.GetInstallationId(), req.GetPolicy(), action)
	if err != nil {
		return nil, err
	}
	if req.GetIdentity().GetSource() != state.Namespace(inst) {
		return nil, fmt.Errorf("%w: artifact source %q is not installation %s's namespace %q", ErrRefused, req.GetIdentity().GetSource(), inst.ID, state.Namespace(inst))
	}
	digest, err := identityDigest(req.GetIdentity())
	if err != nil {
		return nil, err
	}
	var approval state.Approval
	if action == "activate" {
		approval, err = i.state.Approvals.Approve(ctx, inst.ID, req.GetPolicy(), digest, req.GetIdentity().GetExpectedRevision())
	} else {
		approval, err = i.state.Approvals.Standing(ctx, inst.ID, req.GetPolicy(), digest)
	}
	if err != nil {
		return nil, err
	}
	return wire(approval), nil
}

// RevokeArtifact withdraws an approval, for a person present.
func (i *Issuer) RevokeArtifact(ctx context.Context, req *artifactv1.RevokeRequest) (*artifactv1.Approval, error) {
	inst, err := i.artifactCaller(ctx, req.GetParentToken(), req.GetActorCredential(), req.GetInstallationId(), req.GetPolicy(), "activate")
	if err != nil {
		return nil, err
	}
	approval, err := i.state.Approvals.Revoke(ctx, inst.ID, req.GetPolicy(), req.GetApprovalId())
	if err != nil {
		return nil, err
	}
	return wire(approval), nil
}

// artifactCaller checks who asks and what they hold: the parent is addressed to
// the module proving itself, its owner's organisation is the installation's,
// and it holds the policy action for that installation's owner. Consent (activate) is
// the person's own: a human owner, with no module acting between.
func (i *Issuer) artifactCaller(ctx context.Context, parent, credential, installation, policy, action string) (state.Installation, error) {
	if policy == "" {
		return state.Installation{}, fmt.Errorf("%w: an artifact request names its policy, a resource kind", ErrRefused)
	}
	decoded, err := workcontext.Decode(parent)
	if err != nil {
		return state.Installation{}, err
	}
	verified, err := i.svc.Verify(ctx, parent, decoded.Context().GetAudience())
	if err != nil {
		return state.Installation{}, err
	}
	claims := verified.Context()
	actor, err := i.state.VerifyWorkload(ctx, credential)
	if err != nil {
		return state.Installation{}, fmt.Errorf("an artifact request names the module asking: %w", err)
	}
	if claims.GetAudience() != actor.Principal {
		return state.Installation{}, fmt.Errorf("%w: %s asks about a context addressed to %s", ErrRefused, actor.Name, claims.GetAudience())
	}
	inst, ok := i.state.Installation(installation)
	if !ok || inst.Status != state.Active || inst.Organization != claims.GetTenantId() {
		return state.Installation{}, fmt.Errorf("%w: installation %q is not an active installation of %s", state.ErrUnknown, installation, claims.GetTenantId())
	}
	if action == "activate" && (claims.GetOwnerPrincipalKind() != "human" || verified.Actor() != nil) {
		return state.Installation{}, fmt.Errorf("%w: consent to an artifact is given by a person present, not through a module acting for them", ErrRefused)
	}
	// The installation record establishes the owner of its consent records.
	// Identity.Subject is opaque and Revoke carries only an approval id: neither
	// establishes a policy resource id. Require coverage of the owner's whole
	// policy kind, refusing resource-limited scopes rather than dropping ids.
	// Module installations have no solution principal. An empty owner in needed
	// requires owner-unrestricted coverage; it never admits an owned scope.
	needed := []*basev0.WorkScopeV1{{ResourceKind: policy, Actions: []string{action}, ResourceOwnerId: inst.PrincipalID}}
	if !state.Attenuates(needed, verified.EffectiveScopes()) {
		return state.Installation{}, fmt.Errorf("%w: %s does not hold %s:%s for installation owner %q without resource-id restrictions; artifact identity does not establish a policy resource id", ErrRefused, claims.GetOwnerPrincipalId(), policy, action, inst.PrincipalID)
	}
	return inst, nil
}

// identityDigest is "sha256:<hex>" of the identity's deterministic encoding.
func identityDigest(identity *artifactv1.Identity) (string, error) {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(identity)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func wire(a state.Approval) *artifactv1.Approval {
	return &artifactv1.Approval{QualifiedName: a.QualifiedName(), Digest: a.Digest, ExpectedRevision: a.Revision}
}
