package issuer

import (
	"context"
	"fmt"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"

	"gateway/pkg/business/state"
	artifactv1 "gateway/pkg/gen/host/artifact/v1"
)

// The artifact interface (codefly.dev/artifact): a person's consent to an exact
// authored artifact a module runs, for one installation, under one policy. Who
// may decide is the shared core's one decision (authority.DecideArtifact,
// decide.Artifact), the one every host makes; this host keeps the approvals.
// Consent is durable: state.Approvals keeps it in the module's store when one
// is composed, so a restart of this process still answers a run.

// Artifact answers Approve or Authorize (action "activate" or "run").
func (i *Issuer) Artifact(ctx context.Context, action string, req *artifactv1.ArtifactRequest) (*artifactv1.Approval, error) {
	identity := identityOf(req.GetIdentity())
	inst, err := i.artifactCaller(ctx, req.GetParentToken(), req.GetActorCredential(), req.GetInstallationId(), req.GetPolicy(), action, &identity)
	if err != nil {
		return nil, err
	}
	digest := decide.ArtifactDigest(identity)
	var approval state.Approval
	if action == decide.ArtifactActivate {
		approval, err = i.state.Approvals.Approve(ctx, inst.ID, req.GetPolicy(), digest, identity.ExpectedRevision)
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
	inst, err := i.artifactCaller(ctx, req.GetParentToken(), req.GetActorCredential(), req.GetInstallationId(), req.GetPolicy(), decide.ArtifactActivate, nil)
	if err != nil {
		return nil, err
	}
	approval, err := i.state.Approvals.Revoke(ctx, inst.ID, req.GetPolicy(), req.GetApprovalId())
	if err != nil {
		return nil, err
	}
	return wire(approval), nil
}

// artifactCaller proves the module asking by its workload credential, then
// asks the shared core whether it may decide.
func (i *Issuer) artifactCaller(ctx context.Context, parent, credential, installation, policy, action string, identity *decide.ArtifactIdentity) (state.Installation, error) {
	actor, err := i.state.VerifyWorkload(ctx, credential)
	if err != nil {
		return state.Installation{}, fmt.Errorf("an artifact request names the module asking: %w", err)
	}
	return i.svc.DecideArtifact(ctx, parent, authority.Workload{Module: actor.Name}, installation, policy, action, identity)
}

func identityOf(id *artifactv1.Identity) decide.ArtifactIdentity {
	out := decide.ArtifactIdentity{Schema: id.GetSchema(), Source: id.GetSource(), Subject: id.GetSubject(), ExpectedRevision: id.GetExpectedRevision()}
	for _, c := range id.GetContracts() {
		out.Contracts = append(out.Contracts, decide.ArtifactContract{Kind: c.GetKind(), Name: c.GetName(), Digest: c.GetDigest()})
	}
	return out
}

func wire(a state.Approval) *artifactv1.Approval {
	return &artifactv1.Approval{QualifiedName: a.QualifiedName(), Digest: a.Digest, ExpectedRevision: a.Revision}
}
