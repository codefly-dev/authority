package issuer

import (
	"context"
	"slices"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/access"
	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"

	accessv1 "gateway/pkg/gen/host/access/v1"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

// The access interface (codefly.dev/access) is the wire over the shared
// access core (libraries/authority-core/go/access), which decides and reads
// the same in-memory store the authority does. What this file adds is the
// wire alone: the asking module attested from its workload credential, and
// the messages.

// AccessGrant makes or refreshes one grant.
func (i *Issuer) AccessGrant(ctx context.Context, req *accessv1.GrantRequest) (*accessv1.GrantResponse, error) {
	w, err := i.accessActor(ctx, req.GetActor())
	if err != nil {
		return nil, err
	}
	var expires time.Time
	if req.GetExpiresAtUnix() != 0 {
		expires = time.Unix(req.GetExpiresAtUnix(), 0)
	}
	grant, revision, err := i.state.Access().Grant(ctx, access.GrantRequest{Token: req.GetToken(), Actor: w, Target: target(req.GetTarget()),
		Placement: placement(req.GetPlacement()), Subject: subject(req.GetSubject()), Actions: req.GetActions(), ExpiresAt: expires})
	if err != nil {
		return nil, err
	}
	return &accessv1.GrantResponse{Grant: wireGrant(grant), Revision: wireRevision(revision)}, nil
}

// AccessRevoke ends one grant.
func (i *Issuer) AccessRevoke(ctx context.Context, req *accessv1.RevokeRequest) (*accessv1.RevokeResponse, error) {
	w, err := i.accessActor(ctx, req.GetActor())
	if err != nil {
		return nil, err
	}
	grant, revision, err := i.state.Access().Revoke(ctx, access.RevokeRequest{Token: req.GetToken(), Actor: w, Target: target(req.GetTarget()),
		Placement: placement(req.GetPlacement()), Subject: subject(req.GetSubject())})
	if err != nil {
		return nil, err
	}
	return &accessv1.RevokeResponse{Revoked: wireGrant(grant), Revision: wireRevision(revision)}, nil
}

// AccessListGrants answers the grants on one reference.
func (i *Issuer) AccessListGrants(ctx context.Context, req *accessv1.ListGrantsRequest) (*accessv1.ListGrantsResponse, error) {
	w, err := i.accessActor(ctx, req.GetActor())
	if err != nil {
		return nil, err
	}
	grants, revision, err := i.state.Access().ListGrants(ctx, access.ListRequest{Token: req.GetToken(), Actor: w, Target: target(req.GetTarget()), Placement: placement(req.GetPlacement())})
	if err != nil {
		return nil, err
	}
	out := &accessv1.ListGrantsResponse{Revision: wireRevision(revision)}
	for _, g := range grants {
		out.Grants = append(out.Grants, wireGrant(g))
	}
	return out, nil
}

// AccessForget ends every grant on a reference that is gone.
func (i *Issuer) AccessForget(ctx context.Context, req *accessv1.ForgetRequest) (*accessv1.ForgetResponse, error) {
	w, err := i.accessActor(ctx, req.GetActor())
	if err != nil {
		return nil, err
	}
	forgotten, revision, err := i.state.Access().Forget(ctx, access.ForgetRequest{Token: req.GetToken(), Actor: w, Target: target(req.GetTarget()), EveryVersion: req.GetEveryVersion()})
	if err != nil {
		return nil, err
	}
	return &accessv1.ForgetResponse{Forgotten: int32(forgotten), Revision: wireRevision(revision)}, nil
}

// AccessCheck decides one action on one placed resource.
func (i *Issuer) AccessCheck(ctx context.Context, req *accessv1.CheckRequest) (*accessv1.CheckResponse, error) {
	out, err := i.accessCheck(ctx, req.GetToken(), req.GetActor(), req.GetAction(), []*accessv1.Placement{req.GetPlacement()}, req.GetMinRevision(), nil, req.GetFreshness())
	if err != nil {
		return nil, err
	}
	return out.GetResults()[0], nil
}

// AccessCheckBatch decides one action on many placed resources, in order.
func (i *Issuer) AccessCheckBatch(ctx context.Context, req *accessv1.CheckBatchRequest) (*accessv1.CheckBatchResponse, error) {
	return i.accessCheck(ctx, req.GetToken(), req.GetActor(), req.GetAction(), req.GetPlacements(), req.GetMinRevision(), req.GetItemMinRevisions(), req.GetFreshness())
}

func (i *Issuer) accessCheck(ctx context.Context, token string, actor *authorityv1.WorkloadCredential, action string, placements []*accessv1.Placement, min *accessv1.AccessRevision, itemMins []*accessv1.AccessRevision, freshness accessv1.Freshness) (*accessv1.CheckBatchResponse, error) {
	w, err := i.accessActor(ctx, actor)
	if err != nil {
		return nil, err
	}
	r := access.CheckRequest{Token: token, Actor: w, Action: action, MinRevision: minimum(min), Head: freshness == accessv1.Freshness_FRESHNESS_HEAD}
	for _, m := range itemMins {
		r.ItemMinRevisions = append(r.ItemMinRevisions, minimum(m))
	}
	for _, p := range placements {
		r.Placements = append(r.Placements, placement(p))
	}
	decisions, revision, err := i.state.Access().Check(ctx, r)
	if err != nil {
		return nil, err
	}
	out := &accessv1.CheckBatchResponse{Revision: wireRevision(revision)}
	for _, d := range decisions {
		result := &accessv1.CheckResponse{Decision: accessv1.Decision_DECISION_DENIED, Reason: d.Reason, Revision: wireRevision(revision)}
		if d.Allowed {
			result.Decision = accessv1.Decision_DECISION_ALLOWED
			result.ValidUntilUnix = d.ValidUntil.Unix()
		}
		for _, b := range d.Bases {
			result.ViewerBases = append(result.ViewerBases, wireBasis[b])
		}
		out.Results = append(out.Results, result)
	}
	return out, nil
}

// AccessListViewerGrants pages the viewer's direct grants.
func (i *Issuer) AccessListViewerGrants(ctx context.Context, req *accessv1.ListViewerGrantsRequest) (*accessv1.ListViewerGrantsResponse, error) {
	w, err := i.accessActor(ctx, req.GetActor())
	if err != nil {
		return nil, err
	}
	page, err := i.state.Access().ListViewerGrants(ctx, access.ViewerGrantsRequest{Token: req.GetToken(), Actor: w, Kinds: req.GetResourceKinds(), Action: req.GetAction(),
		PageSize: int(req.GetPageSize()), PageToken: req.GetPageToken(), MinRevision: minimum(req.GetMinRevision())})
	if err != nil {
		return nil, err
	}
	out := &accessv1.ListViewerGrantsResponse{NextPageToken: page.NextPage, Revision: wireRevision(page.Revision), ValidUntilUnix: page.ValidUntil.Unix()}
	for _, r := range page.Resources {
		out.Resources = append(out.Resources, &accessv1.ResourceRef{ResourceKind: r.Kind, ResourceId: r.ResourceID, Version: r.Version})
	}
	return out, nil
}

// accessActor attests the module asking from its workload credential.
func (i *Issuer) accessActor(ctx context.Context, actor *authorityv1.WorkloadCredential) (authority.Workload, error) {
	return i.workload(ctx, actor.GetCredential(), "an access question is asked by the module serving the kind")
}

var wireBasis = map[access.Basis]accessv1.Basis{
	access.RoleScope: accessv1.Basis_BASIS_ROLE_SCOPE, access.AncestorGrant: accessv1.Basis_BASIS_ANCESTOR_GRANT,
	access.ResourceGrant: accessv1.Basis_BASIS_RESOURCE_GRANT, access.VersionGrant: accessv1.Basis_BASIS_VERSION_GRANT,
}

// minimum is the revision a caller named as a minimum, as it sent it; the
// core parses and refuses it.
func minimum(r *accessv1.AccessRevision) access.Minimum {
	return access.Minimum{Organization: r.GetOrganizationId(), Opaque: r.GetOpaque()}
}

// wireRevision is a revision in the core's one encoding, which the module
// stores and returns and never reads.
func wireRevision(r access.Revision) *accessv1.AccessRevision {
	return &accessv1.AccessRevision{OrganizationId: r.Organization, Opaque: r.Opaque()}
}

func target(r *accessv1.ResourceRef) access.Target {
	return access.Target{Kind: r.GetResourceKind(), ResourceID: r.GetResourceId(), Version: r.GetVersion()}
}

func node(n *accessv1.PlacedNode) access.Node {
	return access.Node{Kind: n.GetRef().GetResourceKind(), ResourceID: n.GetRef().GetResourceId(), Version: n.GetRef().GetVersion(), Owner: n.GetOwnerId()}
}

func placement(p *accessv1.Placement) access.Placement {
	out := access.Placement{Resource: node(p.GetResource())}
	for _, a := range p.GetAncestors() {
		out.Ancestors = append(out.Ancestors, node(a))
	}
	return out
}

// subject is the one subject a request names; none, for a request that names
// no subject, which the core refuses.
func subject(s *accessv1.Subject) domain.AccessSubject {
	switch v := s.GetSubject().(type) {
	case *accessv1.Subject_PersonId:
		return domain.AccessSubject{Kind: domain.AccessPerson, ID: v.PersonId}
	case *accessv1.Subject_TeamId:
		return domain.AccessSubject{Kind: domain.AccessTeam, ID: v.TeamId}
	case *accessv1.Subject_InstallationId:
		return domain.AccessSubject{Kind: domain.AccessInstallation, ID: v.InstallationId}
	}
	return domain.AccessSubject{}
}

func wireGrant(g domain.AccessGrant) *accessv1.AccessGrant {
	out := &accessv1.AccessGrant{GrantId: g.ID, OrganizationId: g.Organization, Actions: slices.Clone(g.Actions), GrantedBy: g.GrantedBy, CreatedAtUnix: g.CreatedAt.Unix(),
		Resource: &accessv1.ResourceRef{ResourceKind: g.Kind, ResourceId: g.ResourceID, Version: g.Version}, Subject: &accessv1.Subject{}}
	if !g.ExpiresAt.IsZero() {
		out.ExpiresAtUnix = g.ExpiresAt.Unix()
	}
	switch g.Subject.Kind {
	case domain.AccessPerson:
		out.Subject.Subject = &accessv1.Subject_PersonId{PersonId: g.Subject.ID}
	case domain.AccessTeam:
		out.Subject.Subject = &accessv1.Subject_TeamId{TeamId: g.Subject.ID}
	case domain.AccessInstallation:
		out.Subject.Subject = &accessv1.Subject_InstallationId{InstallationId: g.Subject.ID}
	}
	return out
}
