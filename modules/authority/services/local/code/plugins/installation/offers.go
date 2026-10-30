package installation

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	installationv1 "gateway/pkg/gen/host/installation/v1"
	authorityplugin "gateway/plugins/authority"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/offers"
	runnablev0 "github.com/codefly-dev/core/generated/go/codefly/runnable/v0"
	"github.com/codefly-dev/core/runnable"
	codefly "github.com/codefly-dev/sdk-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// runnableBindings is the workspace group `codefly generate runnable-bindings`
// writes: one prepared Runnable binding per composed operation, keyed
// MODULE__OPERATION. It is what a tool caller runs, so it is what a review shows.
const runnableBindings = "runnable-bindings"

// RunnableReader reads the run's prepared Runnable bindings by key; nil when the
// run composes none.
type RunnableReader func(context.Context) (map[string]*runnablev0.PreparedBinding, error)

// composedRunnables reads the group through the SDK, as every tool caller does.
func composedRunnables(ctx context.Context) (map[string]*runnablev0.PreparedBinding, error) {
	sdk := codefly.For(ctx)
	keys, err := sdk.WorkspaceConfigurationKeys(runnableBindings)
	if errors.Is(err, codefly.ErrWorkspaceConfigurationAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]*runnablev0.PreparedBinding{}
	for _, key := range keys {
		raw, err := sdk.WorkspaceConfiguration(runnableBindings, key)
		if err != nil {
			return nil, fmt.Errorf("%s/%s: %w", runnableBindings, key, err)
		}
		if out[key], err = runnable.DecodePrepared([]byte(raw)); err != nil {
			return nil, fmt.Errorf("%s/%s: %w", runnableBindings, key, err)
		}
	}
	return out, nil
}

// Offers serves OfferService: the setup read beside the installation interface.
type Offers struct {
	installationv1.UnimplementedOfferServiceServer
	plugin    *Plugin
	runnables RunnableReader
}

// ListOffers lists what an administrator sets up: the delivered solutions and
// the module pages declaring roles (the core decides which).
func (o *Offers) ListOffers(ctx context.Context, req *installationv1.ListOffersRequest) (*installationv1.ListOffersResponse, error) {
	caller, err := o.plugin.caller(ctx)
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	offers, err := o.plugin.State.Service().Offers(ctx, caller, req.GetOrganizationId())
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	slices.SortFunc(offers, func(a, b domain.Module) int { return strings.Compare(a.Name, b.Name) })
	out := &installationv1.ListOffersResponse{}
	for _, m := range offers {
		out.Offers = append(out.Offers, &installationv1.Offer{Target: m.Name, Generation: m.Generation})
	}
	return out, nil
}

// ReviewOffer projects one consistent read of the offer: an administrator's,
// with the consent Install takes, or a member's who holds a role on the
// installation, without it (the core decides which). The tools are joined
// from the composed bindings by operation; nothing here is a decision.
func (o *Offers) ReviewOffer(ctx context.Context, req *installationv1.ReviewRequest) (*installationv1.ReviewedOffer, error) {
	caller, err := o.plugin.caller(ctx)
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	offer, err := o.plugin.State.Service().ReviewOffer(ctx, caller, req.GetOrganizationId(), req.GetTarget())
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	var bindings map[string]*runnablev0.PreparedBinding
	if o.runnables != nil {
		if bindings, err = o.runnables(ctx); err != nil {
			return nil, status.Errorf(codes.Unavailable, "the run's tool bindings cannot be read: %v", err)
		}
	}
	return o.plugin.review(offer, bindings)
}

// review adapts the shared projection to this host's generated wire types.
func (p *Plugin) review(offer authority.ReviewedOffer, bindings map[string]*runnablev0.PreparedBinding) (*installationv1.ReviewedOffer, error) {
	projected, err := offers.Project(offer, bindings)
	if err != nil {
		return nil, authorityplugin.Status(err)
	}
	out := &installationv1.ReviewedOffer{Target: projected.Target, ToolsComposed: projected.ToolsComposed, InstallationRole: projected.InstallationRole}
	for _, d := range projected.EdgeDependencies {
		out.EdgeDependencies = append(out.EdgeDependencies, &installationv1.OfferDependency{Module: d.Module, Presence: d.Presence})
	}
	if a := projected.Approval; a != nil {
		out.Approval = &installationv1.ConsentApproval{TargetId: a.TargetID, Generation: a.Generation, ExpectedRevision: a.ExpectedRevision, Digest: a.Digest}
	}
	if projected.Installation != nil {
		// Use the reviewed role names, never a second read of a later delivery.
		roles := make([]string, 0, len(projected.Roles))
		for _, role := range projected.Roles {
			roles = append(roles, role.Name)
		}
		out.Installation = wireInstallation(*projected.Installation, roles)
	}
	for _, b := range projected.Ceiling {
		out.Ceiling = append(out.Ceiling, &installationv1.OfferBinding{Binding: b.Binding, Module: b.Module, Scopes: scopesToWire(b.Scopes)})
	}
	for _, r := range projected.Roles {
		role := &installationv1.OfferRole{Name: r.Name, Scopes: scopesToWire(r.Scopes)}
		for _, c := range r.Capabilities {
			capability := &installationv1.OfferCapability{Module: c.Module, Operation: c.Operation, Requires: scopesToWire(c.Requires)}
			for _, t := range c.Tools {
				capability.Tools = append(capability.Tools, &installationv1.OfferTool{Name: t.Name, Binding: t.Binding, Write: t.Write})
			}
			role.Capabilities = append(role.Capabilities, capability)
		}
		out.Roles = append(out.Roles, role)
	}
	return out, nil
}

func scopesToWire(scopes []*offers.Scope) []*installationv1.OfferScope {
	var out []*installationv1.OfferScope
	for _, s := range scopes {
		out = append(out, &installationv1.OfferScope{ResourceKind: s.ResourceKind, Actions: s.Actions, AttachedOnly: s.AttachedOnly, ResourceIds: s.ResourceIDs})
	}
	return out
}
