package installation

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	installationv1 "gateway/pkg/gen/host/installation/v1"
	authorityplugin "gateway/plugins/authority"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
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

// ListOffers lists the delivered solutions, for an administrator.
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

func (p *Plugin) review(offer authority.ReviewedOffer, bindings map[string]*runnablev0.PreparedBinding) (*installationv1.ReviewedOffer, error) {
	m, inst := offer.Module, offer.Installation
	a := offer.Approval
	out := &installationv1.ReviewedOffer{Target: m.Name, ToolsComposed: len(bindings) > 0}
	// A member's read carries no consent tuple: only an administrator consents.
	if a.Digest != "" {
		out.Approval = &installationv1.ConsentApproval{TargetId: a.TargetID, Generation: a.Generation, ExpectedRevision: a.ExpectedRevision, Digest: a.Digest}
	}
	if inst.ID != "" {
		out.Installation = p.wire(inst)
	}
	for _, id := range slices.Sorted(maps.Keys(m.Bindings)) {
		b := m.Bindings[id]
		out.Ceiling = append(out.Ceiling, &installationv1.OfferBinding{Binding: id, Module: b.Audience, Scopes: offerScopes(b.InvokeScopes, false, nil)})
	}
	modules := slices.Clone(offer.Modules)
	slices.SortFunc(modules, func(a, b domain.Module) int { return strings.Compare(a.Name, b.Name) })
	for _, name := range slices.Sorted(maps.Keys(m.Roles)) {
		role := &installationv1.OfferRole{Name: name, Scopes: offerScopes(m.Roles[name], false, nil)}
		role.Scopes = append(role.Scopes, offerScopes(m.OwnedRoles[name], true, inst.Owned)...)
		// What the role reaches, by kind and action: its confinement to the
		// installation narrows resources, never which operations it covers.
		held := scope.Unowned(stripIDs(append(slices.Clone(m.Roles[name]), m.OwnedRoles[name]...)))
		for _, target := range modules {
			for _, method := range slices.Sorted(maps.Keys(target.Methods)) {
				policy := target.Methods[method]
				if policy.AnyCheckedCaller || len(policy.Requires) == 0 || !scope.Attenuates(policy.Requires, held) {
					continue
				}
				c := &installationv1.OfferCapability{Module: target.Name, Operation: method, Requires: offerScopes(policy.Requires, false, nil)}
				tools, err := toolsOf(target.Name, method, held, bindings)
				if err != nil {
					return nil, err
				}
				c.Tools = tools
				role.Capabilities = append(role.Capabilities, c)
			}
		}
		out.Roles = append(out.Roles, role)
	}
	return out, nil
}

// toolsOf is every tool-exposed Connect binding of one operation whose invoke
// and lookup scopes the role covers: the exposures a tool caller lists. The
// same tool composed from the operation's Connect and gRPC endpoints is one
// tool, named by its Connect binding, as a tool caller lists it.
func toolsOf(module, method string, held []*basev0.WorkScopeV1, bindings map[string]*runnablev0.PreparedBinding) ([]*installationv1.OfferTool, error) {
	var out []*installationv1.OfferTool
	keys := slices.Sorted(maps.Keys(bindings))
	connectFirst := func(key string) int {
		if bindings[key].GetOperation().GetEndpoint() == "connect" {
			return 0
		}
		return 1
	}
	slices.SortStableFunc(keys, func(a, b string) int { return connectFirst(a) - connectFirst(b) })
	for _, key := range keys {
		b := bindings[key]
		op := b.GetOperation()
		if op.GetModule() != module || op.GetSpelling() != method || b.GetPolicy().GetTool() == nil || b.GetCall().GetConnect() == nil {
			continue
		}
		if !scope.Attenuates(append(slices.Clone(b.GetPolicy().GetInvokeScopes()), b.GetPolicy().GetLookupScopes()...), held) {
			continue
		}
		tool, err := runnable.ToolFromPrepared(b)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "the composed binding %s is not a valid tool: %v", key, err)
		}
		if slices.ContainsFunc(out, func(t *installationv1.OfferTool) bool { return t.GetName() == tool.GetName() }) {
			continue
		}
		out = append(out, &installationv1.OfferTool{Name: tool.GetName(), Binding: key, Write: tool.GetEffect() != runnablev0.ToolExposure_EFFECT_READ_ONLY})
	}
	return out, nil
}

func stripIDs(in []*basev0.WorkScopeV1) []*basev0.WorkScopeV1 {
	out := make([]*basev0.WorkScopeV1, 0, len(in))
	for _, sc := range in {
		out = append(out, &basev0.WorkScopeV1{ResourceKind: sc.GetResourceKind(), Actions: sc.GetActions()})
	}
	return out
}

func offerScopes(in []*basev0.WorkScopeV1, attached bool, owned map[string][]string) []*installationv1.OfferScope {
	var out []*installationv1.OfferScope
	for _, sc := range scope.Normalize(in) {
		s := &installationv1.OfferScope{ResourceKind: sc.GetResourceKind(), Actions: sc.GetActions(), AttachedOnly: attached}
		if attached {
			s.ResourceIds = slices.Clone(owned[sc.GetResourceKind()])
		}
		out = append(out, s)
	}
	return out
}
