// Package offers projects the shared authority read into the setup facts that
// every host exposes. Hosts supply their composed bindings and convert the
// result to their generated wire types; no host repeats scope or tool selection.
package offers

import (
	"maps"
	"slices"
	"strings"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	runnablev0 "github.com/codefly-dev/core/generated/go/codefly/runnable/v0"
	"github.com/codefly-dev/core/runnable"
)

// Review is presentation of an already-authorized, consistent core read.
// Approval is absent on a member's read; projection never grants consent.
type Review struct {
	Target           string
	Approval         *domain.ConsentApproval
	Installation     *domain.Installation
	Ceiling          []*Binding
	Roles            []*Role
	ToolsComposed    bool
	InstallationRole string
	EdgeDependencies []domain.EdgeDependency
}

type Binding struct {
	Binding, Module string
	Scopes          []*Scope
}

type Role struct {
	Name         string
	Scopes       []*Scope
	Capabilities []*Capability
}

type Capability struct {
	Module, Operation string
	Requires          []*Scope
	Tools             []*Tool
}

type Tool struct {
	Name, Binding string
	Write         bool
}

type Scope struct {
	ResourceKind string
	Actions      []string
	AttachedOnly bool
	ResourceIDs  []string
}

// Project joins the reviewed declaration to composed tool bindings. It does
// not read host state or authorize callers: Service.ReviewOffer owns that read.
// Invalid exposed bindings fail with a domain refusal.
func Project(offer authority.ReviewedOffer, bindings map[string]*runnablev0.PreparedBinding) (*Review, error) {
	m, inst := offer.Module, offer.Installation
	a := offer.Approval
	out := &Review{Target: m.Name, ToolsComposed: len(bindings) > 0,
		InstallationRole: m.InstallationRole, EdgeDependencies: slices.Clone(m.EdgeDependencies)}
	// A member's read carries no consent tuple: only an administrator consents.
	if a.Digest != "" {
		out.Approval = &domain.ConsentApproval{TargetID: a.TargetID, Generation: a.Generation, ExpectedRevision: a.ExpectedRevision, Digest: a.Digest}
	}
	if inst.ID != "" {
		out.Installation = &inst
	}
	for _, id := range slices.Sorted(maps.Keys(m.Bindings)) {
		b := m.Bindings[id]
		out.Ceiling = append(out.Ceiling, &Binding{Binding: id, Module: b.Audience, Scopes: offerScopes(b.InvokeScopes, false, nil)})
	}
	modules := slices.Clone(offer.Modules)
	slices.SortFunc(modules, func(a, b domain.Module) int { return strings.Compare(a.Name, b.Name) })
	for _, name := range slices.Sorted(maps.Keys(m.Roles)) {
		role := &Role{Name: name, Scopes: offerScopes(m.Roles[name], false, nil)}
		role.Scopes = append(role.Scopes, offerScopes(m.OwnedRoles[name], true, inst.Owned)...)
		// What the role reaches, by kind and action: its confinement to the
		// installation narrows resources, never which operations it covers.
		held := scope.Unowned(append(slices.Clone(m.Roles[name]), m.OwnedRoles[name]...))
		for _, target := range modules {
			for _, method := range slices.Sorted(maps.Keys(target.Methods)) {
				policy := target.Methods[method]
				if policy.AnyCheckedCaller || len(policy.Requires) == 0 || !scope.Attenuates(policy.Requires, held) {
					continue
				}
				c := &Capability{Module: target.Name, Operation: method, Requires: offerScopes(policy.Requires, false, nil)}
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

// toolsOf is every Connect binding of one operation whose invoke
// and lookup scopes the role covers: the exposures a tool caller lists. The
// same tool composed from the operation's Connect and gRPC endpoints is one
// tool, named by its Connect binding, as a tool caller lists it.
func toolsOf(module, method string, held []*basev0.WorkScopeV1, bindings map[string]*runnablev0.PreparedBinding) ([]*Tool, error) {
	var out []*Tool
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
		if op.GetModule() != module || op.GetSpelling() != method || b.GetCall().GetConnect() == nil {
			continue
		}
		if !scope.Attenuates(append(slices.Clone(b.GetPolicy().GetInvokeScopes()), b.GetPolicy().GetLookupScopes()...), held) {
			continue
		}
		tool, err := runnable.ToolFromPrepared(b)
		if err != nil {
			return nil, domain.NotNow("the composed binding %s is not a valid tool: %v", key, err)
		}
		if slices.ContainsFunc(out, func(t *Tool) bool { return t.Name == tool.GetName() }) {
			continue
		}
		out = append(out, &Tool{Name: tool.GetName(), Binding: key, Write: tool.GetEffect() != runnablev0.ToolExposure_EFFECT_READ_ONLY})
	}
	return out, nil
}

func offerScopes(in []*basev0.WorkScopeV1, attached bool, owned map[string][]string) []*Scope {
	var out []*Scope
	for _, sc := range scope.Normalize(in) {
		s := &Scope{ResourceKind: sc.GetResourceKind(), Actions: sc.GetActions(), AttachedOnly: attached}
		if attached {
			s.ResourceIDs = slices.Clone(owned[sc.GetResourceKind()])
		}
		out = append(out, s)
	}
	return out
}
