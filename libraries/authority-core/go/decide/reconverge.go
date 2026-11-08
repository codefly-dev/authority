package decide

import (
	"fmt"
	"maps"
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
)

// Widens lists what next asks of an organization that approved the reviewed
// surface of approved, in the order a review shows it; empty means next asks
// nothing new and an active installation re-converges on it without a click.
// The reviewed surface is what Review and ReviewOffer show an administrator:
// the kind, each role and installation-owned role with its scopes, each
// binding with its audience and scopes, each edge dependency, the installation
// role selector and each method's policy. next widens when it adds a role, a
// binding, an edge dependency or a method; reaches further with a role or a
// binding; readdresses a binding; asks standing authority the approved
// declaration did not (any selector change but to "none"); or lets a method
// be called with less than the approved one required (more roles then cover
// it). A role, binding, edge dependency or method dropped, or a scope cut,
// narrows and is never listed: nothing new is asked, and what was issued
// under the wider declaration ends by its revision.
func Widens(approved, next domain.Module) []string {
	var out []string
	if approved.Kind != next.Kind {
		out = append(out, fmt.Sprintf("kind %s is now %s", approved.Kind, next.Kind))
	}
	for _, name := range slices.Sorted(maps.Keys(next.Roles)) {
		was, ok := approved.Roles[name]
		switch {
		case !ok:
			out = append(out, "role "+name+" added")
		case !scope.Attenuates(next.Roles[name], was):
			out = append(out, "role "+name+" reaches further")
		}
	}
	for _, name := range slices.Sorted(maps.Keys(next.OwnedRoles)) {
		was, ok := approved.OwnedRoles[name]
		switch {
		case !ok:
			out = append(out, "installation-owned role "+name+" added")
		case !scope.Attenuates(next.OwnedRoles[name], was):
			out = append(out, "installation-owned role "+name+" reaches further")
		}
	}
	for _, id := range slices.Sorted(maps.Keys(next.Bindings)) {
		b := next.Bindings[id]
		was, ok := approved.Bindings[id]
		switch {
		case !ok:
			out = append(out, "binding "+id+" added")
		case was.Audience != b.Audience:
			out = append(out, fmt.Sprintf("binding %s readdressed from %s to %s", id, was.Audience, b.Audience))
		case !scope.Attenuates(b.InvokeScopes, was.InvokeScopes) || !scope.Attenuates(b.HeadlessScopes, was.HeadlessScopes) || !scope.Attenuates(b.LookupScopes, was.LookupScopes):
			out = append(out, "binding "+id+" reaches further")
		}
	}
	for _, d := range next.EdgeDependencies {
		if !slices.Contains(approved.EdgeDependencies, d) {
			out = append(out, fmt.Sprintf("edge dependency on %s (%s) added", d.Module, d.Presence))
		}
	}
	if next.InstallationRole != approved.InstallationRole && next.InstallationRole != domain.NoInstallationRole {
		if next.InstallationRole == "" {
			out = append(out, "installation role left to the installer")
		} else {
			out = append(out, "installation role "+next.InstallationRole+" asked")
		}
	}
	for _, method := range slices.Sorted(maps.Keys(next.Methods)) {
		policy := next.Methods[method]
		was, ok := approved.Methods[method]
		switch {
		case !ok:
			out = append(out, "method "+method+" added")
		case policy.AnyCheckedCaller && !was.AnyCheckedCaller:
			out = append(out, "method "+method+" opened to any checked caller")
		case !policy.AnyCheckedCaller && !scope.Attenuates(was.Requires, policy.Requires):
			out = append(out, "method "+method+" requires less")
		}
	}
	return out
}

// UpgradeAvailable reports whether inst, an installation of m, stands on a
// consent approved at a generation behind the delivered one: a redelivery
// asked more than the approved offer and waits for an administrator's
// approval (Install with a fresh review). An installation the host or
// composition installed without consent never offers one.
func UpgradeAvailable(inst domain.Installation, m domain.Module) bool {
	return inst.Status == domain.Active && inst.Target == m.Name && inst.Consent.OperationID != "" &&
		inst.Consent.Generation != 0 && inst.Consent.Generation < m.Generation
}
