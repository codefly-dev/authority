package authority

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// pageReach is what each role of a module page (a module declaring roles,
// installed by composition, so held by no consent) reaches through its
// bindings, the declaration it reaches with, and the composition it was
// read in.
type pageReach struct {
	m       domain.Module
	rows    map[string][]domain.ReachRow
	modules []domain.Module
}

// pageReaches is every composed module page's pageReach, by name. Both what a
// page's role reaches on the page itself and what it reaches through its
// bindings are compared; a solution is held by its installations' consents
// instead (reconverge).
func pageReaches(tx Tx) (map[string]pageReach, error) {
	modules, err := tx.Modules()
	if err != nil {
		return nil, err
	}
	out := map[string]pageReach{}
	for _, m := range modules {
		if m.Kind == domain.KindSolution || !decide.RoleGated(m) {
			continue
		}
		rows, err := bindingReach(m, modules)
		if err != nil {
			return nil, err
		}
		out[m.Name] = pageReach{m, rows, modules}
	}
	return out, nil
}

// bindingReach is decide.ReachOf's rows through m's bindings.
func bindingReach(m domain.Module, modules []domain.Module) (map[string][]domain.ReachRow, error) {
	reach, err := decide.ReachOf(m, modules)
	if err != nil {
		return nil, err
	}
	rows := map[string][]domain.ReachRow{}
	for role, all := range reach {
		for _, row := range all {
			if row.Via == decide.ReachBinding {
				rows[role] = append(rows[role], row)
			}
		}
	}
	return rows, nil
}

// widenedPageRoles is the roles of a module page whose reach through its
// bindings now widens beyond what it reached before, and what widened: each
// role alone, then the roles left held together (decide.JointRoles over
// them), which may reach what none reaches alone; if they do, every one of
// them widened.
func widenedPageRoles(was, now pageReach) (map[string]bool, []string, error) {
	widened := map[string]bool{}
	var asks []string
	// A page role is compared on what it can do: its scopes and the
	// operations they admit at each module. A row's Policies list every
	// method of the module, so a method added there that the role can never
	// call would otherwise end its grants; a relaxed or newly admitted
	// operation the role can call is in Operations.
	admitted := func(rows []domain.ReachRow) []domain.ReachRow {
		out := make([]domain.ReachRow, len(rows))
		for i, row := range rows {
			row.Policies = nil
			out[i] = row
		}
		return out
	}
	widens := func(role string, before, after []domain.ReachRow) []string {
		return decide.ReachWidensWithin(map[string][]domain.ReachRow{role: admitted(before)}, map[string][]domain.ReachRow{role: admitted(after)}, was.m)
	}
	var left []string
	names := map[string]bool{}
	for role := range now.m.Roles {
		names[role] = true
	}
	for role := range now.m.OwnedRoles {
		names[role] = true
	}
	for _, role := range slices.Sorted(maps.Keys(names)) {
		// What the role reaches on the page itself counts as much as what it
		// reaches through the page's bindings: a grant of a role is an
		// administrator's approval of what the role meant then, never of a
		// wider meaning a later delivery gave the same name.
		own := ownWidened(was.m, now.m, role)
		further := widens(role, was.rows[role], now.rows[role])
		if len(own)+len(further) > 0 {
			widened[role] = true
			asks = append(asks, own...)
			asks = append(asks, further...)
			continue
		}
		left = append(left, role)
	}
	if len(left) < 2 {
		return widened, asks, nil
	}
	only := func(m domain.Module) domain.Module {
		m.Roles = maps.Clone(m.Roles)
		maps.DeleteFunc(m.Roles, func(role string, _ []*basev0.WorkScopeV1) bool { return !slices.Contains(left, role) })
		return m
	}
	before, err := bindingReach(only(was.m), was.modules)
	if err != nil {
		return nil, nil, err
	}
	after, err := bindingReach(only(now.m), now.modules)
	if err != nil {
		return nil, nil, err
	}
	if further := widens(decide.JointRoles, before[decide.JointRoles], after[decide.JointRoles]); len(further) > 0 {
		for _, role := range left {
			widened[role] = true
		}
		asks = append(asks, further...)
	}
	return widened, asks, nil
}

// ownWidened is what a role of next reaches on the module itself beyond what
// the role of the same name reached in was: the role's own scopes, and the
// installation-owned role's. A role was did not declare has no grants to
// widen.
func ownWidened(was, next domain.Module, role string) []string {
	var out []string
	if before, ok := was.Roles[role]; ok && !scope.Attenuates(next.Roles[role], before) {
		out = append(out, "role "+role+" reaches further on "+next.Name)
	}
	if before, ok := was.OwnedRoles[role]; ok && !scope.Attenuates(next.OwnedRoles[role], before) {
		out = append(out, "installation-owned role "+role+" reaches further on "+next.Name)
	}
	return out
}

// dropWidenedPageGrants ends, once a delivery changed the composition, the
// grants of every module page role whose reach through the page's bindings
// widened beyond what it reached before (decide.ReachWidensWithin against the
// page's declaration then): no consent holds a module page's installation,
// so an administrator's grant is the only approval its holders have, and a
// delivery, of the page or of any module it reaches, never widens what that
// grant gave. The installation's revision moves (what was issued under the
// grant ends), each grant is journaled as role.revoked, and
// installation.role_reach_widened names what widened, for an administrator
// to grant again. A widening of the roles held together ends every role's
// grants. So does what a role reaches on the page itself: the grants of an
// installation nothing approved never take a wider meaning from a delivery.
func (s *Service) dropWidenedPageGrants(ctx context.Context, tx Tx, applied string, before map[string]pageReach) error {
	after, err := pageReaches(tx)
	if err != nil {
		return err
	}
	all, err := tx.Installations("")
	if err != nil {
		return err
	}
	changed := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(after)) {
		was, ok := before[name]
		if !ok {
			continue // newly composed: nothing granted under an earlier reach
		}
		widened, asks, err := widenedPageRoles(was, after[name])
		if err != nil {
			return err
		}
		if len(widened) == 0 {
			continue
		}
		roles := slices.Sorted(maps.Keys(widened))
		for _, inst := range all {
			// Every active installation of the page, a consent receipt on it
			// or not: no consent caps a module page's reach (approvedReach
			// bounds solutions alone), so none may skip this.
			if inst.Target != name || inst.Status != domain.Active {
				continue
			}
			grants, err := tx.RoleGrants(inst.ID)
			if err != nil {
				return err
			}
			dropped := false
			for _, g := range grants {
				if !widened[g.Role] {
					continue
				}
				if err := tx.DeleteRoleGrant(g); err != nil {
					return err
				}
				r := RoleRequest{Organization: inst.Organization, InstallationID: inst.ID, Role: g.Role, PersonID: g.PersonID, TeamID: g.TeamID}
				if err := s.journal(ctx, tx, r.event(domain.RoleRevoked, "delivery:"+applied)); err != nil {
					return err
				}
				dropped = true
			}
			if !dropped {
				continue
			}
			inst.Revision++
			if err := tx.PutInstallation(inst); err != nil {
				return err
			}
			detail := map[string]string{"target": name, "delivered": applied, "roles": strings.Join(roles, ","), "widened": strings.Join(asks, "; "), "revision": fmt.Sprint(inst.Revision)}
			if err := s.journal(ctx, tx, domain.Event{Kind: domain.InstallationRoleReachWidened, Organization: inst.Organization, Subject: inst.ID, Detail: detail}); err != nil {
				return err
			}
			changed[inst.Organization] = true
		}
	}
	for _, org := range slices.Sorted(maps.Keys(changed)) {
		if err := tx.BumpAuthorizationRevision(org); err != nil {
			return err
		}
	}
	return nil
}
