package authority

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
)

// offeredReach is what each of a target's roles reaches in the composition
// a transaction reads (decide.ReachOf), as a consent records it.
type offeredReach struct {
	rows         map[string][]domain.ReachRow
	text, digest string
}

func reachIn(tx Tx, m domain.Module) (offeredReach, error) {
	modules, err := tx.Modules()
	if err != nil {
		return offeredReach{}, err
	}
	rows, err := decide.ReachOf(m, modules)
	if err != nil {
		return offeredReach{}, err
	}
	text, digest, err := decide.EncodeReach(rows)
	return offeredReach{rows, text, digest}, err
}

// reachWidens is what now reaches beyond the reach inst's consent approved;
// a consent recorded before reach was kept approved an unknown one.
func reachWidens(inst domain.Installation, now offeredReach) ([]string, error) {
	if inst.Consent.ReachDigest == "" {
		return []string{"approved reach unknown: review and approve the delivered offer"}, nil
	}
	approved, err := decide.DecodeReach(inst.Consent.Reach)
	if err != nil {
		return nil, err
	}
	return decide.ReachWidens(approved, now.rows), nil
}

// reconvergeReach holds every other consented installation to the reach its
// consent approved, once applied changed the composition: a module
// redelivered, or newly composed, can change what a role on a solution
// reaches without the solution changing. Where the reach its approved
// declaration has now asks nothing new, the consent advances to it, the
// revision moves (what was issued under the wider reach ends) and the change
// is journaled as installation.reconverged; where it asks more, the consent
// stands, holders keep the approved reach (approvedReach), and
// installation.upgrade_available names what widened.
func (s *Service) reconvergeReach(ctx context.Context, tx Tx, applied string) error {
	all, err := tx.Installations("")
	if err != nil {
		return err
	}
	computed := map[string]offeredReach{}
	changed := map[string]bool{}
	for _, inst := range all {
		if inst.Target == applied || inst.Status != domain.Active || inst.Consent.OperationID == "" || inst.Consent.ReachDigest == "" {
			continue
		}
		m, err := tx.ModuleNamed(inst.Target)
		if errors.Is(err, domain.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if m, err = approvedModule(tx, inst, m); err != nil {
			return err
		}
		key := fmt.Sprintf("%s@%d", m.Name, m.Generation)
		now, ok := computed[key]
		if !ok {
			if now, err = reachIn(tx, m); err != nil {
				return err
			}
			computed[key] = now
		}
		if now.digest == inst.Consent.ReachDigest {
			continue
		}
		asks, err := reachWidens(inst, now)
		if err != nil {
			return err
		}
		detail := map[string]string{"target": inst.Target, "approved_generation": fmt.Sprint(inst.Consent.Generation), "generation": fmt.Sprint(m.Generation), "delivered": applied}
		if len(asks) > 0 {
			detail["widened"] = strings.Join(asks, "; ")
			if err := s.journal(ctx, tx, domain.Event{Kind: domain.InstallationUpgradeAvailable, Organization: inst.Organization, Subject: inst.ID, Detail: detail}); err != nil {
				return err
			}
			continue
		}
		inst.Consent.Reach, inst.Consent.ReachDigest = now.text, now.digest
		inst.Revision++
		detail["revision"] = fmt.Sprint(inst.Revision)
		if err := tx.PutInstallation(inst); err != nil {
			return err
		}
		if err := s.journal(ctx, tx, domain.Event{Kind: domain.InstallationReconverged, Organization: inst.Organization, Subject: inst.ID, Detail: detail}); err != nil {
			return err
		}
		changed[inst.Organization] = true
	}
	for _, org := range slices.Sorted(maps.Keys(changed)) {
		if err := tx.BumpAuthorizationRevision(org); err != nil {
			return err
		}
	}
	return nil
}

// approvedReach is what p may hold at module through the solutions among
// principals (a verified chain's current actor and services), by the reach
// each solution's installation consent approved for the roles p holds on it:
// the scopes and the operations of module its rows list, intersected across
// those solutions. bounded is false when no solution on the path has an
// approved reach to bound by (none consented, or a consent recorded before
// reach was kept). A solution whose delivery, or a module it reaches, asks
// more than its consent approved therefore grants nobody the wider reach
// until an administrator approves it.
func approvedReach(tx Tx, p domain.Person, principals []string, module string) (held Scopes, operations map[string]bool, bounded bool, err error) {
	seen := map[string]bool{}
	for _, principal := range principals {
		if seen[principal] {
			continue
		}
		seen[principal] = true
		m, err := tx.Module(principal)
		if err != nil || m.Kind != domain.KindSolution {
			continue
		}
		inst, err := installationOf(tx, p.Organization, m.Name)
		if err != nil || inst.Status != domain.Active || inst.Consent.ReachDigest == "" {
			continue
		}
		reach, err := decide.DecodeReach(inst.Consent.Reach)
		if err != nil {
			return nil, nil, false, err
		}
		grants, err := tx.RoleGrants(inst.ID)
		if err != nil {
			return nil, nil, false, err
		}
		var here Scopes
		ops := map[string]bool{}
		for _, role := range decide.HeldRoles(p, inst, grants) {
			for _, row := range reach[role] {
				if row.Module != module || row.Via == decide.ReachPerson {
					continue
				}
				here = append(here, row.Scopes...)
				for _, op := range row.Operations {
					ops[op] = true
				}
			}
		}
		if !bounded {
			held, operations, bounded = scope.Normalize(here), ops, true
			continue
		}
		held = scope.Intersect(held, here)
		for op := range operations {
			if !ops[op] {
				delete(operations, op)
			}
		}
	}
	return held, operations, bounded, nil
}

// UpgradeAvailable reports whether inst offers an upgrade an administrator
// approves through Install: its consent stands behind the delivered
// generation (decide.UpgradeAvailable), or what its approved declaration's
// roles reach in the composition now asks more than its consent approved,
// or that approved reach is unknown.
func (s *Service) UpgradeAvailable(ctx context.Context, inst domain.Installation) (bool, error) {
	var out bool
	err := s.store.Read(ctx, func(tx Tx) error {
		out = false
		m, err := tx.ModuleNamed(inst.Target)
		if errors.Is(err, domain.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		out, err = upgradeAvailable(tx, inst, m)
		return err
	})
	return out, err
}

func upgradeAvailable(tx Tx, inst domain.Installation, m domain.Module) (bool, error) {
	if decide.UpgradeAvailable(inst, m) {
		return true, nil
	}
	if inst.Status != domain.Active || inst.Consent.OperationID == "" || inst.Target != m.Name {
		return false, nil
	}
	now, err := reachIn(tx, m)
	if err != nil || now.digest == inst.Consent.ReachDigest {
		return false, err
	}
	asks, err := reachWidens(inst, now)
	return len(asks) > 0, err
}
