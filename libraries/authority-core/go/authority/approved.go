package authority

import (
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// ApprovedDeclaration is the declaration that governs what inst's holders
// hold: its target as composed now while inst's consent stands at that
// generation (or the installation was never consented to, or its consent
// predates the generation being kept), otherwise the generation the consent
// approved, as the store keeps it. It is the rule issuance applies, exported
// so a host that states what a holder may hold never restates it. A target no
// longer composed answers domain.ErrNotFound; an approved generation the
// store does not keep, or keeps as something other than what was consented
// to, is refused by name (approvedModule).
func ApprovedDeclaration(tx Tx, inst domain.Installation) (domain.Module, error) {
	m, err := tx.ModuleNamed(inst.Target)
	if err != nil {
		return domain.Module{}, err
	}
	return approvedModule(tx, inst, m)
}

// ApprovedDeclaration is ApprovedDeclaration read in one transaction.
func (s *Service) ApprovedDeclaration(ctx context.Context, inst domain.Installation) (domain.Module, error) {
	var m domain.Module
	err := s.store.Read(ctx, func(tx Tx) (err error) {
		m, err = ApprovedDeclaration(tx, inst)
		return err
	})
	return m, err
}

// approvedModule is ApprovedDeclaration given m, inst's target as composed
// now: m while the consent stands at its generation (or names none),
// otherwise the generation the consent approved, as the store kept it. A
// redelivery that asked more than the consent approved therefore grants
// nobody the wider roles until an administrator upgrades. A generation the
// store does not keep is refused by name: a host must keep what an active
// consent names. So is a kept declaration whose offer digest is not the one
// the consent recorded: whatever wrote that row, it is not what an
// administrator approved. A digest that differs only because the module's
// encoding changed fails the same way, closed: the installation reads as an
// upgrade, and its review records the digest anew.
//
// The scopes that govern the installation's sources are answered only where
// someone approved them (approvedGovernance).
func approvedModule(tx Tx, inst domain.Installation, m domain.Module) (domain.Module, error) {
	approved, err := approvedGeneration(tx, inst, m)
	if err == nil && !approvedGovernance(inst) {
		approved.SourceGovernance = nil
	}
	return approved, err
}

// approvedGovernance reports whether inst's declaration may govern its
// sources: only where someone approved it. A consent at a kept generation is
// an administrator's review, whoever made the installation; with no consent,
// only a host's own install of a solution, naming its installer and holding a
// principal of its own, approved it. A legacy consent (an operation and no
// kept generation) proves no approved baseline, and an installation made by
// composition (no installer, or the receipt composition took) was never
// approved at all, even after its target's delivery becomes a solution — until an administrator reviews it:
// who manages its sources is never something no administrator has seen.
func approvedGovernance(inst domain.Installation) bool {
	if inst.Consent.OperationID == domain.ComposedConsent {
		return false // composition's receipt is nobody's review
	}
	if inst.Consent.OperationID != "" {
		return inst.Consent.Generation != 0
	}
	return inst.InstalledBy != "" && inst.PrincipalID != ""
}

// approvedGeneration is approvedModule before governance is held to it.
func approvedGeneration(tx Tx, inst domain.Installation, m domain.Module) (domain.Module, error) {
	c := inst.Consent
	if c.OperationID == "" || c.Generation == 0 || c.Generation > m.Generation || inst.Target != m.Name {
		return m, nil
	}
	if c.Generation == m.Generation {
		approved, reread, err := approvedReading(tx, inst, m)
		if err != nil || !reread {
			return m, err
		}
		return approved, nil
	}
	approved, err := tx.ApprovedModule(m.Name, c.Generation, c.Digest)
	if errors.Is(err, domain.ErrNotFound) && c.Digest != "" {
		// Kept under another digest only: whatever wrote it, not this offer.
		approved, err = tx.ApprovedModule(m.Name, c.Generation, "")
	}
	if errors.Is(err, domain.ErrNotFound) {
		return m, domain.NotNow("the generation %d of %s that installation %s approved is not kept; review and approve the delivered offer", c.Generation, m.Name, inst.ID)
	}
	if err != nil {
		return domain.Module{}, err
	}
	if c.Digest != "" {
		digest, err := OfferDigest(approved)
		if err != nil {
			return domain.Module{}, err
		}
		if digest != c.Digest {
			return domain.Module{}, domain.NotNow("the generation %d of %s kept for installation %s is not the offer it approved; review and approve the delivered offer", c.Generation, m.Name, inst.ID)
		}
	}
	return approved, nil
}

// approvedReading is, when m's generation was read again since inst's consent
// approved it (Service.RereadModule) as a declaration the store keeps by the
// digest the consent recorded, that approved reading: the consent stands at
// m's generation and still holds what it approved, not the re-read. reread
// is false when the consent approved m as it is, and when the store keeps no
// declaration by the recorded digest: an offer digest the module's encoding
// changed since is no re-read, and a consent is held to its reach either way
// (approvedReach).
func approvedReading(tx Tx, inst domain.Installation, m domain.Module) (domain.Module, bool, error) {
	c := inst.Consent
	if c.OperationID == "" || c.Generation != m.Generation || c.Digest == "" || inst.Target != m.Name {
		return m, false, nil
	}
	if now, err := OfferDigest(m); err != nil || now == c.Digest {
		return m, false, err
	}
	approved, err := tx.ApprovedModule(m.Name, c.Generation, c.Digest)
	if errors.Is(err, domain.ErrNotFound) {
		return m, false, nil
	}
	if err != nil {
		return m, false, err
	}
	digest, err := OfferDigest(approved)
	return approved, err == nil && digest == c.Digest, err
}

// dropUndeclaredGrants deletes every grant on inst of a role next does not
// declare, when inst's consent advances to next: a grant of a role nobody
// declares any more would otherwise sleep in the store until a later
// generation declared the name again, and its holders would hold whatever
// that generation meant by it, with no administrator having granted that.
// Each deletion is journaled as a revocation by actor.
//
// STOPGAP (one release, domain.LegacyInstallerRole): when next declares
// exactly admin and user, a grant of an old person role moves instead of
// ending (domain.CrossoverRole): installer to admin; editor, viewer and
// steward to user, least privilege. The move is journaled as a grant and a
// revocation by actor, each with Detail domain.CrossoverFrom naming the old
// role and domain.CrossoverBasis naming the rule; a subject who holds the new
// role already, or gains it from another old grant here, is granted (and
// journaled) once.
func (s *Service) dropUndeclaredGrants(ctx context.Context, tx Tx, inst domain.Installation, next domain.Module, actor string) error {
	grants, err := tx.RoleGrants(inst.ID)
	if err != nil {
		return err
	}
	held := map[domain.RoleGrant]bool{}
	for _, g := range grants {
		held[g] = true
	}
	for _, g := range grants {
		if _, declared := next.Roles[g.Role]; declared {
			continue
		}
		role, basis, crossover := domain.CrossoverRole(g.Role, next.Roles)
		if crossover {
			moved := g
			moved.Role = role
			if !held[moved] {
				if err := tx.PutRoleGrant(moved); err != nil {
					return err
				}
				held[moved] = true
				r := RoleRequest{Organization: inst.Organization, InstallationID: inst.ID, Role: role, PersonID: g.PersonID, TeamID: g.TeamID}
				e := r.event(domain.RoleGranted, actor)
				e.Detail[domain.CrossoverFrom] = g.Role
				e.Detail[domain.CrossoverBasis] = basis
				if err := s.journal(ctx, tx, e); err != nil {
					return err
				}
			}
		}
		if err := tx.DeleteRoleGrant(g); err != nil {
			return err
		}
		r := RoleRequest{Organization: inst.Organization, InstallationID: inst.ID, Role: g.Role, PersonID: g.PersonID, TeamID: g.TeamID}
		e := r.event(domain.RoleRevoked, actor)
		if crossover {
			e.Detail[domain.CrossoverFrom] = g.Role
			e.Detail[domain.CrossoverBasis] = basis
		}
		if err := s.journal(ctx, tx, e); err != nil {
			return err
		}
	}
	return nil
}

// crossoverAsks lists, in a review's words, the moves the crossover makes of
// inst's grants when next replaces their declaration: one line per old role
// a grant on inst holds. It names what an update asks where the declaration
// comparison cannot (a consent behind the delivered generation, or of
// unknown generation). STOPGAP (one release, domain.LegacyInstallerRole).
func crossoverAsks(tx Tx, inst domain.Installation, next domain.Module) ([]string, error) {
	grants, err := tx.RoleGrants(inst.ID)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, g := range grants {
		if seen[g.Role] {
			continue
		}
		seen[g.Role] = true
		if _, declared := next.Roles[g.Role]; declared {
			continue
		}
		if role, _, ok := domain.CrossoverRole(g.Role, next.Roles); ok {
			out = append(out, "holders of role "+g.Role+" move to "+role)
		}
	}
	slices.Sort(out)
	return out, nil
}

// crossesOnly reports whether next asks of inst, an installation held by the
// receipt composition took (domain.ComposedConsent), nothing but the
// page-role rename: a grant on inst holds an old role next crosses over
// (crossoverAsks), and next asks nothing beyond the declaration inst's
// receipt approved read with each old role under the name it crosses to
// (crossedOver), neither of the declaration (decide.Widens) nor of the reach
// (reachWidens). Composition's receipt is nobody's review
// (approvedGovernance), so no administrator owes an approval of the rename:
// the receipt advances with the delivery and the grants cross over then, as
// an unconsented installation's do (reconverge). Anything more next asks
// holds the installation at its receipt, offering the upgrade, whose
// approval crosses the grants over. STOPGAP (one release,
// domain.LegacyInstallerRole).
func crossesOnly(tx Tx, inst domain.Installation, next domain.Module, now offeredReach) (bool, error) {
	if inst.Consent.OperationID != domain.ComposedConsent {
		return false, nil
	}
	if moves, err := crossoverAsks(tx, inst, next); err != nil || len(moves) == 0 {
		return false, err
	}
	approved, err := approvedModule(tx, inst, next)
	if err != nil {
		if unadoptable(err) {
			return false, nil // held, and refused by name, until an approval
		}
		return false, err
	}
	crossed := crossedOver(approved, next)
	if len(decide.Widens(crossed, next)) > 0 {
		return false, nil
	}
	if inst.Consent.ReachDigest == "" {
		return true, nil
	}
	reach, err := decide.DecodeReach(inst.Consent.Reach)
	if err != nil {
		return false, err
	}
	reach = crossedNames(reach, next, mergeReachRows)
	return len(decide.ReachWidensWithin(reach, now.rows, crossed)) == 0, nil
}

// crossedOver is m with each old role named as the role it crosses to when
// next replaces it (domain.CrossoverRole), the old roles crossing to one role
// together holding what each held. STOPGAP (one release,
// domain.LegacyInstallerRole).
func crossedOver(m, next domain.Module) domain.Module {
	m.Roles = crossedNames(m.Roles, next, func(a, b decide.Scopes) decide.Scopes { return slices.Concat(a, b) })
	m.Through = crossedNames(m.Through, next, func(a, b map[string]decide.Scopes) map[string]decide.Scopes {
		out := map[string]decide.Scopes{}
		maps.Copy(out, a)
		for binding, scopes := range b {
			out[binding] = slices.Concat(out[binding], scopes)
		}
		return out
	})
	return m
}

// crossedNames is in keyed by role, each old role's entry under the role it
// crosses to when next replaces it (domain.CrossoverRole), merged with what
// that role holds already. STOPGAP (one release, domain.LegacyInstallerRole).
func crossedNames[V any](in map[string]V, next domain.Module, merge func(a, b V) V) map[string]V {
	if in == nil {
		return nil
	}
	out := make(map[string]V, len(in))
	for name, v := range in {
		if role, _, ok := domain.CrossoverRole(name, next.Roles); ok {
			name = role
		}
		if held, ok := out[name]; ok {
			v = merge(held, v)
		}
		out[name] = v
	}
	return out
}

// mergeReachRows is the reach of two roles held together: one row per
// module, way and confinement, holding the scopes and the operations of
// both. A row's policies are its module's, the same in both. STOPGAP (one
// release, domain.LegacyInstallerRole).
func mergeReachRows(a, b []domain.ReachRow) []domain.ReachRow {
	out := slices.Clone(a)
	for _, r := range b {
		i := slices.IndexFunc(out, func(o domain.ReachRow) bool {
			return o.Module == r.Module && o.Via == r.Via && o.Confinement == r.Confinement
		})
		if i < 0 {
			out = append(out, r)
			continue
		}
		o := out[i]
		o.Scopes = slices.Concat(o.Scopes, r.Scopes)
		o.Operations = slices.Compact(slices.Sorted(slices.Values(slices.Concat(o.Operations, r.Operations))))
		policies := maps.Clone(r.Policies)
		if policies == nil {
			policies = map[string]domain.MethodPolicy{}
		}
		maps.Copy(policies, o.Policies)
		o.Policies = policies
		out[i] = o
	}
	return out
}
