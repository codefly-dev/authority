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
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// composition is every composed module by principal.
func composition(tx Tx) (map[string]domain.Module, error) {
	all, err := tx.Modules()
	composed := make(map[string]domain.Module, len(all))
	for _, m := range all {
		composed[m.Principal] = m
	}
	return composed, err
}

// unreachedNow is, per composed module naming a reach through a binding, what
// the composition leaves unreached of it (decide.UnreachedOf), joined.
func unreachedNow(tx Tx) (map[string]string, error) {
	composed, err := composition(tx)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, m := range composed {
		if gaps := decide.UnreachedOf(m, composed); len(gaps) > 0 {
			out[m.Name] = strings.Join(gaps, "; ")
		}
	}
	return out, nil
}

// journalReach journals, once per change against before (unreachedNow
// before the delivery), each active installation whose target's declared
// reach a delivery left unreached or reached again. The delivery stands
// either way: an unreached reach grants nothing there, as each hop narrows.
func (s *Service) journalReach(ctx context.Context, tx Tx, before map[string]string) error {
	after, err := unreachedNow(tx)
	if err != nil {
		return err
	}
	changed := map[string]bool{}
	for name := range before {
		changed[name] = before[name] != after[name]
	}
	for name := range after {
		changed[name] = before[name] != after[name]
	}
	all, err := tx.Installations("")
	if err != nil {
		return err
	}
	for _, inst := range all {
		if inst.Status != domain.Active || !changed[inst.Target] {
			continue
		}
		e := domain.Event{Kind: domain.InstallationReachRestored, Organization: inst.Organization, Subject: inst.ID, Detail: map[string]string{"target": inst.Target}}
		if after[inst.Target] != "" {
			e.Kind, e.Detail["unreached"] = domain.InstallationReachUnreached, after[inst.Target]
		}
		if err := s.journal(ctx, tx, e); err != nil {
			return err
		}
	}
	return nil
}

// Unreached is what inst's target names through a binding that the
// composition does not reach now (decide.UnreachedOf): a readiness condition
// of the installation, beside an upgrade available, which re-converges by
// itself once a delivery reaches it again.
func (s *Service) Unreached(ctx context.Context, inst domain.Installation) ([]string, error) {
	var out []string
	err := s.store.Read(ctx, func(tx Tx) error {
		m, err := tx.ModuleNamed(inst.Target)
		if errors.Is(err, domain.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		composed, err := composition(tx)
		out = decide.UnreachedOf(m, composed)
		return err
	})
	return out, err
}

// DeclarationDigest is the digest of m's declaration as a store keeps it:
// every scope set normalized, an empty set and an absent one alike, each
// binding named by its key, shared kinds as a set. Roles and Methods keep
// absent apart from empty, as a store keeps whether a module declared any.
// Two deliveries of one module at one generation are the same delivery when
// their digests are equal (ApplyModule).
func DeclarationDigest(m domain.Module) (string, error) { return OfferDigest(asStored(m)) }

// asStored is m as DeclarationDigest reads it.
func asStored(m domain.Module) domain.Module {
	m.ResourceKinds, m.SourceGovernance = scope.Normalize(m.ResourceKinds), scope.Normalize(m.SourceGovernance)
	var bindings map[string]domain.Binding
	for id, b := range m.Bindings {
		if bindings == nil {
			bindings = map[string]domain.Binding{}
		}
		bindings[id] = domain.Binding{ID: id, Audience: b.Audience,
			InvokeScopes: scope.Normalize(b.InvokeScopes), HeadlessScopes: scope.Normalize(b.HeadlessScopes), LookupScopes: scope.Normalize(b.LookupScopes)}
	}
	m.Bindings = bindings
	roles := func(in map[string][]*basev0.WorkScopeV1, keepEmpty bool) map[string][]*basev0.WorkScopeV1 {
		if len(in) == 0 && !(keepEmpty && in != nil) {
			return nil
		}
		out := make(map[string][]*basev0.WorkScopeV1, len(in))
		for name, s := range in {
			out[name] = scope.Normalize(s)
		}
		return out
	}
	m.Roles, m.OwnedRoles = roles(m.Roles, true), roles(m.OwnedRoles, false)
	var through map[string]map[string][]*basev0.WorkScopeV1
	for role, byBinding := range m.Through {
		if kept := roles(byBinding, false); kept != nil {
			if through == nil {
				through = map[string]map[string][]*basev0.WorkScopeV1{}
			}
			through[role] = kept
		}
	}
	m.Through = through
	if m.Methods != nil {
		methods := make(map[string]domain.MethodPolicy, len(m.Methods))
		for name, p := range m.Methods {
			methods[name] = domain.MethodPolicy{Requires: scope.Normalize(p.Requires), AnyCheckedCaller: p.AnyCheckedCaller}
		}
		m.Methods = methods
	}
	m.SharedKinds = slices.Sorted(slices.Values(m.SharedKinds))
	if len(m.EdgeDependencies) == 0 {
		m.EdgeDependencies = nil
	}
	return m
}

// admission is what the core decides about a delivered module before it
// writes anything: the module it replaces, if any (exists), whether that
// module was withdrawn and is delivered again, and whether the delivery is
// a replay of the held generation, which changes nothing. Every other verdict
// is a refusal, and it is one verdict: Admit asks it read-only and ApplyModule
// writes on it, so what one would refuse the other refuses.
type admission struct {
	previous                  domain.Module
	exists, withdrawn, replay bool
}

// admit decides m against the store as it stands: a tombstone's principal and
// generation, a held generation delivered again (a replay when the
// declaration is the same, refused when it is not), an older generation, a
// principal that is another module's, a person's, a client's or an
// installation's, and what m's roles name through a binding that the
// composition this delivery would leave does not reach (decide.Unreached).
// m is validated (decide.ValidateModule) and serves decide.Served(m).
func admit(tx Tx, m domain.Module) (admission, error) {
	var a admission
	previous, err := tx.ModuleNamed(m.Name)
	a.exists = err == nil
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return a, err
	}
	a.previous = previous
	if !a.exists {
		// A module withdrawn before keeps its principal and its last
		// generation: a redelivery never renames it or rewinds it. Its
		// principal stays its own: no other module claims it. A tombstone
		// is never cleared; a module that must change principal is
		// delivered under a new name.
		if tomb, err := tx.TombstoneByPrincipal(m.Principal); err == nil && tomb.Name != m.Name {
			return a, domain.Refuse("principal %q is withdrawn %s's for life; %s cannot claim it", m.Principal, tomb.Name, m.Name)
		} else if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return a, err
		}
		tomb, err := tx.Tombstone(m.Name)
		a.withdrawn = err == nil
		switch {
		case err == nil && tomb.Principal != m.Principal:
			return a, domain.Refuse("%s is principal %q for life; a delivery cannot rename it %q", m.Name, tomb.Principal, m.Principal)
		case err == nil && tomb.Generation >= m.Generation:
			return a, domain.NotNow("%s was withdrawn at %d, got %d", m.Name, tomb.Generation, m.Generation)
		case err != nil && !errors.Is(err, domain.ErrNotFound):
			return a, err
		}
	}
	if a.exists && !previous.StandIn && previous.Generation == m.Generation {
		// A host composes one delivery on more than one path at once (its
		// delivery endpoint's pass and its reconcile loop's), so the
		// generation a path brings may be the one another just composed.
		// The same declaration is a replay and changes nothing; another
		// one at the held generation is refused, naming both.
		held, err := DeclarationDigest(previous)
		if err != nil {
			return a, err
		}
		delivered, err := DeclarationDigest(m)
		if err != nil {
			return a, err
		}
		if held != delivered {
			return a, domain.NotNow("%s generation %d is held as %s and delivered as %s; a changed declaration is a new generation",
				m.Name, m.Generation, held, delivered)
		}
		a.replay = true
		return a, nil
	}
	if a.exists && !previous.StandIn && previous.Generation > m.Generation {
		return a, domain.NotNow("%s is at %d, got %d", m.Name, previous.Generation, m.Generation)
	}
	if other, err := tx.Module(m.Principal); err == nil && other.Name != m.Name {
		return a, domain.Refuse("principal %q already belongs to %s", m.Principal, other.Name)
	}
	if a.exists && previous.Principal != m.Principal {
		return a, domain.Refuse("%s is principal %q for life; a delivery cannot rename it %q", m.Name, previous.Principal, m.Principal)
	}
	if _, err := tx.Person(m.Principal); err == nil {
		return a, domain.Refuse("principal %q names a person; a module's principal is its own", m.Principal)
	}
	if _, err := tx.Client(m.Principal); err == nil {
		return a, domain.Refuse("principal %q names an external client; a module's principal is its own", m.Principal)
	} else if !errors.Is(err, domain.ErrNotFound) {
		return a, err
	}
	if _, err := tx.InstallationByPrincipal(m.Principal); err == nil {
		return a, domain.Refuse("principal %q names an installation's principal; a module's principal is its own", m.Principal)
	}
	// What the delivered module's roles name through a binding is
	// reachable from it in the composition this delivery leaves
	// (decide.Unreached). What it leaves of another module's is reported
	// on that module's installations, never refused (journalReach).
	composed, err := composition(tx)
	if err != nil {
		return a, err
	}
	delete(composed, previous.Principal)
	composed[m.Principal] = m
	return a, decide.Unreached(m, composed)
}

// Admit answers, without writing, whether ApplyModule would compose m now:
// its validation (decide.ValidateModule), the generation and principal rules,
// a held generation delivered differently, and what its roles name through a
// binding that the composition would not reach (decide.Unreached). nil is
// the held generation delivered again (a replay) or a delivery the core
// would record; every refusal is the one ApplyModule would make, with its
// code. A host that keeps a record of each delivery beside the core's asks
// it before recording one, and records the delivery only once ApplyModule
// has taken it: the answer stands for the composition as it is now, and the
// apply decides again on its own transaction.
func (s *Service) Admit(ctx context.Context, m domain.Module) error {
	if err := decide.ValidateModule(m); err != nil {
		return err
	}
	m.ResourceKinds = decide.Served(m)
	return s.store.Read(ctx, func(tx Tx) error {
		_, err := admit(tx, m)
		return err
	})
}

// ApplyModule records a delivered module at a newer generation and holds a
// module installation at every organization, unless the host installs
// modules itself (Config.HostInstallsModules). Only a solution is installed
// by an administrator, through Review and Install; every module is installed
// by composition, roles or not, page or not. A module's roles decide who may
// use it, through role grants on that composition installation, never
// whether it is installed: a module that gains or loses roles keeps its
// installations as they are, and the grants of a role the delivered
// generation no longer declares end with the delivery (reconverge). A
// narrowing invalidates the capabilities issued before it; a
// withdrawn owner-aware declaration refuses its owner-selected ones for good.
// An active installation consented to survives the delivery: its consent
// re-converges on the new generation when the reviewed offer asks nothing the
// approved one did not (reconverge), and otherwise stands, offering an
// upgrade; its role grants are kept either way. A module page's installation
// is consented to by composition (domain.ComposedConsent, adoptLegacyReach),
// so a delivery that widens what one of its roles reaches, of the page or of
// a module it reaches, never revokes a grant and never widens one: holders
// keep the approved reach until the upgrade is approved.
func (s *Service) ApplyModule(ctx context.Context, m domain.Module) ([]string, error) {
	if err := decide.ValidateModule(m); err != nil {
		return nil, err
	}
	m.ResourceKinds = decide.Served(m)
	var ids []string
	err := s.store.Write(ctx, func(tx Tx) error {
		ids = nil // a retried transaction starts over
		a, err := admit(tx, m)
		if err != nil || a.replay {
			return err
		}
		previous, exists, withdrawn := a.previous, a.exists, a.withdrawn
		unreachedBefore, err := unreachedNow(tx)
		if err != nil {
			return err
		}
		// A consent recorded before reach was kept adopts the reach it has
		// before this delivery changes the composition, so what the
		// delivery widens is measured against it; a module page's
		// installation no consent holds yet takes its receipt the same way.
		if err := s.adoptLegacyReach(ctx, tx, false); err != nil {
			return err
		}
		before, err := reachesBefore(tx, m.Name)
		if err != nil {
			return err
		}
		if exists && previous.OwnerAware && !m.OwnerAware {
			if err := tx.BumpOwnerAwareRevision(m.Principal); err != nil {
				return err
			}
		}
		if err := tx.PutModule(m); err != nil {
			return err
		}
		if exists {
			// The consent digest is of the module as the store answers it to
			// Review, so the delivered one is compared as stored.
			stored, err := tx.ModuleNamed(m.Name)
			if err != nil {
				return err
			}
			if err := s.reconverge(ctx, tx, previous, stored); err != nil {
				return err
			}
		}
		if withdrawn {
			// Delivered again after a withdrawal: an installation a host kept
			// active through it (Config.HostInstallsModules) follows this
			// generation, and the grants of a role it no longer declares end.
			if err := s.dropGrantsAfterWithdrawal(ctx, tx, m); err != nil {
				return err
			}
		}
		if err := s.reconvergeReach(ctx, tx, m.Name, before); err != nil {
			return err
		}
		if err := s.journalReach(ctx, tx, unreachedBefore); err != nil {
			return err
		}
		if err := s.journal(ctx, tx, domain.Event{Kind: domain.ModuleApplied, Subject: m.Name, Detail: map[string]string{"principal": m.Principal, "kind": m.Kind, "generation": fmt.Sprint(m.Generation)}}); err != nil {
			return err
		}
		if m.Kind == domain.KindSolution || s.cfg.HostInstallsModules {
			return nil
		}
		orgs, err := tx.Organizations()
		if err != nil {
			return err
		}
		for _, org := range orgs {
			id := s.cfg.InstallationID(org.ID, m.Name)
			inst, err := tx.Installation(id)
			switch {
			case errors.Is(err, domain.ErrNotFound):
				inst, err := s.composedInstallation(tx, org.ID, m.Name)
				if err != nil {
					return err
				}
				if err := tx.PutInstallation(inst); err != nil {
					return err
				}
			case err != nil:
				return err
			default:
				changed, err := s.withComposedPrincipal(tx, &inst)
				if err != nil {
					return err
				}
				if inst.Status == domain.Revoked && withdrawn {
					// A module withdrawn and delivered again is installed again,
					// at a revision above every capability sealed before. Only a
					// withdrawal is undone this way: an installation the host
					// retired stays retired (Uninstall refuses a module's).
					inst.Status, changed = domain.Active, true
				}
				if changed {
					inst.Revision++
					if err := tx.PutInstallation(inst); err != nil {
						return err
					}
				}
			}
			ids = append(ids, id)
		}
		slices.Sort(ids)
		return nil
	})
	return ids, err
}

// dropGrantsAfterWithdrawal ends, on every active installation of m, the
// grants of a role m no longer declares.
func (s *Service) dropGrantsAfterWithdrawal(ctx context.Context, tx Tx, m domain.Module) error {
	all, err := tx.Installations("")
	if err != nil {
		return err
	}
	for _, inst := range all {
		if inst.Target == m.Name && inst.Status == domain.Active {
			if err := s.dropUndeclaredGrants(ctx, tx, inst, m, "delivery:"+m.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

// reconverge moves every active installation of previous to next. A
// narrowing raises each one's revision, so what was issued under the wider
// declaration ends. An installation consented to is held to what its consent
// approved: when next asks nothing new of it (decide.Widens is empty), the
// consent advances to next's generation and digest, the revision moves, and
// the change is journaled as installation.reconverged; when next asks more,
// the installation stands on its consent, offering an upgrade an administrator
// approves through Install, and installation.upgrade_available names what
// widened. The approved surface compared is previous, the generation the
// consent names; a consent already behind previous cannot be proven a
// superset of next and keeps offering its upgrade (its widening is then
// "approved generation N is behind"); a receipt recorded before the consent
// kept its generation approved an unknown one and offers its upgrade once.
// What next's roles reach in the composition counts as asked too
// (decide.ReachWidens against the approved reach, which a consent recorded
// before reach was kept adopted first), and an advancing consent records it.
// When a consent advances, the grants of roles next no longer declares end
// with it (dropUndeclaredGrants). An installation no consent holds (a
// module's, which composition installed, or one a host installed without
// one) follows the delivered declaration: it advances with every delivery,
// so the grants of a role next no longer declares end now. No other grant is
// touched here.
func (s *Service) reconverge(ctx context.Context, tx Tx, previous, next domain.Module) error {
	all, err := tx.Installations("")
	if err != nil {
		return err
	}
	narrowed := decide.Narrowed(previous, next)
	digest, err := OfferDigest(next)
	if err != nil {
		return err
	}
	approvedDigest, err := OfferDigest(previous)
	if err != nil {
		return err
	}
	widened := decide.Widens(previous, next)
	reach, err := reachIn(tx, next)
	if err != nil {
		return err
	}
	changed := map[string]bool{}
	for _, inst := range all {
		if inst.Target != previous.Name || inst.Status != domain.Active {
			continue
		}
		moved := narrowed
		if inst.Consent.OperationID == "" {
			if err := s.dropUndeclaredGrants(ctx, tx, inst, next, "delivery:"+next.Name); err != nil {
				return err
			}
		} else {
			asks := widened
			switch {
			case inst.Consent.Generation == 0:
				asks = []string{"approved generation unknown: review and approve the delivered offer"}
			case inst.Consent.Generation != previous.Generation || inst.Consent.Digest != approvedDigest:
				asks = []string{fmt.Sprintf("approved generation %d is behind the delivered %d", inst.Consent.Generation, previous.Generation)}
			default:
				further, err := reachWidens(inst, reach, previous)
				if err != nil {
					return err
				}
				asks = append(slices.Clone(asks), further...)
			}
			detail := map[string]string{"target": inst.Target, "approved_generation": fmt.Sprint(inst.Consent.Generation), "generation": fmt.Sprint(next.Generation)}
			if len(asks) == 0 {
				inst.Consent.Generation, inst.Consent.Digest = next.Generation, digest
				inst.Consent.ReachDigest, inst.Consent.Reach = reach.digest, reach.text
				moved = true
				detail["revision"] = fmt.Sprint(inst.Revision + 1)
				if role := inst.AgentRole; role != "" && role != domain.NoInstallationRole {
					if _, declared := next.Roles[role]; !declared {
						detail["agent_role_undeclared"] = role
					}
				}
				if err := tx.PutApprovedModule(next); err != nil {
					return err
				}
				if err := s.dropUndeclaredGrants(ctx, tx, inst, next, "delivery:"+next.Name); err != nil {
					return err
				}
				if err := s.journal(ctx, tx, domain.Event{Kind: domain.InstallationReconverged, Organization: inst.Organization, Subject: inst.ID, Detail: detail}); err != nil {
					return err
				}
			} else {
				detail["widened"] = strings.Join(asks, "; ")
				if err := s.journal(ctx, tx, domain.Event{Kind: domain.InstallationUpgradeAvailable, Organization: inst.Organization, Subject: inst.ID, Detail: detail}); err != nil {
					return err
				}
			}
		}
		if !moved {
			continue
		}
		inst.Revision++
		if err := tx.PutInstallation(inst); err != nil {
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

// OrganizationAdded holds every composed module, roles or not, installed at an organization
// the host created after those modules were delivered, as ApplyModule holds
// them at every organization that existed then: the order of delivery and
// sign-up never decides whether an organization may use a module. It is
// idempotent, and a module installation an administrator or a withdrawal
// retired stays retired. It answers the organization's module installations.
func (s *Service) OrganizationAdded(ctx context.Context, org string) ([]string, error) {
	var ids []string
	err := s.store.Write(ctx, func(tx Tx) error {
		ids = nil
		if _, err := tx.Organization(org); err != nil {
			return notFound(err)
		}
		if s.cfg.HostInstallsModules {
			return nil // the host installs a module where its administrators consent
		}
		modules, err := tx.Modules()
		if err != nil {
			return err
		}
		for _, m := range modules {
			if m.Kind == domain.KindSolution {
				continue // installed by an administrator, through Review and Install
			}
			id := s.cfg.InstallationID(org, m.Name)
			if inst, err := tx.Installation(id); errors.Is(err, domain.ErrNotFound) {
				composed, err := s.composedInstallation(tx, org, m.Name)
				if err != nil {
					return err
				}
				if err := tx.PutInstallation(composed); err != nil {
					return err
				}
			} else if err != nil {
				return err
			} else if changed, err := s.withComposedPrincipal(tx, &inst); err != nil {
				return err
			} else if changed {
				inst.Revision++
				if err := tx.PutInstallation(inst); err != nil {
					return err
				}
			}
			ids = append(ids, id)
		}
		slices.Sort(ids)
		return nil
	})
	return ids, err
}

// ReconcileOrganizations adopts the reach of every consent recorded before
// reach was kept (AdoptLegacyReach), then holds every composed module at every organization
// (OrganizationAdded at each), and does nothing more when the host installs modules: what a host runs when it starts, so an
// organization created while the authority could not record it still holds
// the modules it may use.
func (s *Service) ReconcileOrganizations(ctx context.Context) error {
	if err := s.AdoptLegacyReach(ctx); err != nil {
		return err
	}
	if s.cfg.HostInstallsModules {
		return nil // nothing is installed by the core to reconcile
	}
	// One read finds the organizations missing a module installation, so a
	// host with many organizations writes only where something is missing.
	var missing []string
	if err := s.store.Read(ctx, func(tx Tx) error {
		missing = nil
		orgs, err := tx.Organizations()
		if err != nil {
			return err
		}
		modules, err := tx.Modules()
		if err != nil {
			return err
		}
		all, err := tx.Installations("")
		if err != nil {
			return err
		}
		// An installation recorded before composition gave module
		// installations a principal is missing one (withComposedPrincipal).
		held := map[string]bool{}
		for _, inst := range all {
			held[inst.ID] = inst.PrincipalID != "" || inst.Status == domain.Revoked
		}
		for _, org := range orgs {
			for _, m := range modules {
				if m.Kind != domain.KindSolution && !held[s.cfg.InstallationID(org.ID, m.Name)] {
					missing = append(missing, org.ID)
					break
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	for _, org := range missing {
		if _, err := s.OrganizationAdded(ctx, org); err != nil {
			return fmt.Errorf("organization %s: %w", org, err)
		}
	}
	return nil
}

// WithdrawModule removes a module: its installations are revoked and the
// delegations granted to it end.
func (s *Service) WithdrawModule(ctx context.Context, name string) error {
	return s.store.Write(ctx, func(tx Tx) error {
		all, err := tx.Installations("")
		if err != nil {
			return err
		}
		withdrawn, err := tx.ModuleNamed(name)
		if err != nil {
			return notFound(err)
		}
		hostOwned := s.cfg.HostInstallsModules && withdrawn.Kind != domain.KindSolution
		for _, inst := range all {
			if inst.Target != name || inst.Status == domain.Revoked {
				continue
			}
			if !hostOwned {
				if err := s.revoke(tx, inst); err != nil {
					return err
				}
			} else if err := s.endGrantsOfWithdrawn(ctx, tx, inst); err != nil {
				return err
			}
		}
		delegations, err := tx.Delegations()
		if err != nil {
			return err
		}
		for _, d := range delegations {
			if d.Module == name && !d.Revoked {
				d.Revoked = true
				if err := tx.PutDelegation(d); err != nil {
					return err
				}
				if err := tx.BumpAuthorizationRevision(d.Organization); err != nil {
					return err
				}
			}
		}
		m := withdrawn
		unreachedBefore, err := unreachedNow(tx)
		if err != nil {
			return err
		}
		if err := tx.PutTombstone(domain.Tombstone{Name: m.Name, Principal: m.Principal, Generation: m.Generation}); err != nil {
			return err
		}
		if err := s.journal(ctx, tx, domain.Event{Kind: domain.ModuleWithdrawn, Subject: m.Name, Detail: map[string]string{"principal": m.Principal, "generation": fmt.Sprint(m.Generation)}}); err != nil {
			return err
		}
		if err := tx.DeleteModule(name); err != nil {
			return err
		}
		return s.journalReach(ctx, tx, unreachedBefore)
	})
}

// endGrantsOfWithdrawn ends every grant on an installation the host keeps
// through its module's withdrawal. The installation stays (the host owns it),
// but a grant kept would hold whatever a later delivery of the same role name
// meant, which nobody approved: each grant is journaled as role.revoked and
// the installation's and the organization's revisions move, so what was issued
// under the grants ends.
func (s *Service) endGrantsOfWithdrawn(ctx context.Context, tx Tx, inst domain.Installation) error {
	grants, err := tx.RoleGrants(inst.ID)
	if err != nil || len(grants) == 0 {
		return err
	}
	if err := s.dropUndeclaredGrants(ctx, tx, inst, domain.Module{Name: inst.Target}, "withdrawn:"+inst.Target); err != nil {
		return err
	}
	inst.Revision++
	if err := tx.PutInstallation(inst); err != nil {
		return err
	}
	return tx.BumpAuthorizationRevision(inst.Organization)
}

// InstallStep converges one installation; a retry may repeat it. It is
// optional: a host passes nil for a solution that declares no install
// endpoint, and the installation is active as soon as it is recorded.
type InstallStep func(ctx context.Context, inst domain.Installation) error

// Install installs a solution at an organization: pending until its step
// converges, then active; the host's own setup asking the same install while
// it is pending resumes it. A module, roles or not, is never installed here:
// composition installs it wherever it is composed. Its principal is stable per organization and
// target, so a reinstall reuses it; nobody holds a role until granted one,
// the installing person included. The caller must administer the organization.
// On an active installation, a fresh approval of an offer its consent has not
// approved (a redelivery that asked more) is an upgrade: the step runs first
// (idempotent by contract, so a failed one is retried by the same approval),
// on the installation as it will stand, then one transaction moves the
// consent to the approved generation, its revision and its agent role, keeps
// its installer and every grant of a role still declared, and the
// installation is active throughout. A fresh approval of the offer the consent
// already approved is refused as already installed. Role grants are deleted
// by RevokeRole and by an uninstall alone, never by an install.
// A delivered installation-role selector is authoritative: a named role is
// selected unless the caller names that same role, and "none" selects no standing
// authority when the caller supplies no role. A caller may never supply "none".
// With no selector, the caller must name a declared role as before.
// A module page (a module declaring roles) is installed by composition, never
// here; what Install takes for one is the approval of its pending upgrade,
// by an administrator or by a holder of the page's installer role on its
// installation (approver), which records the consent the receipt composition
// took stood in for.
func (s *Service) Install(ctx context.Context, caller Person, org, target, agentRole, installedBy string, approval *domain.ConsentApproval, step InstallStep) (domain.Installation, error) {
	if approval != nil {
		copy := *approval
		approval = &copy
	}
	return s.install(ctx, func(tx Tx) error { return approver(tx, caller, org, target) }, caller, org, target, agentRole, installedBy, approval, step)
}

// InstallAsHost is for trusted host setup, never a request handler. It installs
// a solution without person authorization; an absent person cannot select it.
// It records no consent, so the installation follows every delivery of its
// solution (reconverge): a role a delivery widens is held by its grants at
// once. That is the setup's own doing and no person can reach it: Install
// refuses a person's request without a consent, which holds the installation
// to what it approved.
func (s *Service) InstallAsHost(ctx context.Context, org, target, agentRole, installedBy string, step InstallStep) (domain.Installation, error) {
	return s.install(ctx, func(Tx) error { return nil }, Person{}, org, target, agentRole, installedBy, nil, step)
}

func (s *Service) install(ctx context.Context, authorize func(Tx) error, caller Person, org, target, agentRole, installedBy string, approval *domain.ConsentApproval, step InstallStep) (domain.Installation, error) {
	var inst domain.Installation
	var generation uint64
	var intent string
	var replayed, upgrading bool
	var selectedRole string
	requestedOwner := installedBy
	if installedBy == "" && caller.ID != "" {
		installedBy = caller.ID
	}
	err := s.store.Write(ctx, func(tx Tx) error {
		replayed, upgrading = false, false
		if err := authorize(tx); err != nil {
			return err
		}
		if caller.ID != "" {
			var err error
			intent, err = consentIntent(caller, org, target, agentRole, requestedOwner, approval)
			if err != nil {
				return err
			}
		}
		if _, err := tx.Organization(org); err != nil {
			return notFound(err)
		}
		m, err := tx.ModuleNamed(target)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		if err != nil {
			return domain.Missing("%q is not a composed solution; a module is installed by composition", target)
		}
		id := s.cfg.InstallationID(org, target)
		existing, found := tx.Installation(id)
		if m.Kind != domain.KindSolution {
			// A module page's installation may be its host's own record,
			// under the host's own id: its upgrade lands on that record.
			existing, found = installationOf(tx, org, target)
		}
		if found != nil && !errors.Is(found, domain.ErrNotFound) {
			return found
		}
		if m.Kind != domain.KindSolution && (!decide.RoleGated(m) || approval == nil || found != nil || existing.Status != domain.Active) {
			return domain.Missing("%q is not a composed solution; a module is installed by composition, and only the upgrade of a page's active installation is approved here", target)
		}
		generation = m.Generation
		selectedRole, err = installationRole(m, agentRole)
		if err != nil {
			return err
		}
		reach, err := reachIn(tx, m)
		if err != nil {
			return err
		}
		p, err := memberRecord(tx, org, installedBy)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		if err != nil || p.Organization != org {
			return domain.Refuse("owner %q is not a member of %s", installedBy, org)
		}
		err = found
		if approval != nil {
			same, err := checkConsent(m, existing, approval, intent, reach)
			if err != nil {
				return err
			}
			if same && existing.Status == domain.Active {
				inst, replayed = existing, true
				return nil
			}
		}
		if err == nil && existing.Status == domain.Pending {
			if existing.AgentRole != selectedRole || existing.InstalledBy != installedBy {
				return domain.NotNow("%s is pending at %s as %s for %s; only that install resumes it", target, org, existing.AgentRole, existing.InstalledBy)
			}
			// The same install asked again resumes its pending attempt: its
			// step converges idempotently, and its revision stays the one the
			// first attempt took, so a revoke or a reinstall since is told apart.
			// A fresh approval supersedes the unfinished attempt instead: checkConsent
			// held it to the current generation, digest and the pending revision, so
			// it consents to exactly what is pending now. The revision moves with its
			// receipt, so the superseded operation can neither resume nor acknowledge.
			if approval != nil && existing.Consent.OperationID != approval.OperationID {
				existing.Revision++
				existing.Consent = receipt(approval, intent, existing.Revision, m, reach)
				inst = existing
				if err := tx.PutInstallation(existing); err != nil {
					return err
				}
				return s.journal(ctx, tx, requested(caller, existing))
			}
			inst = existing
			return nil
		}
		if err == nil && existing.Status != domain.Revoked {
			current := receipt(approval, intent, 0, m, reach)
			if approval == nil || (existing.Consent.Generation == current.Generation && existing.Consent.Digest == current.Digest && existing.Consent.ReachDigest == current.ReachDigest) {
				return &domain.Refusal{Code: domain.Denied, Cause: domain.ErrAlreadyInstalled, Reason: fmt.Sprintf("%s is already installed at %s", target, org)}
			}
			// An upgrade: the administrator reviewed the delivered offer and
			// approved what it asks beyond the consent that stands. Nothing is
			// written yet: the step runs on the installation as it will
			// stand, and the transaction after it moves the consent.
			upgrading = true
			inst = existing
			inst.Revision++
			inst.Consent = receipt(approval, intent, inst.Revision, m, reach)
			inst.AgentRole = selectedRole
			return nil
		}
		principal := s.cfg.PrincipalID(org, target)
		if err := principalFree(tx, principal, id, target, org); err != nil {
			return err
		}
		inst = domain.Installation{ID: id, Organization: org, Target: target, Status: domain.Pending, Revision: existing.Revision + 1,
			AgentRole: selectedRole, PrincipalID: principal, InstalledBy: installedBy}
		if approval != nil {
			inst.Consent = receipt(approval, intent, inst.Revision, m, reach)
			if err := tx.PutApprovedModule(m); err != nil {
				return err
			}
		}
		if err := tx.PutInstallation(inst); err != nil {
			return err
		}
		return s.journal(ctx, tx, requested(caller, inst))
	})
	if err != nil {
		return inst, err
	}
	if replayed {
		return inst, nil
	}
	if step != nil {
		if err := step(ctx, inst); err != nil {
			return inst, err
		}
	}
	err = s.store.Write(ctx, func(tx Tx) error {
		current, err := tx.Installation(inst.ID)
		if err != nil {
			return notFound(err)
		}
		if err := authorize(tx); err != nil {
			return err
		}
		m, err := tx.ModuleNamed(target)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		if err == nil && approval != nil {
			reach, err := reachIn(tx, m)
			if err != nil {
				return err
			}
			same, err := checkConsent(m, current, approval, intent, reach)
			if err != nil {
				return err
			}
			if !same && upgrading {
				if current.Status != domain.Active || current.Revision+1 != inst.Revision || m.Generation != generation {
					return domain.NotNow("installation %s changed before its upgrade was recorded", inst.ID)
				}
				return s.upgrade(ctx, tx, caller, &current, approval, intent, selectedRole, m, reach, &inst)
			}
			if !same {
				return domain.NotNow("INSTALLATION_APPROVAL_OPERATION_CONFLICT: approval changed before acknowledgement")
			}
			if current.Status == domain.Active {
				inst = current
				return nil
			}
		}
		if err != nil || m.Generation != generation || current.Status != domain.Pending || current.Revision != inst.Revision {
			return domain.NotNow("installation attempt %s changed before acknowledgement", inst.ID)
		}
		current.Status = domain.Active
		inst = current
		if err := tx.PutInstallation(current); err != nil {
			return err
		}
		return s.journal(ctx, tx, domain.Event{Kind: domain.InstallationActivated, Organization: current.Organization, Actor: caller.ID, Subject: current.ID,
			Detail: map[string]string{"target": current.Target, "revision": fmt.Sprint(current.Revision)}})
	})
	return inst, err
}

// upgrade records an approved upgrade on the active installation current,
// after its step converged: the consent, revision and agent role move, the
// installer stays, the approved generation is kept, grants of roles m no
// longer declares end, and the organization's authorization revision moves so
// what the earlier consent issued ends. The upgrader is the journal's actor.
func (s *Service) upgrade(ctx context.Context, tx Tx, caller Person, current *domain.Installation, approval *domain.ConsentApproval, intent, selectedRole string, m domain.Module, reach offeredReach, out *domain.Installation) error {
	current.Revision++
	current.Consent = receipt(approval, intent, current.Revision, m, reach)
	if m.Kind == domain.KindSolution {
		// A module page's installation holds no standing authority, and
		// the record is its host's: the role it holds is left as recorded.
		current.AgentRole = selectedRole
	}
	if err := tx.PutInstallation(*current); err != nil {
		return err
	}
	if err := tx.PutApprovedModule(m); err != nil {
		return err
	}
	if err := tx.BumpAuthorizationRevision(current.Organization); err != nil {
		return err
	}
	if err := s.dropUndeclaredGrants(ctx, tx, *current, m, caller.ID); err != nil {
		return err
	}
	*out = *current
	return s.journal(ctx, tx, domain.Event{Kind: domain.InstallationUpgraded, Organization: current.Organization, Actor: caller.ID, Subject: current.ID,
		Detail: map[string]string{"target": current.Target, "role": current.AgentRole, "generation": fmt.Sprint(m.Generation), "revision": fmt.Sprint(current.Revision), "operation": approval.OperationID}})
}

// receipt is the consent an approval of m's current offer records: the
// operation, its intent, the revision it binds and what it approved, the
// reach of m's roles included.
func receipt(a *domain.ConsentApproval, intent string, revision uint64, m domain.Module, reach offeredReach) domain.ConsentReceipt {
	digest, _ := OfferDigest(m) // checkConsent computed it already; m marshals
	r := domain.ConsentReceipt{Revision: revision, Generation: m.Generation, Digest: digest, ReachDigest: reach.digest, Reach: reach.text}
	if a != nil {
		r.OperationID, r.Intent = a.OperationID, intent
	}
	return r
}

// installationRole applies the signed declaration, not a preference derived from
// role order, human grants or bindings. The request is left unchanged for consent
// intent and transaction retries. "none" is a stored marker, not a role lookup.
func installationRole(m domain.Module, requested string) (string, error) {
	if requested == domain.NoInstallationRole {
		return "", domain.Refuse("none is an installation_role declaration, not a caller-supplied role")
	}
	selected := m.InstallationRole
	if selected == "" && requested == "" && m.Kind != domain.KindSolution {
		// A module's installation holds no standing authority unless its
		// declaration selects a role (composedInstallation).
		return domain.NoInstallationRole, nil
	}
	if selected == "" {
		selected = requested
	} else if requested != "" && requested != selected {
		return "", domain.Refuse("role %q cannot override %s's installation_role declaration", requested, m.Name)
	}
	if m.InstallationRole == domain.NoInstallationRole {
		return domain.NoInstallationRole, nil
	}
	if _, ok := m.Roles[selected]; !ok {
		return "", domain.Missing("role %q is not one %s declares", selected, m.Name)
	}
	return selected, nil
}

// requested is the journal entry of an installation attempt recorded pending.
func requested(caller Person, inst domain.Installation) domain.Event {
	return domain.Event{Kind: domain.InstallationRequested, Organization: inst.Organization, Actor: caller.ID, Subject: inst.ID,
		Detail: map[string]string{"target": inst.Target, "role": inst.AgentRole, "principal": inst.PrincipalID, "installed_by": inst.InstalledBy,
			"revision": fmt.Sprint(inst.Revision), "operation": inst.Consent.OperationID}}
}

// Uninstall disables a solution installation and its principal at once, clears
// its grants (with RevokeRole, the one other place a grant ends) and revokes
// capabilities sealed to it or its organization. The
// caller must currently administer the organization. A module installation,
// roles or not, holds no principal and belongs to host composition: a person
// cannot uninstall it.
func (s *Service) Uninstall(ctx context.Context, caller Person, organization, installationID string) error {
	return s.store.Write(ctx, func(tx Tx) error {
		p, err := memberAs(tx, caller, organization)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		// Authorize before reading the installation: unauthorized callers
		// cannot tell a present installation from an absent one.
		if err != nil || !decide.IsAdministrator(p) {
			return decide.ForeignInstallation(installationID, organization)
		}
		inst, err := installationIn(tx, organization, installationID)
		if err != nil {
			return err
		}
		// This identity survives withdrawal of the module manifest. A
		// solution always has both its own principal and an installer.
		if inst.PrincipalID == "" || inst.InstalledBy == "" {
			return domain.Refuse("%s is installed by composition: it is withdrawn, never uninstalled", inst.Target)
		}
		if err := s.revoke(tx, inst); err != nil {
			return err
		}
		return s.journal(ctx, tx, uninstalled(caller.ID, inst))
	})
}

// UninstallAsHost retires an installation for trusted host setup and teardown,
// never for a request handler. A module stays retired through routine delivery;
// only host withdrawal and redelivery reactivate it.
func (s *Service) UninstallAsHost(ctx context.Context, organization, installationID string) error {
	return s.store.Write(ctx, func(tx Tx) error {
		inst, err := installationIn(tx, organization, installationID)
		if err != nil {
			return err
		}
		if s.cfg.HostInstallsModules && inst.InstalledBy == "" {
			if m, err := tx.ModuleNamed(inst.Target); err == nil && m.Kind != domain.KindSolution {
				return domain.Refuse("%s is a module installed by its host's consent; the host uninstalls it", inst.Target)
			}
		}
		if err := s.revoke(tx, inst); err != nil {
			return err
		}
		return s.journal(ctx, tx, uninstalled("", inst))
	})
}

// composedInstallation is a module's installation at org by composition:
// active, holding no standing authority, with the principal that owns what
// the module's page creates in a module that checks owners, as a solution's
// installation owns what its page creates (decide.ModuleRoleAt). A principal
// another identity already holds is not taken: the installation then holds
// none and owns nothing (fails closed). A module page's holds composition's
// receipt (composedReceipt): it is held at the reach the page has now, and
// a delivery widening it offers an upgrade; a module declaring no role holds
// no consent, and follows its delivery.
func (s *Service) composedInstallation(tx Tx, org, module string) (domain.Installation, error) {
	inst := domain.Installation{ID: s.cfg.InstallationID(org, module), Organization: org, Target: module, Status: domain.Active, Revision: 1}
	if _, err := s.withComposedPrincipal(tx, &inst); err != nil {
		return inst, err
	}
	m, err := tx.ModuleNamed(module)
	if err != nil {
		return inst, err
	}
	if m.Kind != domain.KindSolution && decide.RoleGated(m) {
		err = composedReceipt(tx, &inst, m)
	}
	return inst, err
}

// withComposedPrincipal gives a composition installation recorded without a
// principal its principal, when no other identity holds it, and reports
// whether it did. The caller raises the revision, so capabilities sealed to it
// before end at their next check.
func (s *Service) withComposedPrincipal(tx Tx, inst *domain.Installation) (bool, error) {
	if inst.PrincipalID != "" {
		return false, nil
	}
	principal := s.cfg.PrincipalID(inst.Organization, inst.Target)
	if err := principalFree(tx, principal, inst.ID, inst.Target, inst.Organization); err != nil {
		if _, refused := domain.CodeOf(err); refused {
			return false, nil
		}
		return false, err
	}
	inst.PrincipalID = principal
	return true, nil
}

// principalFree refuses an installation principal another identity holds: a
// module, a person, another installation, a withdrawn module or an external
// client. Every installation principal, a solution's or a composition's,
// is checked here.
func principalFree(tx Tx, principal, id, target, org string) error {
	if _, err := tx.Module(principal); err == nil {
		return domain.Refuse("the principal %q of %s at %s names a module", principal, target, org)
	} else if !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	if _, err := tx.Person(principal); err == nil {
		return domain.Refuse("the principal %q of %s at %s names a person", principal, target, org)
	} else if !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	if other, err := tx.InstallationByPrincipal(principal); err == nil && other.ID != id {
		return domain.Refuse("the principal %q of %s at %s is another installation's", principal, target, org)
	} else if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	if _, err := tx.TombstoneByPrincipal(principal); err == nil {
		return domain.Refuse("the principal %q of %s at %s is a withdrawn module's", principal, target, org)
	} else if !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	if _, err := tx.Client(principal); err == nil {
		return domain.Refuse("installation principal %q belongs to an external client", principal)
	} else if !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	return nil
}

func uninstalled(actor string, inst domain.Installation) domain.Event {
	return domain.Event{Kind: domain.InstallationUninstalled, Organization: inst.Organization, Actor: actor, Subject: inst.ID,
		Detail: map[string]string{"target": inst.Target, "revision": fmt.Sprint(inst.Revision + 1)}}
}

func installationIn(tx Tx, organization, installationID string) (domain.Installation, error) {
	inst, err := tx.Installation(installationID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && inst.Organization != organization) {
		return inst, decide.ForeignInstallation(installationID, organization)
	}
	return inst, err
}

// revoke disables inst: its revision and its organization's authorization
// revision both move, and its grants are cleared.
func (s *Service) revoke(tx Tx, inst domain.Installation) error {
	inst.Owned = nil
	inst.Status = domain.Revoked
	inst.Revision++
	if err := tx.PutInstallation(inst); err != nil {
		return err
	}
	if err := tx.BumpAuthorizationRevision(inst.Organization); err != nil {
		return err
	}
	return tx.DeleteRoleGrants(inst.ID)
}

// Installations answers an organization's installations, for its administrator.
func (s *Service) Installations(ctx context.Context, caller Person, org string) ([]domain.Installation, error) {
	var out []domain.Installation
	err := s.store.Read(ctx, func(tx Tx) error {
		p, err := memberAs(tx, caller, org)
		if err != nil || !decide.IsAdministrator(p) {
			return domain.Refuse("installation administration requires an administrator or owner of organization %q", org)
		}
		out, err = tx.Installations(org)
		return err
	})
	return out, err
}

// Composed answers a composed module by name, as its delivery declared it.
func (s *Service) Composed(ctx context.Context, name string) (domain.Module, error) {
	var m domain.Module
	err := s.store.Read(ctx, func(tx Tx) (err error) {
		m, err = tx.ModuleNamed(name)
		return notFound(err)
	})
	return m, err
}
