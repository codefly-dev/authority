package authority

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

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

// reachWidens is what now reaches beyond the reach inst's consent approved.
// A consent recorded before reach was kept asks nothing: it adopts what its
// approved declaration reaches now (adoptLegacyReach), which is what its
// holders hold now.
func reachWidens(inst domain.Installation, now offeredReach, declared domain.Module) ([]string, error) {
	if inst.Consent.ReachDigest == "" {
		return nil, nil
	}
	approved, err := decide.DecodeReach(inst.Consent.Reach)
	if err != nil {
		return nil, err
	}
	return decide.ReachWidensWithin(approved, now.rows, declared), nil
}

// consentedNow is an active consented installation whose consent recorded
// its reach, the approved declaration of its target, and what that
// declaration's roles reach in the composition a transaction reads.
type consentedNow struct {
	inst domain.Installation
	m    domain.Module
	now  offeredReach
}

// consentedReaches is every consentedNow but those of applied, the reach
// computed once per target generation. A consent whose approved declaration
// is refused (not kept) is skipped: its holders are refused by name until an
// administrator approves again.
func consentedReaches(tx Tx, applied string) ([]consentedNow, error) {
	all, err := tx.Installations("")
	if err != nil {
		return nil, err
	}
	computed := map[string]offeredReach{}
	var out []consentedNow
	for _, inst := range all {
		if inst.Target == applied || inst.Status != domain.Active || inst.Consent.OperationID == "" || inst.Consent.ReachDigest == "" {
			continue
		}
		m, err := tx.ModuleNamed(inst.Target)
		if errors.Is(err, domain.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if m, err = approvedModule(tx, inst, m); err != nil {
			if unadoptable(err) {
				continue
			}
			return nil, err
		}
		key := fmt.Sprintf("%s@%d", m.Name, m.Generation)
		now, ok := computed[key]
		if !ok {
			if now, err = reachIn(tx, m); err != nil {
				return nil, err
			}
			computed[key] = now
		}
		out = append(out, consentedNow{inst, m, now})
	}
	return out, nil
}

// reachesBefore is what each consented installation's roles reach, by
// installation, before a delivery changes the composition.
func reachesBefore(tx Tx, applied string) (map[string]string, error) {
	list, err := consentedReaches(tx, applied)
	out := map[string]string{}
	for _, c := range list {
		out[c.inst.ID] = c.now.digest
	}
	return out, err
}

// reconvergeReach holds every other consented installation to the reach its
// consent approved, once applied changed the composition: a module
// redelivered, or newly composed, can change what a role on a solution
// reaches without the solution changing. Where the reach its approved
// declaration has now asks nothing new, the consent advances to it, the
// revision moves (what was issued under the wider reach ends) and the change
// is journaled as installation.reconverged; where it asks more, the consent
// stands, holders keep the approved reach (approvedReach), and
// installation.upgrade_available names what widened. An installation whose
// reach the delivery did not change (before, as reachesBefore read it) is
// left as it is and journals nothing: a widening already offered is not
// offered again by every later delivery.
func (s *Service) reconvergeReach(ctx context.Context, tx Tx, applied string, before map[string]string) error {
	list, err := consentedReaches(tx, applied)
	if err != nil {
		return err
	}
	changed := map[string]bool{}
	for _, c := range list {
		inst, m, now := c.inst, c.m, c.now
		if now.digest == inst.Consent.ReachDigest {
			continue
		}
		if was, ok := before[inst.ID]; ok && was == now.digest {
			continue
		}
		asks, err := reachWidens(inst, now, m)
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

// reachCell is what one role reaches at one module: its rows' scopes there,
// and every operation of the module with the policy approved for it.
type reachCell struct {
	scopes   Scopes
	policies map[string]domain.MethodPolicy
}

// reachIndex is a reach by role, then by module, for enforcement.
type reachIndex map[string]map[string]reachCell

func indexReach(reach map[string][]domain.ReachRow) reachIndex {
	out := reachIndex{}
	for role, rows := range reach {
		byModule := map[string]reachCell{}
		for _, row := range rows {
			if row.Via == decide.ReachPerson {
				continue
			}
			cell, ok := byModule[row.Module]
			if !ok {
				cell = reachCell{policies: map[string]domain.MethodPolicy{}}
			}
			cell.scopes = scope.Normalize(append(cell.scopes, row.Scopes...))
			for op, p := range row.Policies {
				cell.policies[op] = p
			}
			byModule[row.Module] = cell
		}
		out[role] = byModule
	}
	return out
}

// admits is whether the approved cell admits operation for a call carrying
// effective: its approved policy applied both to the scopes the cell holds,
// the roles held together, and to what the call itself carries. A call
// narrowed below the role is held to the approved policy on its own scopes,
// so a delivery relaxing what an operation requires admits no narrowed call
// to it before an administrator approves the relaxation.
func (c reachCell) admits(module, operation string, effective Scopes) bool {
	p, ok := c.policies[operation]
	return ok && decide.AdmitPolicy(module, operation, p, c.scopes) == nil && decide.AdmitPolicy(module, operation, p, effective) == nil
}

// consentedReach is the reach inst's consent approved, indexed and cached by
// its digest. A consent recorded before reach was kept, and not adopted yet
// (adoptLegacyReach), is held to what its approved declaration reaches in
// the composition now: what its holders have now, never more.
func (s *Service) consentedReach(tx Tx, inst domain.Installation) (reachIndex, error) {
	if inst.Consent.ReachDigest != "" {
		if cached, ok := s.reaches.get(inst.Consent.ReachDigest); ok {
			return cached, nil
		}
		// What the store holds is trusted only as the reach the consent
		// recorded: its digest is the one the approval named.
		if decide.DigestReach(inst.Consent.Reach) != inst.Consent.ReachDigest {
			return nil, domain.NotNow("the approved reach recorded for installation %s does not match its digest; review and approve the delivered offer", inst.ID)
		}
		reach, err := decide.DecodeReach(inst.Consent.Reach)
		if err != nil {
			return nil, err
		}
		index := indexReach(reach)
		s.reaches.put(inst.Consent.ReachDigest, index)
		return index, nil
	}
	m, err := tx.ModuleNamed(inst.Target)
	if err != nil {
		return nil, notFound(err)
	}
	if m, err = approvedModule(tx, inst, m); err != nil {
		return nil, err
	}
	now, err := reachIn(tx, m)
	if err != nil {
		return nil, err
	}
	return indexReach(now.rows), nil
}

// reachCacheSize bounds the decoded reaches a service keeps.
const reachCacheSize = 256

// reachCache keeps decoded reaches by digest, at most size, evicting the
// oldest first. A digest names one reach for ever, so an entry never goes
// stale.
type reachCache struct {
	mu    sync.Mutex
	size  int
	byKey map[string]reachIndex
	order []string
}

func (c *reachCache) get(digest string) (reachIndex, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	index, ok := c.byKey[digest]
	return index, ok
}

func (c *reachCache) put(digest string, index reachIndex) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byKey == nil {
		c.byKey = map[string]reachIndex{}
	}
	if _, ok := c.byKey[digest]; ok {
		return
	}
	size := c.size
	if size <= 0 {
		size = reachCacheSize
	}
	for len(c.order) >= size {
		delete(c.byKey, c.order[0])
		c.order = c.order[1:]
	}
	c.byKey[digest] = index
	c.order = append(c.order, digest)
}

// reachOwner is whom a capability acts for: a person, through the solutions
// among principals (a verified chain's current actor and services), or an
// installation's agent, by its principal.
type reachOwner struct {
	person     *domain.Person
	principals []string
	agent      string
}

// approvedReach is what owner may hold at module by the reach the consent of
// each installation it acts through approved, a solution's or a module
// page's, for the roles it holds there: a person's roles granted on each
// consented target on the path, intersected across them; an agent's own
// installation role. held is the scopes; admits reports whether an operation
// of module is admitted by the policy approved for it to the roles' scopes
// there, held together, and to the scopes the call itself carries. bounded
// is false when no consented installation bounds it (none on the path, or an
// installation installed by its host without consent). A delivery of the
// target, or of any module it reaches, that asks more than its consent
// approved therefore grants nobody, person or agent, the wider reach until
// the upgrade is approved.
func (s *Service) approvedReach(tx Tx, owner reachOwner, module string) (held Scopes, admits func(operation string, effective Scopes) bool, bounded bool, err error) {
	var cells []reachCell
	admits = func(operation string, effective Scopes) bool {
		for _, c := range cells {
			if !c.admits(module, operation, effective) {
				return false
			}
		}
		return true
	}
	bound := func(inst domain.Installation, roles []string) error {
		if inst.Status != domain.Active || inst.Consent.OperationID == "" {
			return nil
		}
		index, err := s.consentedReach(tx, inst)
		if err != nil {
			return err
		}
		here := reachCell{policies: map[string]domain.MethodPolicy{}}
		switch len(roles) {
		case 0:
		case 1:
			here = index[roles[0]][module]
		default:
			// Roles held together reach what all the declared roles reach
			// together (decide.JointRoles), within the held roles' scopes:
			// a chain one role keeps going may carry another's further, and
			// an operation two roles cover only together is theirs.
			m, err := tx.ModuleNamed(inst.Target)
			if err != nil {
				return notFound(err)
			}
			if m, err = approvedModule(tx, inst, m); err != nil {
				return err
			}
			var declared Scopes
			for _, role := range roles {
				declared = append(declared, m.Roles[role]...)
				declared = append(declared, m.OwnedRoles[role]...)
			}
			joint := index[decide.JointRoles][module]
			here = reachCell{scopes: scope.Intersect(joint.scopes, scope.Unowned(declared)), policies: joint.policies}
		}
		cells = append(cells, here)
		if !bounded {
			held, bounded = here.scopes, true
			return nil
		}
		held = scope.Intersect(held, here.scopes)
		return nil
	}
	if owner.agent != "" {
		inst, err := tx.InstallationByPrincipal(owner.agent)
		if err != nil || inst.AgentRole == "" || inst.AgentRole == domain.NoInstallationRole {
			return nil, nil, false, nil // issuance refuses an agent with no installation or no standing authority
		}
		return held, admits, bounded, bound(inst, []string{inst.AgentRole})
	}
	p := owner.person
	seen := map[string]bool{}
	for _, principal := range owner.principals {
		if seen[principal] {
			continue
		}
		seen[principal] = true
		m, err := tx.Module(principal)
		if err != nil || !decide.RoleGated(m) {
			continue
		}
		inst, err := installationOf(tx, p.Organization, m.Name)
		if err != nil {
			continue
		}
		grants, err := tx.RoleGrants(inst.ID)
		if err != nil {
			return nil, nil, false, err
		}
		if err := bound(inst, decide.HeldRoles(*p, inst, grants)); err != nil {
			return nil, nil, false, err
		}
	}
	return held, admits, bounded, nil
}

// adoptLegacyReach records, once, the reach of every active consent recorded
// before reach was kept: what its approved declaration reaches in the
// composition as it stands, which is what its holders hold now. It runs
// before a delivery changes the composition and when a host starts, so a
// later widening is measured against it and capped. Each adoption is
// journaled as installation.reach_adopted; nothing issued ends.
//
// A module page's installation no consent holds (composition's, or one its
// host installed) takes its receipt here the same way, by composition
// (domain.ComposedConsent): the delivered generation, its offer digest and
// what its roles reach now, and the generation is kept as its approved one.
// From then on it is held as a consented solution is: a delivery, of the
// page or of a module it reaches, that widens what a role reaches offers an
// upgrade (reconverge, reconvergeReach) that an administrator or the page's
// installer approves through Install, and until then its grants answer at
// the reach held, none revoked and none widened. A solution its host
// installed without consent is left as it is: it follows its delivery by
// that host's own doing.
//
// A consent whose approved declaration cannot be read (a generation the
// store does not keep, or keeps as something other than what was approved:
// a host migration may record such an approval) is skipped, never failing
// the pass: its reach stays unadopted, it offers its upgrade, and its
// holders stay refused by name (approvedModule), so it fails closed until an
// administrator approves the delivered offer. A delivery's pass skips it
// silently, since every delivery would repeat it; a host's start
// (journalSkips) journals it once per start as
// installation.upgrade_available, naming why its reach was not adopted.
func (s *Service) adoptLegacyReach(ctx context.Context, tx Tx, journalSkips bool) error {
	all, err := tx.Installations("")
	if err != nil {
		return err
	}
	for _, inst := range all {
		if inst.Status != domain.Active || inst.Consent.ReachDigest != "" {
			continue
		}
		m, err := tx.ModuleNamed(inst.Target)
		if errors.Is(err, domain.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if inst.Consent.OperationID == "" {
			if m.Kind == domain.KindSolution || !decide.RoleGated(m) {
				continue
			}
			if err := s.holdByComposition(ctx, tx, inst, m); err != nil {
				return err
			}
			continue
		}
		if m, err = approvedModule(tx, inst, m); err != nil {
			if !unadoptable(err) {
				return err
			}
			if journalSkips {
				if err := s.journal(ctx, tx, domain.Event{Kind: domain.InstallationUpgradeAvailable, Organization: inst.Organization, Subject: inst.ID,
					Detail: map[string]string{"target": inst.Target, "approved_generation": fmt.Sprint(inst.Consent.Generation), "reach_unadopted": err.Error()}}); err != nil {
					return err
				}
			}
			continue
		}
		now, err := reachIn(tx, m)
		if err != nil {
			return err
		}
		inst.Consent.Reach, inst.Consent.ReachDigest = now.text, now.digest
		if err := tx.PutInstallation(inst); err != nil {
			return err
		}
		if err := s.journal(ctx, tx, domain.Event{Kind: domain.InstallationReachAdopted, Organization: inst.Organization, Subject: inst.ID,
			Detail: map[string]string{"target": inst.Target, "approved_generation": fmt.Sprint(inst.Consent.Generation), "reach": now.digest}}); err != nil {
			return err
		}
	}
	return nil
}

// holdByComposition records on inst, a module page's installation no consent
// holds, the receipt composition takes (composedReceipt), journaled as
// installation.reach_adopted with "held_by" composition.
func (s *Service) holdByComposition(ctx context.Context, tx Tx, inst domain.Installation, m domain.Module) error {
	if err := composedReceipt(tx, &inst, m); err != nil {
		return err
	}
	if err := tx.PutInstallation(inst); err != nil {
		return err
	}
	return s.journal(ctx, tx, domain.Event{Kind: domain.InstallationReachAdopted, Organization: inst.Organization, Subject: inst.ID,
		Detail: map[string]string{"target": inst.Target, "approved_generation": fmt.Sprint(m.Generation), "reach": inst.Consent.ReachDigest, "held_by": domain.ComposedConsent}})
}

// composedReceipt gives inst, a module page's installation, the receipt
// composition takes: m, as delivered now, is its approved generation (kept
// for it), and what m's roles reach now is the reach it is held at.
func composedReceipt(tx Tx, inst *domain.Installation, m domain.Module) error {
	digest, err := OfferDigest(m)
	if err != nil {
		return err
	}
	now, err := reachIn(tx, m)
	if err != nil {
		return err
	}
	inst.Consent = domain.ConsentReceipt{OperationID: domain.ComposedConsent, Revision: inst.Revision, Generation: m.Generation, Digest: digest, ReachDigest: now.digest, Reach: now.text}
	return tx.PutApprovedModule(m)
}

// AdoptLegacyReach is adoptLegacyReach in one transaction, for a host that
// starts without reconciling organizations.
func (s *Service) AdoptLegacyReach(ctx context.Context) error {
	return s.store.Write(ctx, func(tx Tx) error { return s.adoptLegacyReach(ctx, tx, true) })
}

// unadoptable is whether err is an installation's own state refusing its
// approved declaration, which one installation's pass skips, rather than
// the store failing.
func unadoptable(err error) bool {
	_, refused := domain.CodeOf(err)
	return refused
}

// UpgradeAvailable reports whether inst offers an upgrade an administrator
// approves through Install: its consent stands behind the delivered
// generation (decide.UpgradeAvailable), or what its approved declaration's
// roles reach in the composition now asks more than its consent approved.
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
	asks, err := reachWidens(inst, now, m)
	return len(asks) > 0, err
}
