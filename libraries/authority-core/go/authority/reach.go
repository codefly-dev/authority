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
func reachWidens(inst domain.Installation, now offeredReach) ([]string, error) {
	if inst.Consent.ReachDigest == "" {
		return nil, nil
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

// admits is whether the approved cell admits operation: its approved policy
// applied to the scopes the cell holds, the roles held together.
func (c reachCell) admits(module, operation string) bool {
	p, ok := c.policies[operation]
	return ok && decide.AdmitPolicy(module, operation, p, c.scopes) == nil
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
// each solution installation it acts through approved, for the roles it
// holds there: a person's roles granted on each consented solution on the
// path, intersected across them; an agent's own installation role. held is
// the scopes; admits reports whether an operation of module is admitted by
// the policy approved for it to the roles' scopes there, held together. bounded
// is false when no consented solution bounds it (none on the path, or an
// installation installed by its host without consent). A delivery of the
// solution, or of any module it reaches, that asks more than its consent
// approved therefore grants nobody, person or agent, the wider reach until
// an administrator approves it.
func (s *Service) approvedReach(tx Tx, owner reachOwner, module string) (held Scopes, admits func(operation string) bool, bounded bool, err error) {
	var cells []reachCell
	admits = func(operation string) bool {
		for _, c := range cells {
			if !c.admits(module, operation) {
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
		// The roles held together: their scopes there joined, so an
		// operation two roles cover only together is the reach of both.
		here := reachCell{policies: map[string]domain.MethodPolicy{}}
		for _, role := range roles {
			cell := index[role][module]
			here.scopes = append(here.scopes, cell.scopes...)
			for op, p := range cell.policies {
				here.policies[op] = p
			}
		}
		here.scopes = scope.Normalize(here.scopes)
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
		if err != nil || m.Kind != domain.KindSolution {
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
func (s *Service) adoptLegacyReach(ctx context.Context, tx Tx) error {
	all, err := tx.Installations("")
	if err != nil {
		return err
	}
	for _, inst := range all {
		if inst.Status != domain.Active || inst.Consent.OperationID == "" || inst.Consent.ReachDigest != "" {
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

// AdoptLegacyReach is adoptLegacyReach in one transaction, for a host that
// starts without reconciling organizations.
func (s *Service) AdoptLegacyReach(ctx context.Context) error {
	return s.store.Write(ctx, func(tx Tx) error { return s.adoptLegacyReach(ctx, tx) })
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
	asks, err := reachWidens(inst, now)
	return len(asks) > 0, err
}
