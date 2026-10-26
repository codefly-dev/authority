package authority

import (
	"context"
	"errors"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"slices"
	"strings"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
)

// MaxOwnedPerKind bounds the exact ids carried by an installation-owned grant.
const MaxOwnedPerKind = 32

// AttachmentRequest presents the capability to the attested serving module.
// The owner is derived from verified provenance, never a caller-supplied id.
type AttachmentRequest struct {
	Token, Kind, ResourceID string
	Store                   Workload
}

// AttachResource attaches an id through one installation. Verification precedes
// the transaction; revision, current provenance and exclusivity are decided
// together under the store's write transaction.
func (s *Service) AttachResource(ctx context.Context, r AttachmentRequest) (string, error) {
	if err := decide.ValidResourceID(r.ResourceID); err != nil {
		return "", err
	}
	var actor domain.Module
	err := s.store.Read(ctx, func(tx Tx) (err error) { actor, err = attachmentServer(tx, r.Store, r.Kind); return err })
	if err != nil {
		return "", err
	}
	verified, err := s.Verify(ctx, r.Token, actor.Principal)
	if err != nil {
		return "", err
	}
	if !mayAttach(scope.Unowned(verified.EffectiveScopes()), r.Kind, "") {
		return "", domain.Refuse("the capability holds no create on the whole of %s; existing resources require AuthorizeTransfer", r.Kind)
	}
	wc := verified.Context()
	var owner string
	err = s.store.Write(ctx, func(tx Tx) error {
		owner = ""
		current, err := attachmentServer(tx, r.Store, r.Kind)
		if err != nil {
			return err
		}
		if current.Principal != actor.Principal || current.Generation != actor.Generation {
			return domain.Refuse("serving module changed during attachment")
		}
		if err := s.attachmentFresh(tx, wc); err != nil {
			return err
		}
		candidates := []string{}
		if inst, err := tx.InstallationByPrincipal(wc.GetOwnerPrincipalId()); err == nil {
			candidates = append(candidates, inst.ID)
		} else if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		for _, principal := range solutionPrincipals(wc, actor.Principal) {
			m, err := tx.Module(principal)
			if err != nil {
				return notFound(err)
			}
			if m.Kind == domain.KindSolution {
				inst, err := installationOf(tx, wc.GetTenantId(), m.Name)
				if err != nil {
					return err
				}
				candidates = append(candidates, inst.ID)
			}
		}
		slices.Sort(candidates)
		candidates = slices.Compact(candidates)
		if len(candidates) == 0 {
			return domain.Refuse("the capability was issued through no installation")
		}
		if len(candidates) != 1 {
			return domain.Refuse("the capability was issued through %d installations (%s); an attachment has exactly one owner", len(candidates), strings.Join(candidates, ", "))
		}
		inst, err := tx.Installation(candidates[0])
		if err != nil {
			return err
		}
		if inst.Organization != wc.GetTenantId() || inst.Status != domain.Active {
			return domain.Refuse("installation %s is not active at %s", inst.ID, wc.GetTenantId())
		}
		if !mayAttach(verified.EffectiveScopes(), r.Kind, inst.PrincipalID) {
			return domain.Refuse("the capability holds no create for this installation; existing resources require AuthorizeTransfer")
		}
		if err := attachOwned(tx, inst, r.Kind, r.ResourceID); err != nil {
			return err
		}
		owner = inst.ID
		return nil
	})
	return owner, err
}

// DetachResource releases the serving module's deleted resource and invalidates
// previously issued capabilities. The bound counts only currently attached ids.
func (s *Service) DetachResource(ctx context.Context, caller Workload, org, kind, id string) (string, error) {
	if err := decide.ValidResourceID(id); err != nil {
		return "", err
	}
	if org == "" {
		return "", domain.Malformed("a detachment names the organization the resource belongs to")
	}
	var owner string
	err := s.store.Write(ctx, func(tx Tx) error {
		owner = ""
		if _, err := attachmentServer(tx, caller, kind); err != nil {
			return err
		}
		if _, err := tx.Organization(org); err != nil {
			return notFound(err)
		}
		all, err := tx.Installations(org)
		if err != nil {
			return err
		}
		for _, inst := range all {
			if !slices.Contains(inst.Owned[kind], id) {
				continue
			}
			inst.Owned[kind] = slices.DeleteFunc(inst.Owned[kind], func(held string) bool { return held == id })
			inst.Revision++
			if err := tx.PutInstallation(inst); err != nil {
				return err
			}
			if err := tx.BumpAuthorizationRevision(org); err != nil {
				return err
			}
			owner = inst.ID
			return nil
		}
		return nil
	})
	return owner, err
}

func attachmentServer(tx Tx, caller Workload, kind string) (domain.Module, error) {
	m, err := tx.ModuleNamed(caller.Module)
	if err != nil {
		return m, notFound(err)
	}
	servers, err := servingModules(tx, kind)
	if err != nil {
		return m, err
	}
	slices.Sort(servers)
	if !slices.Contains(servers, m.Name) {
		return m, domain.Refuse("%s does not serve %s, so it attaches none of its resources", m.Name, kind)
	}
	if len(servers) != 1 {
		return m, domain.Refuse("%s is served by %s; an attachment needs the kind's one serving module", kind, strings.Join(servers, ", "))
	}
	return m, nil
}

func mayAttach(scopes Scopes, kind, installationPrincipal string) bool {
	return slices.ContainsFunc(scopes, func(sc *basev0.WorkScopeV1) bool {
		if sc.GetResourceKind() != kind {
			return false
		}
		whole, every := len(sc.GetResourceIds()) == 0, slices.Contains(sc.GetActions(), scope.AnyAction)
		return whole && (sc.GetResourceOwnerId() == "" || sc.GetResourceOwnerId() == installationPrincipal) && (every || slices.Contains(sc.GetActions(), "create"))
	})
}

// attachmentFresh fences verification against changes before the write snapshot.
func (s *Service) attachmentFresh(tx Tx, wc *basev0.WorkContextV1) error {
	revision, err := tx.AuthorizationRevision(wc.GetTenantId())
	if err != nil {
		return err
	}
	if revision != wc.GetAuthorizationRevision() {
		return domain.Refuse("authorization revision superseded during attachment")
	}
	// Recheck the owner and every actor's seal/epoch inside the write snapshot.
	check := func(principal string, sealID string, revision, epoch uint64) error {
		seal, err := s.src.sealIn(tx, principal, sealID)
		if err != nil {
			return err
		}
		liveEpoch, err := s.src.epochIn(tx, principal)
		if err != nil {
			return err
		}
		if seal.InstallationRevision != revision || liveEpoch != epoch {
			return domain.Refuse("capability provenance superseded during attachment")
		}
		return nil
	}
	seal := wc.GetSeal()
	if err := check(wc.GetOwnerPrincipalId(), seal.GetInstallationId(), seal.GetInstallationRevision(), seal.GetPrincipalEpoch()); err != nil {
		return err
	}
	for _, hop := range wc.GetActorChain() {
		epoch, err := s.src.epochIn(tx, hop.GetPrincipalId())
		if err != nil {
			return err
		}
		if epoch != hop.GetPrincipalEpoch() {
			return domain.Refuse("actor provenance superseded during attachment")
		}
	}
	return nil
}

// attachOwned is shared by creation and an authorized transfer. The caller has
// established the active installation and authorization in this write transaction.
func attachOwned(tx Tx, inst domain.Installation, kind, id string) error {
	all, err := tx.Installations(inst.Organization)
	if err != nil {
		return err
	}
	for _, other := range all {
		if other.ID != inst.ID && slices.Contains(other.Owned[kind], id) {
			return domain.Refuse("%s %q is owned by installation %s; a resource has one owner in an organisation", kind, id, other.ID)
		}
	}
	if !slices.Contains(inst.Owned[kind], id) {
		if len(inst.Owned[kind]) >= MaxOwnedPerKind {
			return domain.Refuse("installation %s already owns %d of %s, the most a capability carries", inst.ID, MaxOwnedPerKind, kind)
		}
		if inst.Owned == nil {
			inst.Owned = map[string][]string{}
		}
		inst.Owned[kind] = append(inst.Owned[kind], id)
		slices.Sort(inst.Owned[kind])
		if err := tx.PutInstallation(inst); err != nil {
			return err
		}
	}
	return nil
}
