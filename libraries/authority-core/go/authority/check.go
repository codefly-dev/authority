package authority

import (
	"context"
	"errors"
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	resources "github.com/codefly-dev/authority/libraries/resources/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
)

// Check verifies a capability for the audience the caller is, and refuses
// owner-selected scopes the audience can no longer honour: an audience that
// does not declare owner-aware checking now, or one that withdrew it after
// the capability was issued through a binding to it (never revived). A
// capability issued in a cast is refused once the cast no longer holds
// (castHolds). A person's capability naming no installation it came through,
// at an audience that declares no roles, is refused (ownSession): no issuance
// makes one, and an organisation role admits none.
func (s *Service) Check(ctx context.Context, token, audience string) (*workcontext.Verified, uint64, error) {
	verified, err := s.Verify(ctx, token, audience)
	if errors.Is(err, workcontext.ErrRevoked) {
		// Verified up to the revocation: name an owner-aware withdrawal,
		// which core reports as a binding incarnation that moved.
		if decoded, derr := workcontext.Decode(token); derr == nil {
			wc := decoded.Context()
			if scope.HasOwner(effectiveOf(wc)) && wc.GetOperationBinding().GetBindingId() != "" {
				if current, berr := s.src.OperationBinding(ctx, wc.GetOperationBinding().GetBindingId()); berr == nil && current.Incarnation != wc.GetOperationBinding().GetIncarnation() {
					return nil, 0, domain.Refuse("the capability was revoked: it was issued through a binding re-created since, or before %s last withdrew owner-aware checking; only a fresh capability carries owner-selected scopes", audience)
				}
			}
		}
	}
	if err != nil {
		return nil, 0, err
	}
	var revision uint64
	err = s.store.Read(ctx, func(tx Tx) error {
		m, err := tx.Module(audience)
		if err != nil {
			return notFound(err)
		}
		if err := decide.OwnerAware(m, verified.EffectiveScopes()); err != nil {
			return err
		}
		if err := castOfClaims(tx, verified.Context()); err != nil {
			return err
		}
		if err := ownSession(tx, verified.Context(), m); err != nil {
			return err
		}
		revision, err = tx.AuthorizationRevision(verified.Context().GetTenantId())
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return verified, revision, nil
}

// CheckMethod is Check, then what the audience module's delivery declares
// for method applied to what the call's current actor holds (the last hop's
// grant, never the owner's authority above it): decide.AdmitMethod. An empty
// method is Check alone. Advisory decides the method but does not enforce it:
// a sound capability is answered with the method's refusal beside it, the
// same refusal a check that enforces it returns as its error.
// The exact reserved InstallationStepHTTPMethod (POST /_codefly/installations)
// and InstallationStepRPCMethod (/host.installation.v1.InstallableService/Install)
// instead require a setup-only credential for the current consented pending
// attempt, independently of delivered method policy. Ordinary capabilities are
// refused there. The receiver supplies its actual method and delivered audience;
// it compares verified organization and installation seal with body and carriers
// before callback or cached acknowledgement. Advisory never relaxes this path.
func (s *Service) CheckMethod(ctx context.Context, token, audience, method string, advisory bool) (verified *workcontext.Verified, revision uint64, refusal error, err error) {
	if audience == "" {
		return nil, 0, nil, domain.Refuse("a check names the audience the caller is")
	}
	if method == InstallationStepHTTPMethod || method == InstallationStepRPCMethod {
		// Setup credentials never enter ordinary checking. Advisory cannot
		// relax this authentication boundary or activate an installation.
		verified, revision, err = s.VerifyInstallationStep(ctx, token, audience)
		return verified, revision, nil, err
	}
	if verified, revision, err = s.Check(ctx, token, audience); err != nil || method == "" {
		return verified, revision, nil, err
	}
	err = s.store.Read(ctx, func(tx Tx) error {
		m, err := tx.Module(audience)
		if err != nil {
			return notFound(err)
		}
		if refusal = decide.AdmitMethod(m, method, verified.EffectiveScopes()); refusal != nil {
			return nil
		}
		refusal, err = s.withinApprovedReach(tx, verified.Context(), verified.EffectiveScopes(), m, method)
		return err
	})
	if err != nil {
		return nil, 0, nil, err
	}
	if refusal != nil && !advisory {
		return nil, 0, nil, refusal
	}
	return verified, revision, refusal, nil
}

// Grant is one way a capability covers resources of a kind: a resource match
// and, when set, the owner the resource must have.
type Grant struct {
	resources.Grant
	Owner string
}

// ListResources answers which resources of kind a checked capability may act
// on with action, decided now: a person's through a solution are its roles on
// the principal's data, a person's at a module page declaring roles that
// page's roles granted them, cut to any ids the capability names; a module's
// or an installation's own work is bounded by the capability alone. A
// person's capability that came through neither is refused when it is
// checked (Check).
func (s *Service) ListResources(ctx context.Context, token, audience, kind, action string) ([]Grant, error) {
	if audience == "" || kind == "" || action == "" {
		return nil, domain.Refuse("a resource question names the audience, a kind and an action")
	}
	verified, _, err := s.Check(ctx, token, audience)
	if err != nil {
		return nil, err
	}
	effective := verified.EffectiveScopes()
	if !scope.HoldsAction(effective, kind, action) {
		return nil, domain.Refuse("the capability holds no %s:%s", kind, action)
	}
	wc := verified.Context()
	var out []Grant
	err = s.store.Read(ctx, func(tx Tx) error {
		rows := effective
		if wc.GetOwnerPrincipalKind() == "human" {
			p, err := personOfClaims(tx, wc)
			if err != nil {
				return ownerGone(err, wc.GetOwnerPrincipalId())
			}
			at, err := tx.Module(wc.GetAudience())
			if err != nil && !errors.Is(err, domain.ErrNotFound) {
				return err
			}
			// A capability that came through a page or a module is bounded
			// by what it came through, as issuance bounded it (the issuing
			// hop's principals and the chain's); the audience's own roles,
			// selected to its own installation, bound only a person's own
			// session. Intersecting both answered a page reaching a store
			// with roles of its own no resources at all.
			principals := solutionPrincipals(wc, wc.GetAudience())
			if len(principals) > 1 {
				principals = principals[1:]
			}
			ceiling, bounded, cerr := solutionCeiling(tx, p, principals, at)
			if cerr != nil {
				return cerr
			}
			if bounded {
				rows = scope.Intersect(effective, ceiling)
			} else {
				// A person's own session at a solution or a module page
				// declaring roles answers from their roles there, as issuance
				// does. Check admitted nothing else of a person's.
				h, err := held(tx, p, at)
				if err != nil {
					return err
				}
				rows = scope.Intersect(effective, h)
			}
		}
		out = grantsOf(rows, kind, action)
		return nil
	})
	return out, err
}

func holds(sc *basev0.WorkScopeV1, kind, action string) bool {
	return sc.GetResourceKind() == kind && (slices.Contains(sc.GetActions(), action) || slices.Contains(sc.GetActions(), scope.AnyAction))
}

// grantsOf projects the rows of kind holding action: their ids, or every
// resource, each qualified by the row's owner.
func grantsOf(rows Scopes, kind, action string) []Grant {
	out := []Grant{}
	for _, sc := range rows {
		if !holds(sc, kind, action) {
			continue
		}
		if len(sc.GetResourceIds()) == 0 {
			out = append(out, Grant{Grant: resources.Grant{All: true}, Owner: sc.GetResourceOwnerId()})
			continue
		}
		for _, id := range sc.GetResourceIds() {
			out = append(out, Grant{Grant: resources.Grant{ID: id}, Owner: sc.GetResourceOwnerId()})
		}
	}
	return out
}

// effectiveOf is a context's effective scopes: its last actor's, else its own.
func effectiveOf(wc *basev0.WorkContextV1) Scopes {
	if chain := wc.GetActorChain(); len(chain) > 0 {
		return chain[len(chain)-1].GetGrantedScopes()
	}
	return wc.GetAuthorityScopes()
}

// withinApprovedReach refuses a call to a method of m that the reach a
// consented installation approved does not list for its caller: a person
// acting through the solution or module page, for the roles they hold on
// it, or the installation's own agent, for its agent role (approvedReach).
// A delivery of m, or of the target, that admits more than was approved
// admits nobody more until the upgrade is approved, and the approved policy
// holds on effective, what the call itself carries, as well as on the
// approved reach.
func (s *Service) withinApprovedReach(tx Tx, wc *basev0.WorkContextV1, effective Scopes, m domain.Module, method string) (error, error) {
	owner := reachOwner{}
	switch wc.GetOwnerPrincipalKind() {
	case "agent":
		owner.agent = wc.GetOwnerPrincipalId()
	case "human":
		owner.principals = reachedThrough(tx, wc, m.Principal)
		p, err := personOfClaims(tx, wc)
		if err != nil {
			return ownerGone(err, wc.GetOwnerPrincipalId()), nil
		}
		owner.person = &p
	default:
		return nil, nil
	}
	_, admits, bounded, err := s.approvedReach(tx, owner, m.Name)
	if err != nil || !bounded {
		return nil, err
	}
	// Each face of an operation is held to its own approved policy.
	if key, ok := decide.MethodKey(m, method); ok && admits(key, effective) {
		return nil, nil
	}
	return domain.Refuse("%s at %s is beyond the reach its installation approved; approving the delivered upgrade reaches it", method, m.Name), nil
}

// reachedThrough is the targets a person's call at module came through, whose
// installations' consent bounds it, read as what the person holds there is
// (throughSolutions): a call whose actor chain names a solution or a module
// page declaring roles holds those targets' roles at module, so it is bounded
// by their installations' consent alone, never by module's own page as well,
// whose roles the person need not hold. A call naming no such target (the
// person's own root at module, their client's call there, or a hop from a
// module declaring no roles) holds module's own roles when it is a page, so
// module's installation's consent bounds it.
func reachedThrough(tx Tx, wc *basev0.WorkContextV1, module string) []string {
	principals := solutionPrincipals(wc, module)
	if through := principals[1:]; anyRoleGated(tx, through) {
		return through
	}
	return principals
}

// ownSession refuses a person's capability at m that names no target whose
// roles could have admitted it: no solution and no module page declaring
// roles on its path, m itself included. That is a person's own session at a
// module declaring no roles, which holds nothing (decide.NoRoles) and which
// no issuance of this core makes; one minted by another host or an earlier
// version is refused here, at every check.
func ownSession(tx Tx, wc *basev0.WorkContextV1, m domain.Module) error {
	if wc.GetOwnerPrincipalKind() != "human" || anyRoleGated(tx, reachedThrough(tx, wc, m.Principal)) {
		return nil
	}
	return decide.NoRoles(m)
}

// anySolution is whether a solution is among principals.
func anySolution(tx Tx, principals []string) bool {
	return slices.ContainsFunc(principals, func(principal string) bool {
		m, err := tx.Module(principal)
		return err == nil && m.Kind == domain.KindSolution
	})
}

// anyRoleGated is whether a target whose installation a consent may hold, a
// solution or a module page declaring roles, is among principals.
func anyRoleGated(tx Tx, principals []string) bool {
	return slices.ContainsFunc(principals, func(principal string) bool {
		m, err := tx.Module(principal)
		return err == nil && decide.RoleGated(m)
	})
}
