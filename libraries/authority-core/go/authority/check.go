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
// the capability was issued through a binding to it (never revived).
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
		refusal = decide.AdmitMethod(m, method, verified.EffectiveScopes())
		return nil
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
// the principal's data, a person's own their organization roles' matchers,
// cut to any ids the capability names; a module's or an installation's own
// work is bounded by the capability alone.
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
			p, err := tx.Member(wc.GetTenantId(), wc.GetOwnerPrincipalId())
			if err != nil {
				return domain.Refuse("the owner %s is no longer a member", wc.GetOwnerPrincipalId())
			}
			ceiling, bounded, err := solutionCeiling(tx, p, solutionPrincipals(wc, wc.GetAudience()))
			if err != nil {
				return err
			}
			if bounded {
				rows = scope.Intersect(effective, ceiling)
			} else {
				roles, err := orgRoles(tx, p)
				if err != nil {
					return err
				}
				out = narrow(decide.ResourceGrants(roles, kind, action), effective, kind, action)
				return nil
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

// narrow cuts an organization role's matchers to the ids the capability
// names, when it names any.
func narrow(matchers []resources.Grant, effective Scopes, kind, action string) []Grant {
	var ids []string
	for _, sc := range effective {
		if !holds(sc, kind, action) {
			continue
		}
		if len(sc.GetResourceIds()) == 0 {
			out := make([]Grant, 0, len(matchers))
			for _, m := range matchers {
				out = append(out, Grant{Grant: m})
			}
			return out
		}
		ids = append(ids, sc.GetResourceIds()...)
	}
	covered, err := resources.Compile(matchers)
	out := []Grant{}
	if err != nil {
		return out
	}
	for _, id := range ids {
		if covered.Matches(id) {
			out = append(out, Grant{Grant: resources.Grant{ID: id}})
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
