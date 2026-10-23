// Package decide is the hop's one question to the authority: may this call to
// this method reach the module, and for whom. The authority's Check answers
// both; the hop decides nothing it did not answer, and passes each refusal on
// with its reason.
package decide

import (
	"context"
	"slices"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/hop/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Checker is the authority's Check, as the interface's generated client serves it.
type Checker interface {
	Check(ctx context.Context, in *authorityv1.CheckRequest, opts ...grpc.CallOption) (*authorityv1.CheckResponse, error)
}

// Decider decides for one module: Audience is the module's principal, the
// audience a Work Context must be addressed to for the hop to let it through.
// What each method of the module requires is the authority's to apply: it holds
// the policy the module's delivery declared, and Check names the method.
type Decider struct {
	Authority Checker
	Audience  string
}

// Decide returns who a call to method is for, or the refusal.
func (d Decider) Decide(ctx context.Context, method string, md metadata.MD) (hop.Identity, error) {
	tokens := md.Get(hop.WorkContextKey)
	switch len(tokens) {
	case 0:
		return hop.Identity{}, status.Errorf(codes.Unauthenticated, "the call to %s carries no Work Context; the hop lets through only a call the authority checked", d.Audience)
	case 1:
	default:
		return hop.Identity{}, status.Errorf(codes.InvalidArgument, "the call to %s carries %d Work Contexts; exactly one says who it is for", d.Audience, len(tokens))
	}
	checked, err := d.Authority.Check(ctx, &authorityv1.CheckRequest{Token: tokens[0], Audience: d.Audience, Method: method})
	if err != nil {
		refusal := status.Convert(err)
		if refusal.Code() == codes.Unavailable || refusal.Code() == codes.DeadlineExceeded {
			return hop.Identity{}, status.Errorf(codes.Unavailable, "the hop could not reach the authority to check the call to %s: %s", d.Audience, refusal.Message())
		}
		return hop.Identity{}, status.Errorf(refusal.Code(), "the authority refused the call to %s: %s", d.Audience, refusal.Message())
	}
	return IdentityOf(checked.GetContext()), nil
}

// IdentityOf reads who a checked Work Context is for. Its scopes are the
// effective ones: the owner's authority narrowed by every actor's grant. A scope
// limited to named resources is left out rather than widened to its whole kind.
func IdentityOf(wc *authorityv1.WorkContextV1) hop.Identity {
	id := hop.Identity{
		Owner:     wc.GetOwnerPrincipalId(),
		OwnerKind: wc.GetOwnerPrincipalKind(),
		Tenant:    wc.GetTenantId(),
		Binding:   wc.GetOperationBinding().GetBindingId(),
	}
	scopes := flatten(wc.GetAuthorityScopes())
	for _, actor := range wc.GetActorChain() {
		id.Actors = append(id.Actors, actor.GetPrincipalId())
		if granted := actor.GetGrantedScopes(); len(granted) > 0 {
			held := flatten(granted)
			scopes = slices.DeleteFunc(scopes, func(s string) bool { return !slices.Contains(held, s) })
		}
	}
	id.Scopes = scopes
	return id
}

func flatten(scopes []*authorityv1.WorkScopeV1) []string {
	var out []string
	for _, s := range scopes {
		if len(s.GetResourceIds()) > 0 {
			continue
		}
		for _, action := range s.GetActions() {
			if scope := s.GetResourceKind() + ":" + action; !slices.Contains(out, scope) {
				out = append(out, scope)
			}
		}
	}
	return out
}
