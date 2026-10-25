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
	"github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Checker is the authority's Check, as the interface's generated client serves it.
type Checker interface {
	Check(ctx context.Context, in *authorityv1.CheckRequest, opts ...grpc.CallOption) (*authorityv1.CheckResponse, error)
}

// Decider decides for the modules a hop stands in front of. A caller addresses
// its Work Context to the module it calls, so the hop reads the module from the
// context's audience, unverified, and the authority's Check verifies that
// audience and that the module serves the method. A context addressed to a
// module the hop does not front is refused before the authority is asked.
type Decider struct {
	Authority Checker
	Modules   map[string]bool
	// Permissive is hop/ENFORCEMENT=warn: the authority is still asked, and
	// whatever it answers the call goes through, stamped with who the token
	// says it is (a developer identity when there is none) and with the
	// refusal the hop did not make, which it also logs. The composition says
	// so; a cell never does.
	Permissive bool
	// Warned is told each refusal the permissive hop let through.
	Warned func(method string, err error)
	// AudienceOf reads the module a token is addressed to; nil decodes it with
	// core, unverified, which is all the hop needs before the authority checks.
	AudienceOf func(token string) (string, error)
}

func coreAudience(token string) (string, error) {
	decoded, err := workcontext.Decode(token)
	if err != nil {
		return "", err
	}
	return decoded.Context().GetAudience(), nil
}

// Decide returns the module a call is for and who it acts for, or the refusal.
func (d Decider) Decide(ctx context.Context, method string, md metadata.MD) (string, hop.Identity, error) {
	module, id, err := d.decide(ctx, method, md)
	if err == nil || !d.Permissive {
		return module, id, err
	}
	refusal := err
	module, id, err = d.permit(method, md, refusal)
	if err == nil && d.Warned != nil {
		d.Warned(method, refusal)
	}
	return module, id, err
}

// permit is the permissive hop's answer to a refusal: the module the call
// names (or its sole upstream), the identity the token claims unverified
// (or a developer's), and the refusal carried as the stamp's advisory.
func (d Decider) permit(method string, md metadata.MD, refusal error) (string, hop.Identity, error) {
	id := hop.Identity{Owner: "developer", OwnerKind: "human", Tenant: "local", Advisory: refusal.Error()}
	module := ""
	if tokens := md.Get(hop.WorkContextKey); len(tokens) == 1 {
		if decoded, err := workcontext.Decode(tokens[0]); err == nil {
			wc := decoded.Context()
			id = hop.Identity{Owner: wc.GetOwnerPrincipalId(), OwnerKind: wc.GetOwnerPrincipalKind(), Tenant: wc.GetTenantId(),
				Task: wc.GetTaskId(), Expires: wc.GetExpiresAtUnix(), Binding: wc.GetOperationBinding().GetBindingId(), Advisory: refusal.Error()}
			for _, scope := range wc.GetAuthorityScopes() {
				for _, action := range scope.GetActions() {
					id.Scopes = append(id.Scopes, scope.GetResourceKind()+":"+action)
				}
			}
			for _, actor := range wc.GetActorChain() {
				id.Actors = append(id.Actors, actor.GetPrincipalId())
			}
			if d.Modules[wc.GetAudience()] {
				module = wc.GetAudience()
			}
		}
	}
	if module == "" {
		names := make([]string, 0, len(d.Modules))
		for name, enabled := range d.Modules {
			if enabled {
				names = append(names, name)
			}
		}
		slices.Sort(names)
		if len(names) == 0 {
			return "", hop.Identity{}, status.Errorf(codes.Internal, "the hop fronts no module")
		}
		if len(names) > 1 {
			return "", hop.Identity{}, status.Errorf(codes.FailedPrecondition, "the permissive hop cannot route %s without a module audience; it fronts %v", method, names)
		}
		module = names[0]
	}
	if id.Owner == "" || id.Tenant == "" {
		id.Owner, id.OwnerKind, id.Tenant = "developer", "human", "local"
	}
	return module, id, nil
}

func (d Decider) decide(ctx context.Context, method string, md metadata.MD) (string, hop.Identity, error) {
	tokens := md.Get(hop.WorkContextKey)
	switch len(tokens) {
	case 0:
		return "", hop.Identity{}, status.Errorf(codes.Unauthenticated, "the call to %s carries no Work Context; the hop lets through only a call the authority checked", method)
	case 1:
	default:
		return "", hop.Identity{}, status.Errorf(codes.InvalidArgument, "the call to %s carries %d Work Contexts; exactly one says who it is for", method, len(tokens))
	}
	audienceOf := d.AudienceOf
	if audienceOf == nil {
		audienceOf = coreAudience
	}
	module, err := audienceOf(tokens[0])
	if err != nil {
		return "", hop.Identity{}, status.Errorf(codes.Unauthenticated, "the call to %s carries a Work Context that does not decode: %v", method, err)
	}
	if !d.Modules[module] {
		return "", hop.Identity{}, status.Errorf(codes.PermissionDenied, "the call to %s is addressed to %q, a module this hop does not stand in front of", method, module)
	}
	checked, err := d.Authority.Check(ctx, &authorityv1.CheckRequest{Token: tokens[0], Audience: module, Method: method, Advisory: d.Permissive})
	if err != nil {
		refusal := status.Convert(err)
		if refusal.Code() == codes.Unavailable || refusal.Code() == codes.DeadlineExceeded {
			return "", hop.Identity{}, status.Errorf(codes.Unavailable, "the hop could not reach the authority to check the call to %s: %s", module, refusal.Message())
		}
		return "", hop.Identity{}, status.Errorf(refusal.Code(), "the authority refused the call to %s: %s", module, refusal.Message())
	}
	id := IdentityOf(checked.GetContext())
	if d.Permissive && checked.GetRefusal() != "" {
		id.Advisory = checked.GetRefusal()
		if d.Warned != nil {
			d.Warned(method, status.Error(codes.PermissionDenied, id.Advisory))
		}
	}
	return module, id, nil
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
		Task:      wc.GetTaskId(),
		Expires:   wc.GetExpiresAtUnix(),
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
