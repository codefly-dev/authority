// Package decide is the hop's one decision: may this call reach the module, and
// for whom. It asks the authority's Check; it decides nothing the authority did
// not answer, and every refusal names its reason.
package decide

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/hop/go"
	hopv1 "github.com/codefly-dev/authority/libraries/hop/go/gen/authority/hop/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Checker is the authority's Check, as the interface's generated client serves it.
type Checker interface {
	Check(ctx context.Context, in *authorityv1.CheckRequest, opts ...grpc.CallOption) (*authorityv1.CheckResponse, error)
}

// ErrNoMethod is a method the module does not serve.
var ErrNoMethod = errors.New("the module serves no such method")

// Policies answers what a method of the module declares; nil when it declares
// nothing, an error when the declarations cannot be read.
type Policies interface {
	Policy(ctx context.Context, method string) (*hopv1.Policy, error)
}

// Decider decides for one module: Audience is the module's principal, the
// audience a Work Context must be addressed to for the hop to let it through,
// and Policies are what each of its methods declares.
type Decider struct {
	Authority Checker
	Audience  string
	Policies  Policies
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
	checked, err := d.Authority.Check(ctx, &authorityv1.CheckRequest{Token: tokens[0], Audience: d.Audience})
	if err != nil {
		refusal := status.Convert(err)
		if refusal.Code() == codes.Unavailable || refusal.Code() == codes.DeadlineExceeded {
			return hop.Identity{}, status.Errorf(codes.Unavailable, "the hop could not reach the authority to check the call to %s: %s", d.Audience, refusal.Message())
		}
		return hop.Identity{}, status.Errorf(refusal.Code(), "the authority refused the call to %s: %s", d.Audience, refusal.Message())
	}
	id := IdentityOf(checked.GetContext())
	policy, err := d.Policies.Policy(ctx, method)
	if errors.Is(err, ErrNoMethod) {
		return hop.Identity{}, status.Errorf(codes.Unimplemented, "%s serves no method %s", d.Audience, method)
	}
	if err != nil {
		return hop.Identity{}, status.Errorf(codes.Unavailable, "the hop cannot read what %s declares for %s: %v", d.Audience, method, err)
	}
	if err := Admits(policy, id); err != nil {
		return hop.Identity{}, status.Errorf(codes.PermissionDenied, "%s refuses %s for %s: %v", d.Audience, method, id.Owner, err)
	}
	return id, nil
}

// Admits applies one method's declaration to who the call is for. A method
// that declares nothing, or declares both that it requires something and that
// it requires nothing, is refused: the hop never reads an absent or ambiguous
// declaration as permission.
func Admits(policy *hopv1.Policy, id hop.Identity) error {
	switch {
	case policy == nil:
		return errors.New("the method declares no policy")
	case policy.GetAnyCheckedCaller() && len(policy.GetRequires()) > 0:
		return errors.New("the method's policy both requires scopes and requires none")
	case policy.GetAnyCheckedCaller():
		return nil
	case len(policy.GetRequires()) == 0:
		return errors.New("the method's policy requires nothing and does not say so")
	}
	var missing []string
	for _, r := range policy.GetRequires() {
		if r.GetResourceKind() == "" || len(r.GetActions()) == 0 {
			return errors.New("the method's policy names a requirement with no kind or no action")
		}
		for _, action := range r.GetActions() {
			if !id.Has(r.GetResourceKind(), action) {
				missing = append(missing, r.GetResourceKind()+":"+action)
			}
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("it requires %s, which the call does not hold (it holds %s)", strings.Join(missing, ", "), holds(id.Scopes))
	}
	return nil
}

func holds(scopes []string) string {
	if len(scopes) == 0 {
		return "nothing"
	}
	return strings.Join(scopes, ", ")
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
