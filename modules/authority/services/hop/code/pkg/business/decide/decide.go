// Package decide is the hop's one question to the authority: may this call to
// this method reach the module, and for whom. The authority's Check answers
// both; the hop decides nothing it did not answer, and passes each refusal on
// with its reason.
package decide

import (
	"context"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	"slices"
	"strings"

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
type Decision struct {
	Module   string
	Identity hop.Identity
	// Route is the destination; the authority checks the actual HTTP request.
	Route *routing.RouteEndpoint
}

type Decider struct {
	Routes    *routing.Routing
	Authority Checker
	Modules   map[string]bool
	// Permissive is hop/ENFORCEMENT=warn: the authority is asked for advice,
	// verifies the Work Context as always, and answers what the method's
	// policy would have refused beside the verified identity; the call goes
	// through stamped with that identity and the refusal as its advisory,
	// which the hop also logs. An unsound or missing Work Context is still
	// refused. The composition says so; a cell never does.
	Permissive bool
	// Warned is told each policy refusal the permissive hop let through.
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
// Permissive changes one answer only: the authority verified the Work Context
// and the method's policy would have refused it (decide's advisory path). A
// call whose Work Context is missing, unsound or addressed elsewhere, or that
// the authority could not be asked about, is refused in either mode.
func (d Decider) Decide(ctx context.Context, method string, md metadata.MD) (Decision, error) {
	return d.decide(ctx, method, md)
}

func (d Decider) decide(ctx context.Context, method string, md metadata.MD) (Decision, error) {
	tokens := md.Get(hop.WorkContextKey)
	switch len(tokens) {
	case 0:
		return Decision{}, status.Errorf(codes.Unauthenticated, "the call to %s carries no Work Context; the hop lets through only a call the authority checked", method)
	case 1:
	default:
		return Decision{}, status.Errorf(codes.InvalidArgument, "the call to %s carries %d Work Contexts; exactly one says who it is for", method, len(tokens))
	}
	audienceOf := d.AudienceOf
	if audienceOf == nil {
		audienceOf = coreAudience
	}
	module, err := audienceOf(tokens[0])
	if err != nil {
		return Decision{}, status.Errorf(codes.Unauthenticated, "the call to %s carries a Work Context that does not decode: %v", method, err)
	}
	if !d.Modules[module] {
		return Decision{}, status.Errorf(codes.PermissionDenied, "the call to %s is addressed to %q, a module this hop does not stand in front of", method, module)
	}
	transport := "grpc"
	if !strings.HasPrefix(method, "/") {
		transport = "http"
	}
	selected, policy, routeErr := d.Routes.Resolve(module, transport, method)
	if routeErr != nil {
		return Decision{}, status.Error(codes.NotFound, routeErr.Error())
	}
	route := &selected
	checked, err := d.Authority.Check(ctx, &authorityv1.CheckRequest{Token: tokens[0], Audience: module, Method: policy, Advisory: d.Permissive})
	if err != nil {
		refusal := status.Convert(err)
		if refusal.Code() == codes.Unavailable || refusal.Code() == codes.DeadlineExceeded {
			return Decision{}, status.Errorf(codes.Unavailable, "the hop could not reach the authority to check the call to %s: %s", module, refusal.Message())
		}
		return Decision{}, status.Errorf(refusal.Code(), "the authority refused the call to %s: %s", module, refusal.Message())
	}
	id := IdentityOf(checked.GetContext())
	if d.Permissive && checked.GetRefusal() != "" {
		id.Advisory = checked.GetRefusal()
		if d.Warned != nil {
			d.Warned(method, status.Error(codes.PermissionDenied, id.Advisory))
		}
	}
	return Decision{Module: module, Identity: id, Route: route}, nil
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
