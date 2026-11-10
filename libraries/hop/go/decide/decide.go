// Package decide is the hop's one question to the authority: may this call to
// this method reach the module, and for whom. The authority's Check answers
// both; the hop decides nothing it did not answer, and passes each refusal on
// with its reason.
package decide

import (
	"context"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	"slices"
	"strconv"
	"strings"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/hop/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Checker is the authority's Check, as the interface's generated client serves it.
type Checker interface {
	Check(ctx context.Context, in *authorityv1.CheckRequest, opts ...grpc.CallOption) (*authorityv1.CheckResponse, error)
}

// Decider decides for the modules a hop stands in front of. A caller addresses
// its Work Context to the module it calls, so the hop reads the module from the
// context's audience, unverified, and the authority's Check verifies that
// audience and that the module serves the method. A context addressed to a
// module the hop does not front is refused before the authority is asked, and
// so is one addressed to a fronted module for a method another fronted module
// publishes: the caller presented the wrong module's context (PermissionDenied,
// naming both). Only a method no fronted module publishes is NotFound.
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
		// A destination another fronted module publishes is known: the
		// context is for the wrong module, which is a refusal of the caller,
		// never an unknown destination. The authority is not asked.
		if owners := d.publishers(transport, method, module); len(owners) > 0 {
			return Decision{}, status.Errorf(codes.PermissionDenied, "the call to %s is for %s, but its Work Context is addressed to %q; a Work Context is honoured only at the module it is addressed to", method, strings.Join(owners, ", "), module)
		}
		return Decision{}, status.Error(codes.NotFound, routeErr.Error())
	}
	route := &selected
	checked, err := d.Authority.Check(ctx, &authorityv1.CheckRequest{Token: tokens[0], Audience: module, Method: policy})
	if err != nil {
		refusal := status.Convert(err)
		if refusal.Code() == codes.Unavailable || refusal.Code() == codes.DeadlineExceeded {
			return Decision{}, status.Errorf(codes.Unavailable, "the hop could not reach the authority to check the call to %s: %s", module, refusal.Message())
		}
		return Decision{}, status.Errorf(refusal.Code(), "the authority refused the call to %s: %s", module, refusal.Message())
	}
	if checked.GetRefusal() != "" {
		return Decision{}, status.Error(codes.PermissionDenied, "the authority refused the method policy")
	}
	id := IdentityOf(checked.GetContext())
	return Decision{Module: module, Identity: id, Route: route}, nil
}

// publishers are the modules this hop fronts, other than addressed, that
// publish method on transport, in a stable order.
func (d Decider) publishers(transport, method, addressed string) []string {
	var owners []string
	for module, fronted := range d.Modules {
		if !fronted || module == addressed {
			continue
		}
		if _, _, err := d.Routes.Resolve(module, transport, method); err == nil {
			owners = append(owners, strconv.Quote(module))
		}
	}
	slices.Sort(owners)
	return owners
}

// IdentityOf reads who the authority's checked context is for, with the one
// derivation the module's Verifier also applies to the token it authenticates
// (hop.IdentityOf); the two must agree or the module refuses the call.
func IdentityOf(wc *authorityv1.WorkContextV1) hop.Identity {
	wire, err := proto.Marshal(wc)
	if err != nil {
		return hop.Identity{}
	}
	claims := &basev0.WorkContextV1{}
	if err := proto.Unmarshal(wire, claims); err != nil {
		return hop.Identity{}
	}
	return hop.IdentityOf(claims)
}
