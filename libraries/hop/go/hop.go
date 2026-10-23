// Package hop is the stamp's contract: what the hop in front of a module writes
// onto a call it let through, and how the module reads it.
//
// The hop has checked the call's Work Context with the authority. The module
// believes the stamp only when it carries this run's proof; any other call did
// not come through the hop, and the module's interceptor refuses it by name. A
// module that reads the stamp verifies no token and asks no authority: the hop
// did both. In a cell the mesh is why nothing reaches the module around the hop;
// on a laptop, with no mesh, the proof is.
package hop

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// WorkContextKey carries the caller's Work Context to the hop, as everywhere.
// The hop forwards it, so a module acting onward can ask for a child.
const WorkContextKey = "x-codefly-work-context"

// The stamp. Every key the hop writes starts with StampPrefix, and the hop
// removes every such key a caller sent before writing its own.
const (
	StampPrefix  = "x-codefly-hop-"
	ProofKey     = StampPrefix + "proof"
	OwnerKey     = StampPrefix + "owner"
	OwnerKindKey = StampPrefix + "owner-kind"
	TenantKey    = StampPrefix + "tenant"
	ActorsKey    = StampPrefix + "actors"
	ScopesKey    = StampPrefix + "scopes"
	BindingKey   = StampPrefix + "binding"
)

// Identity is who a call is for, as the hop established it.
type Identity struct {
	Owner     string
	OwnerKind string
	Tenant    string
	// Actors are the modules acting for the owner, in order.
	Actors []string
	// Scopes are what the call may do, each "<resource kind>:<action>".
	Scopes []string
	// Binding is the operation binding the last actor exercises, when it names one.
	Binding string
}

// Has reports whether the identity may do action on kind.
func (i Identity) Has(kind, action string) bool {
	for _, s := range i.Scopes {
		if s == kind+":"+action {
			return true
		}
	}
	return false
}

// ErrNoStamp is a call that did not come through this run's hop.
var ErrNoStamp = errors.New("the call did not come through the hop: it carries no stamp with this run's proof")

// Strip removes every stamp key a caller may have sent: a stamp is the hop's to
// write and no one else's.
func Strip(md metadata.MD) {
	for key := range md {
		if strings.HasPrefix(strings.ToLower(key), StampPrefix) {
			delete(md, key)
		}
	}
}

// Stamp writes identity and the run's proof onto md, after stripping whatever
// stamp a caller sent.
func Stamp(md metadata.MD, id Identity, proof string) {
	Strip(md)
	md.Set(ProofKey, proof)
	md.Set(OwnerKey, id.Owner)
	md.Set(OwnerKindKey, id.OwnerKind)
	md.Set(TenantKey, id.Tenant)
	md.Set(ActorsKey, strings.Join(id.Actors, ","))
	md.Set(ScopesKey, strings.Join(id.Scopes, ","))
	if id.Binding != "" {
		md.Set(BindingKey, id.Binding)
	}
}

// Read returns the identity the hop stamped, or ErrNoStamp when md does not
// carry this run's proof. An empty proof is never accepted: a module with no
// proof delivered reads every call as one that bypassed the hop.
func Read(md metadata.MD, proof string) (Identity, error) {
	got := first(md, ProofKey)
	if proof == "" || got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(proof)) != 1 {
		return Identity{}, ErrNoStamp
	}
	id := Identity{Owner: first(md, OwnerKey), OwnerKind: first(md, OwnerKindKey), Tenant: first(md, TenantKey), Binding: first(md, BindingKey)}
	if id.Owner == "" || id.Tenant == "" {
		return Identity{}, ErrNoStamp
	}
	id.Actors = split(first(md, ActorsKey))
	id.Scopes = split(first(md, ScopesKey))
	return id, nil
}

type identityKey struct{}

// FromContext returns the identity the module's interceptor read off the call.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

// UnaryServerInterceptor gives each call the identity the hop stamped, and
// refuses a call that bypassed the hop. Health checks pass unstamped: the run
// probes the module directly, and they read no data.
func UnaryServerInterceptor(proof string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, err := admit(ctx, info.FullMethod, proof)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor is UnaryServerInterceptor for streams.
func StreamServerInterceptor(proof string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := admit(ss.Context(), info.FullMethod, proof)
		if err != nil {
			return err
		}
		return handler(srv, &stamped{ServerStream: ss, ctx: ctx})
	}
}

func admit(ctx context.Context, method, proof string) (context.Context, error) {
	if strings.HasPrefix(method, "/grpc.health.v1.Health/") {
		return ctx, nil
	}
	md, _ := metadata.FromIncomingContext(ctx)
	id, err := Read(md, proof)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	return context.WithValue(ctx, identityKey{}, id), nil
}

type stamped struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *stamped) Context() context.Context { return s.ctx }

func first(md metadata.MD, key string) string {
	if v := md.Get(key); len(v) > 0 {
		return v[0]
	}
	return ""
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
