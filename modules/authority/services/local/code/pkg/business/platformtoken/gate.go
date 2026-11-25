// Package platformtoken lets a caller of the local authority present a user
// token of the OBIN platform where a session bearer goes.
//
// A host serves this only when it builds a Gate and installs its
// interceptors: with none installed, such a token is one more bearer that
// names no session. The Gate verifies and maps the token
// (obintoken.Adapter), opens or finds the session it is on this host
// (state.OpenAdmitted), and hands the call on carrying that session in the
// token's place, so every plugin reads a session exactly as it does today.
// Anything refused is Unauthenticated, and ends what the token had opened.
package platformtoken

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/codefly-dev/authority/libraries/authority-core/go/obintoken"

	"gateway/pkg/business/state"
)

// Gate admits platform tokens to one host.
type Gate struct {
	Adapter *obintoken.Adapter
	State   *state.State
}

// own is the methods a platform token's session is never handed to: each
// opens or lists a session that acts as something other than the one role
// the token names.
var own = map[string]bool{
	"/host.session.v1.SessionService/OpenRoleView":      true,
	"/host.session.v1.SessionService/OpenTeamCast":      true,
	"/host.session.v1.SessionService/ListCastableTeams": true,
}

// UnaryInterceptor admits the platform token a unary call carries.
func (g *Gate) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, err := g.admit(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamInterceptor admits the platform token a stream carries.
func (g *Gate) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := g.admit(stream.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return handler(srv, admitted{stream, ctx})
	}
}

type admitted struct {
	grpc.ServerStream
	ctx context.Context
}

func (a admitted) Context() context.Context { return a.ctx }

// admit answers ctx unchanged for a call that carries no platform token, and
// for one that does, ctx carrying the session the token is here.
func (g *Gate) admit(ctx context.Context, method string) (context.Context, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	token := ""
	for _, value := range md.Get("authorization") {
		if bearer, found := strings.CutPrefix(value, "Bearer "); found && bearer != "" {
			token = bearer
			break
		}
	}
	// A session bearer is this host's own identifier and has no dot; a signed
	// token has exactly two.
	if strings.Count(token, ".") != 2 {
		return ctx, nil
	}
	admission, err := g.Adapter.Admit(ctx, token)
	if err != nil {
		var refusal *obintoken.Refusal
		if !errors.As(err, &refusal) {
			return nil, status.Error(codes.Unauthenticated, "the platform token is refused")
		}
		if refusal.TokenID != "" {
			g.State.EndAdmitted(refusal.TokenID)
		}
		return nil, status.Error(codes.Unauthenticated, "the platform token is refused: "+refusal.Reason)
	}
	if own[method] {
		return nil, status.Error(codes.PermissionDenied, "a platform token acts as the one role it names: it opens no other session")
	}
	session, err := g.State.OpenAdmitted(ctx, admission)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "the platform token is refused: "+err.Error())
	}
	md = md.Copy()
	md.Set("authorization", "Bearer "+session.ID)
	return metadata.NewIncomingContext(ctx, md), nil
}
