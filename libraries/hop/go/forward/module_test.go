package forward_test

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// The module these tests stand the hop in front of: one unary method, Version,
// which answers a string. It is served over gRPC through its ServiceDesc and
// over Connect through connect's own handler, and its messages are well-known
// types, so the library carries no API of its own for a test to call.
const (
	moduleService    = "module.v1.ModuleService"
	versionProcedure = "/" + moduleService + "/Version"
)

// versioner is the module's one method.
type versioner interface {
	Version(ctx context.Context) (string, error)
}

// registerModule serves m's Version on s, through s's interceptors.
func registerModule(s grpc.ServiceRegistrar, m versioner) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: moduleService,
		HandlerType: (*versioner)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: "Version",
			Handler: func(srv any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				in := new(emptypb.Empty)
				if err := decode(in); err != nil {
					return nil, err
				}
				answer := func(ctx context.Context, _ any) (any, error) {
					version, err := srv.(versioner).Version(ctx)
					if err != nil {
						return nil, err
					}
					return wrapperspb.String(version), nil
				}
				if interceptor == nil {
					return answer(ctx, in)
				}
				return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: versionProcedure}, answer)
			},
		}},
	}, m)
}

// version calls the module's Version over conn, as a gRPC client would.
func version(ctx context.Context, conn grpc.ClientConnInterface) (string, error) {
	out := new(wrapperspb.StringValue)
	err := conn.Invoke(ctx, versionProcedure, &emptypb.Empty{}, out)
	return out.GetValue(), err
}

// connectVersion serves Version over Connect (and gRPC and gRPC-Web, as every
// Connect listener does), answering through answer.
func connectVersion(answer func(context.Context, *connect.Request[emptypb.Empty]) (*connect.Response[wrapperspb.StringValue], error)) *connect.Handler {
	return connect.NewUnaryHandler(versionProcedure, answer)
}
