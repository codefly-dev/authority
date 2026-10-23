package hop

import (
	"context"
	"net"
	"strings"

	"google.golang.org/grpc"
)

// RESTThroughHop sends a module's REST gateway through the hop. The gateway
// translates each REST call into a gRPC call with its exact method name; this
// dial option makes that call reach the hop instead of the module's own gRPC
// server, so the hop decides and stamps it the way it does every gRPC call and
// forwards it to the module. The REST listener itself decides nothing.
//
// hopEndpoint is the hop's gRPC endpoint as the composition resolves it.
func RESTThroughHop(hopEndpoint string) grpc.DialOption {
	address := hopEndpoint
	for _, scheme := range []string{"grpc://", "http://", "tcp://"} {
		address = strings.TrimPrefix(address, scheme)
	}
	return grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", address)
	})
}
