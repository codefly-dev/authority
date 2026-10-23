// Package policy reads the policy a module declares on each method it serves,
// from the module itself over gRPC reflection. That is the module's running
// declaration on a laptop, where the module serves reflection; in a cell the
// same declarations come from the module's published contract.
package policy

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	hopv1 "github.com/codefly-dev/authority/libraries/hop/go/gen/authority/hop/v1"
	"google.golang.org/grpc"
	reflectionv1 "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	"hop/pkg/business/decide"
)

// Fresh is how long a read service's declarations are trusted before they are
// read again, so a module restarted with tighter declarations is enforced
// within it.
const Fresh = 10 * time.Second

// Reader reads and briefly remembers a module's declarations, by service.
type Reader struct {
	Module *grpc.ClientConn
	Now    func() time.Time

	mu       sync.Mutex
	services map[string]read
}

type read struct {
	at       time.Time
	policies map[string]*hopv1.Policy // by method name; nil when the method declares none
}

// Policy returns what method ("/package.Service/Method") declares, nil when it
// declares nothing. An error is the module's declarations being unreadable.
func (r *Reader) Policy(ctx context.Context, method string) (*hopv1.Policy, error) {
	service, name, ok := strings.Cut(strings.TrimPrefix(method, "/"), "/")
	if !ok {
		return nil, fmt.Errorf("%q is not a method name", method)
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cached, known := r.services[service]
	if _, declared := cached.policies[name]; !known || !declared || now().Sub(cached.at) > Fresh {
		policies, err := r.load(ctx, service)
		if err != nil {
			return nil, err
		}
		cached = read{at: now(), policies: policies}
		if r.services == nil {
			r.services = map[string]read{}
		}
		r.services[service] = cached
	}
	policy, declared := cached.policies[name]
	if !declared {
		return nil, fmt.Errorf("%w: %s", decide.ErrNoMethod, method)
	}
	return policy, nil
}

func (r *Reader) load(ctx context.Context, service string) (map[string]*hopv1.Policy, error) {
	stream, err := reflectionv1.NewServerReflectionClient(r.Module).ServerReflectionInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot read the module's declarations: %w", err)
	}
	defer func() { _ = stream.CloseSend() }()
	if err := stream.Send(&reflectionv1.ServerReflectionRequest{
		MessageRequest: &reflectionv1.ServerReflectionRequest_FileContainingSymbol{FileContainingSymbol: service},
	}); err != nil {
		return nil, fmt.Errorf("cannot read the module's declarations: %w", err)
	}
	answer, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("cannot read the module's declarations: %w", err)
	}
	if refusal := answer.GetErrorResponse(); refusal != nil {
		return nil, fmt.Errorf("the module does not describe %s: %s", service, refusal.GetErrorMessage())
	}
	pkg, short := "", service
	if i := strings.LastIndex(service, "."); i >= 0 {
		pkg, short = service[:i], service[i+1:]
	}
	// Options are decoded against the registered types, so the policy extension
	// this binary links is read as a message rather than kept as unknown bytes.
	decode := proto.UnmarshalOptions{Resolver: protoregistry.GlobalTypes}
	for _, raw := range answer.GetFileDescriptorResponse().GetFileDescriptorProto() {
		file := &descriptorpb.FileDescriptorProto{}
		if err := decode.Unmarshal(raw, file); err != nil {
			return nil, fmt.Errorf("the module's description of %s does not decode: %w", service, err)
		}
		if file.GetPackage() != pkg {
			continue
		}
		for _, s := range file.GetService() {
			if s.GetName() != short {
				continue
			}
			policies := make(map[string]*hopv1.Policy, len(s.GetMethod()))
			for _, m := range s.GetMethod() {
				policies[m.GetName()] = nil
				if m.GetOptions() != nil && proto.HasExtension(m.GetOptions(), hopv1.E_Policy) {
					policies[m.GetName()], _ = proto.GetExtension(m.GetOptions(), hopv1.E_Policy).(*hopv1.Policy)
				}
			}
			return policies, nil
		}
	}
	return nil, fmt.Errorf("the module's description does not contain %s", service)
}
