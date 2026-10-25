package hop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Issuer is the authority interface's Issue, as its generated client serves it.
type Issuer interface {
	Issue(ctx context.Context, in *authorityv1.IssueRequest, opts ...grpc.CallOption) (*authorityv1.IssueResponse, error)
}

// Outbound is how a module calls another module through the hop: it asks the
// authority to issue the Work Context the call carries. A module never mints.
//
// ForCaller acts for whoever called this module: a child of the caller's
// checked context, through one of this module's declared bindings, so the
// callee sees the caller's authority narrowed by the binding. ForModule acts
// for the module itself in one organisation, through a binding that declares
// headless scopes.
type Outbound struct {
	Authority Issuer
	// Credential returns this workload's credential as the run attests it, read
	// fresh on every call so a rotation takes effect.
	Credential func() (string, error)
}

// Option shapes one issue: Lookup asks for the binding's lookup scopes alone.
type Option func(*authorityv1.IssueRequest)

// Lookup issues for reading a receipt back: the binding's lookup scopes only,
// never the authority to repeat the effect.
func Lookup() Option { return func(r *authorityv1.IssueRequest) { r.Operation = "lookup" } }

// ErrNoCaller is ForCaller on a call that did not arrive through the hop.
var ErrNoCaller = errors.New("hop: no caller to act for: the call carries no checked Work Context")

// ForCaller returns ctx carrying a child of the caller's Work Context, issued
// through binding.
func (o Outbound) ForCaller(ctx context.Context, binding string, opts ...Option) (context.Context, error) {
	caller, ok := FromContext(ctx)
	if !ok || caller.Context == "" {
		return nil, ErrNoCaller
	}
	credential, err := o.Credential()
	if err != nil {
		return nil, err
	}
	return o.issue(ctx, binding, &authorityv1.IssueRequest{
		As:                 &authorityv1.IssueRequest_ParentToken{ParentToken: caller.Context},
		Actor:              &authorityv1.WorkloadCredential{Credential: credential},
		OperationBindingId: binding,
	}, opts...)
}

// ForParent is ForCaller for a module that reads the stamp itself: parent is
// the caller's checked Work Context, the one the stamp's digest binds.
func (o Outbound) ForParent(ctx context.Context, parent, binding string, opts ...Option) (context.Context, error) {
	if parent == "" {
		return nil, ErrNoCaller
	}
	credential, err := o.Credential()
	if err != nil {
		return nil, err
	}
	return o.issue(ctx, binding, &authorityv1.IssueRequest{
		As:                 &authorityv1.IssueRequest_ParentToken{ParentToken: parent},
		Actor:              &authorityv1.WorkloadCredential{Credential: credential},
		OperationBindingId: binding,
	}, opts...)
}

// ForDelegation returns ctx carrying a Work Context issued from a delegation a
// person granted this module: owned by that person, with this module as actor.
// No live capability is presented; the authority re-checks the delegation and
// what its grantor holds, and renewing is calling again.
func (o Outbound) ForDelegation(ctx context.Context, delegation, binding string, opts ...Option) (context.Context, error) {
	credential, err := o.Credential()
	if err != nil {
		return nil, err
	}
	return o.issue(ctx, binding, &authorityv1.IssueRequest{
		As:                 &authorityv1.IssueRequest_Delegation{Delegation: &authorityv1.DelegationRef{DelegationId: delegation}},
		Actor:              &authorityv1.WorkloadCredential{Credential: credential},
		OperationBindingId: binding,
	}, opts...)
}

// ForModule returns ctx carrying a Work Context for this module's own work in
// organization, issued through binding. An empty organization asks the authority
// to resolve the module's installed tenant: its delivered tenant pin or sole
// active installing organization. Ambiguous or absent authority is refused by
// the authority with a reason. Each issued context attests one organization.
func (o Outbound) ForModule(ctx context.Context, organization, binding string, opts ...Option) (context.Context, error) {
	credential, err := o.Credential()
	if err != nil {
		return nil, err
	}
	return o.issue(ctx, binding, &authorityv1.IssueRequest{
		As:                 &authorityv1.IssueRequest_Workload{Workload: &authorityv1.WorkloadCredential{Credential: credential}},
		OrganizationId:     organization,
		OperationBindingId: binding,
	}, opts...)
}

func (o Outbound) issue(ctx context.Context, binding string, req *authorityv1.IssueRequest, opts ...Option) (context.Context, error) {
	for _, opt := range opts {
		opt(req)
	}
	issued, err := o.Authority.Issue(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("hop: the authority refused to issue through binding %q: %w", binding, err)
	}
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Set(WorkContextKey, issued.GetToken())
	return metadata.NewOutgoingContext(ctx, md), nil
}

// WorkloadTokenFile is where a run names the file holding this workload's
// credential.
const WorkloadTokenFile = "CODEFLY__WORKLOAD_TOKEN_FILE"

// RunCredential reads this workload's credential from the file the run names,
// on every call.
func RunCredential() (string, error) {
	path := os.Getenv(WorkloadTokenFile)
	if path == "" {
		return "", fmt.Errorf("hop: %s is not set: the run attests no credential for this workload (declare module-identity)", WorkloadTokenFile)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("hop: read this workload's credential: %w", err)
	}
	credential := strings.TrimSpace(string(data))
	if credential == "" {
		return "", fmt.Errorf("hop: this workload's credential at %s is empty", path)
	}
	return credential, nil
}
