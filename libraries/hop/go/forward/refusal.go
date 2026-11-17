package forward

import (
	"cmp"
	"context"

	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/decide"
	"github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Refusal is one call the front door refused, as a host records it: why, and
// what identifies the call. The hop keeps no record of its own; a host that
// keeps one hands the front door a sink (Config.Refused).
type Refusal struct {
	// Method is the call: a gRPC procedure ("/package.Service/Method") or an
	// HTTP request ("<VERB> <path>").
	Method string
	// Code and Reason are the refusal as the hop decided it. Reason is the
	// hop's own line, which can name what the caller is not told (a module's
	// address in a transport error): it is for the host's record, never for
	// a caller.
	Code   codes.Code
	Reason string
	// Module is the module the call is addressed to, when its Work Context
	// says one.
	Module string
	// Organization, Owner, Actor, Binding and Task identify the work the
	// call is part of: the owner's tenant, whose authority it runs on, the
	// last module acting for them (the owner, when none), the operation
	// binding that actor exercises and the task. Empty for a call that
	// carries no Work Context the hop can read.
	Organization, Owner, Actor, Binding, Task string
	// Claimed says those identifiers were read from the call's Work Context
	// unverified: the authority did not check this call, or refused it.
	// False, they are the identity the authority checked.
	Claimed bool
	// ByAuthority says the authority answered the check and the refusal is
	// its own, passed on: the authority decided it and tells its own host
	// (authority.Config.Decisions). Every other refusal is the hop's, made
	// without the authority, which hears of it from nobody else.
	ByAuthority bool
}

// Sink receives each refusal a face makes, on the refused call's context.
type Sink func(ctx context.Context, r Refusal)

// refused tells a face's refusal of the call to method: to the log, when
// logged (the refusals the log was always told, by the line it was always
// told them), and to the sink, every one. d is the decision as far as it
// got: the checked identity of a call refused after its admission, the
// module and whose refusal it is of one refused before.
func refused(ctx context.Context, log func(method string, err error), sink Sink, logged bool, method string, md metadata.MD, d decide.Decision, err error) {
	if logged && log != nil {
		log(method, err)
	}
	if sink == nil {
		return
	}
	st := status.Convert(err)
	r := Refusal{Method: method, Code: st.Code(), Reason: st.Message(), Module: cmp.Or(d.Module, d.Addressed), ByAuthority: d.Answered}
	if id := d.Identity; id.Owner != "" {
		r.Organization, r.Owner, r.Actor, r.Binding, r.Task = id.Tenant, id.Owner, id.Owner, id.Binding, id.Task
		if len(id.Actors) > 0 {
			r.Actor = id.Actors[len(id.Actors)-1]
		}
	} else if tokens := md.Get(hop.WorkContextKey); len(tokens) == 1 {
		// Read, not verified: enough to say which call was refused, and
		// marked as no more than that.
		if decoded, derr := workcontext.Decode(tokens[0]); derr == nil {
			id := hop.IdentityOf(decoded.Context())
			r.Organization, r.Owner, r.Actor, r.Binding, r.Task, r.Claimed = id.Tenant, id.Owner, id.Owner, id.Binding, id.Task, true
			if len(id.Actors) > 0 {
				r.Actor = id.Actors[len(id.Actors)-1]
			}
			if r.Module == "" {
				r.Module = decoded.Context().GetAudience()
			}
		}
	}
	sink(ctx, r)
}
