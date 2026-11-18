package hop

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	"github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A call lives no longer than the Work Context that admitted it. The stamp's
// own window (stamp.Lifetime) bounds only when an admitted call may start; a
// stream that started inside it would otherwise run for as long as both ends
// kept it open, past the context's expiry. The hop bounds every call it
// forwards at the checked context's expiry, and the module's stream
// interceptor does the same, so a long stream is opened again, and so checked
// again, on a current context.

// ErrExpired is the cause a call's context ends with when the Work Context
// that admitted it expires: Unauthenticated, with the caller-safe reason
// refusal.Expired.
var ErrExpired = fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, refusal.Expired)

// UntilExpiry bounds ctx at the instant the admitting Work Context expires.
// A context that ends for that reason reports Expired.
func UntilExpiry(ctx context.Context, expires time.Time) (context.Context, context.CancelFunc) {
	return context.WithDeadlineCause(ctx, expires, ErrExpired)
}

// Expired reports whether ctx ended because the Work Context that admitted
// its call expired, rather than because its caller ended it.
func Expired(ctx context.Context) bool {
	return ctx.Err() != nil && errors.Is(context.Cause(ctx), ErrExpired)
}

// ExpiredStatus is what a caller is told when its call ends at that expiry.
func ExpiredStatus() error {
	return status.Error(codes.Unauthenticated, ErrExpired.Error())
}
