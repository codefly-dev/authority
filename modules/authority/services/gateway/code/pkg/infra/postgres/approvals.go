// Package postgres is the gateway's state in the module's own store
// (services/store), reached as the runtime role app_authority: it may read,
// record and revoke approvals, and nothing else (the store's migration 1).
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"gateway/pkg/business/state"
)

// Approvals keeps consent in the store's `approvals` table, one row per
// (installation, policy, digest), so a restart of the gateway still answers a
// run. A revoked row stays, marked: nothing here deletes.
type Approvals struct {
	pool *pgxpool.Pool
}

// NewApprovals wraps a pool connected as the runtime read-write principal.
func NewApprovals(pool *pgxpool.Pool) *Approvals { return &Approvals{pool: pool} }

var _ state.Approvals = (*Approvals)(nil)

const columns = `id, installation, policy, digest, revision, revoked`

// Approve records consent, or answers the approval already standing for the
// same artifact: one statement, so two people approving at once agree on one
// row. The conflict branch changes nothing and returns what stands.
func (a *Approvals) Approve(ctx context.Context, installation, policy, digest string, revision int64) (state.Approval, error) {
	approval, err := scan(a.pool.QueryRow(ctx, `INSERT INTO approvals (id, installation, policy, digest, revision)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (installation, policy, digest) DO UPDATE SET revision = approvals.revision
		RETURNING `+columns, uuid.NewString(), installation, policy, digest, revision))
	if err != nil {
		return state.Approval{}, fmt.Errorf("postgres: recording consent: %w", err)
	}
	if approval.Revoked {
		return state.Approval{}, fmt.Errorf("%w: this artifact's approval was revoked for %s", state.ErrForbidden, installation)
	}
	return approval, nil
}

// Standing answers the approval of the artifact for a run, or refuses.
func (a *Approvals) Standing(ctx context.Context, installation, policy, digest string) (state.Approval, error) {
	approval, err := scan(a.pool.QueryRow(ctx, `SELECT `+columns+` FROM approvals
		WHERE installation = $1 AND policy = $2 AND digest = $3 AND NOT revoked`, installation, policy, digest))
	if errors.Is(err, pgx.ErrNoRows) {
		return state.Approval{}, fmt.Errorf("%w: no approval stands for this artifact at %s", state.ErrForbidden, installation)
	}
	if err != nil {
		return state.Approval{}, fmt.Errorf("postgres: reading consent: %w", err)
	}
	return approval, nil
}

// Revoke withdraws an approval, permanently; the row stays, marked, with the
// first revocation's time.
func (a *Approvals) Revoke(ctx context.Context, installation, policy, id string) (state.Approval, error) {
	approval, err := scan(a.pool.QueryRow(ctx, `UPDATE approvals
		SET revoked = true, revoked_at = COALESCE(revoked_at, now())
		WHERE id = $1 AND installation = $2 AND policy = $3
		RETURNING `+columns, id, installation, policy))
	if errors.Is(err, pgx.ErrNoRows) {
		return state.Approval{}, fmt.Errorf("%w: approval %q is not one of %s's under %s", state.ErrUnknown, id, installation, policy)
	}
	if err != nil {
		return state.Approval{}, fmt.Errorf("postgres: revoking consent: %w", err)
	}
	return approval, nil
}

func scan(row pgx.Row) (state.Approval, error) {
	var a state.Approval
	err := row.Scan(&a.ID, &a.Installation, &a.Policy, &a.Digest, &a.Revision, &a.Revoked)
	return a, err
}
