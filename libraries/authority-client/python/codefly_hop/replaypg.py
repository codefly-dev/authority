"""Async hop admission reservations in the consuming module's Postgres.

This is the Python counterpart of ``libraries/hop/go/replaypg``, using the
asyncpg pool interface. It shares the same table and nonce namespace with Go.
The consumer owns migrations, the pool and its timeouts, readiness and closure,
and schedules ``collect``. No connection or credential is resolved here.

The async implementation follows Model Gateway's original admission adapter
(https://github.com/obin-ai/module-model-gateway/pull/216); replay semantics now live with the
authority library. Use with ``Verifier.admit_async``, not synchronous admission.
"""

from datetime import UTC, datetime

from .call import Expired, Replayed


MIGRATION = """CREATE TABLE IF NOT EXISTS hop_admissions (
\tnonce TEXT PRIMARY KEY,
\tretain_until TIMESTAMPTZ NOT NULL,
\tactive BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS hop_admissions_retain_until ON hop_admissions (retain_until);"""

# Reserve's clock check and insert are not one instant. Keep the same margin
# as Go so a concurrent collection cannot revive a nonce near its expiry.
COLLECT_MARGIN_S = 60

_RESERVE = """WITH reserved AS (
    INSERT INTO hop_admissions (nonce, retain_until, active)
    SELECT $1, $2::timestamptz, TRUE WHERE $2::timestamptz > clock_timestamp()
    ON CONFLICT (nonce) DO NOTHING
    RETURNING nonce)
SELECT CASE WHEN EXISTS (SELECT 1 FROM reserved) THEN 'reserved'
    WHEN $2::timestamptz > clock_timestamp() THEN 'replayed'
    ELSE 'expired' END"""


class Store:
    """Async reservation store shared by every replica using the same database.

    ``pool`` supplies asyncpg's awaited ``execute`` and ``fetchval`` methods.
    Each operation must commit before returning; do not pass a connection held
    inside a caller's uncommitted transaction. Backend failures propagate to the
    verifier, which refuses admission with ``stamp_store``.
    """

    shared = True

    def __init__(self, pool):
        if pool is None:
            raise ValueError("hop replay: a Postgres replay store needs a connection pool")
        self._pool = pool

    async def reserve_async(self, nonce: str, retain_until: int) -> None:
        """Reserve once, or raise Replayed / Expired on the database's clock."""
        if not nonce:
            raise ValueError("hop replay: a reservation needs a nonce")
        outcome = await self._pool.fetchval(
            _RESERVE, nonce, datetime.fromtimestamp(retain_until, UTC)
        )
        if outcome == "reserved":
            return
        if outcome == "replayed":
            raise Replayed()
        if outcome == "expired":
            raise Expired()
        raise RuntimeError("hop replay: unexpected reservation outcome")

    async def finish_async(self, nonce: str) -> None:
        """Mark work finished without deleting or reopening its reservation."""
        await self._pool.execute(
            "UPDATE hop_admissions SET active = FALSE WHERE nonce = $1", nonce
        )

    async def consume_async(self, nonce: str, retain_until: int) -> None:
        """Consume without a hold; the verifier checks late completion itself."""
        if not nonce:
            raise ValueError("hop replay: a reservation needs a nonce")
        status = await self._pool.execute(
            "INSERT INTO hop_admissions (nonce, retain_until) VALUES ($1, $2) "
            "ON CONFLICT (nonce) DO NOTHING",
            nonce,
            datetime.fromtimestamp(retain_until, UTC),
        )
        if status == "INSERT 0 0":
            raise Replayed()

    async def collect(self) -> int:
        """Collect crashed or finished holds a margin past their retention."""
        status = await self._pool.execute(
            "DELETE FROM hop_admissions WHERE retain_until < now() - make_interval(secs => $1)",
            float(COLLECT_MARGIN_S),
        )
        return int(status.rsplit(" ", 1)[-1])
