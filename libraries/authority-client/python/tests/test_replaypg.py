"""The public adapter's durable contract against real Postgres.

HOP_TEST_POSTGRES is an asyncpg-compatible PostgreSQL URI. Each test uses an
isolated schema in that database; CI supplies its existing local test server.
"""

import asyncio
from contextlib import asynccontextmanager
import os
from pathlib import Path
import re
import time
from uuid import uuid4

import pytest

from codefly_hop import Expired, Replayed, Unauthenticated, Verifier
from codefly_hop.replaypg import COLLECT_MARGIN_S, MIGRATION, Store
from test_hop import FIXTURE, Keys, METHOD, published


def test_migration_is_shared_with_go():
    source = (Path(__file__).parents[3] / "hop/go/replaypg/replaypg.go").read_text()
    assert MIGRATION == re.search(r"const Migration = `(.*?)`", source, re.S)[1]


def test_a_pool_is_required():
    with pytest.raises(ValueError, match="connection pool"):
        Store(None)


def test_backend_failure_refuses_admission_outside_local(monkeypatch):
    class Unavailable:
        async def fetchval(self, *args):
            raise TimeoutError("private backend diagnostic")

    monkeypatch.setenv("CODEFLY__ENVIRONMENT", "production")
    verifier = Verifier(
        Keys(published()), audience=FIXTURE["audience"],
        replay=Store(Unavailable()), now=lambda: FIXTURE["now"],
    )

    async def check():
        with pytest.raises(Unauthenticated) as caught:
            async with verifier.admit_async(FIXTURE["headers"], METHOD):
                pytest.fail("an unavailable replay store admitted a handler")
        assert caught.value.code == "stamp_store"
        assert "private" not in str(caught.value)

    asyncio.run(check())


@asynccontextmanager
async def database():
    dsn = os.environ.get("HOP_TEST_POSTGRES")
    if not dsn:
        pytest.skip("HOP_TEST_POSTGRES names no Postgres")
    # Missing test dependencies must fail when a database was selected.
    import asyncpg

    schema = "hop_test_" + uuid4().hex
    setup = await asyncpg.connect(dsn, command_timeout=5)
    pool = None
    try:
        await setup.execute(f'CREATE SCHEMA "{schema}"')
        pool = await asyncpg.create_pool(
            dsn, min_size=1, max_size=4, command_timeout=5,
            server_settings={"search_path": schema},
        )
        await pool.execute(MIGRATION)
        yield pool, dsn, schema
    finally:
        if pool is not None:
            await pool.close()
        await setup.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await setup.close()


def test_concurrent_replicas_admit_once_and_reconnection_keeps_the_nonce():
    async def check():
        async with database() as (pool, dsn, schema):
            import asyncpg

            nonce, until = "codefly-hop-v1:test-key:" + uuid4().hex, int(time.time()) + 30
            first, second = Store(pool), Store(pool)
            outcomes = await asyncio.gather(
                *(store.reserve_async(nonce, until) for store in [first, second] * 8),
                return_exceptions=True,
            )
            assert outcomes.count(None) == 1
            assert sum(isinstance(result, Replayed) for result in outcomes) == 15
            assert await pool.fetchval("SELECT active FROM hop_admissions WHERE nonce=$1", nonce)
            await first.finish_async(nonce)
            assert not await pool.fetchval("SELECT active FROM hop_admissions WHERE nonce=$1", nonce)
            with pytest.raises(Replayed):
                await second.reserve_async(nonce, until + 30)
            assert int(await pool.fetchval(
                "SELECT extract(epoch FROM retain_until) FROM hop_admissions WHERE nonce=$1", nonce
            )) == until
            # A new pool holds no process state from the admitting replica.
            replacement = await asyncpg.create_pool(
                dsn, min_size=1, max_size=1, command_timeout=5,
                server_settings={"search_path": schema},
            )
            try:
                with pytest.raises(Replayed):
                    await Store(replacement).reserve_async(nonce, until)
            finally:
                await replacement.close()

    asyncio.run(check())


def test_collection_expires_crashed_holds_without_reviving_delayed_admissions():
    async def check():
        async with database() as (pool, _, _):
            store = Store(pool)
            for nonce in ("crashed", "inside-margin", "live"):
                await store.reserve_async(nonce, int(time.time()) + 30)
            await pool.execute(
                "UPDATE hop_admissions SET retain_until=now()-make_interval(secs=>$1) WHERE nonce='crashed'",
                float(COLLECT_MARGIN_S + 1),
            )
            await pool.execute(
                "UPDATE hop_admissions SET retain_until=now()-interval '1 second' WHERE nonce='inside-margin'"
            )
            assert await store.collect() == 1
            with pytest.raises(Expired):
                await store.reserve_async("crashed", int(time.time()) - 1)
            assert await pool.fetchval("SELECT count(*) FROM hop_admissions") == 2
            # Race collection with a delayed duplicate inside the retention margin.
            for _ in range(20):
                results = await asyncio.gather(
                    store.reserve_async("inside-margin", int(time.time()) - 1),
                    store.collect(), return_exceptions=True,
                )
                assert isinstance(results[0], Expired)
                assert results[1] == 0

    asyncio.run(check())


def test_consumption_is_shared_with_reservation_and_never_refreshes_it():
    async def check():
        async with database() as (pool, _, _):
            store, until = Store(pool), int(time.time()) + 30
            await store.consume_async("consumed", until)
            with pytest.raises(Replayed):
                await store.reserve_async("consumed", until + 30)
            await store.reserve_async("reserved", until)
            with pytest.raises(Replayed):
                await store.consume_async("reserved", until + 30)
            with pytest.raises(ValueError, match="nonce"):
                await store.reserve_async("", until)
            with pytest.raises(ValueError, match="nonce"):
                await store.consume_async("", until)

    asyncio.run(check())
