"""The shared httpx client must not outlive the event loop it was built on.

Measured on the real product path: a CTF2 solve run had every platform tool call
fail with ``Event loop is closed``, followed by 30s ``PoolTimeout`` on every later
call, because the module-level AsyncClient had been created inside an earlier
``asyncio.run()`` and was then reused from the agent's own loop. The platform tool
face was completely unusable, and the agent had no way to tell why.

A read-only probe does NOT catch this -- it stays inside one loop, which is why it
looked healthy right up until the agent ran.
"""

from __future__ import annotations

import asyncio

import pytest

from vulnclaw.ctf_platform import client as ctf2_client
from vulnclaw.gcs_platform import client as gcs_client


@pytest.fixture(autouse=True)
def _forget_cached_clients():
    for module in (ctf2_client, gcs_client):
        module._client = None
        module._client_loop = None
    yield
    for module in (ctf2_client, gcs_client):
        module._client = None
        module._client_loop = None


async def _grab(module):
    return module.get_client()


class TestClientFollowsTheEventLoop:
    def test_a_second_event_loop_gets_a_fresh_client(self):
        """This is the regression: the old code handed back a dead-loop client."""
        first = asyncio.run(_grab(ctf2_client))
        second = asyncio.run(_grab(ctf2_client))
        assert first is not second

    def test_within_one_loop_the_client_is_reused(self):
        async def twice():
            return ctf2_client.get_client(), ctf2_client.get_client()

        one, two = asyncio.run(twice())
        assert one is two

    def test_gcs_client_has_the_same_guarantee(self):
        first = asyncio.run(_grab(gcs_client))
        second = asyncio.run(_grab(gcs_client))
        assert first is not second

    def test_the_loop_is_remembered_alongside_the_client(self):
        asyncio.run(_grab(ctf2_client))
        assert ctf2_client._client_loop is not None

    def test_outside_any_loop_a_client_is_still_usable(self):
        """CLI helpers call these synchronously; that must not explode."""
        assert ctf2_client.get_client() is not None
