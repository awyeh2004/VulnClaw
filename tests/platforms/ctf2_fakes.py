"""A fake CTF2 client, shared by the adapter tests and the CLI integration test.

Lives in its own module rather than inside one test file so a second test module can
use it without importing from another test module (which makes collection order and
duplicate module names a hazard).

The point of the fake is that it returns **recorded real payloads** (see
``ctf2_payloads``) rather than invented ones: the CTF2 shapes differ from the obvious
guess in ways a made-up sample does not reproduce -- four field names were wrong in
exactly that way.
"""

from __future__ import annotations


class FakeClient:
    """Every CTF2 client method the adapter uses, backed by canned payloads.

    ``FakeClient(read_challenge=PAYLOAD, submit_flag=PAYLOAD, ...)``; anything not
    supplied returns an empty list envelope so list-shaped calls stay harmless.
    """

    def __init__(self, **payloads):
        self.payloads = payloads
        self.calls: list[tuple] = []
        self._session = payloads.pop("session", "token")

    def is_configured(self) -> bool:
        return True

    def session_token(self) -> str:
        return self._session

    async def _get(self, name, *args, **kwargs):
        self.calls.append((name, args))
        return self.payloads.get(name, {"data": []})

    async def list_practice(self, limit=50):
        return await self._get("list_practice")

    async def list_daily(self, limit=50):
        return await self._get("list_daily")

    async def list_competitions(self, limit=50):
        return await self._get("list_competitions")

    async def list_stage_challenges(self, stage_id, limit=100):
        return await self._get("list_stage_challenges", stage_id)

    async def list_practice_challenges(self, practice_id, page=1, page_size=100):
        return await self._get("list_practice_challenges", practice_id)

    async def read_challenge(self, pid, cid):
        return await self._get("read_challenge", pid, cid)

    async def start_environment(self, pid, cid):
        return await self._get("start_environment", pid, cid)

    async def get_target(self, pid, cid):
        return await self._get("get_target", pid, cid)

    async def stop_target(self, pid, cid):
        return await self._get("stop_target", pid, cid)

    async def submit_flag(self, pid, cid, flag):
        self.calls.append(("submit_flag", (pid, cid, flag)))
        return self.payloads.get("submit_flag", {"data": {"accepted": True}})

    async def list_submissions(self, limit=20):
        return await self._get("list_submissions")


__all__ = ["FakeClient"]
