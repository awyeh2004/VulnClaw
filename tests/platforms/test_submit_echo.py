"""提交结果必须回显实际提交的 flag。

实测（2026-10-19，假如给我三天光明）：三次被拒之后，run 无法判断第 1 次提交的
到底是它解码出的字符串，还是打错的一个变体 —— 平台不回显，我们的消息也不回显，
模型只好花一轮去翻证据猜"我到底发了什么"。值本来就在模型自己的工具参数里，
重复一遍不泄露任何东西，却让每次尝试都能从日志里核对。
"""

from __future__ import annotations

import pytest

from vulnclaw.platforms import tools as ptools


class _Result:
    accepted = False
    message = "flag not accepted"
    raw = {}


class _Adapter:
    async def submit_flag(self, ref, flag):
        return _Result()


class _Ref:
    def token(self):
        return "ctf2:practice:1:2"

    key = "ctf2:practice:1:2"


@pytest.mark.asyncio
async def test_the_rejection_names_the_submitted_value(monkeypatch):
    monkeypatch.setattr(ptools, "_flag_submission_enabled", lambda: True)

    class _Guard:
        def allow(self, key, text):
            return True, ""

        def record(self, key, accepted, flag):
            pass

    monkeypatch.setattr(ptools, "get_guard", lambda: _Guard())

    out = await ptools.submit_flag_via(_Adapter(), _Ref(), "flag{abc_123}")
    assert "not accepted" in out
    assert "(submitted: flag{abc_123})" in out, out
