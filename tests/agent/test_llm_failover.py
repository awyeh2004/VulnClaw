"""Tests for multi-key failover rotation in the LLM call retry loop."""

import asyncio
import sys
from types import ModuleType, SimpleNamespace

import pytest

from vulnclaw.agent.llm_client import (
    _call_with_persistent_retries,
    _call_with_persistent_retries_unbudgeted,
    _hard_compact_messages,
    _is_key_exhausted_error,
    _is_timeout_error,
)
from vulnclaw.agent.subagent.budget import UsageBudget
from vulnclaw.agent.subagent.models import SubagentContext


class FakeAgent:
    """Minimal stand-in exposing the key-pool surface the retry loop uses."""

    def __init__(self, keys):
        self._key_pool = list(keys)
        self._key_index = 0

    def current_key(self):
        return self._key_pool[self._key_index]

    def rotate_api_key(self) -> bool:
        if len(self._key_pool) > 1:
            self._key_index = (self._key_index + 1) % len(self._key_pool)
            return True
        return False


def _ok_response():
    return SimpleNamespace(choices=[object()])


def _full_ok_response():
    message = SimpleNamespace(content="ok", tool_calls=None, reasoning_content=None)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


class TestIsKeyExhaustedError:
    def test_detects_rate_limit_and_quota_signals(self):
        for text in [
            "error code: 429 too many requests",
            "rate limit exceeded",
            "rate_limit_exceeded",
            "your quota has been exhausted",
            "deepseek: insufficient balance (402)",
            "账户余额不足",
            "code 1302 concurrency limit",
            "code 1113 balance",
        ]:
            assert _is_key_exhausted_error(text.lower()) is True, text

    def test_ignores_unrelated_errors(self):
        for text in [
            "connection reset by peer",
            "model not found",
            "invalid function arguments json string",
        ]:
            assert _is_key_exhausted_error(text.lower()) is False, text


class TestRotateApiKey:
    def test_rotate_advances_index(self):
        agent = FakeAgent(["k1", "k2"])
        assert agent.current_key() == "k1"
        assert agent.rotate_api_key() is True
        assert agent.current_key() == "k2"

    def test_rotate_single_key_is_noop(self):
        agent = FakeAgent(["only"])
        assert agent.rotate_api_key() is False
        assert agent.current_key() == "only"


class TestFailover:
    async def test_retry_reuses_one_model_token_admission(self, monkeypatch):
        from vulnclaw.agent import llm_client

        agent = FakeAgent(["only"])
        agent._subagent_ctx = SubagentContext(
            depth=1,
            next_model_token_reservation=80,
            usage_budget=UsageBudget(solve_limit=100, group_limit=100),
            task_context=SimpleNamespace(task_id="leaf", group_id="group"),
        )
        agent.config = SimpleNamespace(subagent=SimpleNamespace())
        attempts = 0

        def request_fn():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise ConnectionError("transient disconnect")
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))],
                usage=SimpleNamespace(prompt_tokens=10, completion_tokens=2),
            )

        async def no_sleep(_seconds):
            return None

        monkeypatch.setattr(llm_client.asyncio, "sleep", no_sleep)
        response, retries = await _call_with_persistent_retries(
            agent, request_fn, "test", max_retries=3
        )

        assert response.choices
        assert retries == 1
        assert attempts == 2
        assert agent._subagent_ctx.llm_requests_used == 1
        snapshot = agent._subagent_ctx.usage_budget.snapshot()
        assert snapshot["inflight_tokens"] == 0
        assert snapshot["used_total"] == 12

    async def test_failed_logical_request_charges_conservative_estimate(self, monkeypatch):
        from vulnclaw.agent import llm_client
        from vulnclaw.i18n import current_lang, init_i18n

        agent = FakeAgent(["only"])
        agent._subagent_ctx = SubagentContext(
            depth=1,
            next_model_token_reservation=80,
            usage_budget=UsageBudget(solve_limit=100, group_limit=100),
            task_context=SimpleNamespace(task_id="leaf", group_id="group"),
        )
        agent.config = SimpleNamespace(subagent=SimpleNamespace())

        async def no_sleep(_seconds):
            return None

        monkeypatch.setattr(llm_client.asyncio, "sleep", no_sleep)
        prev_lang = current_lang()
        init_i18n(lang="zh")  # error message is localized; pin Chinese
        try:
            with pytest.raises(RuntimeError, match="最大重试"):
                await _call_with_persistent_retries(
                    agent,
                    lambda: (_ for _ in ()).throw(ConnectionError("offline")),
                    "test",
                    max_retries=2,
                )
        finally:
            init_i18n(lang=prev_lang)

        snapshot = agent._subagent_ctx.usage_budget.snapshot()
        assert snapshot["inflight_tokens"] == 0
        assert snapshot["used_total"] == 80

    async def test_rotates_past_rate_limited_key(self):
        agent = FakeAgent(["bad", "good"])

        def request_fn():
            if agent.current_key() == "bad":
                raise RuntimeError("Error code: 429 - rate limit exceeded")
            return _ok_response()

        response, _ = await _call_with_persistent_retries(agent, request_fn, "test")
        assert response.choices
        assert agent.current_key() == "good"

    async def test_rotates_past_invalid_key_then_succeeds(self):
        agent = FakeAgent(["bad", "good"])

        def request_fn():
            if agent.current_key() == "bad":
                raise RuntimeError("invalid api key provided")
            return _ok_response()

        response, _ = await _call_with_persistent_retries(agent, request_fn, "test")
        assert response.choices
        assert agent.current_key() == "good"

    async def test_raises_when_all_keys_invalid(self):
        agent = FakeAgent(["bad1", "bad2"])

        def request_fn():
            raise RuntimeError("invalid api key provided")

        with pytest.raises(RuntimeError):
            await _call_with_persistent_retries(agent, request_fn, "test")

    async def test_single_key_auth_error_raises_fast(self):
        agent = FakeAgent(["only"])

        def request_fn():
            raise RuntimeError("unauthorized: invalid api key")

        with pytest.raises(RuntimeError):
            await _call_with_persistent_retries(agent, request_fn, "test")


class TestCallLlmUsesRotatedClient:
    """Regression test: call_llm/call_llm_auto must not close over a stale client.

    rotate_api_key() invalidates agent._client so the *next* _get_client() call
    rebuilds with the new key. If call_llm_auto captured `client =
    agent._get_client()` once and reused it across retries, every retry after a
    rotation would still hit the old (failed) key's client. The retry loop must
    call agent._get_client() fresh on every attempt.
    """

    async def test_call_llm_auto_retries_with_freshly_rotated_client(self, monkeypatch):
        from vulnclaw.agent import llm_client

        class DummyLoop:
            async def run_in_executor(self, executor, fn):
                return fn()

        class DummyClient:
            def __init__(self, key):
                self.key = key
                self.chat = SimpleNamespace(
                    completions=SimpleNamespace(create=self._create)
                )

            def _create(self, **kwargs):
                if self.key == "bad":
                    raise RuntimeError("Error code: 429 - rate limit exceeded")
                return _full_ok_response()

        class DummyAgent:
            _key_pool = ["bad", "good"]
            _key_index = 0

            class _Config:
                class _LLM:
                    model = "gpt-4o-mini"
                    max_tokens = 256
                    temperature = 0.1
                    provider = "openai"
                    reasoning_effort = "high"

                llm = _LLM()

            class _Context:
                @staticmethod
                def get_messages():
                    return []

                @staticmethod
                def add_assistant_message(text):
                    return None

            config = _Config()
            context = _Context()

            def _build_openai_tools(self):
                return []

            def _get_client(self):
                # Mirrors AgentCore._get_client(): reflects the *current*
                # rotation index, not whatever was current when first called.
                return DummyClient(self._key_pool[self._key_index])

            def rotate_api_key(self) -> bool:
                if len(self._key_pool) > 1:
                    self._key_index = (self._key_index + 1) % len(self._key_pool)
                    return True
                return False

        dummy = DummyAgent()
        monkeypatch.setattr(llm_client.asyncio, "get_running_loop", lambda: DummyLoop())

        result = await llm_client.call_llm_auto(dummy, "sys", "round")

        assert dummy._key_index == 1
        assert "ok" in result

    async def test_call_llm_retries_with_freshly_rotated_client(self, monkeypatch):
        from vulnclaw.agent import llm_client

        class DummyLoop:
            async def run_in_executor(self, executor, fn):
                return fn()

        class DummyClient:
            def __init__(self, key):
                self.key = key
                self.chat = SimpleNamespace(
                    completions=SimpleNamespace(create=self._create)
                )

            def _create(self, **kwargs):
                if self.key == "bad":
                    raise RuntimeError("invalid api key provided")
                return _full_ok_response()

        class DummyAgent:
            _key_pool = ["bad", "good"]
            _key_index = 0

            class _Config:
                class _LLM:
                    model = "gpt-4o-mini"
                    max_tokens = 256
                    temperature = 0.1
                    provider = "openai"
                    reasoning_effort = "high"

                llm = _LLM()

            class _Context:
                @staticmethod
                def get_messages():
                    return []

            config = _Config()
            context = _Context()

            def _build_openai_tools(self):
                return []

            def _get_client(self):
                return DummyClient(self._key_pool[self._key_index])

            def rotate_api_key(self) -> bool:
                if len(self._key_pool) > 1:
                    self._key_index = (self._key_index + 1) % len(self._key_pool)
                    return True
                return False

        dummy = DummyAgent()
        monkeypatch.setattr(llm_client.asyncio, "get_running_loop", lambda: DummyLoop())

        await llm_client.call_llm(dummy, "sys")

        assert dummy._key_index == 1


class TestAgentCoreRotation:
    def _agent(self, **llm):
        from vulnclaw.agent.core import AgentCore
        from vulnclaw.config.schema import VulnClawConfig

        config = VulnClawConfig()
        for k, v in llm.items():
            setattr(config.llm, k, v)
        return AgentCore(config)

    def test_pool_from_api_keys(self):
        agent = self._agent(api_keys=["k1", "k2"])
        assert agent._key_pool == ["k1", "k2"]
        assert agent._current_api_key() == "k1"

    def test_pool_falls_back_to_single_key(self):
        agent = self._agent(api_key="solo")
        assert agent._key_pool == ["solo"]
        assert agent.rotate_api_key() is False

    def test_rotate_advances_and_invalidates_client(self, monkeypatch):
        fake_openai = ModuleType("openai")

        class FakeOpenAI:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        fake_openai.OpenAI = FakeOpenAI
        monkeypatch.setitem(sys.modules, "openai", fake_openai)

        agent = self._agent(api_keys=["k1", "k2"])
        agent._get_client()
        assert agent._client is not None
        assert agent.rotate_api_key() is True
        assert agent._client is None
        assert agent._current_api_key() == "k2"


class TestTurnBudgetAndTimeoutLoadShedding:
    """Both features were silently inert before 2026-10-06: the wall-clock budget
    was read with a plain ``getattr`` off a schema that never defined the key, and
    ``rebuild_fn`` had no caller at all -- so neither could ever fire."""

    def test_schema_exposes_the_turn_budget_key(self):
        from vulnclaw.config.schema import SessionConfig

        assert SessionConfig().llm_turn_budget_s == 0, "0 disables the budget"

    def test_timeout_classification(self):
        assert _is_timeout_error("read timed out.") is True
        assert _is_timeout_error("apitimeouterror: request timed out") is True
        assert _is_timeout_error("stream stalled: no first token within 120s") is True
        assert _is_timeout_error("error code: 402 insufficient balance") is False

    def test_hard_compact_keeps_system_and_newest_messages(self):
        messages = [{"role": "system", "content": "sys"}] + [
            {"role": "user", "content": "x" * 4000} for _ in range(10)
        ]
        compacted = _hard_compact_messages(messages)
        assert compacted[0] is messages[0], "the system message is never dropped"
        assert compacted[-1] is messages[-1], "the newest messages survive"
        assert len(compacted) < len(messages)

    def test_hard_compact_never_splits_a_tool_exchange(self):
        """Round15b (2026-10-07) postmortem: hard compaction deleted one message
        at a time from the head, so an ``assistant(tool_calls=...)`` message
        could be dropped while the ``tool`` result answering it survived (or
        the reverse). A strict gateway rejects that payload with 400 — which is
        not a timeout — so the load-shedding ladder never retried it and the
        turn died. Deletion has to stay atomic per exchange.

        The first exchange carries a deliberately oversized assistant message so
        a 50% cut lands *between* the assistant and its tool result: against
        the old per-message loop this fixture yields an orphan ``c0``.
        """
        messages: list[dict] = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "q0"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "c0",
                        "type": "function",
                        "function": {"name": "run", "arguments": "z" * 3000},
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "c0", "content": "r0"},
        ]
        for i in (1, 2, 3):
            messages += [
                {"role": "user", "content": f"q{i}"},
                {
                    "role": "assistant",
                    "content": "a",
                    "tool_calls": [
                        {
                            "id": f"c{i}",
                            "type": "function",
                            "function": {"name": "run", "arguments": "{}"},
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": f"c{i}", "content": f"r{i}"},
            ]

        compacted = _hard_compact_messages(messages)
        assert compacted[0] is messages[0], "the system message is never dropped"
        assert len(compacted) < len(messages), "the middle must actually shrink"

        declared = {
            tc["id"] for msg in compacted for tc in (msg.get("tool_calls") or [])
        }
        orphans = [
            msg.get("tool_call_id")
            for msg in compacted
            if msg.get("role") == "tool" and msg.get("tool_call_id") not in declared
        ]
        assert orphans == [], "a tool result must not outlive the assistant that declared it"
        answered = {
            msg.get("tool_call_id") for msg in compacted if msg.get("role") == "tool"
        }
        assert declared <= answered, "a declared tool_call must be followed by its results"

    @pytest.mark.asyncio
    async def test_budget_exhaustion_raises_before_any_request(self):
        calls = {"n": 0}

        def request_fn():
            calls["n"] += 1
            return _full_ok_response()

        with pytest.raises(RuntimeError, match="turn budget"):
            await _call_with_persistent_retries_unbudgeted(
                FakeAgent([]), request_fn, "stage", budget_s=-1.0
            )
        assert calls["n"] == 0

    @pytest.mark.asyncio
    async def test_first_timeout_retries_the_same_request(self, monkeypatch):
        async def _no_sleep(_seconds):
            return None

        monkeypatch.setattr(asyncio, "sleep", _no_sleep)
        calls = {"n": 0}
        rebuilt = {"n": 0}

        def request_fn():
            calls["n"] += 1
            if calls["n"] == 1:
                raise TimeoutError("Read timed out.")
            return _full_ok_response()

        def rebuild_fn(level):
            rebuilt["n"] += 1
            return _full_ok_response

        response, _ = await _call_with_persistent_retries_unbudgeted(
            FakeAgent([]), request_fn, "stage", rebuild_fn=rebuild_fn
        )
        assert response.choices
        assert calls["n"] == 2, "one timeout, then the same request retried"
        assert rebuilt["n"] == 0, "the ladder must not fire on the first timeout"

    @pytest.mark.asyncio
    async def test_second_timeout_escalates_to_the_rebuilt_request(self, monkeypatch):
        async def _no_sleep(_seconds):
            return None

        monkeypatch.setattr(asyncio, "sleep", _no_sleep)
        good = _full_ok_response()
        levels: list[int] = []

        def timing_out():
            raise TimeoutError("Read timed out.")

        def rebuild_fn(level):
            levels.append(level)
            return lambda: good

        response, _ = await _call_with_persistent_retries_unbudgeted(
            FakeAgent([]), timing_out, "stage", rebuild_fn=rebuild_fn
        )
        assert response is good
        assert levels == [1], "the ladder fires exactly once, on the second timeout"

    def test_every_retry_call_site_wires_the_ladder(self):
        """Guards the exact gap: ``rebuild_fn`` is inert unless a caller passes it,
        and a feature that is silently inert is worse than one that is absent."""
        import inspect

        from vulnclaw.agent import llm_client

        for fn in (llm_client.call_llm, llm_client._call_llm_auto_nonstream):
            assert "rebuild_fn=" in inspect.getsource(fn), fn.__name__
