from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnclaw.agent.context import SessionState
from vulnclaw.agent.prompt_context import build_round_context, generate_attack_summary
from vulnclaw.agent.reasoning_state import PathStep
from vulnclaw.agent.reflexion import FailureCategory, ReflexionEngine


@pytest.fixture(autouse=True)
def _use_chinese_by_default(i18n_language):
    i18n_language("zh")


def _fake_agent(tmp_path: Path, state: SessionState, reflexion=None):
    runtime = SimpleNamespace(
        user_vuln_hint="",
        user_vuln_hint_rounds=0,
        same_path_fail_count=0,
        python_timeout_rounds=0,
        rounds_without_progress=0,
        blocked_targets=set(),
        claimed_flag=None,
        flag_verified=False,
        is_ctf_mode=False,
        is_recon_phase=False,
        reflexion=reflexion,
    )
    session = SimpleNamespace(
        output_dir=tmp_path,
        stale_rounds_threshold=5,
        reasoning_state_enabled=True,
        reflexion_enabled=True,
    )
    return SimpleNamespace(
        context=SimpleNamespace(state=state),
        runtime=runtime,
        config=SimpleNamespace(session=session),
    )


def test_session_state_persists_reasoning(tmp_path):
    state = SessionState(target="example.com")
    state.reasoning.add_fact("framework", "thinkphp", source="fingerprint", confidence=0.8)
    state.reasoning.add_constraint("union keyword blocked", category="waf", severity="blocking")
    state.reasoning.add_path(
        "login sql injection",
        [PathStep(action="test username with quote", target="/login", vuln_type="sqli")],
        priority=5,
    )

    save_path = tmp_path / "session.json"
    state.save(save_path)

    loaded = SessionState.load(save_path)

    assert loaded.reasoning.facts[0].key == "framework"
    assert loaded.reasoning.facts[0].value == "thinkphp"
    assert loaded.reasoning.constraints[0].description == "union keyword blocked"
    assert loaded.reasoning.paths[0].name == "login sql injection"
    assert loaded.reasoning.paths[0].steps[0].action == "test username with quote"


def test_build_round_context_injects_reasoning_and_reflexion(tmp_path):
    state = SessionState(target="example.com")
    state.reasoning.add_fact("candidate", "admin search looks injectable", confidence=0.7)
    state.reasoning.add_path(
        "admin search sqli",
        [PathStep(action="verify with a boolean probe", target="/admin/search", vuln_type="sqli")],
        priority=5,
    )
    state.reasoning.set_active_path("admin search sqli")

    reflexion = ReflexionEngine()
    reflexion.record_attempt(
        path="/admin/search?q='",
        success=False,
        category=FailureCategory.PARAM_ERROR,
        details="syntax did not change the response",
        vuln_type="sqli",
    )

    context = build_round_context(_fake_agent(tmp_path, state, reflexion), 2, 5)

    assert "🧭 当前推理状态" in context
    assert "admin search looks injectable" in context
    assert "admin search sqli" in context
    assert "🔁 反思状态：" in context
    assert "/admin/search?q='" in context
    assert "当前升级级别" in context


def test_build_round_context_renders_english_runtime_labels(tmp_path, i18n_language):
    state = SessionState(target="example.com")
    state.add_step("GET /health returned 200")
    state.add_note("nginx detected")
    agent = _fake_agent(tmp_path, state)

    i18n_language("en")
    context = build_round_context(agent, 1, 5)

    assert "[Autonomous Loop Round 1/5]" in context
    assert "Current target: example.com" in context
    assert "Recent steps: 1 total" in context
    assert "Important notes: nginx detected" in context
    assert "Decide the next action based on the current state" in context
    assert "自主循环" not in context
    assert "当前目标" not in context


def test_build_round_context_preserves_chinese_runtime_labels(tmp_path):
    state = SessionState(target="example.com")
    agent = _fake_agent(tmp_path, state)

    context = build_round_context(agent, 1, 5)

    assert "[自主循环 Round 1/5]" in context
    assert "当前目标: example.com" in context
    assert "请基于当前状态和之前所有发现决定下一步操作" in context


@pytest.mark.asyncio
async def test_generate_attack_summary_requests_an_english_narrative(i18n_language):
    captured: dict = {}

    class DummyClient:
        class chat:
            class completions:
                @staticmethod
                def create(**kwargs):
                    captured.update(kwargs)
                    message = SimpleNamespace(content="English summary")
                    return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    state = SessionState(target="example.com")
    state.add_step("GET /admin")
    state.add_note("nginx detected")
    config = SimpleNamespace(
        llm=SimpleNamespace(
            model="test-model",
            max_tokens=1024,
            temperature=0.2,
            provider="openai",
            reasoning_effort=None,
        )
    )
    agent = SimpleNamespace(
        context=SimpleNamespace(state=state),
        config=config,
        _get_client=lambda: DummyClient(),
    )

    i18n_language("en")
    result = await generate_attack_summary(agent)

    prompt = captured["messages"][0]["content"]
    assert result == "English summary"
    assert "=== Executed Steps ===" in prompt
    assert "=== Key Observations / Results ===" in prompt
    assert "=== Vulnerability Findings ===" in prompt
    assert "Write a detailed attack-path narrative in English" in prompt
    assert "=== 漏洞发现 ===" not in prompt
