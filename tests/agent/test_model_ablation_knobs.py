"""两个"面向模型"的消融开关：默认开启，关闭后只影响模型可见面。

存在的理由是可测量性：2026-09-19 与当前版本的 A/B 显示，当前版本在 3/3 同样解出的
前提下多花 1.8 倍工具调用、2.3 倍时长，而"推理图仪式"是嫌疑之一。要判定这个嫌疑，
必须能单独关掉它，并且保证关掉后**只有模型可见面**变化：

* 13 个 blackboard_* 工具从工具表消失；
* 系统提示里的 Blackboard / LOCK-ANGLES-TENSION 段消失；
* 运行时黑板对象、自动笔记（capture_run_notes）、停滞守卫**照旧**——
  否则量到的就不是"仪式的成本"，而是"功能被拆掉后的成本"。
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.agent import solver
from vulnclaw.agent.blackboard import Blackboard, reasoning_graph_enabled
from vulnclaw.agent.builtin_tools import build_openai_tools
from vulnclaw.config import settings as settings_module


def _cfg(
    *,
    reasoning: bool = True,
    tool_card: bool = True,
    legacy_names: bool = False,
    gcs_legacy: bool = False,
):
    """A stand-in for the real config, with EVERY section the switches read.

    `competition`/`gcs`/`platforms` are here because the per-turn schema path reads its four
    gates out of them: a config object that lacks a section is legitimately "cannot answer"
    and falls back to the file, which would make the no-file-read assertions below pass for
    the wrong reason.
    """
    return SimpleNamespace(
        session=SimpleNamespace(
            reasoning_graph_enabled=reasoning, tool_card_enabled=tool_card
        ),
        competition=SimpleNamespace(expose_legacy_tool_names=legacy_names),
        gcs=SimpleNamespace(tools_enabled=gcs_legacy),
        platforms=SimpleNamespace(),
    )


@pytest.fixture()
def config_switch(monkeypatch):
    """Point every config read at a stub so the test never touches the real file."""

    def install(*, reasoning: bool, tool_card: bool):
        monkeypatch.setattr(
            settings_module,
            "load_config",
            lambda: _cfg(reasoning=reasoning, tool_card=tool_card),
        )

    return install


def _names(tools: list[dict]) -> list[str]:
    return [t["function"]["name"] for t in tools]


def test_reasoning_graph_defaults_on(config_switch):
    config_switch(reasoning=True, tool_card=True)
    assert reasoning_graph_enabled() is True
    names = _names(build_openai_tools(None))
    assert any(n.startswith("blackboard_") for n in names)


def test_reasoning_graph_off_hides_the_whole_tool_family(config_switch):
    config_switch(reasoning=False, tool_card=True)
    names = _names(build_openai_tools(None))
    assert not [n for n in names if n.startswith("blackboard_")], names
    # Everything else must survive: this knob removes one feature, not the face.
    for keep in ("python_execute", "shell_command", "evidence_list", "lookup_playbook"):
        assert keep in names


def test_reasoning_graph_fails_open(monkeypatch):
    def boom():
        raise RuntimeError("config exploded")

    monkeypatch.setattr(settings_module, "load_config", boom)
    assert reasoning_graph_enabled() is True, "a config error must not strip the tool face"


def test_runtime_blackboard_still_exists_when_the_model_face_is_off(config_switch):
    """Auto-capture and the stall guard read the runtime board, so it must stay."""
    config_switch(reasoning=False, tool_card=False)
    board = Blackboard()
    node = board.create_fact("a fact the run produced without the ceremony")
    assert board.get_node(node.id) is not None
    assert board.confirmed_facts() == []


class TestTheSwitchesPreferTheRuntimeConfig:
    """Round8 L4: the file was re-read per call while its sibling switch read the object.

    `builtin_tools._scratch_dir_if_configured` (same commit, `session.solve_work_root`) reads
    `agent.config`; these two switches called `load_config()` instead, and they sit on the
    per-turn path (`build_openai_tools` every turn, `_system_prompt` every round). So the
    file was parsed repeatedly, and an edit made mid-run changed a setting the run had
    already acted on -- two switches of the same kind disagreeing about their source.
    """

    def _recording_load(self, monkeypatch, *, reasoning: bool, tool_card: bool):
        """Count file reads (and who made them) while answering the OPPOSITE of the object."""
        import inspect

        calls: list[str] = []
        file_cfg = _cfg(reasoning=not reasoning, tool_card=not tool_card)

        def fake_load():
            caller = "?"
            for frame in inspect.stack()[1:]:
                module = frame.frame.f_globals.get("__name__", "")
                if module.startswith("vulnclaw") and "settings" not in module:
                    caller = f"{module}.{frame.function}"
                    break
            calls.append(caller)
            return file_cfg

        monkeypatch.setattr(settings_module, "load_config", fake_load)
        return calls

    def test_the_reasoning_switch_reads_the_object_and_not_the_file(self, monkeypatch):
        calls = self._recording_load(monkeypatch, reasoning=False, tool_card=True)
        config = _cfg(reasoning=False, tool_card=True)

        assert reasoning_graph_enabled(config) is False, (
            "the runtime object must win -- the file says the opposite here"
        )
        assert calls == [], "the config file must not be re-read when the object answers"

    def test_the_tool_card_switch_reads_the_object_and_not_the_file(self, monkeypatch):
        calls = self._recording_load(monkeypatch, reasoning=True, tool_card=False)
        agent = SimpleNamespace(config=_cfg(reasoning=True, tool_card=False))

        assert solver._tool_card_enabled(agent) is False
        assert calls == []

    def test_the_solver_switch_forwards_the_agents_config(self, monkeypatch):
        calls = self._recording_load(monkeypatch, reasoning=False, tool_card=True)
        agent = SimpleNamespace(config=_cfg(reasoning=False, tool_card=True))

        assert solver._reasoning_graph_enabled(agent) is False
        assert calls == []

    def test_a_runtime_config_that_cannot_answer_still_falls_back_to_the_file(
        self, config_switch
    ):
        """A config object without `session` (many tests, and older callers) is unknowable."""
        config_switch(reasoning=False, tool_card=False)
        assert reasoning_graph_enabled(SimpleNamespace(safety=SimpleNamespace())) is False
        assert solver._tool_card_enabled(SimpleNamespace(config=SimpleNamespace())) is False

    def test_no_config_at_all_still_falls_back_to_the_file(self, config_switch):
        config_switch(reasoning=False, tool_card=False)
        assert reasoning_graph_enabled() is False
        assert solver._tool_card_enabled() is False

    def test_the_tool_schema_path_reads_no_config_file_at_all(self, monkeypatch):
        """`build_openai_tools` runs every turn: it must not parse the config file there.

        Measured before this fix, with the runtime config already supplied: FIVE reads per
        call -- the ablation switch plus `ctf2_tools_enabled`, `gcs_tools_enabled` and
        `registry._config_enabled` (twice, once per `configured_adapters()` probe). They are
        all threaded now, and the count is zero; the `config=None` shape below still falls
        back to the file exactly once per switch, which is what callers without a runtime
        object need.
        """
        calls = self._recording_load(monkeypatch, reasoning=False, tool_card=True)
        names = _names(build_openai_tools(None, config=_cfg(reasoning=False, tool_card=True)))
        assert not [n for n in names if n.startswith("blackboard_")], names
        assert calls == [], f"the per-turn schema path re-read the config file: {calls}"

    def test_without_a_runtime_config_the_file_is_still_read(self, monkeypatch):
        """The fallback is the whole reason the parameter is optional."""
        calls = self._recording_load(monkeypatch, reasoning=True, tool_card=True)
        build_openai_tools(None)
        assert calls, "a caller with no runtime config must still get an answer"


def test_prompt_block_is_omitted_when_disabled(config_switch, monkeypatch):
    agent = SimpleNamespace(
        context=SimpleNamespace(state=SimpleNamespace(target="http://example.com")),
        runtime=SimpleNamespace(blackboard=Blackboard(), prior_playbook_brief=""),
        session_state=SimpleNamespace(task_constraints=None, target="http://example.com"),
        config=SimpleNamespace(safety=SimpleNamespace(python_execute_enabled=True)),
        active_role=None,
    )
    state = SimpleNamespace(
        goal="capture the flag", origin="http://example.com", correction_hints=[],
        compact_summary="", steps=[], evidence=[],
    )

    config_switch(reasoning=True, tool_card=True)
    on = solver._system_prompt(agent, state)
    assert "# Blackboard" in on and "blackboard_set_lock" in on

    config_switch(reasoning=False, tool_card=True)
    off = solver._system_prompt(agent, state)
    assert "# Blackboard" not in off
    assert "blackboard_set_lock" not in off
    assert len(off) < len(on), "hiding the block must also shrink the prompt"
