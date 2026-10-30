"""Copilot chat must reach the note library without a pinned target (2026-10-30).

Measured on a console-only rehearsal (the mode this feature exists for): in copilot
mode the operator has no target and writes plain questions, so
``_chat_playbook_brief`` produced no queries at all -- four typical questions
(盲水印 / [隐写] / CRC32 / usb.capdata) returned ``matches=0`` and the library was
unreachable exactly where it matters. An explicit ``[隐写]`` label did not help
either: one token fails the lookup's overlap floor.

These tests pin the three decisions that fix it:

* a closed technique vocabulary supplies the query (so a pasted dump cannot invent
  one -- the 2026-10-10 ransomware failure);
* ASCII needles are word-bounded (``lsb`` must not fire inside another word);
* drafts are visible here, because the brief prints ✅/📝 per note and the top hit
  for a real CRC32 question *is* a draft.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent import playbook as pb
from vulnclaw.agent.core import AgentCore, _chat_topic_query
from vulnclaw.config.settings import load_config

STEPS = (
    "LOCK: something concrete and long enough to pass the quality gate.\n"
    "CONFIRMED: witnessed in evidence.\n"
    "ANGLES: [hit] one angle.\n"
    "STEPS: do the thing."
)


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(pb, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(pb, "PLAYBOOKS_DIR", tmp_path / "playbooks")
    pb.ensure_dirs()
    return tmp_path / "playbooks"


def _write(slug: str, fingerprint: str, status: str = "validated") -> None:
    block = [
        "---",
        f"name: {slug}",
        f"fingerprint: {fingerprint}",
        f"status: {status}",
        f"source: {pb.SOURCE_CURATED}",
        "---",
        "",
        STEPS,
        "",
    ]
    (pb.PLAYBOOKS_DIR / f"{slug}.md").write_text("\n".join(block), encoding="utf-8")


# ── the vocabulary itself ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text,needle",
    [
        ("盲水印：两张图看着一样", "盲水印"),
        ("这个 pcap 里 usb.capdata 怎么还原鼠标", "usb.capdata"),
        ("CRC32 压缩包怎么爆破", "CRC32"),
        ("提示词注入怎么打", "prompt injection"),
    ],
)
def test_topic_query_names_the_technique(text, needle):
    assert needle in _chat_topic_query(text)


@pytest.mark.parametrize("text", ["今天天气不错", "帮我看看这个日志", "", "the clsbase test"])
def test_topic_query_stays_empty_for_chatter(text):
    """No technique named -> no query. A pasted dump must not invent a topic."""
    assert _chat_topic_query(text) == ""


def test_ascii_needle_is_word_bounded():
    assert _chat_topic_query("the clsbase field") == ""
    assert "LSB" in _chat_topic_query("try lsb first")


# ── the path that was measurably broken ───────────────────────────────────


def test_chat_brief_reaches_notes_without_a_target(store):
    """No target, plain question -> the note arrives without any label."""
    _write("crc32-note", "CRC32 压缩包 zip 密码 字典 爆破 crc")
    core = AgentCore(load_config(), None)

    brief, matches = core._chat_playbook_brief("", "CRC32 压缩包怎么爆破")

    assert matches, "library unreachable for a plain copilot question"
    assert any(m["slug"] == "crc32-note" for m in matches), matches
    assert "crc32-note" in brief


def test_chat_brief_sees_drafts(store):
    """The top hit for a real question can be a draft; the brief marks it 📝."""
    _write("draft-note", "盲水印 blind watermark DFT fft 镜像 置换", status="draft")
    core = AgentCore(load_config(), None)

    brief, matches = core._chat_playbook_brief("", "盲水印两张图看着一样怎么取 flag")

    assert matches and matches[0]["slug"] == "draft-note", matches
    assert "📝 draft" in brief


def test_chat_brief_stays_silent_for_a_chatty_message(store):
    _write("unrelated-note", "Kubernetes RBAC 权限 提升 集群")
    core = AgentCore(load_config(), None)

    brief, matches = core._chat_playbook_brief("", "今天天气不错，随便聊聊")

    assert matches == [] and brief == ""


# ── copilot mode offers no tools at all (2026-10-30) ─────────────────────
#
# The docstring always claimed "copilot mode tells the agent not to call tools", but
# `call_llm` built the tool schemas regardless: piping a question into copilot.sh
# produced a refused `shell_command` instead of advice, because a non-interactive
# channel has no approval channel. These pin both directions.


def test_copilot_chat_offers_no_tools(monkeypatch):
    import asyncio

    monkeypatch.setenv("VULNCLAW_REPL_NO_AUTO", "1")
    captured = {}

    async def fake_call_llm(agent, system_prompt, *, stream_sink=None, offer_tools=True):
        captured["offer_tools"] = offer_tools
        return "advice only"

    monkeypatch.setattr("vulnclaw.agent.core.call_llm", fake_call_llm, raising=True)
    core = AgentCore(load_config(), None)
    result = asyncio.run(core.chat("两张图看着一样，怎么取 flag？"))

    assert captured["offer_tools"] is False
    assert result.output == "advice only"


def test_normal_chat_still_offers_tools(monkeypatch):
    import asyncio

    monkeypatch.delenv("VULNCLAW_REPL_NO_AUTO", raising=False)
    captured = {}

    async def fake_call_llm(agent, system_prompt, *, stream_sink=None, offer_tools=True):
        captured["offer_tools"] = offer_tools
        return "ok"

    monkeypatch.setattr("vulnclaw.agent.core.call_llm", fake_call_llm, raising=True)
    core = AgentCore(load_config(), None)
    asyncio.run(core.chat("看一下这个 target"))

    assert captured["offer_tools"] is True


# ── attachment work needs chat WITH tools (2026-10-31) ───────────────────
#
# Copilot's no-tools rule makes "advice only" true, but an attachment challenge
# needs the agent to READ the file. The two properties must be separate knobs:
# VULNCLAW_REPL_NO_AUTO still means "single turn, no auto loop", while
# VULNCLAW_CHAT_TOOLS=1 restores the tool schemas.


def test_chat_tools_switch_restores_tools_in_copilot(monkeypatch):
    import asyncio

    monkeypatch.setenv("VULNCLAW_REPL_NO_AUTO", "1")
    monkeypatch.setenv("VULNCLAW_CHAT_TOOLS", "1")
    captured = {}

    async def fake_call_llm(agent, system_prompt, *, stream_sink=None, offer_tools=True):
        captured["offer_tools"] = offer_tools
        return "read the file"

    monkeypatch.setattr("vulnclaw.agent.core.call_llm", fake_call_llm, raising=True)
    core = AgentCore(load_config(), None)
    asyncio.run(core.chat("看看 /root/a.png 里有什么"))

    assert captured["offer_tools"] is True


def test_chat_tools_switch_does_not_enable_the_auto_loop(monkeypatch):
    """NO_AUTO must still win: a paste must not re-enter the autonomous solve loop."""
    from vulnclaw.agent.core import _chat_tools_allowed, _copilot_pins_target

    monkeypatch.setenv("VULNCLAW_REPL_NO_AUTO", "1")
    monkeypatch.setenv("VULNCLAW_CHAT_TOOLS", "1")
    assert _copilot_pins_target() is True
    assert _chat_tools_allowed() is True
