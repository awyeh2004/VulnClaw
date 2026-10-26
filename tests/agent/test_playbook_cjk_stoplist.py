"""CJK template-bigram stop list (audit item D, 2026-10-24).

Measured failure being pinned: an IR checklist note scored 0.231 against an
unrelated router-config challenge because the two shared nothing except the
template boilerplate bigrams (提交/得到/题目/证据…) that appear in >=10% of
the real store (17 bigrams, measured 2026-10-24). The stop list removes those
from scoring; the discriminative bigrams (69% of the store's bigrams are
unique to one note) are untouched, and the unfiltered rescue path survives.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent import playbook as pb
from vulnclaw.agent.playbook import _CJK_STOP, _cjk_signal_tokens, _tokenize


@pytest.fixture()
def tmp_playbooks(monkeypatch, tmp_path):
    d = tmp_path / "playbooks"
    d.mkdir()
    monkeypatch.setattr(pb, "PLAYBOOKS_DIR", d)
    return d


def _save(tmp_playbooks, name: str, fingerprint: str) -> None:
    ack = pb.save_playbook(
        name=name,
        fingerprint=fingerprint,
        steps=(
            "## LOCK\n模板笔记，仅用于停用词回归测试的填充内容。\n"
            "## CONFIRMED\n- 提交得到记录确认（模板句）\n"
            "## ANGLES\n- [A1] 检查文件数据（模板句）\n"
            "- [A2] 更多填充行以满足最短长度要求"
        ),
    )
    assert ack.get("slug"), ack


class TestTokenize:
    def test_stop_bigrams_are_dropped_from_scoring(self):
        tokens = _tokenize("应急响应排查：提交得到题目证据确认")
        assert {"应急", "响应", "排查"} <= tokens
        assert not ({"提交", "得到", "题目", "证据", "确认"} & tokens)

    def test_every_stop_entry_actually_stops(self):
        for bigram in _CJK_STOP:
            assert _cjk_signal_tokens(bigram) == set(), bigram

    def test_rescue_path_keeps_unfiltered_bigrams(self):
        """A body whose only tokens are stopped must stay findable by raw text."""
        tokens = _tokenize("http://提交/")
        assert "提交" in tokens

    def test_discriminative_bigrams_survive(self):
        tokens = _tokenize("荷兰宽带数据泄露事件")
        assert {"荷兰", "宽带", "泄露"} <= tokens


class _RouterVsChecklist:
    """The measured injection scenario, both directions.

    Note A: IR checklist written in the standard capture template -- its
    fingerprint is dominated by the same boilerplate every captured note
    carries (提交/得到/题目/证据/注意/记录/文件/返回/确认…).
    Query B: a router-config decryption challenge whose goal text repeats the
    same boilerplate words but shares NO substantive token with the checklist.
    """


def _checklist_fingerprint() -> str:
    # Boilerplate words separated the way real captured notes separate them
    # (punctuation/space), so the only shared tokens are the stop bigrams
    # themselves -- the exact shape of the measured 0.231 injection.
    return (
        "应急响应排查清单。题目：提交、得到证据。注意：记录、文件、数据、返回、"
        "字节、确认。内存镜像分析，进程排查，计划任务持久化。"
    )


def _router_query() -> str:
    # Same template boilerplate (separated), zero overlap with the checklist's
    # substance.
    return "路由器配置解密。题目：提交、得到证据。注意：记录、文件、数据、返回、确认。"


class TestMeasuredInjectionScenario:
    def test_checklist_no_longer_scores_against_router_challenge(self, tmp_playbooks):
        _save(tmp_playbooks, "ir-triage-checklist", _checklist_fingerprint())
        hits = pb.lookup_playbook(_router_query(), limit=3, min_score=0.15)
        scores = [h["score"] for h in hits if h.get("slug") == "ir-triage-checklist"]
        assert scores == [], f"checklist still injected: {scores}"

    def test_checklist_is_still_found_by_its_own_substance(self, tmp_playbooks):
        _save(tmp_playbooks, "ir-triage-checklist", _checklist_fingerprint())
        hits = pb.lookup_playbook("应急响应 内存镜像 持久化排查", limit=3, min_score=0.15)
        assert any(h.get("slug") == "ir-triage-checklist" for h in hits), hits

    def test_real_target_notes_are_still_found(self, tmp_playbooks):
        _save(tmp_playbooks, "router-config", "路由器配置解密 cisco 配置文件加密算法")
        hits = pb.lookup_playbook(_router_query(), limit=3, min_score=0.15)
        assert any(h.get("slug") == "router-config" for h in hits), hits
