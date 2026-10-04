"""CJK recall: Chinese fingerprints and queries must participate in recall.

Systemic defect measured 2026-10-04: ``_tokenize`` kept only ``[a-z0-9]+``, so
every CJK character was dropped — a Chinese fingerprint tokenized to an empty
set and a pure-Chinese query scored 0 against every note. The playbook store
was structurally dead for Chinese even though the agent writes and queries
notes in Chinese all the time (the ten-drill checklist was unfindable by its
own checklist queries).
"""

from __future__ import annotations

import pytest

from vulnclaw.agent import playbook as pb


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(pb, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(pb, "PLAYBOOKS_DIR", tmp_path / "playbooks")
    pb.ensure_dirs()
    return tmp_path / "playbooks"


class TestTokenizeCjk:
    def test_cjk_runs_become_bigrams(self):
        assert pb._tokenize("应急响应") == {"应急", "急响", "响应"}

    def test_mixed_script_fingerprint_has_both(self):
        tokens = pb._tokenize("排查 webshell 后门")
        assert {"webshell", "排查", "后门"} <= tokens
        assert "b" not in tokens  # single ASCII letters still dropped

    def test_ascii_tokenization_unchanged(self):
        assert pb._tokenize("Weblogic uddiexplorer") == {"weblogic", "uddiexplorer"}

    def test_lone_ideograph_kept_as_unigram(self):
        assert pb._tokenize("查") == {"查"}

    def test_pure_chinese_query_is_no_longer_empty(self):
        assert pb._tokenize("勒索病毒 解密 密钥") != set()


class TestScoreCjk:
    def _note(self, fingerprint: str) -> pb.Playbook:
        return pb.Playbook(
            slug="test-note",
            name="test note",
            fingerprint=fingerprint,
            status="validated",
        )

    def test_chinese_query_scores_against_chinese_fingerprint(self):
        note = self._note("Linux 服务器 应急响应 排查 持久化 后门 挖矿木马")
        # score = share of QUERY tokens found in the note
        assert note.score("应急响应 持久化 排查") > 0.5
        assert note.score("勒索病毒 加密") == 0.0

    def test_unrelated_chinese_query_scores_zero(self):
        note = self._note("Linux 服务器 应急响应 排查 持久化")
        assert note.score("股票行情 天气预报") == 0.0


class TestLookupCjk:
    def test_pure_chinese_query_finds_the_note(self, store):
        self._write_playbook(
            store,
            slug="ir-checklist-test",
            name="IR 通用排查清单",
            fingerprint="Linux 服务器 应急响应 排查 持久化 后门 挖矿木马 勒索病毒 webshell 流量劫持",
        )
        hits = pb.lookup_playbook("应急响应 持久化 排查", limit=3)
        assert hits, "pure-Chinese query must recall the Chinese-fingerprint note"
        assert "排查清单" in hits[0]["name"] or "排查清单" in str(hits[0])

    def test_mixed_query_finds_the_note(self, store):
        self._write_playbook(
            store,
            slug="ir-checklist-mixed",
            name="IR checklist 排查",
            fingerprint="应急响应 排查清单 persistence webshell 后门 持久化",
        )
        hits = pb.lookup_playbook("persistence 持久化 排查", limit=3)
        assert hits and "排查" in str(hits[0])

    @staticmethod
    def _write_playbook(store, *, slug: str, name: str, fingerprint: str) -> None:
        block = [
            "---",
            f"name: {name}",
            f"fingerprint: {fingerprint}",
            "status: validated",
            f"updated_at: 2026-10-04T00:00:00+00:00",
            "---",
            "",
            "1) step one.",
            "",
        ]
        (store / f"{slug}.md").write_text("\n".join(block), encoding="utf-8")
