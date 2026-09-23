"""同类题笔记复用：查询键、命中合并，以及"命中即注入 + 打进日志"。

实测依据（2026-09-23，CTF2 练习场）：

* 在 `[Weblogic]CVE-2017-10271` 上学到的笔记，对**另一个漏洞**的
  `[Weblogic]CVE-2018-2628` 只打 0.222 分，却把真正要紧的东西带过去了（暴露面、
  `ProcessBuilder` 非阻塞这个坑、flag 外带落点），把一轮从 179 秒/19 步压到
  50 秒/8 步；
* 而原来的确定性注入用的是含临时端口的完整 URL 做键 —— 平台每题给新端口，于是
  每轮都像一个全新目标，**永远不会命中**；
* 另一对（ThinkPHP 同类题）时长降了 38% 但**根本没命中笔记**，所以那是抖动，
  不能算收益。这也是为什么必须把命中条目和分数打进日志：没有命中率，
  无法区分"复用有效"和"这次运气好"。
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnclaw.agent import playbook as pb
from vulnclaw.agent import solver

CHALLENGE_A = "Solve CTF2 challenge '[Weblogic]CVE-2017-10271' (category Real, difficulty Easy) on practice 2de971ac"
CHALLENGE_B = "Solve CTF2 challenge '[Weblogic]CVE-2018-2628' (category Real, difficulty Easy) on practice 2de971ac"


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(pb, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(pb, "PLAYBOOKS_DIR", tmp_path / "playbooks")
    pb.ensure_dirs()
    return tmp_path / "playbooks"


def _save_weblogic_note() -> None:
    pb.save_playbook(
        name="Weblogic CVE-2017-10271 wls-wsat XMLDecoder RCE",
        fingerprint="Weblogic CVE-2017-10271 wls-wsat XMLDecoder RCE bea_wls_internal docroot",
        steps=(
            "LOCK: Weblogic exposes /wls-wsat/CoordinatorPortType; the flag is read from "
            "the environment inside the container and written into the docroot served by "
            "/bea_wls_internal/. CONFIRMED: ProcessBuilder.start() is non-blocking, so a "
            "timing oracle is invalid and the command does run; write a JSP shell into the "
            "exploded docRoot and read the flag from it. ANGLES: [hit] xmldecoder payload."
        ),
        status="validated",
    )


# ── class signature ───────────────────────────────────────────────────────

def test_signature_keeps_the_disriminators_and_drops_the_endpoint():
    sig = pb.challenge_class_signature(
        "Target: http://direct-ctf2.dasctf.com:27420\n" + CHALLENGE_B
    )
    assert "Weblogic" in sig and "CVE-2018-2628" in sig
    assert "Real" in sig and "Easy" in sig
    assert "27420" not in sig and "dasctf" not in sig


def test_signature_is_empty_when_the_goal_carries_no_identity():
    assert pb.challenge_class_signature("capture the flag please") == ""


def test_signature_dedupes_a_title_repeated_by_tag_and_quotes():
    sig = pb.challenge_class_signature(CHALLENGE_B)
    assert sig.lower().count("[weblogic]cve-2018-2628") == 1


# ── merged lookup ─────────────────────────────────────────────────────────

def test_multi_lookup_merges_by_slug_and_reports_which_key_matched(store):
    _save_weblogic_note()
    rows = pb.lookup_playbook_multi(
        [("target", "http://direct-ctf2.dasctf.com:27420 " + CHALLENGE_B),
         ("class", pb.challenge_class_signature(CHALLENGE_B))],
        limit=2,
    )
    assert rows, "the class key must find the sibling challenge's note"
    assert rows[0]["query_kind"] == "class"
    assert rows[0]["score"] > 0.222, "a compact class query must outscore the endpoint query"
    assert all("query" in row for row in rows)


def test_multi_lookup_dedupes_a_note_found_by_both_keys(store):
    _save_weblogic_note()
    query = "Weblogic CVE-2017-10271 wls-wsat XMLDecoder RCE"
    rows = pb.lookup_playbook_multi([("target", query), ("class", query)], limit=3)
    assert len(rows) == len({row["slug"] for row in rows})


def test_multi_lookup_on_an_empty_store_returns_nothing(store):
    assert pb.lookup_playbook_multi([("class", "Weblogic CVE-2018-2628")]) == []


# ── injection + logging ───────────────────────────────────────────────────

def _run_injection(store, *, origin: str, goal: str):
    notices: list[str] = []
    events: list[tuple[str, dict]] = []
    runtime = SimpleNamespace(prior_playbook_brief="")
    hits = solver._inject_prior_playbooks(
        origin=origin,
        goal=goal,
        runtime=runtime,
        stream_sink=SimpleNamespace(on_notice=notices.append),
        emit=lambda kind, payload: events.append((kind, payload)),
    )
    return hits, notices, events, runtime


def test_a_sibling_challenge_is_injected_and_logged(store):
    _save_weblogic_note()
    hits, notices, events, runtime = _run_injection(
        store, origin="http://direct-ctf2.dasctf.com:27532", goal=CHALLENGE_B
    )
    assert hits >= 1
    assert "Prior-run notes" in runtime.prior_playbook_brief
    assert "sibling challenge" in runtime.prior_playbook_brief, (
        "a class match must warn that the vulnerability may differ"
    )
    # 操作者可见的那一行，带 slug 与分数
    assert any("score=" in n and "(class)" in n for n in notices), notices
    kind, payload = events[0]
    assert kind == "playbook_injected"
    assert payload["matches"] == hits
    assert payload["hits"][0]["slug"] and payload["hits"][0]["score"] > 0


def test_no_match_is_reported_instead_of_silence(store):
    hits, notices, events, runtime = _run_injection(
        store, origin="http://direct-ctf2.dasctf.com:27532", goal=CHALLENGE_B
    )
    assert hits == 0
    assert runtime.prior_playbook_brief == ""
    assert events == []
    assert any("no prior notes matched" in n for n in notices), notices


def test_a_broken_notice_sink_cannot_break_the_injection(store):
    _save_weblogic_note()

    class Exploding:
        def on_notice(self, message):  # noqa: ARG002
            raise RuntimeError("sink is broken")

    runtime = SimpleNamespace(prior_playbook_brief="")
    hits = solver._inject_prior_playbooks(
        origin="http://direct-ctf2.dasctf.com:27532",
        goal=CHALLENGE_B,
        runtime=runtime,
        stream_sink=Exploding(),
        emit=lambda kind, payload: None,
    )
    assert hits >= 1 and "Prior-run notes" in runtime.prior_playbook_brief
