"""自动笔记不得把手工技术笔记挤出注入名额。

实测背景（2026-09-23）：真正把技术跨题带过去的那条笔记（暴露面、`ProcessBuilder`
非阻塞的坑、flag 外带落点）在真实笔记库里只排第二、0.250 分，而 capture_run_notes
自动写的练习场级笔记 0.727 分。当下的 limit=2 恰好还装得下两条；但自动笔记**每轮
新增一条**，只要将来有两条自动笔记分数 ≥ 那条手工笔记，手工笔记就会从结果里
静默消失 —— 而它正是把一轮从 179 秒/19 步压到 50 秒/8 步的东西。

规则刻意最小化，且**绝不让结果集变小**：

* 有手工笔记命中、但前 limit 条里一条都没有 → 把最后一个名额让给分最高的手工笔记；
* 库里只有自动笔记 → 什么都不改（把它变得更空是错的）。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnclaw.agent import playbook as pb

LONG_STEPS = (
    "LOCK: a concrete lock description that is long enough to pass the quality gate.\n"
    "CONFIRMED: something witnessed in evidence.\n"
    "ANGLES: [hit] one angle."
)


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(pb, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(pb, "PLAYBOOKS_DIR", tmp_path / "playbooks")
    pb.ensure_dirs()
    return tmp_path / "playbooks"


def _write(slug: str, *, name: str, fingerprint: str, with_source: bool, source: str = "") -> None:
    block = [
        "---",
        f"name: {name}",
        f"fingerprint: {fingerprint}",
        "status: validated",
    ]
    if with_source:
        block.append(f"source: {source}")
    block += ["---", "", LONG_STEPS, ""]
    (pb.PLAYBOOKS_DIR / f"{slug}.md").write_text("\n".join(block), encoding="utf-8")


# ── classification ────────────────────────────────────────────────────────

def test_new_auto_notes_record_their_source(store):
    ack = pb.capture_run_notes(
        target="http://x.example.com:1234", goal="get the flag",
        blackboard=pb.Blackboard() if hasattr(pb, "Blackboard") else _board(),
        outcome="solved", final_answer="flag{abc}",
    )
    assert ack and ack.get("source") == pb.SOURCE_AUTO
    body = (pb.PLAYBOOKS_DIR / f"{ack['slug']}.md").read_text(encoding="utf-8")
    assert "source: auto" in body


def _board():
    from vulnclaw.agent.blackboard import Blackboard

    return Blackboard()


def test_model_saved_notes_are_curated_by_default(store):
    ack = pb.save_playbook(
        name="Weblogic wls-wsat XMLDecoder RCE",
        fingerprint="Weblogic CVE-2017-10271 wls-wsat XMLDecoder RCE",
        steps=LONG_STEPS,
        status="validated",
    )
    assert ack["source"] == pb.SOURCE_CURATED
    rows = pb.lookup_playbook("Weblogic CVE-2017-10271", limit=3)
    assert rows and rows[0]["source"] == pb.SOURCE_CURATED


def test_legacy_auto_notes_without_the_field_are_still_recognised(store):
    """A store written before `source` existed must not read as all-curated."""
    _write("legacy-auto", name="AutoNotes direct-ctf2.example.com:1234",
           fingerprint="Weblogic CVE-2018-2628 Real Easy", with_source=False)
    pb2 = pb.list_playbooks()[0]
    assert pb2.source == pb.SOURCE_AUTO and pb2.is_auto


def test_legacy_curated_notes_stay_curated(store):
    _write("legacy-curated", name="Weblogic wls-wsat XMLDecoder RCE",
           fingerprint="Weblogic CVE-2018-2628 Real Easy", with_source=False)
    assert pb.list_playbooks()[0].source == pb.SOURCE_CURATED


# ── the reserve rule ──────────────────────────────────────────────────────

def test_curated_note_keeps_a_slot_when_two_auto_notes_outscore_it(store):
    query = "Weblogic CVE-2018-2628 Real Easy"
    _write("auto-a", name="AutoNotes a", fingerprint=query, with_source=True,
           source=pb.SOURCE_AUTO)
    _write("auto-b", name="AutoNotes b", fingerprint=query, with_source=True,
           source=pb.SOURCE_AUTO)
    _write("curated", name="Weblogic technique note",
           fingerprint="Weblogic CVE-2017-10271 wls-wsat XMLDecoder docroot bea_wls_internal",
           with_source=True, source=pb.SOURCE_CURATED)

    rows = pb.lookup_playbook_multi([("class", query)], limit=2)
    slugs = [r["slug"] for r in rows]
    assert "curated" in slugs, f"curated note was crowded out: {slugs}"
    assert len(rows) == 2, "the result set must not shrink"


def test_an_all_auto_store_is_left_alone(store):
    query = "Weblogic CVE-2018-2628 Real Easy"
    for slug in ("auto-a", "auto-b", "auto-c"):
        _write(slug, name=f"AutoNotes {slug}", fingerprint=query, with_source=True,
               source=pb.SOURCE_AUTO)
    rows = pb.lookup_playbook_multi([("class", query)], limit=2)
    assert len(rows) == 2 and all(r["source"] == pb.SOURCE_AUTO for r in rows)


def test_curated_ordering_is_untouched_when_it_already_ranks(store):
    query = "Weblogic CVE-2018-2628 Real Easy"
    _write("curated", name="Weblogic technique note", fingerprint=query,
           with_source=True, source=pb.SOURCE_CURATED)
    _write("auto-a", name="AutoNotes a", fingerprint="something else entirely",
           with_source=True, source=pb.SOURCE_AUTO)
    rows = pb.lookup_playbook_multi([("class", query)], limit=2)
    assert rows[0]["slug"] == "curated"


def test_empty_store_returns_nothing(store):
    assert pb.lookup_playbook_multi([("class", "Weblogic CVE-2018-2628")], limit=2) == []


def test_the_injection_reports_the_curated_note(store):
    """End to end: the injected brief must carry the technique note."""
    from types import SimpleNamespace

    from vulnclaw.agent import solver

    query = "Weblogic CVE-2018-2628 Real Easy"
    goal = "Solve CTF2 challenge '[Weblogic]CVE-2018-2628' (category Real, difficulty Easy)"
    _write("auto-a", name="AutoNotes a", fingerprint=goal + " " + query,
           with_source=True, source=pb.SOURCE_AUTO)
    _write("auto-b", name="AutoNotes b", fingerprint=goal + " " + query,
           with_source=True, source=pb.SOURCE_AUTO)
    _write("curated", name="Weblogic technique note",
           fingerprint="Weblogic CVE-2017-10271 wls-wsat XMLDecoder bea_wls_internal docroot",
           with_source=True, source=pb.SOURCE_CURATED)

    notices: list[str] = []
    runtime = SimpleNamespace(prior_playbook_brief="")
    hits = solver._inject_prior_playbooks(
        origin="http://direct-ctf2.dasctf.com:27532", goal=goal, runtime=runtime,
        stream_sink=SimpleNamespace(on_notice=notices.append),
        emit=lambda kind, payload: None,
    )
    assert hits == 2
    assert "Weblogic technique note" in runtime.prior_playbook_brief
    assert any("curated" in n for n in notices), notices
