"""漏洞类判别力：class 键命中"同框架"时必须能和"同漏洞类"区分开。

实测背景（2026-09-23，反向对照）：一条 **Weblogic XMLDecoder 反序列化** 的笔记被注入进
一道 **Weblogic SSRF** 题，且因为 class 签名在那种 goal 下退化成单 token("Weblogic")，
它拿了满分 1.0。日志里的词频直接显示运行被带偏：`ssrf` 提及 28 → 3，`bea_wls_internal`
提及 2 → 41。它仍然解出来了，因为那条笔记里的知识是**环境级**的（哪条路径未授权、flag
能从哪里外带），与环境级知识一起迁移过去了。

所以规则是**降权、不排除**：

* 声明了漏洞类且与本次任务**不一致**的笔记，排在一致的笔记之后；
* 没有声明任何漏洞类的笔记不算不一致（沉默不等于矛盾，且多数手工笔记早于这套词表）；
* 不一致的笔记仍然可用 —— 它实测帮上过忙，直接删掉会丢掉那份收益。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnclaw.agent import playbook as pb

LONG_STEPS = (
    "LOCK: something concrete and long enough to pass the quality gate.\n"
    "CONFIRMED: witnessed in evidence.\n"
    "ANGLES: [hit] one angle."
)

# Real goal shapes (the same wording the CTF2 practice field uses). The point of
# writing them out: `challenge_class_signature` yields 4 tokens here -- weblogic /
# cve / real / easy -- so a cross-instance `class` hit reaches the 2-token overlap
# floor as soon as the note's fingerprint carries the CVE, which real notes do
# (target_fingerprint appends the goal text). A goal phrased only as
# "([Weblogic]SSRF)" yields 2 tokens and stays a framework-only match for any
# Weblogic note: that is the measured harm case, gated below.
GOAL_A = "Solve CTF2 challenge [Weblogic]CVE-2017-10271 (category Real, difficulty Easy)"
GOAL_B = "Solve CTF2 challenge [Weblogic]CVE-2018-2628 (category Real, difficulty Easy)"
GOAL_SSRF = "Solve CTF2 challenge [Weblogic]SSRF (category Real, difficulty Easy)"


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(pb, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(pb, "PLAYBOOKS_DIR", tmp_path / "playbooks")
    pb.ensure_dirs()
    return tmp_path / "playbooks"


def _write(slug: str, fingerprint: str, *, source: str = pb.SOURCE_CURATED) -> None:
    block = [
        "---",
        f"name: {slug}",
        f"fingerprint: {fingerprint}",
        "status: validated",
        f"source: {source}",
        "---",
        "",
        LONG_STEPS,
        "",
    ]
    (pb.PLAYBOOKS_DIR / f"{slug}.md").write_text("\n".join(block), encoding="utf-8")


# ── vocabulary ────────────────────────────────────────────────────────────

def test_vocabulary_reads_the_ssrf_case_that_misfired():
    assert pb.vulnerability_classes("[Weblogic]SSRF") == {"ssrf"}
    assert pb.vulnerability_classes("Weblogic CVE-2017-10271 wls-wsat XMLDecoder") >= {
        "deserialization"
    }


def test_vocabulary_is_empty_for_a_classless_text():
    assert pb.vulnerability_classes("a plain web service with no hints") == frozenset()


def test_vocabulary_recognises_chinese_labels():
    assert "sqli" in pb.vulnerability_classes("这题是 SQL注入，login 参数")
    assert "file_read" in pb.vulnerability_classes("疑似文件包含")


# ── two limits found on a real store ──────────────────────────────────────

def test_signature_carries_the_vulnerability_class():
    """Real goal shape: the tag is "[Weblogic]" and the class is OUTSIDE the bracket.

    Without this the signature was one token, so every Weblogic note scored 1.0 and
    the query declared no class -- the agreement rule was a no-op on the exact case
    it exists for.
    """
    sig = pb.challenge_class_signature(
        "This is a CTF challenge web service ([Weblogic]SSRF). Exploit it."
    )
    assert "ssrf" in sig.split(), f"class missing from signature {sig!r}"
    assert pb.vulnerability_classes(sig) == {"ssrf"}


def test_note_classes_are_read_from_name_and_slug_not_only_fingerprint(store):
    """The class must come from the note's declared NAME, not only its fingerprint.

    Real shape: the fingerprint is target-derived (``target_fingerprint`` appends the
    goal text), so framework/CVE tokens are what lift it past the overlap floor, while
    the vulnerability class (XMLDecoder -> deserialization) lives only in the name.
    """
    _write("weblogic-note", "Weblogic CVE-2017-10271 real easy direct-ctf2.dasctf.com target")
    path = pb.PLAYBOOKS_DIR / "weblogic-note.md"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "name: weblogic-note",
            "name: Weblogic CVE-2017-10271 (wls-wsat XMLDecoder RCE) flag exfil",
        ),
        encoding="utf-8",
    )
    rows = pb.lookup_playbook_multi([("class", pb.challenge_class_signature(GOAL_SSRF))], limit=2)
    assert rows, "weblogic+real overlap (2 tokens) must still match"
    assert rows[0]["vuln_classes"], "class must come from the declared name"
    assert "deserialization" in rows[0]["vuln_classes"]
    assert rows[0]["vuln_class_agrees"] is False, (
        "the note's declared class must be read from its NAME (the fingerprint here "
        "names no class at all)"
    )


# ── ranking ───────────────────────────────────────────────────────────────

def test_a_class_matching_note_outranks_a_framework_only_note(store):
    """Two notes that both clear the floor: the same-class note must be injected first.

    The old shape of this test compared two notes against the single-token query
    ``"Weblogic"``. Under the overlap floor that query reaches nothing at all (see
    ``test_the_framework_only_note_is_now_blocked_outright``), so the comparison is
    now made with a query that legitimately matches both notes: the SSRF note on
    ``weblogic+ssrf`` and the deserialization note on ``weblogic+cve``, both 2 tokens.
    """
    _write("weblogic-deser", "Weblogic CVE-2017-10271 XMLDecoder wls-wsat bea_wls_internal")
    _write("weblogic-ssrf", "Weblogic SSRF uddiexplorer operator portlet")
    query = "Weblogic CVE-2017-10271 SSRF"

    rows = pb.lookup_playbook_multi([("class", query)], limit=2)
    assert {r["slug"] for r in rows} == {"weblogic-deser", "weblogic-ssrf"}, rows
    assert rows[0]["slug"] == "weblogic-ssrf", "the same-class note must win"
    assert rows[0]["vuln_class_agrees"] is True
    assert rows[1]["vuln_class_agrees"] is False


def test_a_disagreeing_note_is_demoted_not_dropped(store):
    """Once a note clears the overlap floor, class disagreement demotes but keeps it."""
    _write("weblogic-deser", "Weblogic CVE-2017-10271 XMLDecoder wls-wsat bea_wls_internal")
    _write("weblogic-ssrf", "Weblogic SSRF uddiexplorer operator portlet")
    rows = pb.lookup_playbook_multi([("class", "Weblogic CVE-2017-10271 SSRF")], limit=2)
    assert rows, "a disagreeing note must stay available as a fallback"
    assert [r["slug"] for r in rows] == ["weblogic-ssrf", "weblogic-deser"]
    assert rows[1]["vuln_class_agrees"] is False
    assert rows[1]["vuln_classes"] == ["deserialization"]


def test_the_framework_only_note_is_now_blocked_outright(store):
    """The measured harm case, after the overlap floor.

    Real store, 2026-09-23: goal written as ``([Weblogic]SSRF)``, signature reduced to
    ``Weblogic ssrf``, and a Weblogic **XMLDecoder deserialization** note (whose
    fingerprint carries no class token) scored 1.0 and was injected into the SSRF
    challenge; the run then abandoned SSRF (``ssrf`` mentions 28 -> 3,
    ``bea_wls_internal`` 2 -> 41).

    A framework-only match is 1 overlapping token, so it no longer reaches the
    injection at all. This is a deliberate recall cost: the note's knowledge was
    environmental and did help that run solve, and we trade that for not being
    derailed. The withheld row is reported so the drop stays diagnosable.
    """
    _write("weblogic-deser", "Weblogic wls-wsat XMLDecoder bea_wls_internal docroot")
    blocked: list[dict] = []
    rows = pb.lookup_playbook_multi(
        [("class", pb.challenge_class_signature(GOAL_SSRF))], limit=2, out_blocked=blocked
    )
    assert rows == [], "a framework-only match must not be injected as a class hit"
    assert [b["slug"] for b in blocked] == ["weblogic-deser"]
    assert blocked[0]["overlap_tokens"] == 1


def test_a_silent_note_is_not_treated_as_disagreeing(store):
    _write("classless", "Weblogic CVE-2017-10271 note that names no vulnerability class")
    rows = pb.lookup_playbook_multi([("class", "Weblogic CVE-2017-10271")], limit=2)
    assert rows[0]["vuln_class_agrees"] is True


def test_rows_expose_the_classes_for_the_run_log(store):
    _write("weblogic-ssrf", "Weblogic CVE-2018-2628 ssrf uddiexplorer")
    rows = pb.lookup_playbook_multi([("class", "Weblogic CVE-2018-2628 ssrf")], limit=2)
    assert rows[0]["vuln_classes"] == ["ssrf"]


def test_curated_reserve_still_holds_with_class_ranking(store):
    """The two ranking rules must compose: agreement first, then the reserve."""
    query = "Weblogic CVE-2018-2628 Real Easy"
    _write("auto-a", query, source=pb.SOURCE_AUTO)
    _write("auto-b", query, source=pb.SOURCE_AUTO)
    _write("curated-deser", "Weblogic CVE-2017-10271 XMLDecoder bea_wls_internal wls-wsat")
    rows = pb.lookup_playbook_multi([("class", query)], limit=2)
    slugs = [r["slug"] for r in rows]
    assert "curated-deser" in slugs, f"curated note lost to auto notes: {slugs}"
    assert len(rows) == 2


def test_injection_logs_the_class_mismatch(store):
    from types import SimpleNamespace

    from vulnclaw.agent import solver

    # Real-shape note: target-derived fingerprint (so it clears the 2-token floor via
    # weblogic+real) plus a NAMED class that disagrees with the SSRF challenge.
    _write("weblogic-deser", "Weblogic CVE-2017-10271 real easy XMLDecoder bea_wls_internal")
    notices: list[str] = []
    events: list[tuple[str, dict]] = []
    runtime = SimpleNamespace(prior_playbook_brief="")
    hits = solver._inject_prior_playbooks(
        origin="http://direct-ctf2.dasctf.com:25723",
        goal=GOAL_SSRF,
        runtime=runtime,
        stream_sink=SimpleNamespace(on_notice=notices.append),
        emit=lambda kind, payload: events.append((kind, payload)),
    )
    assert hits >= 1
    assert any("CLASS MISMATCH" in n for n in notices), notices
    _, payload = events[0]
    assert payload["hits"][0]["vuln_class_agrees"] is False


def test_injection_wording_puts_the_challenge_class_first(store):
    """The brief must tell the model that the intended class wins and to verify."""
    from types import SimpleNamespace

    from vulnclaw.agent import solver

    _write("weblogic-deser", "Weblogic CVE-2017-10271 real easy XMLDecoder bea_wls_internal")
    runtime = SimpleNamespace(prior_playbook_brief="")
    solver._inject_prior_playbooks(
        origin="http://direct-ctf2.dasctf.com:25723",
        goal=GOAL_SSRF,
        runtime=runtime,
        stream_sink=SimpleNamespace(on_notice=lambda m: None),
        emit=lambda kind, payload: None,
    )
    brief = runtime.prior_playbook_brief
    assert brief, "the wording assertions below are vacuous unless a brief was built"
    assert "OWN stated vulnerability class wins" in brief
    assert "VERIFY its stated premise on THIS target" in brief
    assert "attack the vulnerability the challenge actually asks for" in brief
