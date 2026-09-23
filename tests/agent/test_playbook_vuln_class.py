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
    """The fingerprint is often just the target string; the name states the class.

    Real shape: the fingerprint shares only "weblogic" with the query (so the note
    is a class-level match), while the technique words live in the name/slug.
    """
    _write("weblogic-note", "Weblogic direct-ctf2.dasctf.com target string")
    path = pb.PLAYBOOKS_DIR / "weblogic-note.md"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "name: weblogic-note",
            "name: Weblogic CVE-2017-10271 (wls-wsat XMLDecoder RCE) flag exfil",
        ),
        encoding="utf-8",
    )
    rows = pb.lookup_playbook_multi([("class", "Weblogic SSRF")], limit=2)
    assert rows, "the note must still match on the framework token"
    assert rows[0]["vuln_classes"], "class must come from the declared name"
    assert "deserialization" in rows[0]["vuln_classes"]
    assert rows[0]["vuln_class_agrees"] is False


# ── ranking ───────────────────────────────────────────────────────────────

def test_a_class_matching_note_outranks_a_framework_only_note(store):
    """Both score 1.0 against the one-token class key; agreement must decide."""
    query = "Weblogic"
    _write("weblogic-deser", "Weblogic CVE-2017-10271 wls-wsat XMLDecoder bea_wls_internal")
    _write("weblogic-ssrf", "Weblogic SSRF uddiexplorer operator portlet")

    rows = pb.lookup_playbook_multi([("class", query)], limit=2)
    # No class in the QUERY itself: agreement cannot discriminate, so score order holds.
    assert [r["slug"] for r in rows] == ["weblogic-deser", "weblogic-ssrf"]

    rows = pb.lookup_playbook_multi([("class", "Weblogic SSRF")], limit=2)
    assert rows[0]["slug"] == "weblogic-ssrf", "the same-class note must win"
    assert rows[0]["vuln_class_agrees"] is True
    assert rows[1]["vuln_class_agrees"] is False


def test_a_disagreeing_note_is_demoted_not_dropped(store):
    query = "Weblogic SSRF"
    _write("weblogic-deser", "Weblogic CVE-2017-10271 wls-wsat XMLDecoder bea_wls_internal")
    rows = pb.lookup_playbook_multi([("class", query)], limit=2)
    assert rows, "a framework-only note must stay available as a fallback"
    assert rows[0]["slug"] == "weblogic-deser"
    assert rows[0]["vuln_class_agrees"] is False
    assert rows[0]["vuln_classes"] == ["deserialization"]


def test_a_silent_note_is_not_treated_as_disagreeing(store):
    _write("classless", "Weblogic some note that names no vulnerability class here")
    rows = pb.lookup_playbook_multi([("class", "Weblogic SSRF")], limit=2)
    assert rows[0]["vuln_class_agrees"] is True


def test_rows_expose_the_classes_for_the_run_log(store):
    _write("weblogic-ssrf", "Weblogic SSRF uddiexplorer")
    rows = pb.lookup_playbook_multi([("class", "Weblogic SSRF")], limit=2)
    assert rows[0]["vuln_classes"] == ["ssrf"]


def test_curated_reserve_still_holds_with_class_ranking(store):
    """The two ranking rules must compose: agreement first, then the reserve."""
    query = "Weblogic SSRF"
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

    _write("weblogic-deser", "Weblogic CVE-2017-10271 XMLDecoder bea_wls_internal wls-wsat")
    notices: list[str] = []
    events: list[tuple[str, dict]] = []
    runtime = SimpleNamespace(prior_playbook_brief="")
    hits = solver._inject_prior_playbooks(
        origin="http://direct-ctf2.dasctf.com:25723",
        goal="This is a CTF challenge web service ([Weblogic]SSRF). Exploit it.",
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

    _write("weblogic-deser", "Weblogic CVE-2017-10271 XMLDecoder bea_wls_internal")
    runtime = SimpleNamespace(prior_playbook_brief="")
    solver._inject_prior_playbooks(
        origin="http://direct-ctf2.dasctf.com:25723",
        goal="This is a CTF challenge web service ([Weblogic]SSRF). Exploit it.",
        runtime=runtime,
        stream_sink=SimpleNamespace(on_notice=lambda m: None),
        emit=lambda kind, payload: None,
    )
    brief = runtime.prior_playbook_brief
    assert "OWN stated vulnerability class wins" in brief
    assert "VERIFY its stated premise on THIS target" in brief
    assert "attack the vulnerability the challenge actually asks for" in brief
