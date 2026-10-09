"""The IR WP export: answer cards reach the deliverable, the report must not carry them.

Both halves of that sentence matter, and they are why this file exists.

``blackboard_record_answer`` records each graded answer twice: a blackboard fact
and a finding with ``vuln_type="ir-answer"`` (title = question, description =
answer, evidence = verbatim output). The report / SARIF / verify-pending
consumers *must skip* those cards -- an answer card is not a vulnerability, and
rendering one promoted a question that merely names a class ("漏洞名称") into a
verified vulnerability (round-10 finding #1).

Skipping is correct for the vulnerability report and useless for the deliverable:
the competition's WP has to carry those conclusions, so they used to be copied by
hand inside a 20-minute window. ``vulnclaw wp`` renders them instead.

Round-3 (2026-10-09) rehearsal finding: the two behaviours were verified together
against a real IR drill, which is how the hand-copy gap was found at all.
"""

from __future__ import annotations

from vulnclaw.agent.context import SessionState, VulnerabilityFinding
from vulnclaw.config.domain_models import ANSWER_CARD_VULN_TYPE
from vulnclaw.report.generator import generate_report
from vulnclaw.report.ir_wp import build_ir_wp, collect_answer_cards

EVIDENCE_ONE = "203.0.113.47 - - [14/Mar/2026:09:22:51 +0800] \"POST /upload.php\" 200"
EVIDENCE_TWO = "*/23 * * * * /bin/sh /var/www/html/uploads/.cache_update.sh"


def _card(question: str, answer: str, evidence: str) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        title=question,
        severity="Info",
        vuln_type=ANSWER_CARD_VULN_TYPE,
        description=answer,
        evidence=evidence,
    )


def _session(*findings: VulnerabilityFinding, run_id: str = "rid-1") -> SessionState:
    session = SessionState(target="ir-drill")
    session.run_id = run_id
    for finding in findings:
        session.add_finding(finding)
    return session


def _two_cards() -> tuple[SessionState, list[VulnerabilityFinding]]:
    first = _card("Q2: 攻击者 IP 是什么？", "203.0.113.47", EVIDENCE_ONE)
    second = _card("Q5: 持久化机制是什么？", "两处 cron + UID=0 账号", EVIDENCE_TWO)
    return _session(first, second), [first, second]


# ── collection ──────────────────────────────────────────────────────────────


def test_cards_are_collected_in_recording_order():
    session, cards = _two_cards()

    collected = collect_answer_cards(session)

    assert [c.title for c in collected] == [c.title for c in cards]


def test_a_verified_vulnerability_is_not_an_answer_card():
    """The marker, not the severity, decides -- Info alone must not qualify."""
    finding = VulnerabilityFinding(title="Reflected XSS", severity="Info", vuln_type="XSS")
    finding.mark_verified()
    session = _session(finding)

    assert collect_answer_cards(session) == []


# ── the rendered WP ─────────────────────────────────────────────────────────


def test_wp_carries_every_answer_and_its_verbatim_evidence():
    session, _ = _two_cards()

    document = build_ir_wp(session, generated_at="2026-10-09T16:30:00")

    assert "Q2: 攻击者 IP 是什么？" in document
    assert "203.0.113.47" in document
    assert "Q5: 持久化机制是什么？" in document
    assert EVIDENCE_ONE in document          # evidence verbatim, not summarized
    assert EVIDENCE_TWO in document
    assert "2 条已自动填入" in document
    assert "ir-drill" in document
    assert "rid-1" in document


def test_wp_states_what_the_machine_did_not_write():
    """The gap is stated where the WP is produced, not only in the runbook."""
    session, _ = _two_cards()

    document = build_ir_wp(session)

    assert "人工待补" in document
    assert "攻击链时间线" in document
    assert "flag 是否已提交" in document


def test_wp_says_so_when_no_cards_were_recorded():
    """An empty answer sheet is a finding about the run, not a blank file."""
    session = _session()

    document = build_ir_wp(session)

    assert "没有记录任何答案卡" in document
    assert "blackboard_record_answer" in document


def test_template_text_is_appended_verbatim():
    session, _ = _two_cards()
    template = "# 应急响应演练报告（WP 骨架）\n\n## 0. 基本信息\n\n| 项 | 内容 |\n"

    document = build_ir_wp(session, template_text=template)

    assert template.strip() in document
    # the auto block still leads, so nothing is hidden behind the skeleton
    assert document.index("答案卡（自动导出") < document.index("交付模板骨架")


# ── the pairing: why the WP exists at all ───────────────────────────────────


def test_the_report_itself_still_omits_answer_cards(tmp_path):
    """Pin the design decision the WP exists to work around.

    If someone later "fixes" the report by rendering answer cards, this fails --
    and that is the point: the same change would print a question like "漏洞名称"
    as a verified vulnerability.
    """
    session, cards = _two_cards()

    report_path = generate_report(session, output_path=str(tmp_path / "report.md"))
    report_text = report_path.read_text(encoding="utf-8")

    for card in cards:
        assert card.title not in report_text
        assert card.description not in report_text
    # ...while the WP is where they do show up
    document = build_ir_wp(session)
    for card in cards:
        assert card.title in document
        assert card.description in document
