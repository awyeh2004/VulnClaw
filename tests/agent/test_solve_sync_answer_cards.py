"""``sync_verified_findings`` must not promote an IR answer card to a verified finding.

Round-10 finding #1: the promotion is evidence-gated, but an answer card whose question
names a class (``... rce ...``) satisfies every gate, so a FINAL that also mentions the
class promoted the question into the report/SARIF verified set.
"""

from __future__ import annotations

from types import SimpleNamespace

from vulnclaw.agent.subagent.solve import sync_verified_findings


class _Finding:
    def __init__(self, title: str, vuln_type: str):
        self.title = title
        self.vuln_type = vuln_type
        self.endpoint = ""
        self.verified = False
        self.verification_status = "pending"
        self.finding_id = f"{title}::{vuln_type}"
        self.note = ""

    def mark_verified(self, note: str = "", evidence_level: str = "") -> None:
        self.verified = True
        self.verification_status = "verified"
        self.note = note


def _agent(findings):
    record = SimpleNamespace(
        tool="shell_command",
        summary="RCE confirmed",
        content="remote code execution via weblogic",
        arguments={},
    )
    state = SimpleNamespace(get_evidence=lambda evidence_id: record)
    session = SimpleNamespace(
        findings=findings,
        agent_state=state,
        subagent_evidence_provenance={},
    )
    return SimpleNamespace(context=SimpleNamespace(state=session))


FINAL = "the vulnerability is rce (remote code execution)"


def test_an_answer_card_is_not_promoted():
    card = _Finding("攻击者用到的 rce 漏洞名称是什么？", "ir-answer")
    promoted = sync_verified_findings(_agent([card]), FINAL, ["e001"])
    assert promoted == []
    assert card.verified is False


def test_a_real_pending_finding_is_still_promoted():
    """Control: the exclusion must not disarm the promotion it exists to do."""
    real = _Finding("Weblogic remote code execution", "远程代码执行")
    promoted = sync_verified_findings(_agent([real]), FINAL, ["e001"])
    assert promoted == [real.finding_id]
    assert real.verified is True
