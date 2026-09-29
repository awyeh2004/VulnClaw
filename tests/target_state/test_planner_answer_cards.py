"""Resume-planner must not treat IR answer cards as pending vulnerabilities.

Round-10 finding #1: ``blackboard_record_answer`` stores the answer sheet as Info /
always-pending findings, so ``build_resume_plan`` saw every card as a candidate and
chose the ``verify_pending_findings`` strategy -- a resumed IR session would be told to
"verify" the answer sheet and would mine URLs/paths out of card titles as targets.
"""

from __future__ import annotations

from vulnclaw.config.domain_models import ANSWER_CARD_VULN_TYPE
from vulnclaw.target_state.planner import build_resume_plan


def _raw(findings):
    return {
        "findings": findings,
        "finding_meta": {},
        "recon_dimensions_completed": {},
        "recon_meta": {},
        "runtime_meta": {},
        "constraint_violation_events": [],
    }


def _answer_card():
    return {
        "title": "Q1: 攻击者 IP 是什么？",
        "vuln_type": ANSWER_CARD_VULN_TYPE,
        "verification_status": "pending",
        "severity": "Info",
        "evidence": "http://ctf2.dasctf.com/",
    }


def _real_finding(status="pending"):
    return {
        "title": "Weblogic wls-wsat XMLDecoder RCE",
        "vuln_type": "远程代码执行",
        "verification_status": status,
        "severity": "Critical",
        "finding_id": "rce-1",
    }


def test_answer_cards_do_not_trigger_verify_pending():
    plan = build_resume_plan(_raw([_answer_card(), _answer_card()]))
    assert plan["strategy"] != "verify_pending_findings"
    assert plan["priority_findings"] == []


def test_a_real_pending_finding_still_triggers_verify_pending():
    plan = build_resume_plan(_raw([_answer_card(), _real_finding()]))
    assert plan["strategy"] == "verify_pending_findings"
