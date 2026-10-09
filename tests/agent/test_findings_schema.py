"""Tests for the structured finding schema + evidence refs + intake quarantine.

Covers the model-level half of the PRD:
- new structured fields round-trip through model_dump/reload,
- typed EvidenceRef serialization (kind/path/request_id),
- intake quarantine fires for ALL severities when a finding lacks
  evidence/vuln_type/remediation, setting needs_manual_review,
- candidates are never dropped (they stay in state.findings).
"""

import pytest

from vulnclaw.agent.context import EvidenceRef, SessionState, VulnerabilityFinding


class TestStructuredFields:
    def test_new_fields_round_trip(self):
        finding = VulnerabilityFinding(
            title="SQLi in login",
            severity="High",
            vuln_type="SQLi",
            description="id parameter injectable",
            impact="Full DB read access for anonymous users",
            evidence="error-based extraction succeeded",
            cvss=8.6,
            cwe="CWE-89",
            target="https://shop.example.com",
            endpoint="https://shop.example.com/login",
            method="POST",
            remediation="Use parameterized queries",
        )
        dumped = finding.model_dump(mode="json")
        assert dumped["impact"] == "Full DB read access for anonymous users"
        assert dumped["cvss"] == 8.6
        assert dumped["cwe"] == "CWE-89"
        assert dumped["endpoint"] == "https://shop.example.com/login"
        assert dumped["method"] == "POST"
        assert dumped["target"] == "https://shop.example.com"

        reloaded = VulnerabilityFinding(**dumped)
        assert reloaded.cvss == 8.6
        assert reloaded.cwe == "CWE-89"
        assert reloaded.method == "POST"
        assert reloaded.impact == finding.impact

    def test_code_location_field(self):
        finding = VulnerabilityFinding(
            title="Hardcoded secret",
            vuln_type="Secret",
            evidence="AWS key literal",
            code_location="src/config.py:42",
        )
        assert finding.code_location == "src/config.py:42"
        assert VulnerabilityFinding(**finding.model_dump()).code_location == "src/config.py:42"

    def test_skill_provenance_optional(self):
        finding = VulnerabilityFinding(
            title="X",
            vuln_type="XSS",
            evidence="reflected",
            skill_provenance={"skill": "xss-hunter", "format": "directory"},
        )
        assert finding.skill_provenance["skill"] == "xss-hunter"
        assert VulnerabilityFinding(**finding.model_dump()).skill_provenance == {
            "skill": "xss-hunter",
            "format": "directory",
        }


class TestEvidenceRef:
    def test_sandbox_output_ref(self):
        ref = EvidenceRef(kind="sandbox_output", path="sandbox/run1/stdout.txt")
        assert ref.kind == "sandbox_output"
        assert ref.path == "sandbox/run1/stdout.txt"
        assert ref.request_id is None

    def test_http_capture_ref_with_request_id(self):
        ref = EvidenceRef(kind="http_capture", path="http/req-42.json", request_id="req-42")
        dumped = ref.model_dump(mode="json")
        assert dumped == {
            "kind": "http_capture",
            "path": "http/req-42.json",
            "request_id": "req-42",
        }

    def test_invalid_kind_rejected(self):
        with pytest.raises(Exception):
            EvidenceRef(kind="screenshot", path="foo.png")

    def test_finding_carries_evidence_refs(self):
        finding = VulnerabilityFinding(
            title="RCE",
            vuln_type="RCE",
            evidence="whoami returned www-data",
            evidence_refs=[
                EvidenceRef(kind="sandbox_output", path="sandbox/rce/out.txt"),
                EvidenceRef(kind="http_capture", path="http/r-7.json", request_id="r-7"),
            ],
        )
        reloaded = VulnerabilityFinding(**finding.model_dump())
        assert len(reloaded.evidence_refs) == 2
        assert reloaded.evidence_refs[0].kind == "sandbox_output"
        assert reloaded.evidence_refs[1].request_id == "r-7"


class TestIntakeQuarantine:
    @pytest.mark.parametrize("severity", ["Critical", "High", "Medium", "Low", "Info"])
    def test_quarantine_fires_for_all_severities(self, severity):
        finding = VulnerabilityFinding(title="Bare thing", severity=severity)
        assert finding.lifecycle_status == "needs_manual_review"
        assert finding.title.startswith("[未验证]")
        assert finding.verification_status != "verified"

    def test_finding_with_vuln_type_is_not_quarantined(self):
        finding = VulnerabilityFinding(title="Has type", severity="Low", vuln_type="Info Leak")
        assert finding.lifecycle_status == "candidate"
        assert not finding.title.startswith("[未验证]")

    def test_finding_with_evidence_is_not_quarantined(self):
        finding = VulnerabilityFinding(
            title="Has evidence", severity="Medium", evidence="something concrete"
        )
        assert finding.lifecycle_status != "needs_manual_review"

    def test_verified_finding_not_re_quarantined(self):
        finding = VulnerabilityFinding(title="Confirmed", severity="High")
        finding.mark_verified(note="confirmed via tool", evidence_level="L4")
        assert finding.verification_status == "verified"
        assert finding.lifecycle_status == "verified"

    def test_promoting_later_matches_being_constructed_verified(self):
        # The quarantine is stamped at CONSTRUCTION time, so a finding built bare
        # and promoted afterwards must end up byte-identical to one constructed
        # already-verified. It used to keep "[未验证]" in the title and the
        # "缺少验证证据" advisory in the description while its status said
        # verified -- so the report printed a ✅ 已验证 row that contradicted
        # itself twice (2026-10-09 audit finding #1).
        finding = VulnerabilityFinding(
            title="Promoted later", description="found by hand", severity="High"
        )
        assert finding.title.startswith("[未验证]")
        assert "缺少验证证据" in finding.description

        finding.mark_verified(note="reproduced")
        assert finding.title == "Promoted later"
        assert finding.description == "found by hand"
        assert finding.verification_status == "verified"
        assert finding.lifecycle_status == "verified"

        constructed = VulnerabilityFinding(
            title="Promoted later", description="found by hand", severity="High", verified=True
        )
        assert (finding.title, finding.description) == (constructed.title, constructed.description)

    def test_rejecting_later_also_lifts_the_quarantine_stamp(self):
        # Rejected is terminal too: a ruled-out report must not stay titled
        # "[未验证]" and keep the "please supply evidence" advice.
        finding = VulnerabilityFinding(title="Bogus", description="guess", severity="High")
        finding.mark_rejected("control request disproved it")
        assert finding.title == "Bogus"
        assert "缺少验证证据" not in finding.description
        assert finding.lifecycle_status == "rejected"

    def test_clear_intake_quarantine_undoes_the_lifecycle_demotion(self):
        # Lifting the marks WITHOUT promoting must also undo the demotion, or a
        # now-substantiated finding stays stuck in needs_manual_review.
        finding = VulnerabilityFinding(title="Bare", severity="Low")
        assert finding.lifecycle_status == "needs_manual_review"
        assert finding.clear_intake_quarantine() is True
        assert finding.lifecycle_status == "candidate"
        assert finding.clear_intake_quarantine() is False  # idempotent

    def test_constructed_verified_bare_finding_keeps_terminal_status(self):
        # A finding constructed already-verified must not be re-stamped "[未验证]"
        # nor demoted to needs_manual_review, even with empty evidence/vuln_type.
        finding = VulnerabilityFinding(title="Confirmed", severity="High", verified=True)
        assert not finding.title.startswith("[未验证]")
        assert finding.verification_status == "verified"
        assert finding.lifecycle_status == "verified"

    def test_constructed_rejected_bare_finding_keeps_terminal_status(self):
        finding = VulnerabilityFinding(
            title="Bogus", severity="High", verification_status="rejected"
        )
        assert not finding.title.startswith("[未验证]")
        assert finding.lifecycle_status == "rejected"

    def test_candidates_are_never_dropped(self):
        state = SessionState(target="https://example.com")
        # Two bare findings with distinct titles must both survive intake.
        assert state.add_finding(VulnerabilityFinding(title="Alpha", severity="Low"))
        assert state.add_finding(VulnerabilityFinding(title="Beta", severity="Low"))
        assert len(state.findings) == 2
        # Both quarantined, neither silently dropped or promoted.
        assert all(f.lifecycle_status == "needs_manual_review" for f in state.findings)

    def test_distinct_bare_findings_get_distinct_ids(self):
        a = VulnerabilityFinding(title="Alpha", severity="Low")
        b = VulnerabilityFinding(title="Beta", severity="Low")
        assert a.finding_id != b.finding_id
        assert a.finding_id
        assert b.finding_id

    def test_add_finding_populates_target(self):
        state = SessionState(target="https://example.com")
        state.add_finding(VulnerabilityFinding(title="X", vuln_type="XSS", evidence="reflected"))
        assert state.findings[0].target == "https://example.com"
