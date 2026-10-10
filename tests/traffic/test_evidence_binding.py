"""Binding captured traffic to findings: all-or-nothing, append-only, versioned.

These tests pin down the two invariants a report depends on -- a failed bind
leaves the finding untouched, and re-binding never silently overwrites what a
human or an earlier turn recorded -- plus the version counter that makes a
mid-run change detectable.
"""

from __future__ import annotations

import shutil

import pytest

from vulnclaw.config.domain_models import (
    EvidenceRef,
    VulnerabilityFinding,
    evidence_binding_signature,
)
from vulnclaw.traffic.binding import (
    EvidenceBindError,
    bind_finding_evidence,
    parse_binding_specs,
    reorder_finding_evidence,
    unbind_finding_evidence,
)
from vulnclaw.traffic.evidence import EvidenceStore
from vulnclaw.traffic.models import CapturedExchange, CapturedRequest, CapturedResponse
from vulnclaw.traffic.store import TrafficStore


def _finding(**overrides) -> VulnerabilityFinding:
    kwargs = dict(
        title="SQL injection in /login",
        severity="High",
        vuln_type="SQLi",
        evidence="error-based injection confirmed",
        remediation="parameterize queries",
    )
    kwargs.update(overrides)
    return VulnerabilityFinding(**kwargs)


def _capture(traffic: TrafficStore, url: str, *, status: int = 500) -> str:
    return traffic.record(
        CapturedExchange(
            request=CapturedRequest(
                method="POST", url=url, headers={"Host": "app.test"}, body=b"id=1"
            ),
            response=CapturedResponse(status=status, body=b"SQL syntax error"),
        ),
        source="proxy",
    ).request_id


def _stores(tmp_path):
    root = tmp_path / "evidence"
    return TrafficStore(root / "traffic"), EvidenceStore(root), root


# ── binding ─────────────────────────────────────────────────────────────────


def test_bind_appends_in_order_with_roles_and_bumps_the_version(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    baseline = _capture(traffic, "https://app.test/login?id=1")
    proof = _capture(traffic, "https://app.test/login?id=1'")

    finding = _finding()
    assert finding.evidence_version == 0

    outcome = bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[
            {"request_id": baseline, "role": "baseline", "note": "normal account"},
            {"request_id": proof, "role": "proof", "note": "payload triggers the error"},
        ],
    )

    assert [ref.role for ref in finding.evidence_refs] == ["baseline", "proof"]
    assert [ref.note for ref in finding.evidence_refs] == [
        "normal account",
        "payload triggers the error",
    ]
    # order is the reading order in the report, and part of the identity
    assert [ref.request_id for ref in finding.evidence_refs] == [baseline, proof]
    # every ref carries the durable handle plus a content hash
    assert all(ref.snapshot_id for ref in finding.evidence_refs)
    assert all(ref.sha256 for ref in finding.evidence_refs)
    assert finding.evidence_version == 1
    assert outcome.version == 1
    assert outcome.bindings == 2
    assert outcome.signature == evidence_binding_signature(finding.evidence_refs)
    assert len(outcome.added) == 2 and not outcome.duplicates


def test_role_defaults_to_supporting(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    finding = _finding()

    bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[{"request_id": _capture(traffic, "https://app.test/a")}],
    )

    assert finding.evidence_refs[0].role == "supporting"


def test_a_later_bind_appends_and_keeps_existing_refs(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    finding = _finding()

    bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[{"request_id": _capture(traffic, "https://app.test/one"), "role": "proof"}],
    )
    bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[{"request_id": _capture(traffic, "https://app.test/two"), "role": "verification"}],
    )

    assert len(finding.evidence_refs) == 2
    assert finding.evidence_version == 2


def test_binding_survives_the_capture_log_being_reclaimed(tmp_path):
    """The end-to-end promise: bind once, then the traffic dir may be deleted."""
    traffic, evidence, root = _stores(tmp_path)
    finding = _finding()

    bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[{"request_id": _capture(traffic, "https://app.test/login?id=1'"), "role": "proof"}],
    )
    shutil.rmtree(root / "traffic")

    snapshot_id = finding.evidence_refs[0].snapshot_id
    assert "SQL syntax error" in evidence.response_text(snapshot_id)


# ── all-or-nothing ──────────────────────────────────────────────────────────


def test_one_unknown_request_id_rejects_the_whole_bind(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    good = _capture(traffic, "https://app.test/login")
    finding = _finding()

    with pytest.raises(EvidenceBindError) as excinfo:
        bind_finding_evidence(
            finding,
            traffic_store=traffic,
            evidence_store=evidence,
            specs=[{"request_id": good, "role": "proof"}, {"request_id": "deadbeefdeadbeef"}],
        )

    assert "deadbeefdeadbeef" in str(excinfo.value)
    # the finding is untouched -- no partial evidence list
    assert finding.evidence_refs == []
    assert finding.evidence_version == 0


def test_one_bad_role_rejects_the_whole_bind(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    finding = _finding()

    with pytest.raises(EvidenceBindError):
        bind_finding_evidence(
            finding,
            traffic_store=traffic,
            evidence_store=evidence,
            specs=[
                {"request_id": _capture(traffic, "https://app.test/a"), "role": "proof"},
                {"request_id": _capture(traffic, "https://app.test/b"), "role": "exploit"},
            ],
        )

    assert finding.evidence_refs == []
    assert finding.evidence_version == 0


def test_a_spec_without_a_request_id_is_rejected(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    finding = _finding()
    with pytest.raises(EvidenceBindError):
        bind_finding_evidence(
            finding,
            traffic_store=traffic,
            evidence_store=evidence,
            specs=[{"role": "proof"}],
        )


def test_an_empty_spec_list_is_rejected(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    with pytest.raises(EvidenceBindError):
        bind_finding_evidence(
            _finding(), traffic_store=traffic, evidence_store=evidence, specs=[]
        )


# ── append, never overwrite ─────────────────────────────────────────────────


def test_rebinding_the_same_capture_is_a_noop_duplicate(tmp_path):
    """The note a human wrote must survive a re-bind of the same snapshot."""
    traffic, evidence, _ = _stores(tmp_path)
    request_id = _capture(traffic, "https://app.test/login")
    finding = _finding()

    bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[{"request_id": request_id, "role": "proof", "note": "operator wrote this"}],
    )
    outcome = bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[{"request_id": request_id, "role": "baseline"}],
    )

    assert len(finding.evidence_refs) == 1
    assert finding.evidence_refs[0].role == "proof"
    assert finding.evidence_refs[0].note == "operator wrote this"
    assert finding.evidence_version == 1  # unchanged
    assert outcome.duplicates and not outcome.added


# ── spec parsing ────────────────────────────────────────────────────────────


def test_parse_binding_specs_accepts_bare_id_strings():
    """A model told to "cite the request_id" will send the simplest form."""
    assert parse_binding_specs(["abc123", "def456"]) == [
        {"request_id": "abc123"},
        {"request_id": "def456"},
    ]


def test_parse_binding_specs_passes_through_objects():
    assert parse_binding_specs([{"request_id": "a", "role": "proof"}]) == [
        {"request_id": "a", "role": "proof"}
    ]


def test_parse_binding_specs_rejects_a_bare_string_and_garbage():
    with pytest.raises(EvidenceBindError):
        parse_binding_specs("abc123")
    with pytest.raises(EvidenceBindError):
        parse_binding_specs([42])


def test_parse_binding_specs_treats_none_as_empty():
    assert parse_binding_specs(None) == []


# ── unbind ──────────────────────────────────────────────────────────────────


def test_unbind_removes_one_binding_and_bumps_the_version(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    finding = _finding()
    bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[
            {"request_id": _capture(traffic, "https://app.test/a"), "role": "baseline"},
            {"request_id": _capture(traffic, "https://app.test/b"), "role": "proof"},
        ],
    )
    doomed = finding.evidence_refs[0].snapshot_id

    outcome = unbind_finding_evidence(finding, snapshot_id=doomed)

    assert len(finding.evidence_refs) == 1
    assert finding.evidence_refs[0].role == "proof"
    assert finding.evidence_version == 2
    assert outcome.bindings == 1


def test_unbind_of_an_unknown_handle_changes_nothing(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    finding = _finding()
    bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[{"request_id": _capture(traffic, "https://app.test/a")}],
    )

    outcome = unbind_finding_evidence(finding, snapshot_id="ffffffffffffffff")

    assert len(finding.evidence_refs) == 1
    assert finding.evidence_version == 1  # unchanged
    assert outcome.duplicates == ("ffffffffffffffff",)


def test_unbind_without_an_identifier_is_rejected(tmp_path):
    with pytest.raises(EvidenceBindError):
        unbind_finding_evidence(_finding())


def test_unbind_matches_the_snapshot_namespace_not_a_colliding_request_id(tmp_path):
    # snapshot_id and request_id share one id space in shape (both 16-hex), so a
    # flat handle lookup let an id naming one ref's snapshot_id also match a
    # DIFFERENT ref's request_id and drop both. Unbinding must remove exactly one.
    finding = _finding()
    finding.evidence_refs = [
        EvidenceRef(kind="http_capture", request_id="r1", snapshot_id="s1"),
        EvidenceRef(kind="http_capture", request_id="s1", snapshot_id="s2"),
    ]

    unbind_finding_evidence(finding, snapshot_id="s1")

    assert [(r.snapshot_id, r.request_id) for r in finding.evidence_refs] == [("s2", "s1")]


def test_unbind_still_accepts_a_legacy_request_id_handle(tmp_path):
    # Refs bound before the snapshot layer existed carry only request_id and must
    # keep working -- including when they are the id-named argument.
    finding = _finding()
    finding.evidence_refs = [
        EvidenceRef(kind="http_capture", request_id="legacy-7"),
        EvidenceRef(kind="http_capture", request_id="keep-me", snapshot_id="s9"),
    ]

    unbind_finding_evidence(finding, snapshot_id="legacy-7")

    assert [r.request_id for r in finding.evidence_refs] == ["keep-me"]


# ── reorder ─────────────────────────────────────────────────────────────────


def test_reorder_requires_the_complete_list(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    finding = _finding()
    bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[
            {"request_id": _capture(traffic, "https://app.test/a")},
            {"request_id": _capture(traffic, "https://app.test/b")},
        ],
    )
    first = finding.evidence_refs[0].snapshot_id

    with pytest.raises(EvidenceBindError):
        reorder_finding_evidence(finding, handles=[first])

    assert finding.evidence_version == 1  # unchanged


def test_reorder_rejects_an_unknown_handle(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    finding = _finding()
    bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[{"request_id": _capture(traffic, "https://app.test/a")}],
    )
    with pytest.raises(EvidenceBindError):
        reorder_finding_evidence(finding, handles=["ffffffffffffffff"])


def test_reorder_rejects_the_same_binding_twice(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    finding = _finding()
    bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[
            {"request_id": _capture(traffic, "https://app.test/a")},
            {"request_id": _capture(traffic, "https://app.test/b")},
        ],
    )
    first = finding.evidence_refs[0].snapshot_id
    with pytest.raises(EvidenceBindError):
        reorder_finding_evidence(finding, handles=[first, first])


def test_reorder_applies_and_bumps_the_version(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    finding = _finding()
    bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[
            {"request_id": _capture(traffic, "https://app.test/a"), "role": "baseline"},
            {"request_id": _capture(traffic, "https://app.test/b"), "role": "proof"},
        ],
    )
    before = evidence_binding_signature(finding.evidence_refs)
    handles = [ref.snapshot_id for ref in reversed(finding.evidence_refs)]

    reorder_finding_evidence(finding, handles=handles)

    assert [ref.role for ref in finding.evidence_refs] == ["proof", "baseline"]
    assert finding.evidence_version == 2
    assert evidence_binding_signature(finding.evidence_refs) != before


def test_reorder_to_the_same_order_is_a_no_op(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    finding = _finding()
    bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[
            {"request_id": _capture(traffic, "https://app.test/a")},
            {"request_id": _capture(traffic, "https://app.test/b")},
        ],
    )
    handles = [ref.snapshot_id for ref in finding.evidence_refs]

    reorder_finding_evidence(finding, handles=handles)

    assert finding.evidence_version == 1  # nothing moved, nothing bumped


# ── the staleness primitive ─────────────────────────────────────────────────


def test_binding_signature_changes_when_anything_about_a_binding_changes(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    finding = _finding()
    bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[{"request_id": _capture(traffic, "https://app.test/a"), "role": "proof"}],
    )
    baseline = evidence_binding_signature(finding.evidence_refs)

    finding.evidence_refs[0].note = "an operator added context"
    assert evidence_binding_signature(finding.evidence_refs) != baseline

    finding.evidence_refs[0].role = "baseline"
    assert evidence_binding_signature(finding.evidence_refs) != baseline


def test_a_finding_with_no_bindings_has_a_stable_empty_signature():
    assert evidence_binding_signature([]) == evidence_binding_signature(None or [])


def test_findings_predating_the_version_field_still_load():
    """Backward compatibility: serialized findings have no evidence_version."""
    finding = VulnerabilityFinding(title="old", severity="Low")
    assert finding.evidence_version == 0
    assert finding.evidence_refs == []

    restored = VulnerabilityFinding.model_validate({"title": "old", "severity": "Low"})
    assert restored.evidence_version == 0


# ── the serialized shape of a ref is part of findings.json's contract ───────


def test_a_legacy_ref_still_serializes_to_its_original_keys():
    """Unchanged refs must not grow keys: findings.json is consumed externally."""
    from vulnclaw.agent.context import EvidenceRef

    ref = EvidenceRef(kind="http_capture", path="http/req-42.json", request_id="req-42")
    assert ref.model_dump(mode="json") == {
        "kind": "http_capture",
        "path": "http/req-42.json",
        "request_id": "req-42",
    }


def test_a_sandbox_ref_keeps_its_explicit_null_request_id():
    """The null is load-bearing for existing consumers; only NEW keys are dropped."""
    from vulnclaw.agent.context import EvidenceRef

    ref = EvidenceRef(kind="sandbox_output", path="sandbox/x/out.txt")
    assert ref.model_dump(mode="json") == {
        "kind": "sandbox_output",
        "path": "sandbox/x/out.txt",
        "request_id": None,
    }


def test_a_pinned_ref_serializes_its_binding_provenance(tmp_path):
    traffic, evidence, _ = _stores(tmp_path)
    finding = _finding()
    bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[
            {
                "request_id": _capture(traffic, "https://app.test/a"),
                "role": "proof",
                "note": "the payload",
            }
        ],
    )

    dumped = finding.evidence_refs[0].model_dump(mode="json")

    assert dumped["role"] == "proof"
    assert dumped["note"] == "the payload"
    assert dumped["snapshot_id"]
    assert dumped["sha256"]
    assert set(dumped) >= {"kind", "path", "request_id", "snapshot_id", "sha256", "role", "note"}


def test_a_pinned_ref_with_a_default_role_still_reports_its_role(tmp_path):
    """Once a ref is pinned its role is meaningful even at the default value."""
    traffic, evidence, _ = _stores(tmp_path)
    finding = _finding()
    bind_finding_evidence(
        finding,
        traffic_store=traffic,
        evidence_store=evidence,
        specs=[{"request_id": _capture(traffic, "https://app.test/a")}],
    )

    dumped = finding.evidence_refs[0].model_dump(mode="json")
    assert dumped["role"] == "supporting"
