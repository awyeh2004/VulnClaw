"""Domain model leaf types — shared across all layers.

These types are pure data models with no dependencies on agent/ internals.
They were extracted from agent/context.py to eliminate reverse dependencies
where infrastructure layers (report/, plugins/, target_state/) imported
directly from the domain layer (agent/).

修改者: Nyaecho
修改时间: 2026-07-08
修改原因: 消除 V2/V3/V4 违规 — 基础设施层不应反向依赖领域层，
         将叶子类型提取到基础设施层 config/ 包中。
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, model_serializer

from vulnclaw.i18n import I18nLoader, _

# ──────────────────────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────────────────────


class PentestPhase(str, Enum):
    """Language-neutral penetration-test phase identities."""

    IDLE = "idle"
    RECON = "recon"
    VULN_DISCOVERY = "vuln_discovery"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"

    @classmethod
    def _missing_(cls, value: object) -> Optional[PentestPhase]:
        """Migrate persisted display labels without making them identities.

        Older session files serialized localized enum values. Resolve those
        values through the translation catalog at the persistence boundary;
        every newly serialized value remains a canonical id.
        """
        if not isinstance(value, str):
            return None

        normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
        for phase in cls:
            if normalized in {phase.value, phase.name.lower()}:
                return phase


        for lang in ("zh", "en"):
            translator = I18nLoader(lang)
            for phase in cls:
                if value == translator.t(f"phase.{phase.value}"):
                    return phase
        return None


def phase_canonical_id(phase: PentestPhase | str | None) -> Optional[str]:
    """Return the canonical id for a phase-like value, if valid.

    Only accepts canonical ids and enum members. Localized display labels are
    migrated to identities exclusively at the persistence boundary (see
    ``PentestPhase._missing_``); routing this runtime canonicalizer through
    that migration would leak translations back into phase identity.
    """
    if phase is None:
        return None
    if isinstance(phase, PentestPhase):
        return phase.value
    if not isinstance(phase, str):
        return None
    resolved = phase_from_canonical_id(phase)
    return resolved.value if resolved else None


def phase_from_canonical_id(canonical_id: str) -> Optional[PentestPhase]:
    """Resolve a canonical phase id, returning ``None`` for unknown ids."""
    normalized = canonical_id.strip().lower().replace("-", "_").replace(" ", "_")
    return next((phase for phase in PentestPhase if phase.value == normalized), None)


def phase_display_name(
    phase: PentestPhase | str,
    lang: Optional[str] = None,
) -> str:
    """Resolve a localized display label from a canonical phase identity."""
    canonical_id = phase_canonical_id(phase)
    if canonical_id is None:
        return str(phase)

    key = f"phase.{canonical_id}"
    if lang is None:

        return _(key)


    return I18nLoader(lang).t(key)


class StepStatus(str, Enum):
    """步骤执行状态."""

    SUCCESS = "success"  # 成功
    FAILURE = "failure"  # 失败
    SKIPPED = "skipped"  # 跳过
    INFO = "info"  # 信息收集


# ──────────────────────────────────────────────────────────────
# Pydantic Models
# ──────────────────────────────────────────────────────────────

# Typed evidence-reference kinds. ``sandbox_output`` refs land under
# ``evidence/sandbox/`` (produced by the sandbox PRD), ``http_capture`` refs are
# resolved against the pinned-evidence store via ``snapshot_id`` (falling back to
# the capture log via ``request_id`` for refs bound before pinning existed), and
# ``file`` refs point at any other artifact inside the per-run ``evidence/`` tree.
EvidenceKind = Literal["sandbox_output", "http_capture", "file"]

#: What part a piece of evidence plays in proving a finding. Without this a
#: reader cannot tell the normal-case request from the request that proved the
#: bug, which is exactly the comparison that makes an HTTP finding legible.
#: ``baseline`` = the unmodified control request; ``proof`` = the request that
#: demonstrates the vulnerability; ``verification`` = a follow-up check (e.g.
#: confirming impact); ``supporting`` = anything else (the default, so refs
#: written before roles existed keep loading unchanged).
EvidenceRole = Literal["baseline", "proof", "verification", "supporting"]

DEFAULT_EVIDENCE_ROLE: EvidenceRole = "supporting"

EVIDENCE_ROLES: tuple[EvidenceRole, ...] = (
    "baseline",
    "proof",
    "verification",
    "supporting",
)


class EvidenceRef(BaseModel):
    """A typed pointer from a finding into the per-run ``evidence/`` tree.

    ``path`` is always relative to that tree so evidence stays portable across
    machines. For an ``http_capture`` the durable handle is ``snapshot_id`` -- an
    immutable, content-addressed copy under ``evidence/blobs/`` -- while
    ``request_id`` remains the (reclaimable) capture-log id. Refs bound before
    the snapshot layer existed carry only ``request_id`` and are still resolved
    against the live store, so both shapes must keep working.

    ``role`` / ``note`` / ``sha256`` / ``captured_at`` are all defaulted: a ref
    serialized by an older build must deserialize unchanged.
    """

    kind: EvidenceKind = Field(description="sandbox_output | http_capture | file")
    path: str = Field(default="", description="Path relative to the per-run evidence/ tree")
    request_id: Optional[str] = Field(
        default=None, description="Traffic-store request id for http_capture refs"
    )
    # ── pinned-evidence handle (http_capture) ────────────────────────────
    snapshot_id: Optional[str] = Field(
        default=None, description="Immutable pinned-snapshot id for http_capture refs"
    )
    sha256: Optional[str] = Field(
        default=None, description="Content hash of the pinned response body, when present"
    )
    captured_at: Optional[str] = Field(
        default=None, description="Capture timestamp carried over from the traffic index"
    )
    # ── provenance a reader needs to interpret the pair ──────────────────
    role: EvidenceRole = Field(
        default=DEFAULT_EVIDENCE_ROLE, description="baseline | proof | verification | supporting"
    )
    note: str = Field(default="", description="Why this exchange is evidence for the finding")

    @model_serializer(mode="wrap")
    def _serialize_without_empty_provenance(self, handler: Any, info: Any) -> dict[str, Any]:
        """Omit binding fields that carry no information.

        ``evidence_refs`` is part of the published ``findings.json`` /
        SARIF-adjacent contract, and a ref can appear many times per finding, so
        the new pinned-evidence fields must not bloat every ref that never used
        them. A legacy ``http_capture`` ref therefore serializes to exactly the
        same three keys it always did, and the extra keys appear only on refs
        that are actually pinned or annotated.
        """
        data = handler(self)
        if data.get("snapshot_id") is None:
            # Not pinned: nothing about the binding extension applies.
            data.pop("snapshot_id", None)
            data.pop("sha256", None)
            data.pop("captured_at", None)
            if data.get("role") == DEFAULT_EVIDENCE_ROLE:
                data.pop("role", None)
        if not data.get("note"):
            data.pop("note", None)
        return data


def evidence_binding_signature(refs: list[EvidenceRef]) -> str:
    """Deterministic hash over a finding's ordered evidence bindings.

    Used as the staleness primitive: a report records the signature it rendered
    and can then prove whether the bindings changed underneath it. Order is part
    of the identity because the list order is the reading order in the report.
    """
    import hashlib

    hasher = hashlib.sha256()
    for ref in refs or []:
        hasher.update(
            "\x1f".join(
                [
                    str(ref.kind or ""),
                    str(ref.snapshot_id or ref.request_id or ""),
                    str(ref.role or DEFAULT_EVIDENCE_ROLE),
                    str(ref.sha256 or ""),
                    str(ref.note or ""),
                ]
            ).encode("utf-8", "replace")
        )
        hasher.update(b"\x1e")
    return hasher.hexdigest()[:16]



#: ``vuln_type`` marker for IR answer-sheet cards. ``blackboard_record_answer``
#: stores the answer sheet as Info / always-pending findings so it lives in the
#: finding store, but an answer card is NOT a vulnerability: report / SARIF /
#: verify-pending / ``--fail-on`` consumers must skip these, or a question that
#: merely names a class (e.g. "漏洞名称") is promoted to a verified finding and
#: printed in the report (round-10 finding #1).
ANSWER_CARD_VULN_TYPE = "ir-answer"


def is_answer_card(finding: Any) -> bool:
    """Whether ``finding`` (a finding model or a raw finding dict) is an answer card."""
    if isinstance(finding, dict):
        return str(finding.get("vuln_type") or "") == ANSWER_CARD_VULN_TYPE
    return str(getattr(finding, "vuln_type", "") or "") == ANSWER_CARD_VULN_TYPE


def answer_card_number(title_or_question: str) -> str:
    """Extract 'Q<n>' from an answer-card title/question, '' if absent.

    NFKC-folded first: the model drifts between full- and half-width
    punctuation ('：' vs ':', 'Ｑ' vs 'Q'), and idempotency/merge guards that
    match by number must survive that drift (round-11 finding #3).
    """
    import re
    import unicodedata

    normalized = unicodedata.normalize("NFKC", str(title_or_question or ""))
    m = re.match(r"\s*(Q\d+)\b", normalized)
    return m.group(1) if m else ""


def normalize_answer_question(text: str) -> str:
    """Canonical identity key for an answer card: NFKC + whitespace-stripped +
    case-folded question text.

    This is THE single identity mechanism for answer-card idempotency and
    merge dedup (round-12 finding F1): matching by question NUMBER alone
    silently dropped same-number/different-question cards together with their
    evidence on merge, while matching by raw title let width/punctuation
    drift reopen the duplicate channel. Every consumer — record_answer
    idempotency and merge_session_state — must key on this function.
    """
    import re
    import unicodedata

    normalized = unicodedata.normalize("NFKC", str(text or ""))
    return re.sub(r"\s+", "", normalized).lower()


def answer_card_text_without_number(text: str) -> str:
    """Relaxed fallback identity: canonical key with a leading ``Q<n>`` marker
    stripped.

    The marker is part of the stored title, so a numbered re-record of an
    unnumbered card ("Q1: 攻击者IP" vs "攻击者IP") matched neither the number
    leg (the old card carries no number) nor the text leg (the marker rides
    inside the text) — record_answer opened a second card and merge kept both
    (round14 F-C). This key removes a leading Q-number (NFKC-folded first, so
    full-width "Ｑ１：" collapses to "q1:") and delegates to
    :func:`normalize_answer_question`, keeping ONE identity mechanism that is
    merely marker-insensitive at the front. Consumers must always try the
    number leg first; this only runs when that leg misses.
    """
    import re
    import unicodedata

    normalized = unicodedata.normalize("NFKC", str(text or ""))
    stripped = re.sub(r"(?i)^\s*q\d+\s*[:.、,-]?\s*", "", normalized)
    return normalize_answer_question(stripped)


def answer_cards_same_identity(question_a: str, question_b: str) -> bool:
    """Whether two answer-card titles denote the same answer-sheet entry.

    ONE pairwise predicate shared by record_answer idempotency and
    merge_session_state (round-12 F1 number-vs-text, round-13 F5 double key,
    round-14 F-C mixed marker pair):

    - both numbered: the number IS the identity — a competition sheet has
      exactly one Q1, so the same number folds even when the wording drifted
      or differs, and DIFFERENT numbers are different rows even when the
      wording is identical ("Q1: 问题" / "Q2: 问题" are adjacent sheet rows);
    - mixed or both unnumbered: the marker is part of the stored title, so
      compare on the number-stripped text ("Q1: X" vs "X" is a re-record of
      one question, not a second card).
    """
    num_a = answer_card_number(question_a)
    num_b = answer_card_number(question_b)
    if num_a and num_b:
        return num_a == num_b
    return answer_card_text_without_number(question_a) == answer_card_text_without_number(
        question_b
    )


def answer_card_evidence_merge(existing_evidence: str, new_evidence: str) -> str:
    """Merge new evidence into an existing card's evidence, dropping duplicates.

    Returns the combined string; empty/new-identical inputs are no-ops. Used
    by both record_answer re-records and cross-session merges so incremental
    evidence is never dropped with the card.
    """
    existing = str(existing_evidence or "").strip()
    new = str(new_evidence or "").strip()
    if not new or new in existing:
        return existing
    if not existing:
        return new
    return f"{existing} | {new}"


class RetestVerdict(str, Enum):
    """复测结论三选一（A1 借鉴 ARTEX 的 ``finding_retests.verdict``）。"""

    REPRODUCED = "reproduced"
    FIXED = "fixed"
    INCONCLUSIVE = "inconclusive"


class RetestStatus(str, Enum):
    """一次复测记录的生命周期。``RUNNING`` 只属于「正在进行的那一条」。"""

    RUNNING = "running"
    COMPLETED = "completed"
    STOPPED = "stopped"


class RetestRecord(BaseModel):
    """一条 finding 的一次复测会话记录（A1 / ARTEX ``finding_retests`` 的文件式对应物）。

    ``snapshot`` 在发起复测的那一刻冻结 —— 复测期间 finding 被改写（补证据、改严重度）
    都不会移动本轮结论的依据，所以「依据什么判的」事后可复现。``verdict`` 只有第一轮
    （``round == 1``）能写；后续追问轮只能附记录，不能改写结论。
    """

    retest_id: str
    finding_id: str
    round: int = 1
    status: RetestStatus = RetestStatus.RUNNING
    verdict: str = Field(default="", description="reproduced/fixed/inconclusive，未判定时为空")
    note: str = Field(default="", description="复测人（或上层）写的一句话依据")
    snapshot: dict[str, Any] = Field(default_factory=dict, description="发起时冻结的 finding + 约束快照")
    created_at: str = ""
    updated_at: str = ""
    completed_at: Optional[str] = None

    @property
    def is_fixed(self) -> bool:
        """只有「已完成 且 结论为 fixed」才算修复 —— 复测唯一的处置翻转条件。"""

        return self.status is RetestStatus.COMPLETED and self.verdict == RetestVerdict.FIXED.value


def _now_iso(now: datetime | None = None) -> str:
    return (now or datetime.now()).isoformat()


#: The two marks ``model_post_init``'s intake quarantine leaves on an
#: unsubstantiated finding. They are named here (not inlined) because they are
#: *reversible*: a finding that is later promoted to a terminal status must end
#: up byte-identical to one constructed terminal in the first place, and
#: ``clear_intake_quarantine`` is what guarantees that.
UNVERIFIED_TITLE_PREFIX = "[未验证]"
UNVERIFIED_DESCRIPTION_MARKER = "缺少验证证据"
#: The injected advisory, minus its leading space, so it can be removed exactly.
UNVERIFIED_DESCRIPTION_NOTICE = (
    "(⚠️ 此漏洞缺少验证证据/vuln_type/修复建议三字段，"
    "LLM 上报时未附实际测试结果。请补充证据后再作为正式漏洞。)"
)


def is_unsubstantiated(finding: Any) -> bool:
    """Whether a finding carries none of the signals the intake quarantine keys on.

    ONE definition, because two consumers must agree: ``model_post_init`` decides
    whether to quarantine with it, and ``report_finding`` decides whether a
    ``verified`` claim rests on anything checkable. A bare "title + verified=true"
    report must not pass the report/SARIF gate that the quarantine exists to guard
    (2026-10-09 audit finding #1).
    """
    return not (
        getattr(finding, "evidence", "")
        or getattr(finding, "vuln_type", "")
        or getattr(finding, "remediation", "")
    )


class VulnerabilityFinding(BaseModel):
    """A single vulnerability finding."""

    title: str = Field(description="Vulnerability title")
    severity: str = Field(default="Medium", description="Critical/High/Medium/Low/Info")
    vuln_type: str = Field(default="", description="Vulnerability type (SQLi, XSS, RCE, etc.)")
    description: str = Field(default="", description="Detailed description (what/where)")
    impact: str = Field(
        default="", description="Consequence / business risk (distinct from description)"
    )
    evidence: str = Field(default="", description="Proof/evidence of the finding")
    cve: Optional[str] = Field(default=None, description="Associated CVE ID")
    cvss: Optional[float] = Field(default=None, description="CVSS base score (0.0-10.0)")
    cwe: Optional[str] = Field(default=None, description="CWE identifier, e.g. 'CWE-89'")
    remediation: str = Field(default="", description="Fix recommendation")
    # ★ Structured location — ties findings to a concrete request/route or code site.
    target: str = Field(default="", description="Owning target (ties to the Target model)")
    endpoint: Optional[str] = Field(default=None, description="Affected URL/endpoint")
    method: Optional[str] = Field(default=None, description="HTTP method, e.g. 'POST'")
    code_location: Optional[str] = Field(
        default=None, description="file:line for repo/SAST-style findings"
    )
    # ★ Typed evidence references into the per-run evidence/ tree (alongside the
    # free-text ``evidence`` blob, which is retained for backward compatibility).
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    # ★ Monotonic counter bumped every time a binding is (re)written. A report
    # records the version it rendered so a reader -- or a later re-render -- can
    # tell whether the evidence moved after the report was written. 0 means "never
    # bound", which is also what every pre-existing finding deserializes to.
    evidence_version: int = Field(default=0, description="Binding revision, bumped on (re)bind")
    # ★ Optional skill-loading provenance (reserved by the skill-loading PRD);
    # mapped into finding metadata / SARIF ``properties`` when present.
    skill_provenance: Optional[dict[str, Any]] = Field(default=None)
    subagent_provenance: Optional[dict[str, Any]] = Field(
        default=None,
        description="Owning sub-agent task identity when this finding was merged",
    )
    poc_script: Optional[str] = Field(default=None, description="Generated PoC script path")
    evidence_level: str = Field(default="L1", description="L1-L4 evidence strength")
    lifecycle_status: str = Field(
        default="candidate",
        description="candidate/pending_verification/verified/rejected/needs_manual_review",
    )

    # ★ 漏洞验证状态追踪
    verified: bool = Field(default=False, description="是否已通过 PoC 验证")
    verification_status: str = Field(
        default="pending", description="验证状态: pending/verified/rejected"
    )
    verified_at: Optional[str] = Field(default=None, description="验证时间")
    verification_note: str = Field(default="", description="验证备注/排除原因")

    # ★ 漏洞唯一标识（用于去重）
    finding_id: str = Field(default="", description="漏洞唯一标识：vuln_type + target + location")

    # ★ 复测（A1）：发起时冻结快照，结论只有第一轮能写，只有 fixed 才翻转 lifecycle_status。
    # 旧 finding 反序列化为空列表，因此这条字段是纯增量。
    retest_history: list[RetestRecord] = Field(
        default_factory=list, description="历次复测记录（含追问轮），最新在末尾"
    )

    def model_post_init(self, *args, **kwargs) -> None:
        # ★ Generate the dedup identity FIRST, from the caller-supplied fields —
        # before the intake quarantine below rewrites the description. Otherwise the
        # injected warning text (which contains "/vuln_type/…") is picked up as a
        # bogus location and every bare finding collides on the same nonsense id.
        if not self.finding_id:
            self.finding_id = self._generate_finding_id()

        # ★ Intake quarantine (no hard rejection).
        # A finding with no evidence, no vuln_type and no remediation carries no
        # substantiating signal. For ANY severity we prefix the title, annotate the
        # description, and quarantine it as ``needs_manual_review`` — it stays in run
        # state / audit trail but is excluded from the report/SARIF gate until an
        # actual evidence chain is attached. (Previously this fired for High/Critical
        # only and did not set a lifecycle status.) The whole unit is skipped for a
        # finding that is already verified/rejected — an explicitly promoted finding
        # keeps its terminal status and is never re-stamped "[未验证]".
        is_bare = is_unsubstantiated(self)
        is_terminal = self.verified or self.verification_status in ("verified", "rejected")
        if is_bare and not is_terminal:
            if not self.title.startswith(UNVERIFIED_TITLE_PREFIX):
                self.title = f"{UNVERIFIED_TITLE_PREFIX} {self.title}"
            if UNVERIFIED_DESCRIPTION_MARKER not in self.description:
                self.description = (
                    UNVERIFIED_DESCRIPTION_NOTICE
                    + (f" {self.description}" if self.description else "")
                )
            self.lifecycle_status = "needs_manual_review"

        self._sync_status_fields()

    def clear_intake_quarantine(self) -> bool:
        """Lift the intake-quarantine marks once the finding no longer warrants them.

        The quarantine is stamped at *construction* time and its own docstring
        promises that an explicitly promoted finding "keeps its terminal status
        and is never re-stamped [未验证]" — but a finding built bare and promoted
        *afterwards* (``report_finding(verified=true)``, the verifier, a
        sub-agent FINAL) used to keep the ``[未验证]`` title and the "缺少验证证据"
        advisory while its status fields said ``verified``. The report then
        printed a row marked ✅ 已验证 whose own title contradicted it, and the
        advisory contradicted it again in the body.

        Returns whether anything was removed, so callers can log it. Only the
        *marks* are undone: the caller has already decided the status, so
        ``lifecycle_status`` is left alone when the finding is terminal.
        """
        stripped = False

        if self.title.startswith(UNVERIFIED_TITLE_PREFIX):
            bare = self.title[len(UNVERIFIED_TITLE_PREFIX) :].strip()
            if bare:
                self.title = bare
                stripped = True

        if UNVERIFIED_DESCRIPTION_MARKER in self.description:
            cleaned = self.description.replace(UNVERIFIED_DESCRIPTION_NOTICE, "").strip()
            # Guard against a half-matching variant (the notice was edited after
            # the finding was written): drop the whole leading parenthetical.
            if UNVERIFIED_DESCRIPTION_MARKER in cleaned and cleaned.startswith("("):
                end = cleaned.find(")")
                if end != -1:
                    cleaned = cleaned[end + 1 :].strip()
            self.description = cleaned
            stripped = True

        if stripped and not (self.verified or self.verification_status in ("verified", "rejected")):
            # The quarantine also demoted the lifecycle; recompute it from the
            # fields the finding now carries.
            self.lifecycle_status = "candidate"
            self._sync_status_fields()

        return stripped

    def _sync_status_fields(self) -> None:
        """Keep lifecycle and evidence metadata consistent with verification state."""
        if self.verified or self.verification_status == "verified":
            self.verified = True
            self.verification_status = "verified"
            self.lifecycle_status = "verified"
            if self.evidence_level in ("", "L1", "L2", "L3"):
                self.evidence_level = "L4"
            return

        if self.verification_status == "rejected":
            self.verified = False
            self.lifecycle_status = "rejected"
            if self.evidence_level in ("", "L1", "L2"):
                self.evidence_level = "L3"
            return

        self.verified = False
        self.verification_status = "pending"
        if self.lifecycle_status == "needs_manual_review":
            if self.evidence_level in ("", "L1"):
                self.evidence_level = "L2"
            return
        if self.lifecycle_status == "candidate":
            self.evidence_level = self.evidence_level or "L1"
            return
        if self.evidence_level in ("", "L1"):
            self.lifecycle_status = "candidate"
            self.evidence_level = "L1"
        else:
            self.lifecycle_status = "pending_verification"

    def mark_manual_review(self, note: str = "", evidence_level: str = "L2") -> None:
        """Mark a finding as requiring manual review."""
        self.verified = False
        self.verification_status = "pending"
        self.lifecycle_status = "needs_manual_review"
        self.evidence_level = evidence_level
        if note:
            self.verification_note = note

    def _generate_finding_id(self) -> str:
        """Generate unique vulnerability identifier for deduplication.

        Key improvement: also checks the evidence field (populated by Layer 2
        auto-detection) in addition to description, since auto-detected findings
        put URLs/paths in evidence, not description.
        """
        location = ""
        # Try description first, then evidence (Layer 2 auto-findings put URLs there)
        for field in (self.description, self.evidence):
            if not field:
                continue
            url_match = re.search(r'https?://[^\s<>"\')\]]+', field)
            if url_match:
                location = url_match.group(0)
                break
            path_match = re.search(r'/[^\s<>"\')\]]+', field)
            if path_match:
                location = path_match.group(0)
                break

        # Use vuln_type as dedup key; location only if non-empty (avoids "SQL注入_")
        if location:
            return f"{self.vuln_type}_{location}"[:50]
        if self.vuln_type:
            return self.vuln_type[:50]
        # Bare finding (no vuln_type, no location): fall back to a title-derived key
        # so distinct placeholders stay distinct in state / findings.json audit.
        base_title = re.sub(rf"^{re.escape(UNVERIFIED_TITLE_PREFIX)}\s*", "", self.title).strip()
        return base_title[:50]

    def mark_verified(self, note: str = "", evidence_level: str = "L4") -> None:
        """标记漏洞为已验证."""
        self.verified = True
        self.verification_status = "verified"
        self.lifecycle_status = "verified"
        self.evidence_level = evidence_level
        self.verified_at = datetime.now().isoformat()
        self.verification_note = note
        # Promotion is terminal, so the "[未验证]" stamp the intake quarantine put
        # on the title/description must go: leaving it made the report print a
        # ✅ 已验证 row whose own title said 未验证 (2026-10-09 audit finding #1).
        self.clear_intake_quarantine()

    def mark_rejected(self, reason: str, evidence_level: str = "L3") -> None:
        """标记漏洞为已拒绝（误报）."""
        self.verified = False
        self.verification_status = "rejected"
        self.lifecycle_status = "rejected"
        self.evidence_level = evidence_level
        self.verified_at = datetime.now().isoformat()
        self.verification_note = reason
        # Rejected is terminal too: a bogus report should not stay titled
        # "[未验证]" once it has been explicitly ruled out.
        self.clear_intake_quarantine()


class TaskConstraints(BaseModel):
    """Structured hard constraints for an autonomous pentest task."""

    allowed_ports: list[int] = Field(default_factory=list)
    blocked_ports: list[int] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(default_factory=list)
    blocked_hosts: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    blocked_paths: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    blocked_actions: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    strict_mode: bool = Field(default=False)

    def is_empty(self) -> bool:
        return not any(
            [
                self.allowed_ports,
                self.blocked_ports,
                self.allowed_hosts,
                self.blocked_hosts,
                self.allowed_paths,
                self.blocked_paths,
                self.allowed_actions,
                self.blocked_actions,
                self.notes,
                self.strict_mode,
            ]
        )

    def add_blocked_hosts(self, hosts: Any) -> list[str]:
        """Merge hosts into ``blocked_hosts``, de-duplicating and keeping order.

        Used for the operator's hard denylist (``safety.denied_hosts``): every
        run must carry it, so the merge has to be idempotent — the same
        constraints object is re-hardened on each context reset and each
        ``apply_task_constraints`` call, and a duplicated entry would otherwise
        grow the prompt block round after round.

        Returns the entries that were actually added, so a caller can log or
        assert on the delta. Entries are normalized (lower-cased, trailing dot
        stripped) to match how ``host_in_scope`` compares them.
        """
        added: list[str] = []
        for raw in hosts or ():
            host = str(raw or "").strip().lower().rstrip(".")
            if host and host not in self.blocked_hosts:
                self.blocked_hosts.append(host)
                added.append(host)
        return added

    def to_prompt_block(self) -> str:
        """Render constraints into a stable prompt block for every round."""
        if self.is_empty():
            return ""

        lines = ["## 当前任务硬约束"]
        if self.allowed_ports:
            lines.append(f"- 仅允许测试端口: {', '.join(str(p) for p in self.allowed_ports)}")
        if self.blocked_ports:
            lines.append(f"- 禁止测试端口: {', '.join(str(p) for p in self.blocked_ports)}")
        if self.allowed_hosts:
            lines.append(f"- 仅允许测试主机: {', '.join(self.allowed_hosts)}")
        if self.blocked_hosts:
            lines.append(f"- 禁止测试主机: {', '.join(self.blocked_hosts)}")
        if self.allowed_paths:
            lines.append(f"- 仅允许测试路径: {', '.join(self.allowed_paths)}")
        if self.blocked_paths:
            lines.append(f"- 禁止测试路径: {', '.join(self.blocked_paths)}")
        if self.allowed_actions:
            lines.append(f"- 仅允许动作: {', '.join(self.allowed_actions)}")
        if self.blocked_actions:
            lines.append(f"- 禁止动作: {', '.join(self.blocked_actions)}")
        if self.notes:
            lines.append(f"- 其他限制: {'; '.join(self.notes)}")
        if self.strict_mode:
            lines.append("- 严格模式: 超出范围时只记录，不主动测试，不调用工具执行。")
        return "\n".join(lines)


class ConstraintViolationEvent(BaseModel):
    """Structured audit event for a blocked constraint violation."""

    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    kind: str = Field(default="constraint_violation")
    code: str = Field(default="", description="Stable violation code")
    severity: str = Field(default="medium", description="low | medium | high")
    source: str = Field(default="", description="command | phase | tool")
    action: str = Field(default="", description="Normalized action name")
    tool_name: str = Field(default="", description="Tool name when source=tool")
    phase: str = Field(default="", description="Current phase label")
    summary: str = Field(default="", description="Human-readable summary")
    detail: str = Field(default="", description="Detailed diagnostic message")


class StepRecord(BaseModel):
    """单个渗透步骤的结构化记录."""

    phase: PentestPhase = Field(description="所属阶段")
    round: int = Field(default=0, description="轮次")
    action: str = Field(default="", description="执行的动作（如端口扫描、漏洞探测）")
    target: str = Field(default="", description="目标（IP/URL/路径等）")
    result: str = Field(default="", description="执行结果摘要")
    status: StepStatus = Field(default=StepStatus.INFO, description="执行状态")
    detail: str = Field(default="", description="详细信息（可选）")

    def to_summary(self) -> str:
        """转换为可读的摘要行."""
        status_icon = {
            StepStatus.SUCCESS: "✅",
            StepStatus.FAILURE: "❌",
            StepStatus.SKIPPED: "⏭️",
            StepStatus.INFO: "ℹ️",
        }.get(self.status, "")

        result = self.result[:60] + ("..." if len(self.result) > 60 else "")
        return f"{status_icon} Round {self.round}: {self.action} → {result}"

    def to_brief(self) -> str:
        """转换为简短摘要（用于列表显示）."""
        return f"{self.action}: {self.result}"[:80]

    def to_legacy_string(self) -> str:
        """生成向后兼容的原始字符串格式."""
        status_icon = {
            StepStatus.SUCCESS: "✅",
            StepStatus.FAILURE: "❌",
            StepStatus.SKIPPED: "⏭️",
            StepStatus.INFO: "ℹ️",
        }.get(self.status, "")
        return f"Round {self.round}: {status_icon} {self.action} → {self.result}"

    @classmethod
    def from_legacy_string(cls, step_str: str, phase: PentestPhase = PentestPhase.IDLE) -> StepRecord:
        """从旧版字符串格式创建 StepRecord."""
        # 提取 Round 号
        round_match = re.search(r"Round\s*(\d+)", step_str)
        round_num = int(round_match.group(1)) if round_match else 0

        # 提取状态图标
        status = StepStatus.INFO
        if "✅" in step_str:
            status = StepStatus.SUCCESS
        elif "❌" in step_str:
            status = StepStatus.FAILURE
        elif "⏭️" in step_str:
            status = StepStatus.SKIPPED

        # 提取动作和结果
        action_match = re.search(r"[✅❌⏭️ℹ️]\s*(.+?)→", step_str)
        action = action_match.group(1).strip() if action_match else ""

        result_match = re.search(r"→\s*(.+)$", step_str)
        result = result_match.group(1).strip() if result_match else ""

        # 推断阶段
        inferred_phase = phase
        if "阶段切换" in step_str:
            for candidate in PentestPhase:
                if phase_display_name(candidate, "zh") in step_str:
                    inferred_phase = candidate
                    break

        return cls(
            phase=inferred_phase,
            round=round_num,
            action=action or step_str[:60],
            result=result,
            status=status,
            detail=step_str,
        )


# ──────────────────────────────────────────────────────────────
# Pure policy functions (no agent/ dependencies)
# ──────────────────────────────────────────────────────────────

PHASE_TO_ACTION: dict[PentestPhase, str] = {
    PentestPhase.RECON: "recon",
    PentestPhase.VULN_DISCOVERY: "scan",
    PentestPhase.EXPLOITATION: "exploit",
    PentestPhase.POST_EXPLOITATION: "post_exploitation",
    PentestPhase.REPORTING: "report",
}


def normalize_action_name(action: str) -> str:
    """Normalize action aliases into a shared policy namespace."""
    lowered = (action or "").strip().lower()
    aliases = {
        "run": "run",
        "recon": "recon",
        "scan": "scan",
        "exploit": "exploit",
        "post": "post_exploitation",
        "post_exploitation": "post_exploitation",
        "report": "report",
        "reporting": "report",
        "persistent": "persistent",
    }
    return aliases.get(lowered, lowered)


def validate_action_constraints(action: str, constraints: TaskConstraints) -> str | None:
    """Return a constraint violation message when a task action is out of scope."""
    if constraints.is_empty():
        return None

    normalized = normalize_action_name(action)
    allowed = [normalize_action_name(item) for item in constraints.allowed_actions]
    blocked = [normalize_action_name(item) for item in constraints.blocked_actions]

    # Composite commands (run, persistent) include all phases;
    # fine-grained enforcement happens inside the loop via phase/tool checks.
    if normalized in ("run", "persistent"):
        if normalized in blocked:
            return f"constraint_violation: command '{normalized}' is blocked by task constraints"
        return None

    if allowed and normalized not in allowed:
        return f"constraint_violation: command '{normalized}' is outside allowed actions [{', '.join(allowed)}]"

    if normalized in blocked:
        return f"constraint_violation: command '{normalized}' is blocked by task constraints"

    return None
