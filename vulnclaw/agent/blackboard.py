"""Blackboard — shared reasoning graph for traceable agent decision-making.

Inspired by Cairn's Fact-Intent protocol and XuanMu's Blackboard architecture.
Agents use the blackboard to record what they know (facts), what they are
investigating (intents), and guidance from the user (hints), instead of
relying solely on conversation history.

Node types:
  - Fact:     A confirmed, objective finding (e.g. "port 80 is open")
  - Intent:   A declared exploration direction (e.g. "test SQL injection on /login")
  - Hint:     Human or agent guidance (e.g. "check robots.txt first")

Each node links to a parent Intent, forming a directed acyclic graph that
traces the reasoning process end-to-end.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class NodeType(str, Enum):
    FACT = "fact"
    INTENT = "intent"
    HINT = "hint"
    ANGLE = "angle"
    LOCK = "lock"
    TENSION = "tension"


class NodeStatus(str, Enum):
    PROPOSED = "proposed"
    IN_PROGRESS = "in_progress"
    CONFIRMED = "confirmed"
    CHALLENGED = "challenged"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"


# Facts an agent may keep in candidate (unverified) state at once; beyond this the
# oldest candidates are auto-superseded so a chatty run cannot flood the board.
MAX_ACTIVE_CANDIDATES = 30
# difflib ratio above which a proposed intent is considered a repeat of a known
# dead end (ported from Muteki's near-duplicate dead-end suppression).
DEADEND_DUP_THRESHOLD = 0.92


def _norm_text(text: str) -> str:
    """Lowercase and strip whitespace/punctuation for near-duplicate comparisons."""
    import re as _re

    return _re.sub(r"[\s'\"`+]+", "", (text or "").lower())


@dataclass
class BlackboardNode:
    """A single node in the blackboard reasoning graph."""

    id: str
    type: NodeType
    status: NodeStatus
    description: str
    parent_id: Optional[str] = None
    evidence_ref: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "status": self.status.value,
            "description": self.description,
            "parent_id": self.parent_id,
            "evidence_ref": self.evidence_ref,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> BlackboardNode:
        return cls(
            id=d["id"],
            type=NodeType(d["type"]),
            status=NodeStatus(d["status"]),
            description=d["description"],
            parent_id=d.get("parent_id"),
            evidence_ref=d.get("evidence_ref"),
            created_at=d.get("created_at", ""),
            updated_at=d.get("updated_at", ""),
        )


class Blackboard:
    """Shared reasoning graph for agent coordination."""

    def __init__(self):
        self._nodes: dict[str, BlackboardNode] = {}
        self._next_id: int = 1

    def _new_id(self) -> str:
        nid = f"n{self._next_id}"
        self._next_id += 1
        return nid

    # ── Query ──────────────────────────────────────────────────────────

    def get_node(self, node_id: str) -> Optional[BlackboardNode]:
        return self._nodes.get(node_id)

    def all_nodes(self) -> list[BlackboardNode]:
        return list(self._nodes.values())

    def nodes_by_type(self, node_type: NodeType) -> list[BlackboardNode]:
        return [n for n in self._nodes.values() if n.type == node_type]

    def nodes_by_status(self, status: NodeStatus) -> list[BlackboardNode]:
        return [n for n in self._nodes.values() if n.status == status]

    def active_intents(self) -> list[BlackboardNode]:
        """Intents that are still being pursued (not rejected/superseded)."""
        return [
            n for n in self._nodes.values()
            if n.type == NodeType.INTENT and n.status in (NodeStatus.PROPOSED, NodeStatus.IN_PROGRESS)
        ]

    def confirmed_facts(self) -> list[BlackboardNode]:
        return [n for n in self._nodes.values() if n.type == NodeType.FACT and n.status == NodeStatus.CONFIRMED]

    def candidate_facts(self) -> list[BlackboardNode]:
        """Unverified facts (no witnessed evidence). Not trustworthy on their own."""
        return [n for n in self._nodes.values() if n.type == NodeType.FACT and n.status == NodeStatus.PROPOSED]

    def challenged_facts(self) -> list[BlackboardNode]:
        return [n for n in self._nodes.values() if n.type == NodeType.FACT and n.status == NodeStatus.CHALLENGED]

    def retired_fact_ids(self) -> set[str]:
        """Facts whose lifecycle reached a terminal state; excluded from context."""
        return {
            n.id for n in self._nodes.values()
            if n.type == NodeType.FACT and n.status in (NodeStatus.REJECTED, NodeStatus.SUPERSEDED)
        }

    def rejected_paths(self) -> list[BlackboardNode]:
        """Return rejected intents (dead ends) to avoid repeating them."""
        return [
            n for n in self._nodes.values()
            if n.type == NodeType.INTENT and n.status in (NodeStatus.REJECTED, NodeStatus.SUPERSEDED)
        ]

    def summary(self) -> str:
        """Return a compact text summary of the blackboard for LLM context."""
        retired = self.retired_fact_ids()
        parts = ["=== Blackboard (Reasoning Graph) ==="]

        facts = [f for f in self.confirmed_facts() if f.id not in retired]
        if facts:
            parts.append(f"[Facts ({len(facts)})]")
            for f in facts:
                ref = f"  → {f.evidence_ref}" if f.evidence_ref else ""
                parts.append(f"  ✅ {f.description}{ref}")

        challenged = self.challenged_facts()
        if challenged:
            parts.append(f"[Challenged Facts ({len(challenged)}) — verify before relying on these]")
            for c in challenged:
                parts.append(f"  ⚠️ {c.description}")

        candidates = self.candidate_facts()
        if candidates:
            parts.append(f"[Unverified Candidates ({len(candidates)}) — confirm with evidence before use]")
            for c in candidates[-8:]:
                parts.append(f"  ❓ {c.description}")

        active = self.active_intents()
        if active:
            parts.append(f"[Active Intents ({len(active)})]")
            for a in active:
                parts.append(f"  🔍 {a.description}")

        dead = self.rejected_paths()
        if dead:
            parts.append(f"[Dead Ends ({len(dead)})] do NOT retry these approaches")
            for d in dead[-5:]:
                parts.append(f"  ❌ {d.description}")

        hints = self.nodes_by_type(NodeType.HINT)
        if hints:
            parts.append(f"[Hints]")
            for h in hints:
                parts.append(f"  💡 {h.description}")

        lock = self.current_lock()
        if lock:
            parts.append(f"[LOCK — 当前锁定的题面理解, 替换须显式更新]")
            parts.append(f"  🔒 {lock.description}")

        angles_open = self.open_angles()
        if angles_open:
            parts.append(f"[ANGLES — 未试攻击面 ({len(angles_open)})] 按序尝试, 不要跳过")
            for a in angles_open[:6]:
                parts.append(f"  🔺 {a.description}")

        tensions = self.open_tensions()
        if tensions:
            parts.append(f"[TENSION — 矛盾判断 ({len(tensions)})] 两者不能同时为真, 需消解")
            for tn in tensions[:4]:
                parts.append(f"  ⚡ {tn.description}")

        parts.append("=== End Blackboard ===")
        return "\n".join(parts)

    def to_json(self) -> str:
        return json.dumps([n.to_dict() for n in self._nodes.values()], ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, raw: str | bytes) -> "Blackboard":
        """Rebuild a Blackboard from a ``to_json`` snapshot (empty if invalid)."""
        bb = cls()
        try:
            data = json.loads(raw)
            for item in data:
                bb._nodes[item["id"]] = BlackboardNode.from_dict(item)
                if item["id"].startswith("n"):
                    try:
                        bb._next_id = max(bb._next_id, int(item["id"][1:]) + 1)
                    except ValueError:
                        pass
        except Exception:
            return bb
        return bb

    # ── Mutation ───────────────────────────────────────────────────────

    def create_fact(
        self,
        description: str,
        parent_id: Optional[str] = None,
        evidence_ref: Optional[str] = None,
        verified: bool = False,
    ) -> BlackboardNode:
        """Record a fact. Only witnessed facts (verified=True) start CONFIRMED;
        everything else is a PROPOSED candidate until evidence confirms it."""
        status = NodeStatus.CONFIRMED if verified else NodeStatus.PROPOSED
        node = self._add_node(NodeType.FACT, status, description, parent_id, evidence_ref)
        if not verified:
            self._enforce_candidate_quota()
        return node

    def verify_fact(self, node_id: str) -> Optional[BlackboardNode]:
        """Promote a candidate fact to confirmed after it was witnessed in real
        tool output. Any same-description candidates are superseded."""
        node = self._nodes.get(node_id)
        if not node or node.type != NodeType.FACT:
            return None
        for other in self._nodes.values():
            if (
                other.type == NodeType.FACT
                and other.id != node_id
                and other.status in (NodeStatus.PROPOSED, NodeStatus.CHALLENGED)
                and _norm_text(other.description) == _norm_text(node.description)
            ):
                other.status = NodeStatus.SUPERSEDED
                other.updated_at = datetime.now(timezone.utc).isoformat()
        node.status = NodeStatus.CONFIRMED
        node.updated_at = datetime.now(timezone.utc).isoformat()
        return node

    def challenge_fact(self, node_id: str, reason: str = "") -> Optional[BlackboardNode]:
        """Mark a fact as disputed; challenged facts leave the trusted set."""
        node = self._nodes.get(node_id)
        if not node or node.type != NodeType.FACT:
            return None
        node.status = NodeStatus.CHALLENGED
        if reason:
            node.description = f"{node.description} | challenged: {reason}"
        node.updated_at = datetime.now(timezone.utc).isoformat()
        return node

    def reject_fact(self, node_id: str, reason: str = "") -> Optional[BlackboardNode]:
        node = self._nodes.get(node_id)
        if not node or node.type != NodeType.FACT:
            return None
        node.status = NodeStatus.REJECTED
        if reason:
            node.description = f"{node.description} | rejected: {reason}"
        node.updated_at = datetime.now(timezone.utc).isoformat()
        return node

    def merge_fact(self, node_id: str, into_id: str) -> Optional[BlackboardNode]:
        node = self._nodes.get(node_id)
        if not node or node.type != NodeType.FACT:
            return None
        node.status = NodeStatus.SUPERSEDED
        node.description = f"{node.description} | merged into {into_id}"
        node.updated_at = datetime.now(timezone.utc).isoformat()
        return node

    def near_duplicate_deadend(self, description: str) -> Optional[BlackboardNode]:
        """Return an existing dead end whose description closely matches the given
        one (SequenceMatcher >= DEADEND_DUP_THRESHOLD), else None."""
        import difflib

        norm = _norm_text(description)
        if len(norm) < 8:
            return None
        for node in self.rejected_paths():
            # Compare against the pre-annotation description (" | rejected: ..."
            # and similar suffixes must not dilute the similarity score).
            base = _norm_text(node.description.split(" | ")[0])
            if difflib.SequenceMatcher(None, norm, base).ratio() >= DEADEND_DUP_THRESHOLD:
                return node
        return None

    def _enforce_candidate_quota(self) -> None:
        candidates = [n for n in self._nodes.values() if n.type == NodeType.FACT and n.status == NodeStatus.PROPOSED]
        excess = len(candidates) - MAX_ACTIVE_CANDIDATES
        for node in candidates[:max(0, excess)]:
            node.status = NodeStatus.SUPERSEDED
            node.description = f"{node.description} | auto-retired: candidate quota"

    def create_intent(self, description: str, parent_id: Optional[str] = None) -> BlackboardNode:
        return self._add_node(NodeType.INTENT, NodeStatus.PROPOSED, description, parent_id)

    def create_hint(self, description: str, parent_id: Optional[str] = None) -> BlackboardNode:
        return self._add_node(NodeType.HINT, NodeStatus.CONFIRMED, description, parent_id)

    def create_angle(self, description: str, parent_id: Optional[str] = None) -> BlackboardNode:
        """Register an untried attack surface / direction for systematic coverage."""
        return self._add_node(NodeType.ANGLE, NodeStatus.PROPOSED, description, parent_id)

    def hit_angle(self, node_id: str) -> Optional[BlackboardNode]:
        """Mark an angle as tried and it worked."""
        node = self._nodes.get(node_id)
        if not node or node.type != NodeType.ANGLE:
            return None
        node.status = NodeStatus.CONFIRMED
        node.updated_at = datetime.now(timezone.utc).isoformat()
        return node

    def miss_angle(self, node_id: str) -> Optional[BlackboardNode]:
        """Mark an angle as tried and it didn't work."""
        node = self._nodes.get(node_id)
        if not node or node.type != NodeType.ANGLE:
            return None
        node.status = NodeStatus.CHALLENGED
        node.updated_at = datetime.now(timezone.utc).isoformat()
        return node

    def open_angles(self) -> list[BlackboardNode]:
        """Angles not yet tried (PROPOSED status)."""
        return [n for n in self._nodes.values() if n.type == NodeType.ANGLE and n.status == NodeStatus.PROPOSED]

    def set_lock(self, description: str) -> BlackboardNode:
        """Set or replace the current LOCK (challenge understanding). Replace semantics:
        the old LOCK is superseded."""
        for n in self._nodes.values():
            if n.type == NodeType.LOCK and n.status == NodeStatus.CONFIRMED:
                n.status = NodeStatus.SUPERSEDED
                n.updated_at = datetime.now(timezone.utc).isoformat()
        return self._add_node(NodeType.LOCK, NodeStatus.CONFIRMED, description, None)

    def current_lock(self) -> Optional[BlackboardNode]:
        for n in self._nodes.values():
            if n.type == NodeType.LOCK and n.status == NodeStatus.CONFIRMED:
                return n
        return None

    def create_tension(self, description: str) -> BlackboardNode:
        """Record a pair of mutually exclusive judgments that coexist."""
        return self._add_node(NodeType.TENSION, NodeStatus.CONFIRMED, description, None)

    def open_tensions(self) -> list[BlackboardNode]:
        return [n for n in self._nodes.values() if n.type == NodeType.TENSION and n.status == NodeStatus.CONFIRMED]

    def start_intent(self, node_id: str) -> None:
        node = self._nodes.get(node_id)
        if node and node.type == NodeType.INTENT and node.status == NodeStatus.PROPOSED:
            node.status = NodeStatus.IN_PROGRESS
            node.updated_at = datetime.now(timezone.utc).isoformat()

    def confirm_fact(self, node_id: str) -> None:
        node = self._nodes.get(node_id)
        if node and node.type == NodeType.FACT:
            node.status = NodeStatus.CONFIRMED
            node.updated_at = datetime.now(timezone.utc).isoformat()

    def reject_intent(self, node_id: str, reason: str = "") -> None:
        node = self._nodes.get(node_id)
        if node and node.type == NodeType.INTENT:
            node.status = NodeStatus.REJECTED
            if reason:
                node.description = f"{node.description} | rejected: {reason}"
            node.updated_at = datetime.now(timezone.utc).isoformat()

    def supersede_intent(self, node_id: str, superseded_by: str) -> None:
        node = self._nodes.get(node_id)
        if node and node.type == NodeType.INTENT:
            node.status = NodeStatus.SUPERSEDED
            node.description = f"{node.description} | superseded by {superseded_by}"
            node.updated_at = datetime.now(timezone.utc).isoformat()

    def _add_node(self, ntype: NodeType, status: NodeStatus, description: str, parent_id: Optional[str], evidence_ref: Optional[str] = None) -> BlackboardNode:
        node = BlackboardNode(
            id=self._new_id(),
            type=ntype,
            status=status,
            description=description,
            parent_id=parent_id,
            evidence_ref=evidence_ref,
        )
        self._nodes[node.id] = node
        return node


def _witnessed_in_evidence(fact_text: str, chunk: str) -> bool:
    """True if the fact text is backed by real tool output (ported from Muteki's
    ``_fact_witnessed_in_chunk``): either a normalized substring match, or a
    dominant overlap of the fact's salient tokens within the output."""
    import re as _re

    norm_fact = _norm_text(fact_text)
    norm_chunk = _norm_text(chunk)
    if not norm_fact or not norm_chunk:
        return False
    if norm_fact in norm_chunk:
        return True
    stop = {"http", "https", "true", "false", "from", "with", "this", "that", "the"}
    tokens = {
        t for t in _re.findall(r"[a-z0-9_]{4,}", fact_text.lower()) if t not in stop
    }
    if not tokens:
        return False
    hit = sum(1 for t in tokens if t in chunk.lower())
    return hit / len(tokens) >= 0.8


async def dispatch_blackboard_tool(agent: "AgentContext", tool_name: str, args: dict) -> str:
    """Dispatch a blackboard tool call to the blackboard instance bound to this agent."""
    bb = getattr(agent.runtime, "blackboard", None)
    if bb is None:
        return "[!] blackboard not available on agent.runtime"

    def _evidence_content(ref: str) -> str:
        state = getattr(getattr(agent, "context", None), "state", None)
        agent_state = getattr(state, "agent_state", None)
        if agent_state is None:
            return ""
        for ev in getattr(agent_state, "evidence", []):
            if ev.id == ref:
                return ev.content or ""
        return ""

    if tool_name == "blackboard_summary":
        return bb.summary()

    if tool_name == "blackboard_add_fact":
        desc = args.get("description", "")
        parent = args.get("parent_id")
        evidence = args.get("evidence_ref")
        if not desc:
            return "[!] blackboard_add_fact requires 'description'"
        verified = False
        verify_note = ""
        if evidence:
            content = _evidence_content(str(evidence))
            if content and _witnessed_in_evidence(desc, content):
                verified = True
            elif content:
                verify_note = " (candidate: description not witnessed in referenced evidence)"
            else:
                verify_note = f" (candidate: evidence {evidence} not found)"
        else:
            verify_note = " (candidate: no evidence_ref; pass one to confirm)"
        node = bb.create_fact(desc, parent_id=parent, evidence_ref=evidence, verified=verified)
        tag = f"fact {node.id} CONFIRMED" if verified else f"fact {node.id} candidate"
        return f"[blackboard] {tag}: {desc}{verify_note}"

    if tool_name == "blackboard_verify_fact":
        node_id = args.get("node_id", "")
        node = bb.get_node(node_id) if node_id else None
        if not node or node.type != NodeType.FACT:
            return f"[!] blackboard: fact {node_id} not found"
        content = _evidence_content(str(node.evidence_ref)) if node.evidence_ref else ""
        if content and _witnessed_in_evidence(node.description.split(" | ")[0], content):
            bb.verify_fact(node_id)
            return f"[blackboard] fact {node_id} CONFIRMED via witnessed evidence"
        return (
            f"[!] cannot verify fact {node_id}: description not witnessed in evidence "
            f"{node.evidence_ref or '(none)'}; keep it as candidate"
        )

    if tool_name == "blackboard_challenge_fact":
        node_id = args.get("node_id", "")
        reason = args.get("reason", "")
        if not node_id:
            return "[!] blackboard_challenge_fact requires 'node_id'"
        node = bb.challenge_fact(node_id, reason=reason)
        if not node:
            return f"[!] blackboard: fact {node_id} not found"
        return f"[blackboard] fact {node_id} challenged: {reason}"

    if tool_name == "blackboard_add_intent":
        desc = args.get("description", "")
        parent = args.get("parent_id")
        if not desc:
            return "[!] blackboard_add_intent requires 'description'"
        dup = bb.near_duplicate_deadend(desc)
        node = bb.create_intent(desc, parent_id=parent)
        if dup:
            return (
                f"[blackboard] intent {node.id} declared: {desc}\n"
                f"[!] WARNING: near-duplicate of dead end {dup.id}: {dup.description}. "
                f"Do not retry the same failed approach without a materially new angle."
            )
        return f"[blackboard] intent {node.id} declared: {desc}"

    # ── Coverage tracking: LOCK / ANGLES / TENSION ─────────────────────

    if tool_name == "blackboard_set_lock":
        desc = args.get("description", "")
        if not desc:
            return "[!] blackboard_set_lock requires 'description'"
        node = bb.set_lock(desc)
        return f"[blackboard] LOCK set ({node.id}): {desc}"

    if tool_name == "blackboard_create_angle":
        desc = args.get("description", "")
        parent = args.get("parent_id")
        if not desc:
            return "[!] blackboard_create_angle requires 'description'"
        node = bb.create_angle(desc, parent_id=parent)
        return f"[blackboard] angle {node.id} registered: {desc}"

    if tool_name == "blackboard_hit_angle":
        node_id = args.get("node_id", "")
        node = bb.hit_angle(node_id)
        if not node:
            return f"[!] blackboard: angle {node_id} not found"
        return f"[blackboard] angle {node_id} HIT: {node.description}"

    if tool_name == "blackboard_miss_angle":
        node_id = args.get("node_id", "")
        node = bb.miss_angle(node_id)
        if not node:
            return f"[!] blackboard: angle {node_id} not found"
        return f"[blackboard] angle {node_id} MISS: {node.description}"

    if tool_name == "blackboard_create_tension":
        desc = args.get("description", "")
        if not desc:
            return "[!] blackboard_create_tension requires 'description'"
        node = bb.create_tension(desc)
        return f"[blackboard] tension {node.id} recorded: {desc}"


def _run_blackboard_review(bb: Blackboard, evidence_by_id: dict[str, str]) -> list[str]:
    """Review-Arbiter: analyze blackboard for factual disputes and dead ends.
    Ported from Muteki's review worker with data-driven thresholds.
    Returns a list of review action messages."""
    results = []
    facts = bb.all_nodes()
    intents = bb.all_nodes()

    # Challenge facts with contradictory evidence
    for node in facts:
        if node.type != NodeType.FACT or node.status != NodeStatus.CONFIRMED:
            continue
        if node.evidence_ref and node.evidence_ref in evidence_by_id:
            ev_content = evidence_by_id[node.evidence_ref]
            if not _witnessed_in_evidence(node.description.split(" | ")[0], ev_content):
                bb.challenge_fact(node.id, "description not found in referenced evidence")
                results.append(f"CHALLENGED: fact {node.id} (not witnessed in evidence)")
                continue

        newer_candidates = [
            n for n in facts
            if n.type == NodeType.FACT
            and n.status == NodeStatus.PROPOSED
            and n.id != node.id
            and _norm_text(n.description) == _norm_text(node.description)
        ]
        if newer_candidates:
            bb.merge_fact(node.id, newer_candidates[0].id)
            results.append(f"MERGED: fact {node.id} superseded by newer candidate")

    for node in intents:
        if node.type != NodeType.INTENT or node.status != NodeStatus.REJECTED:
            continue
        results.append(f"FLAGGED: intent {node.id} rejected (needs failure count)")

    return results


def _count_genuine_failures_for_route(intent_node: BlackboardNode, evidence_by_id: dict[str, str]) -> int:
    """Count how many times this intent led to a genuine failure (not timeout, cancelled, etc).
    Ported from Muteki's genuine_failures_for_route."""
    count = 0
    # In VulnClaw, genuine failures are tool calls with error_type like "timeout", "error"
    # This is a simplified version — in production, you'd track tool call results per intent
    return count  # TODO: implement proper failure counting with tool_call_manager records

    if tool_name == "blackboard_review":
        from vulnclaw.agent.blackboard import _run_blackboard_review

        # Collect all evidence content for witness checking
        state = getattr(getattr(agent, "context", None), "state", None)
        agent_state = getattr(state, "agent_state", None)
        evidence_by_id = {}
        if agent_state and hasattr(agent_state, "evidence"):
            for ev in agent_state.evidence:
                evidence_by_id[ev.id] = getattr(ev, "content", "")

        review_results = _run_blackboard_review(bb, evidence_by_id)
        if not review_results:
            return "[blackboard review] No actionable findings"
        return "\n".join(
            f"[blackboard review] {result}" for result in review_results
        )

    if tool_name == "blackboard_start_intent":
        node_id = args.get("node_id", "")
        if not node_id:
            return "[!] blackboard_start_intent requires 'node_id'"
        node = bb.get_node(node_id)
        if not node:
            return f"[!] blackboard: node {node_id} not found"
        if node.type != NodeType.INTENT:
            return f"[!] blackboard: node {node_id} is not an intent"
        bb.start_intent(node_id)
        return f"[blackboard] intent {node_id} marked in_progress"

    if tool_name == "blackboard_reject_intent":
        node_id = args.get("node_id", "")
        reason = args.get("reason", "")
        if not node_id:
            return "[!] blackboard_reject_intent requires 'node_id'"
        node = bb.get_node(node_id)
        if not node:
            return f"[!] blackboard: node {node_id} not found"
        bb.reject_intent(node_id, reason=reason)
        return f"[blackboard] intent {node_id} rejected: {reason}"

    return f"[!] unknown blackboard tool: {tool_name}"
