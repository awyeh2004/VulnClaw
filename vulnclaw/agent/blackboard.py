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


class NodeStatus(str, Enum):
    PROPOSED = "proposed"
    IN_PROGRESS = "in_progress"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"


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

    def rejected_paths(self) -> list[BlackboardNode]:
        """Return rejected intents (dead ends) to avoid repeating them."""
        return [
            n for n in self._nodes.values()
            if n.type == NodeType.INTENT and n.status in (NodeStatus.REJECTED, NodeStatus.SUPERSEDED)
        ]

    def summary(self) -> str:
        """Return a compact text summary of the blackboard for LLM context."""
        parts = ["=== Blackboard (Reasoning Graph) ==="]

        facts = self.confirmed_facts()
        if facts:
            parts.append(f"[Facts ({len(facts)})]")
            for f in facts:
                ref = f"  → {f.evidence_ref}" if f.evidence_ref else ""
                parts.append(f"  ✅ {f.description}{ref}")

        active = self.active_intents()
        if active:
            parts.append(f"[Active Intents ({len(active)})]")
            for a in active:
                parts.append(f"  🔍 {a.description}")

        dead = self.rejected_paths()
        if dead:
            parts.append(f"[Dead Ends ({len(dead)})]")
            for d in dead[-5:]:
                parts.append(f"  ❌ {d.description}")

        hints = self.nodes_by_type(NodeType.HINT)
        if hints:
            parts.append(f"[Hints]")
            for h in hints:
                parts.append(f"  💡 {h.description}")

        parts.append("=== End Blackboard ===")
        return "\n".join(parts)

    def to_json(self) -> str:
        return json.dumps([n.to_dict() for n in self._nodes.values()], ensure_ascii=False, indent=2)

    # ── Mutation ───────────────────────────────────────────────────────

    def create_fact(self, description: str, parent_id: Optional[str] = None, evidence_ref: Optional[str] = None) -> BlackboardNode:
        return self._add_node(NodeType.FACT, NodeStatus.CONFIRMED, description, parent_id, evidence_ref)

    def create_intent(self, description: str, parent_id: Optional[str] = None) -> BlackboardNode:
        return self._add_node(NodeType.INTENT, NodeStatus.PROPOSED, description, parent_id)

    def create_hint(self, description: str, parent_id: Optional[str] = None) -> BlackboardNode:
        return self._add_node(NodeType.HINT, NodeStatus.CONFIRMED, description, parent_id)

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


async def dispatch_blackboard_tool(agent: "AgentContext", tool_name: str, args: dict) -> str:
    """Dispatch a blackboard tool call to the blackboard instance bound to this agent."""
    from vulnclaw.agent.runtime_state import get_or_create_blackboard

    bb = get_or_create_blackboard(agent)

    if tool_name == "blackboard_summary":
        return bb.summary()

    if tool_name == "blackboard_add_fact":
        desc = args.get("description", "")
        parent = args.get("parent_id")
        evidence = args.get("evidence_ref")
        if not desc:
            return "[!] blackboard_add_fact requires 'description'"
        node = bb.create_fact(desc, parent_id=parent, evidence_ref=evidence)
        return f"[blackboard] fact {node.id} recorded: {desc}"

    if tool_name == "blackboard_add_intent":
        desc = args.get("description", "")
        parent = args.get("parent_id")
        if not desc:
            return "[!] blackboard_add_intent requires 'description'"
        node = bb.create_intent(desc, parent_id=parent)
        return f"[blackboard] intent {node.id} declared: {desc}"

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
