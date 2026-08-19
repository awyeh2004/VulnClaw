"""WebMap — shared site-structure recorder for web challenges.

Web challenges involve many pages and endpoints whose relationships (links,
forms, redirects, iframe embeds, AJAX calls) are hard to keep straight in
conversation history. Agents record pages and edges here with lightweight
tools and render a Mermaid flowchart for human review, instead of re-scraping
the same pages every round.

Sibling of ``blackboard`` (reasoning DAG): the blackboard records *findings
and directions*; WebMap records *web page structure* (URLs, methods, forms,
and how pages link to each other). Like the blackboard it lives on
``agent.runtime`` and is visible to all agents.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

_EDGE_KINDS = frozenset({"link", "form", "redirect", "iframe", "ajax", "script"})
_MAX_PAGES = 500
_MAX_EDGES = 1000


def _norm_url(url: str) -> str:
    """Best-effort URL normalization for stable node keys."""
    u = (url or "").strip().strip("'\"")
    frag = u.find("#")
    if frag != -1:
        u = u[:frag]
    return u


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class WebPage:
    """A single discovered page/endpoint in the site map."""

    url: str
    method: str = "GET"
    params: str = ""
    content_type: str = ""
    notes: str = ""
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "content_type": self.content_type,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> WebPage:
        return cls(
            url=d["url"],
            method=d.get("method", "GET"),
            params=d.get("params", ""),
            content_type=d.get("content_type", ""),
            notes=d.get("notes", ""),
            created_at=d.get("created_at", ""),
            updated_at=d.get("updated_at", ""),
        )


@dataclass
class WebEdge:
    """A directed relationship between two mapped URLs."""

    from_url: str
    to_url: str
    kind: str = "link"
    notes: str = ""
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {
            "from_url": self.from_url,
            "to_url": self.to_url,
            "kind": self.kind,
            "notes": self.notes,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> WebEdge:
        return cls(
            from_url=d["from_url"],
            to_url=d["to_url"],
            kind=d.get("kind", "link"),
            notes=d.get("notes", ""),
            created_at=d.get("created_at", ""),
        )


class WebMap:
    """Shared site-structure graph (pages + edges) for agent coordination."""

    def __init__(self):
        self._pages: dict[str, WebPage] = {}
        self._edges: list[WebEdge] = []
        self._id_by_url: dict[str, str] = {}
        self._next_id = 0
        self._overflow: list[str] = []

    # ── Internal ──────────────────────────────────────────────────────

    def _node_id(self, url: str) -> str:
        key = _norm_url(url)
        if key not in self._id_by_url:
            self._id_by_url[key] = f"u{self._next_id}"
            self._next_id += 1
        return self._id_by_url[key]

    @staticmethod
    def _escape_mermaid(text: str) -> str:
        escaped = (
            str(text)
            .replace("&", "&amp;")
            .replace('"', "&quot;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        return " ".join(escaped.split())

    # ── Query ─────────────────────────────────────────────────────────

    def pages(self) -> list[WebPage]:
        return list(self._pages.values())

    def edges(self) -> list[WebEdge]:
        return list(self._edges)

    def get_page(self, url: str) -> Optional[WebPage]:
        return self._pages.get(_norm_url(url))

    def page_count(self) -> int:
        return len(self._pages)

    def edge_count(self) -> int:
        return len(self._edges)

    def overflow_warnings(self) -> list[str]:
        return list(self._overflow)

    # ── Mutation ──────────────────────────────────────────────────────

    def upsert_page(
        self,
        url: str,
        method: str = "GET",
        params: str = "",
        content_type: str = "",
        notes: str = "",
    ) -> WebPage:
        """Record a page/endpoint. Existing fields are merged (not wiped)."""
        key = _norm_url(url)
        now = _now()
        page = self._pages.get(key)
        if page is None:
            page = WebPage(url=key, created_at=now, updated_at=now)
            self._pages[key] = page
        if method:
            page.method = method
        if params:
            page.params = params if not page.params else f"{page.params}; {params}"
        if content_type:
            page.content_type = content_type
        if notes:
            page.notes = notes if not page.notes else f"{page.notes} | {notes}"
        page.updated_at = now
        return page

    def add_link(self, from_url: str, to_url: str, kind: str = "link", notes: str = "") -> WebEdge:
        """Record a relationship. Unknown endpoints are auto-created as
        placeholder pages so the rendered graph stays connected."""
        if kind not in _EDGE_KINDS:
            raise ValueError(f"unknown edge kind '{kind}' (use one of {sorted(_EDGE_KINDS)})")
        from_key = _norm_url(from_url)
        to_key = _norm_url(to_url)
        if not from_key or not to_key:
            raise ValueError("add_link requires non-empty from_url and to_url")
        self.upsert_page(from_key)
        self.upsert_page(to_key)
        if len(self._edges) >= _MAX_EDGES:
            self._overflow.append(f"edge limit ({_MAX_EDGES}) reached; edge {from_key} -[{kind}]-> {to_key} not stored")
            raise ValueError(f"edge limit ({_MAX_EDGES}) reached")
        edge = WebEdge(from_url=from_key, to_url=to_key, kind=kind, notes=notes)
        self._edges.append(edge)
        return edge

    def reset(self) -> None:
        self._pages.clear()
        self._edges.clear()
        self._id_by_url.clear()
        self._next_id = 0
        self._overflow.clear()

    # ── Rendering ─────────────────────────────────────────────────────

    def summary(self) -> str:
        """Compact text overview of the site map for LLM context."""
        parts = ["=== WebMap (Site Structure) ==="]
        parts.append(f"[Pages ({len(self._pages)})]")
        for p in sorted(self._pages.values(), key=lambda p: p.url):
            bits = [p.method or "GET", p.url]
            if p.content_type:
                bits.append(f"type={p.content_type}")
            if p.params:
                bits.append(f"params={p.params}")
            line = "  " + " | ".join(bits)
            if p.notes:
                line += f"  ({p.notes})"
            parts.append(line)
        parts.append(f"[Edges ({len(self._edges)})]")
        for e in self._edges:
            parts.append(f"  {e.from_url} --[{e.kind}]--> {e.to_url}")
        if self._overflow:
            parts.append(f"[Overflow ({len(self._overflow)})]")
            for w in self._overflow[-5:]:
                parts.append(f"  {w}")
        parts.append("=== End WebMap ===")
        return "\n".join(parts)

    def render_mermaid(self) -> str:
        """Render the site map as a Mermaid flowchart diagram."""
        lines = ["flowchart TD"]
        for p in sorted(self._pages.values(), key=lambda p: p.url):
            nid = self._node_id(p.url)
            method = (p.method or "GET").upper()
            label = f"{method} {p.url}"
            if p.content_type:
                label += f" ({p.content_type})"
            lines.append(f'    {nid}["{self._escape_mermaid(label)}"]')
        for e in self._edges:
            fnid = self._node_id(e.from_url)
            tnid = self._node_id(e.to_url)
            line = f"    {fnid} --\"{e.kind}\"--> {tnid}"
            if e.notes:
                line = f"    {fnid} --\"{e.kind}: {self._escape_mermaid(e.notes)}\"--> {tnid}"
            lines.append(line)
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps(
            {
                "pages": [p.to_dict() for p in self._pages.values()],
                "edges": [e.to_dict() for e in self._edges],
                "overflow": self._overflow,
            },
            ensure_ascii=False,
            indent=2,
        )


def dispatch_web_map_tool(agent: "object", tool_name: str, args: dict) -> str:
    """Dispatch a WebMap tool call to the map bound to this agent."""
    wm = getattr(getattr(agent, "runtime", None), "web_map", None)
    if wm is None:
        return "[!] web_map not available on agent.runtime"

    if tool_name == "web_map_render":
        mermaid = wm.render_mermaid()
        if not wm.pages():
            return "=== WebMap (Site Structure) ===\nNo pages recorded yet. Use web_map_add as you discover endpoints."
        return f"--- Mermaid flowchart (paste into https://mermaid.live) ---\n{mermaid}\n\n--- Text summary ---\n{wm.summary()}"

    if tool_name == "web_map_summary":
        return wm.summary()

    if tool_name == "web_map_add":
        url = str(args.get("url") or "").strip()
        if not url:
            return "[!] web_map_add requires 'url'"
        try:
            page = wm.upsert_page(
                url,
                method=str(args.get("method") or "GET"),
                params=str(args.get("params") or ""),
                content_type=str(args.get("content_type") or ""),
                notes=str(args.get("notes") or ""),
            )
        except ValueError as e:
            return f"[!] web_map_add: {e}"
        return f"[web_map] page recorded: {page.method} {page.url} (params={page.params or '-'} type={page.content_type or '-'})"

    if tool_name == "web_map_link":
        from_url = str(args.get("from_url") or "").strip()
        to_url = str(args.get("to_url") or "").strip()
        kind = str(args.get("kind") or "link").strip()
        notes = str(args.get("notes") or "").strip()
        if not from_url or not to_url:
            return "[!] web_map_link requires 'from_url' and 'to_url'"
        try:
            edge = wm.add_link(from_url, to_url, kind=kind, notes=notes)
        except ValueError as e:
            return f"[!] web_map_link: {e}"
        return f"[web_map] edge recorded: {edge.from_url} -[{edge.kind}]-> {edge.to_url}"

    if tool_name == "web_map_reset":
        wm.reset()
        return "[web_map] site map cleared"

    return f"[!] unknown web_map tool: {tool_name}"
