"""Tests for the Context Vault — model-driven selective archiving.

Covers the five designs layered onto the deterministic compactor:
  1. ref tagging (invisible stable ids per message)
  2. tiered distillation (archive / distill / digest)
  3. protected zone (recent tail + final user message)
  4. restore/search without re-entering the window
  5. phantom-range protection (no new messages ⇒ reject)
"""

from __future__ import annotations

from pathlib import Path

from vulnclaw.agent.context_budget import (
    _is_vault_pointer,
    prepare_context,
)
from vulnclaw.agent.context_vault import (
    _REF_RE,
    _REF_TEMPLATE,
    VaultManager,
    _has_unarchived_message,
    _protected_range,
    assign_refs,
    ref_id,
)


def _message(role: str, content: str, **extra: object) -> dict:
    message: dict = {"role": role, "content": content}
    message.update(extra)
    return message


def _history(size: int = 40, *, tool_every: int = 5) -> list[dict]:
    """A plausible pentest transcript: user/assistant turns plus tool results.

    Generates ``size`` non-system messages (plus the system prefix) so that
    the protected tail is a small slice of the total — leaving a large
    archivable body for vault tests. Tool outputs are weighted like real
    scan results so token estimates stay realistic.
    """
    messages: list[dict] = [_message("system", "You are VulnClaw.")]
    for index in range(1, size):
        if index % tool_every == 0:
            messages.append(
                _message(
                    "assistant",
                    f"running check {index}",
                    tool_calls=[
                        {
                            "id": f"call_{index}",
                            "type": "function",
                            "function": {"name": "http_probe_batch", "arguments": "{}"},
                        }
                    ],
                )
            )
            payload = (
                f"probe output #{index}: 200 OK on /admin, server nginx. "
                "Headers: content-type text/html, server nginx/1.18, "
                "x-powered-by PHP/7.4. Body: login form, CSRF token present. "
                "Links: /admin/login, /admin/reset, /assets/app.js. "
                "Cookies: PHPSESSID=abc123, session cookie httponly. "
                "Response time 412ms, size 8842 bytes. " * 3
            )
            messages.append(
                _message(
                    "tool",
                    payload,
                    tool_call_id=f"call_{index}",
                    name="http_probe_batch",
                )
            )
        else:
            role = "user" if index % 3 == 0 else "assistant"
            messages.append(
                _message(role, f"message number {index} about target 10.0.0.{index % 9 + 1}")
            )
    return messages


def _long_message(role: str, content: str | None = None) -> dict:
    """A message with enough content to push token estimates above the floor."""
    text = content or (
        "Detailed output from the security scan. "
        + "Multiple lines of data that contribute significant token weight. "
        + "This simulates a real-world tool response that might contain dozens "
        + "of lines of port scan results, directory enumeration findings, "
        + "or HTTP response headers. " * 12
    )
    return _message(role, text)


def _history_long(size: int = 60) -> list[dict]:
    """Heavy messages that push token counts high enough to trigger compaction."""
    messages: list[dict] = [_message("system", "You are VulnClaw.")]
    for index in range(1, size):
        role = "user" if index % 3 == 0 else "assistant"
        messages.append(_long_message(role, f"Turn {index}: detailed content block {index}. " + "x" * 400))
    return messages


def _agent_with_vault(tmp_path: Path) -> object:
    """Minimal agent double exposing the ContextManager surface the vault needs."""
    from types import SimpleNamespace

    from vulnclaw.agent.context import ContextManager

    context = ContextManager(max_history=500)
    vault = VaultManager(output_dir=tmp_path)
    context.attach_vault(vault, output_dir=tmp_path)
    state = context.state
    state.target = "10.0.0.5"
    agent = SimpleNamespace(
        context=context,
        session_state=state,
        config=SimpleNamespace(
            session=SimpleNamespace(
                context_auto_compact=True,
                context_compact_trigger_ratio=0.5,
                context_compact_target_ratio=0.35,
                context_recent_message_groups=8,
                context_summary_max_tokens=3500,
                context_output_reserve_tokens=0,
                context_compaction_audit_enabled=True,
            ),
            llm=SimpleNamespace(max_context_tokens=12000, max_tokens=4096),
        ),
    )
    return agent


class TestRefTagging:
    def test_refs_are_assigned_in_order(self):
        messages = _history(30)
        registry: dict = {}
        assign_refs(messages, registry)
        ids = [ref_id(m.get("_vault_ref", "")) for m in messages]
        # System message gets ref 1, then turns 1..N
        assert ids == list(range(1, len(messages) + 1))

    def test_refs_are_stable_on_reassignment(self):
        messages = _history(20)
        registry: dict = {}
        assign_refs(messages, registry)
        first = [m["_vault_ref"] for m in messages]
        # Calling again must not change existing ids.
        assign_refs(messages, registry)
        assert [m["_vault_ref"] for m in messages] == first
        # Next id continues from current position: a new message gets the
        # highest existing id + 1.
        assign_refs([_message("user", "new")], registry)
        assert registry["_next"] == len(messages) + 1
        assert messages[-1]["_vault_ref"] == _REF_TEMPLATE.format(id=len(messages))

    def test_refs_are_invisible_to_content(self):
        messages = _history(5)
        assign_refs(messages, {})
        for message in messages:
            assert "<v#" not in str(message.get("content", ""))

    def test_ref_template_format(self):
        assert _REF_TEMPLATE.format(id=42) == "<v#00042>"
        assert _REF_RE.fullmatch("<v#00123>") is not None
        assert _REF_RE.fullmatch("not-a-ref") is None


class TestTieredDistillation:
    """Tier 1 = archive (pointer), Tier 2 = distill (summary), Tier 3 = digest."""

    def _fresh(self, size: int = 160) -> tuple[VaultManager, list[dict]]:
        vault = VaultManager()
        messages = _history(size)
        assign_refs(messages, vault.registry)
        return vault, messages

    def test_tier1_archive_replaces_range_with_pointer(self):
        vault, messages = self._fresh(160)
        ok, reason, block = vault.archive_range(
            messages, start="<v#00002>", end="<v#00012>", tier=1, topic="recon"
        )
        assert ok is True, reason
        assert block is not None
        assert block.tier == 1
        pointer = vault.render_pointer(block)
        assert pointer["role"] == "system"
        assert "[V]" in pointer["content"] and "vault_search" in pointer["content"]

    def test_tier2_distill_creates_summary_block(self):
        vault, messages = self._fresh(160)
        ok, reason, block = vault.archive_range(
            messages,
            start="<v#00002>",
            end="<v#00012>",
            tier=2,
            topic="login brute",
            summary="admin:/admin login returned 403 on all defaults",
        )
        assert ok is True, reason
        assert block is not None
        assert block.tier == 2
        assert block.summary == "admin:/admin login returned 403 on all defaults"

    def test_tier3_folds_into_aggregation(self):
        vault, messages = self._fresh(160)
        ok, reason, block = vault.archive_range(
            messages, start="<v#00002>", end="<v#00010>", tier=3, topic="recon sweep"
        )
        assert ok is True, reason
        assert block is not None and block.tier == 3

    def test_tier_defaults_to_1(self):
        vault, messages = self._fresh(160)
        ok, reason, block = vault.archive_range(
            messages, start="<v#00002>", end="<v#00012>", tier=1, topic="default tier"
        )
        assert ok is True, reason
        assert block is not None and block.tier == 1


class TestProtectedZone:
    def _fresh(self, size: int = 160) -> tuple[VaultManager, list[dict]]:
        vault = VaultManager()
        messages = _history(size)
        assign_refs(messages, vault.registry)
        return vault, messages

    def test_protected_tail_never_includes_first_message(self):
        messages = _history(160)
        start, end = _protected_range(messages, preserve_recent_messages=6, preserve_recent_tokens=3000)
        assert start > 0  # first message is never in the protected zone
        assert end == len(messages) - 1

    def test_archiving_protected_tail_blocked_without_force(self):
        vault, messages = self._fresh(160)
        # The last messages are the protected tail. With 160 turns and the
        # default 1500-token floor, protection starts somewhere in the 150s.
        protected_start, _ = _protected_range(
            messages,
            preserve_recent_messages=vault.config.preserve_recent_messages,
            preserve_recent_tokens=vault.config.preserve_recent_tokens,
        )
        first_ref = ref_id(messages[protected_start].get("_vault_ref", ""))
        ok, reason, _ = vault.archive_range(
            messages,
            start=f"<v#{first_ref:05d}>",
            end=f"<v#{first_ref + 5:05d}>",
            tier=1,
        )
        assert ok is False
        assert "protected" in reason

    def test_force_overrides_protected_tail(self):
        vault, messages = self._fresh(160)
        protected_start, _ = _protected_range(
            messages,
            preserve_recent_messages=vault.config.preserve_recent_messages,
            preserve_recent_tokens=vault.config.preserve_recent_tokens,
        )
        first_ref = ref_id(messages[protected_start].get("_vault_ref", ""))
        ok, reason, block = vault.archive_range(
            messages,
            start=f"<v#{first_ref:05d}>",
            end=f"<v#{first_ref + 5:05d}>",
            tier=1,
            force=True,
        )
        assert ok is True, reason
        assert block is not None

    def test_body_is_archivable(self):
        vault, messages = self._fresh(160)
        ok, reason, block = vault.archive_range(
            messages,
            start="<v#00002>",
            end="<v#00035>",
            tier=1,
            topic="old recon",
        )
        assert ok is True, reason
        assert block is not None


class TestRestoreAndSearch:
    def _fresh(self, size: int = 160) -> tuple[VaultManager, list[dict]]:
        vault = VaultManager()
        messages = _history(size)
        assign_refs(messages, vault.registry)
        return vault, messages

    def test_search_finds_archived_topic(self):
        vault, messages = self._fresh(160)
        vault.archive_range(
            messages,
            start="<v#00002>",
            end="<v#00010>",
            tier=2,
            topic="nmap port scan",
            summary="22 open, 80 open, 443 filtered",
        )
        hits = vault.search("nmap")
        assert hits and hits[0]["topic"] == "nmap port scan"

    def test_search_returns_empty_for_no_match(self):
        vault, messages = self._fresh(160)
        vault.archive_range(messages, start="<v#00002>", end="<v#00010>", tier=1, topic="x")
        hits = vault.search("nonexistent-topic-xyz")
        assert hits == []

    def test_restore_marks_block_as_restored(self):
        vault, messages = self._fresh(160)
        vault.archive_range(
            messages, start="<v#00002>", end="<v#00010>", tier=1, topic="old"
        )
        block = vault.blocks[-1]
        assert block.restored is False
        ok, msg, _ = vault.restore_range(messages, start="<v#00002>", end="<v#00010>")
        assert ok is True
        assert "1 block" in msg
        assert block.restored is True

    def test_stats_count_active_and_restored(self):
        vault, messages = self._fresh(160)
        vault.archive_range(messages, start="<v#00002>", end="<v#00008>", tier=1, topic="a")
        vault.archive_range(messages, start="<v#00009>", end="<v#00015>", tier=2, topic="b")
        stats = vault.stats(messages)
        assert stats["active_blocks"] == 2
        vault.restore_range(messages, start="<v#00002>", end="<v#00008>")
        stats = vault.stats(messages)
        assert stats["active_blocks"] == 1
        assert stats["restored_blocks"] == 1


class TestPhantomRange:
    def test_rejects_phantom_range(self):
        vault = VaultManager()
        messages = _history(160)
        assign_refs(messages, vault.registry)
        # Archive everything archivable.
        vault.archive_range(
            messages,
            start="<v#00002>",
            end="<v#00039>",
            tier=1,
            topic="full body",
        )
        # Now the whole body is covered — another archive on the same range is a phantom.
        ok, reason, _ = vault.archive_range(
            messages,
            start="<v#00002>",
            end="<v#00020>",
            tier=1,
            topic="phantom",
        )
        assert ok is False
        assert "no new messages" in reason

    def test_has_unarchived_message_tracks_coverage(self):
        vault = VaultManager()
        messages = _history(160)
        assign_refs(messages, vault.registry)
        # Whole list: plenty of archivable body.
        assert _has_unarchived_message(messages, []) is True
        vault.archive_range(
            messages, start="<v#00002>", end="<v#00010>", tier=1, topic="x"
        )
        # Messages outside the block remain unarchived.
        assert _has_unarchived_message(messages, vault.blocks) is True
        # Within the covered span there is nothing left to archive.
        assert _has_unarchived_message(messages, vault.blocks, lo=1, hi=9) is False
        vault.archive_range(
            messages, start="<v#00011>", end="<v#00160>", tier=1, topic="y"
        )
        # Everything outside the protected tail is now covered.
        assert _has_unarchived_message(messages, vault.blocks, lo=1, hi=159) is False


class TestPersistence:
    def test_snapshot_roundtrip(self, tmp_path: Path):
        vault = VaultManager(output_dir=tmp_path)
        messages = _history(160)
        assign_refs(messages, vault.registry)
        vault.archive_range(
            messages,
            start="<v#00002>",
            end="<v#00010>",
            tier=2,
            topic="persisted topic",
            summary="persisted summary",
        )
        # Load into a fresh manager (simulating session resume).
        restored = VaultManager(output_dir=tmp_path)
        count = restored.load_shard()
        assert count == 1
        assert restored.blocks[0].topic == "persisted topic"
        assert restored.registry["_next"] >= 10

    def test_load_shard_returns_zero_when_absent(self, tmp_path: Path):
        vault = VaultManager(output_dir=tmp_path)
        assert vault.load_shard() == 0


class TestPrepareContextIntegration:
    def test_vault_markers_survive_compaction(self, tmp_path: Path):
        agent = _agent_with_vault(tmp_path)
        messages = _history_long(60)
        assign_refs(messages, agent.context.vault.registry)
        # Archive an older range so a pointer message exists.
        ok, _, _ = agent.context.vault.archive_range(
            messages,
            start="<v#00002>",
            end="<v#00020>",
            tier=1,
            topic="old recon",
        )
        assert ok is True
        pointer = agent.context.vault.render_pointer(agent.context.vault.blocks[-1])
        messages.append(pointer)
        result = prepare_context(agent, messages, purpose="agent")
        assert result.compacted is True
        assert any(_is_vault_pointer(m) for m in result.messages)

    def test_prepare_context_untouched_when_within_budget(self, tmp_path: Path):
        agent = _agent_with_vault(tmp_path)
        messages = _history(6)
        result = prepare_context(agent, messages, purpose="agent")
        assert result.compacted is False
        assert len(result.messages) == len(messages)

    def test_digest_lists_vault_blocks(self, tmp_path: Path):
        agent = _agent_with_vault(tmp_path)
        messages = _history_long(55)
        assign_refs(messages, agent.context.vault.registry)
        agent.context.vault.archive_range(
            messages,
            start="<v#00002>",
            end="<v#00015>",
            tier=1,
            topic="recon sweep",
        )
        result = prepare_context(agent, messages, purpose="agent")
        assert result.compacted is True
        rendered = "\n".join(str(m.get("content", "")) for m in result.messages)
        assert "Vault archive index" in rendered
        assert "vault_search" in rendered
