"""Structured note identity fields (audit item A, 2026-10-24).

The recall surface stays the token fingerprint; ``target_ref`` /
``target_hash`` / ``identity_version`` add an IDENTITY tie-break for the
failure tokens cannot express: notes captured from goals that share one
template sentence. Exact-ref match = same challenge, full stop.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent import playbook as pb
from vulnclaw.agent.playbook import derive_target_ref, lookup_playbook

GROUND = "9b7a2c4e-1111-4111-8111-000000000001"
CHAL_A = "9b7a2c4e-1111-4111-8111-000000000002"
CHAL_B = "9b7a2c4e-1111-4111-8111-000000000003"
REF_A = f"ctf2:practice:{GROUND}:{CHAL_A}"
REF_B = f"ctf2:practice:{GROUND}:{CHAL_B}"

TEMPLATE_STEPS = (
    "## LOCK\n同一模板句子产生的两条笔记，token 完全同形，只有平台引用能区分。\n"
    "## CONFIRMED\n- 模板确认行，填充内容以满足最短长度要求。\n"
    "## ANGLES\n- [A1] 模板角度行（填充）\n"
    "- [A2] 第二条填充角度行"
)


@pytest.fixture()
def tmp_playbooks(monkeypatch, tmp_path):
    d = tmp_path / "playbooks"
    d.mkdir()
    monkeypatch.setattr(pb, "PLAYBOOKS_DIR", d)
    return d


def _save(name, fingerprint, *, target_ref="", slug=None):
    ack = pb.save_playbook(
        name=name,
        fingerprint=fingerprint,
        steps=TEMPLATE_STEPS,
        slug=slug,
        target_ref=target_ref,
    )
    assert ack.get("slug"), ack
    return ack["slug"]


class TestDeriveTargetRef:
    def test_extracts_full_ref_from_free_text(self):
        text = f"goal for {REF_A} please solve"
        assert derive_target_ref(text) == REF_A

    def test_no_ref_yields_empty(self):
        assert derive_target_ref("http://t.example", "capture the flag") == ""
        assert derive_target_ref("", "") == ""


class TestFrontmatterRoundtrip:
    def test_identity_fields_are_persisted_and_reloaded(self, tmp_playbooks):
        slug = _save("note-a", "fingerprint a", target_ref=REF_A)
        raw = (tmp_playbooks / f"{slug}.md").read_text(encoding="utf-8")
        assert "identity_version: 1" in raw
        assert f"target_ref: {REF_A}" in raw
        assert "target_hash: " in raw

        loaded = {p.slug: p for p in pb.list_playbooks()}[slug]
        assert loaded.identity_version == 1
        assert loaded.target_ref == REF_A
        assert loaded.target_hash == pb._target_ref_hash(REF_A)

    def test_legacy_note_without_fields_loads_unmodified(self, tmp_playbooks):
        legacy = (
            "---\n"
            "name: Old Note\n"
            "fingerprint: old fingerprint\n"
            "status: validated\n"
            "source: curated\n"
            "updated_at: 2026-09-01T00:00:00\n"
            "---\n\n"
            "## LOCK\n旧笔记正文。\n"
        )
        (tmp_playbooks / "old-note.md").write_text(legacy, encoding="utf-8")
        loaded = {p.slug: p for p in pb.list_playbooks()}["old-note"]
        assert loaded.identity_version == 0
        assert loaded.target_ref == ""
        assert loaded.target_hash == ""
        assert loaded.status == "validated"

    def test_legacy_frontmatter_roundtrips_without_identity_lines(self, tmp_playbooks):
        (tmp_playbooks / "plain.md").write_text(
            "---\nname: Plain\nfingerprint: fp\nstatus: draft\nsource: curated\n"
            "updated_at: t\n---\n\n## LOCK\n正文。\n",
            encoding="utf-8",
        )
        loaded = {p.slug: p for p in pb.list_playbooks()}["plain"]
        assert loaded.to_frontmatter() == {
            "name": "Plain",
            "fingerprint": "fp",
            "status": "draft",
            "source": "curated",
            "updated_at": "t",
        }


class TestIdentityTieBreak:
    def test_exact_ref_outranks_equal_token_score(self, tmp_playbooks):
        """Two notes, IDENTICAL fingerprints (the template-goal collision);
        only the ref separates them and must decide the ranking."""
        shared_fp = "capture the flag 解出附件 flag（misc forensics 取证）"
        _save("note-a", shared_fp, target_ref=REF_A, slug="note-a")
        _save("note-b", shared_fp, target_ref=REF_B, slug="note-b")

        hits = lookup_playbook(f"{shared_fp} {REF_A}", limit=2)
        assert hits, "exact-ref note must clear min_score despite token tie"
        assert hits[0]["slug"] == "note-a"

    def test_ref_note_found_with_zero_token_overlap(self, tmp_playbooks):
        """A goal sentence sharing NO token with the stored fingerprint still
        finds its own note through the ref."""
        _save("note-a", "web unserialization rce gadget chain", target_ref=REF_A)
        hits = lookup_playbook(f"{REF_A} something entirely different", limit=2)
        assert any(h["slug"] == "note-a" for h in hits), hits

    def test_refless_query_and_refless_notes_are_unchanged(self, tmp_playbooks):
        _save("note-a", "web unserialization rce gadget chain")
        hits = lookup_playbook("completely unrelated tokens", limit=2)
        assert hits == []

    def test_wrong_ref_does_not_boost(self, tmp_playbooks):
        _save("note-a", "web unserialization rce gadget chain", target_ref=REF_A)
        hits = lookup_playbook(f"unrelated words {REF_B}", limit=2)
        assert hits == []


class TestCaptureStoresRef:
    def test_capture_run_notes_persists_the_platform_ref(self, tmp_playbooks):
        ack = pb.capture_run_notes(
            target=REF_A,
            goal="capture the flag 解出附件（misc forensics 取证）",
            blackboard=None,
            final_answer="flag{structured_identity}",
        )
        assert ack and ack.get("slug"), ack
        loaded = {p.slug: p for p in pb.list_playbooks()}[ack["slug"]]
        assert loaded.target_ref == REF_A
        assert loaded.identity_version == 1
