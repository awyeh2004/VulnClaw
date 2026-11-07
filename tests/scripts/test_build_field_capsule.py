"""The offline field capsule must stay loadable from a ``file://`` URL.

Why this exists (measured 2026-10-30): the capsule is the fallback for an on-site
competition where the operator gets a locked-down PC and nothing but a browser --
no Python, no network beyond the platform, no way to run VulnClaw. That means the
whole artifact is ONE html file, and two failure modes are silent:

* a ``</script>`` sequence inside any note closes the script block early and the
  rest of the document is rendered as text -- the page still "opens", it just has
  no data and no controls;
* a note containing a lone ``</`` breaks the same way in some parsers.

Neither is caught by reading the file, so the checks below run the builder and
inspect the payload.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts" / "build_field_capsule.py"

_PAYLOAD_RE = re.compile(r"const DOCS = (.*?);\n", re.S)


def _build(tmp_path: Path) -> str:
    """Build with an explicit playbook dir.

    The builder defaults to this profile's store, which the suite redirects to a
    sandbox config dir (root conftest). Asserting on the presence of a playbook
    therefore depended on leftovers from earlier runs: a fresh checkout has an
    empty store and the "docs contain a playbook" assertion failed. Seed one.
    """
    playbooks = tmp_path / "playbooks"
    playbooks.mkdir()
    (playbooks / "seeded-note.md").write_text(
        "---\nname: seeded-note\nstatus: validated\n---\n\nseeded body\n",
        encoding="utf-8",
    )
    out = tmp_path / "capsule.html"
    proc = subprocess.run(
        [
            sys.executable, "-X", "utf8", str(SCRIPT), "--out", str(out),
            "--playbook-dir", str(playbooks),
        ],
        capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    return out.read_text(encoding="utf-8")


def test_capsule_embeds_no_script_tag_breakout(tmp_path):
    html = _build(tmp_path)
    match = _PAYLOAD_RE.search(html)
    assert match, "payload not found -- the template variable was renamed?"
    payload = match.group(1)
    assert "</script>" not in payload.lower(), "a note closes the script block early"
    assert "</" not in payload, "an unescaped </ sequence would truncate parsing"


def test_capsule_payload_is_valid_json_with_content(tmp_path):
    html = _build(tmp_path)
    payload = _PAYLOAD_RE.search(html).group(1)
    # The escaping applied by the builder must still parse as JSON.
    docs = json.loads(payload.replace("<\\/", "</"))
    assert isinstance(docs, list) and len(docs) > 100, f"only {len(docs)} documents"
    kinds = {doc["kind"] for doc in docs}
    assert {"skill", "playbook"} <= kinds, kinds
    for doc in docs[:50]:
        assert doc["title"], doc
        assert doc["body"] is not None


# ── defanging must stay surgical ─────────────────────────────────────────────
# The capsule is a knowledge pack: AV rejects the whole download when it contains a
# literal webshell. The first implementation replaced `eval(`/`system(` everywhere
# and destroyed ordinary examples (`model.eval()`, `os.system(...)`, template
# syntax), so the defanging is now line-scoped to payload-shaped lines.

def _load_builder():
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_field_capsule", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _seed_skill_tree(skills: Path) -> None:
    (skills / "_shared" / "references").mkdir(parents=True)
    (skills / "_shared" / "references" / "ctf-mechanisms.md").write_text(
        "ctf submission", encoding="utf-8"
    )
    (skills / "_shared" / "references" / "operational-mechanisms.md").write_text(
        "operational", encoding="utf-8"
    )
    (skills / "CTF-SKILL-MECHANISM-UPDATE.md").write_text("ctf update", encoding="utf-8")
    for name, body in (
        ("ctf-web", "ctf web skill"),
        ("ctf-crypto", "ctf crypto skill"),
        ("competition-mode", "competition skill"),
    ):
        (skills / "specialized" / name / "references").mkdir(parents=True)
        (skills / "specialized" / name / "SKILL.md").write_text(body, encoding="utf-8")
        (skills / "specialized" / name / "references" / "extra.md").write_text(
            f"{body} ref", encoding="utf-8"
        )
    (skills / "specialized" / "web-pentest").mkdir(parents=True)
    (skills / "specialized" / "web-pentest" / "SKILL.md").write_text(
        "web pentest skill", encoding="utf-8"
    )


def test_production_capsule_excludes_ctf_only_skill_docs(tmp_path, monkeypatch):
    builder = _load_builder()
    skills = tmp_path / "skills"
    _seed_skill_tree(skills)
    monkeypatch.setattr(builder, "SKILLS_DIR", skills)
    monkeypatch.setenv("VULNCLAW_PROFILE", "prod")

    bodies = {doc["body"] for doc in builder._collect_skills()}

    assert "ctf submission" not in bodies
    assert "ctf update" not in bodies
    # A whole CTF skill directory goes, references included -- not just SKILL.md.
    for leaked in ("ctf web skill", "ctf web skill ref", "ctf crypto skill",
                   "competition skill", "competition skill ref"):
        assert leaked not in bodies, leaked


def test_production_capsule_keeps_shared_use_skills(tmp_path, monkeypatch):
    builder = _load_builder()
    skills = tmp_path / "skills"
    _seed_skill_tree(skills)
    monkeypatch.setattr(builder, "SKILLS_DIR", skills)
    monkeypatch.setenv("VULNCLAW_PROFILE", "prod")

    bodies = {doc["body"] for doc in builder._collect_skills()}
    assert "operational" in bodies
    assert "web pentest skill" in bodies


def test_ctf_capsule_keeps_ctf_only_skill_docs(tmp_path, monkeypatch):
    builder = _load_builder()
    skills = tmp_path / "skills"
    _seed_skill_tree(skills)
    monkeypatch.setattr(builder, "SKILLS_DIR", skills)
    monkeypatch.setenv("VULNCLAW_PROFILE", "ctf")

    bodies = {doc["body"] for doc in builder._collect_skills()}
    assert {"ctf submission", "ctf update", "ctf web skill", "competition skill"} <= bodies


def test_unset_profile_keeps_ctf_docs(tmp_path, monkeypatch):
    """Only an explicit prod filters; an unset variable stays the CTF default."""
    builder = _load_builder()
    skills = tmp_path / "skills"
    _seed_skill_tree(skills)
    monkeypatch.setattr(builder, "SKILLS_DIR", skills)
    monkeypatch.delenv("VULNCLAW_PROFILE", raising=False)

    bodies = {doc["body"] for doc in builder._collect_skills()}
    assert "ctf submission" in bodies
    assert "ctf web skill" in bodies


def test_ordinary_code_examples_are_not_rewritten():
    builder = _load_builder()
    text = (
        "```python\n"
        "model.eval()\n"
        "assert(os.system('ls') == 0)\n"
        "```\n"
    )
    assert builder._defang_shell_payloads(text) == text


def test_webshell_payloads_are_defanged():
    builder = _load_builder()
    text = "<?php @eval($_POST['cmd']); ?>\n"
    out = builder._defang_shell_payloads(text)
    assert "<?php" not in out
    assert "eval(" not in out
    assert "[?php" in out


def test_multiline_php_block_is_defanged_until_the_close_tag():
    builder = _load_builder()
    text = (
        "```php\n"
        "<?php\n"
        "$c = base64_decode($_POST['x']);\n"
        "system($c);\n"
        "?>\n"
        "```\n"
    )
    out = builder._defang_shell_payloads(text)
    assert "<?php" not in out
    assert "system(" not in out


def test_xml_declaration_is_left_alone():
    builder = _load_builder()
    text = '<?xml version="1.0"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'
    assert builder._defang_shell_payloads(text) == text
