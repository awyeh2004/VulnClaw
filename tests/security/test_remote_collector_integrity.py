"""Regressions for the two defects B3 (real SSH) exposed.

Both were invisible to the original 50 offline unit tests, and both were silent
in production -- which is exactly why they are pinned here with a test each.

Defect 1: nested-quote syntax error in the generated collector
-------------------------------------------------------------
``_collector_script`` recorded each approved command with::

    echo "### command: {cmd}"

For the 11 of 33 commands that themselves contain a double quote, the inner quote
closes the outer string and the whole script fails to parse. Measured on a real
target: ``sh -n`` reported ``Syntax error: end of file unexpected``, the script
aborted with exit 2 after the first 4 sections, and the operator only saw
"no archive produced". So 11 sections silently collected nothing on EVERY target.

Defect 2: cleanup confirmation read the wrong stream
----------------------------------------------------
``run_command_capture`` returns ``(stdout_bytes, stderr_text, error)``. The
confirmation tested ``"CLEANED" not in cleanup_txt`` where ``cleanup_txt`` was the
STDERR text -- but ``echo CLEANED`` writes to STDOUT. Measured:

    stdout = b'CLEANED\\n'   stderr = ''   -> check reported failure

So every collection warned "may still exist on the target" while the target was
verified clean. A permanent false alarm trains the operator to ignore the line,
which defeats the check for the case where something really is left behind.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from vulnclaw.agent import remote
from vulnclaw.agent.remote import (
    _collector_script,
    collector_commands,
    validate_collector_commands,
)


class TestGeneratedScriptIsParseable:
    """Defect 1. The script must survive a real shell parser."""

    def test_generated_script_contains_no_raw_command_echo(self):
        """The dangerous construct specifically must be gone."""
        script = _collector_script("/tmp/.ir-collect-t")
        offenders = [
            line for line in script.splitlines()
            if line.strip().startswith('echo "### command')
        ]
        assert offenders == [], (
            "raw commands must not be interpolated into a double-quoted echo; "
            f"found {len(offenders)} such line(s)"
        )

    def test_every_command_is_recorded_as_a_comment(self):
        """Positive side: the approved commands ARE still visible in the script."""
        script = _collector_script("/tmp/.ir-collect-t")
        documented = [l for l in script.splitlines() if "# approved command:" in l]
        assert len(documented) == len(collector_commands())

    def test_commands_with_double_quotes_exist_in_the_set(self):
        """Guard the guard: if no command had a quote, the bug could not manifest
        and this whole file would be vacuous."""
        quoted = [n for n, c in collector_commands() if '"' in c]
        assert len(quoted) >= 5, (
            f"expected several commands containing double quotes, got {quoted}"
        )

    @pytest.mark.parametrize("shell", [["sh", "-n"], ["dash", "-n"], ["bash", "-n"]])
    def test_shell_syntax_check_passes(self, shell, tmp_path):
        """Parse the generated script with a real shell parser.

        Skips when the shell is unavailable. NOTE: on this machine `bash` resolves
        to a WSL relay that fails at exec with "No such file or directory" and
        returns 1 -- that is an AVOIDED shell, not a script defect, so it is
        skipped on the message rather than counted as a failure (measuring the
        difference matters: a false failure here would hide a real one later).
        """
        script = _collector_script("/tmp/.ir-collect-t")
        path = tmp_path / "collector.sh"
        path.write_text(script, encoding="utf-8", newline="\n")
        try:
            proc = subprocess.run(
                [*shell, str(path)], capture_output=True, timeout=30
            )
        except FileNotFoundError:
            pytest.skip(f"{shell[0]} not available")

        # Decode BOTH ways before deciding anything. On Windows ``bash`` is the
        # WSL relay (C:\windows\system32\bash.exe) and its "cannot create
        # instance" error is UTF-16LE: a UTF-8 decode yields NUL-laced garbage, the
        # markers below never match, and an *unavailable* shell turns into a
        # spurious "the generated script is broken" failure — the exact false
        # failure this helper exists to avoid, and one that would hide a real
        # syntax defect later.
        raw = (proc.stdout or b"") + (proc.stderr or b"")
        blob = raw.decode("utf-8", "replace")
        if "\x00" in blob:
            blob = raw.decode("utf-16-le", "replace")
        blob = blob.replace("\x00", "")

        unavailable_markers = (
            "execvpe",
            "No such file or directory",
            "WSL",
            "is not recognized",
            "CreateInstance",
            "E_ACCESSDENIED",
            "Bash/Service",
        )
        if proc.returncode != 0 and (
            not blob.strip() or any(m in blob for m in unavailable_markers)
        ):
            pytest.skip(f"{shell[0]} could not be executed here: {blob.strip()[:120]}")

        assert proc.returncode == 0, (
            f"{' '.join(shell)} rejected the generated script:\n{blob}"
        )

    def test_no_transport_delimiter_leaks_into_the_script(self):
        """The script travels inside a here-doc; containing the delimiter would
        terminate it early and execute the remainder as shell."""
        assert "__VULNCLAW_COLLECTOR__" not in _collector_script("/tmp/.ir-collect-t")


class TestCommandInvariants:
    """The invariants that make the comment-based recording safe."""

    def test_current_command_set_satisfies_its_invariants(self):
        assert validate_collector_commands() == []

    def test_multiline_command_is_rejected(self, monkeypatch):
        monkeypatch.setattr(
            remote, "collector_commands",
            lambda: [("ok", "id"), ("bad", "echo one\necho two")],
        )
        problems = remote.validate_collector_commands()
        assert any("multiple lines" in p for p in problems)

    def test_duplicate_section_name_is_rejected(self, monkeypatch):
        monkeypatch.setattr(
            remote, "collector_commands",
            lambda: [("dup", "id"), ("dup", "whoami")],
        )
        assert any("duplicate" in p for p in remote.validate_collector_commands())

    def test_unsafe_section_name_is_rejected(self, monkeypatch):
        monkeypatch.setattr(
            remote, "collector_commands",
            lambda: [("has space", "id")],
        )
        assert any("must be [A-Za-z0-9_]+" in p for p in remote.validate_collector_commands())


class TestCleanupConfirmationReadsStdout:
    """Defect 2. The check must look where the marker actually goes."""

    @staticmethod
    def _result():
        return remote.CollectorResult(alias="a", hostname="h")

    async def test_cleanup_success_is_recognised(self, monkeypatch, tmp_path):
        """stdout='CLEANED\\n', stderr='' must count as confirmed."""
        monkeypatch.setattr(
            remote, "_collector_script", lambda *a, **k: "#!/bin/sh\ntrue\n"
        )
        monkeypatch.setattr(remote, "validate_collector_commands", lambda: [])

        calls: list[str] = []

        def fake_capture(host, alias, command, **kwargs):
            calls.append(command)
            if "base64" in command:  # archive download
                import base64 as b64
                blob = b64.b64encode(_make_tar())
                return blob, "", ""
            if command.startswith("rm -f"):
                # THE point: marker on stdout, nothing on stderr.
                return b"CLEANED\n", "", ""
            return b"", "", ""

        monkeypatch.setattr(remote, "run_command_capture", fake_capture)

        cfg = _cfg()
        host, alias = remote.resolve_host(cfg, "drill")
        out = await remote._do_collect(
            _agent(cfg), cfg, host, alias,
            {"local_dir": str(_tmpdir(tmp_path))}, 10.0,
        )
        assert "may still exist on the target" not in out, out
        assert "left clean" in out or "Target left clean" in out, out

    async def test_cleanup_missing_marker_is_reported(self, monkeypatch, tmp_path):
        """Negative case: if CLEANED never appears, we MUST warn."""
        monkeypatch.setattr(remote, "_collector_script", lambda *a, **k: "#!/bin/sh\ntrue\n")
        monkeypatch.setattr(remote, "validate_collector_commands", lambda: [])

        def fake_capture(host, alias, command, **kwargs):
            if "base64" in command:
                import base64 as b64
                return b64.b64encode(_make_tar()), "", ""
            if command.startswith("rm -f"):
                return b"", "", ""  # marker absent
            return b"", "", ""

        monkeypatch.setattr(remote, "run_command_capture", fake_capture)

        cfg = _cfg()
        host, alias = remote.resolve_host(cfg, "drill")
        out = await remote._do_collect(
            _agent(cfg), cfg, host, alias, {"local_dir": str(_tmpdir(tmp_path))}, 10.0
        )
        assert "cleanup did not confirm" in out, out


# ── helpers ──────────────────────────────────────────────────────────────


def _make_tar() -> bytes:
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b"synthetic"
        info = tarfile.TarInfo("col/01-identity.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _tmpdir(tmp_path: Path | None = None) -> Path:
    """A fresh local directory for the unpack.

    Prefers pytest's ``tmp_path``: ``tempfile.mkdtemp`` lands under the harness
    TEMP (redirected to ``.test-tmp`` here), and this sandbox denies creating a
    *subdirectory* inside such a directory — which failed these tests for a reason
    that has nothing to do with the cleanup logic they check.
    """
    if tmp_path is not None:
        target = tmp_path / "unpack"
        target.mkdir(parents=True, exist_ok=True)
        return target
    import tempfile

    return Path(tempfile.mkdtemp(prefix="b3reg-"))


def _cfg():
    from types import SimpleNamespace

    return SimpleNamespace(
        remote=SimpleNamespace(
            hosts={"drill": {"hostname": "127.0.0.1", "port": 2200, "username": "u"}},
            connect_timeout_s=5.0,
            command_timeout_s=10.0,
        ),
        safety=SimpleNamespace(permission_mode="full_access", trusted_commands=[]),
        gcs=SimpleNamespace(tools_enabled=False),
        competition=SimpleNamespace(allow_flag_submission=False),
    )


def _agent(cfg):
    from types import SimpleNamespace

    return SimpleNamespace(config=cfg, runtime=SimpleNamespace(run_id="t"))
