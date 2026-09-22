"""Child-output decoding must not depend on the parent's locale.

Measured defect (locale=cp936, Chinese Windows). A *correct* generated PoC whose
stdout contained one byte invalid for cp936 produced:

    returncode 0, stdout None
    -> `result.stdout + result.stderr` raised TypeError
    -> the generic handler returned -3
    -> parse_result reported EXECUTION_ERROR

i.e. a verified vulnerability was reported as "the PoC failed to run", silently.
The bug is data-dependent -- whether a byte decodes depends on it and its
neighbour (``b'\\xa8\\xa8'`` is valid cp936, ``b'\\xa8 '`` is not) -- which is why
it never showed up in tests.
"""

from __future__ import annotations

import locale
import subprocess
import sys
import textwrap

import pytest

from vulnclaw.utils.subprocess_text import (
    CHILD_ENCODING,
    combine_output,
    run_text,
)

# A byte that is an incomplete multibyte sequence under cp936.
def _emit_bytes(expr: str) -> str:
    return textwrap.dedent(
        f"""
        import sys
        sys.stdout.buffer.write({expr})
        sys.stdout.buffer.flush()
        """
    )


class TestRunTextNeverDependsOnLocale:
    def test_ascii_output_is_unchanged(self):
        r = run_text([sys.executable, "-c", "print('ok')"], timeout=30)
        assert r.returncode == 0
        assert r.stdout.strip() == "ok"

    def test_undecodable_bytes_do_not_lose_the_stream(self):
        """The core regression: the marker must survive, and stdout must be str."""
        r = run_text(
            [sys.executable, "-c", _emit_bytes(r"b'[CONFIRMED] sqli \x81 verified'")],
            timeout=30,
        )
        assert r.returncode == 0
        assert r.stdout is not None, "stdout must never be None"
        assert "[CONFIRMED]" in r.stdout, f"marker lost: {r.stdout!r}"
        assert "\ufffd" in r.stdout, "the bad byte should become U+FFFD, not vanish"

    def test_utf8_output_round_trips(self):
        code = _emit_bytes("'验证成功'.encode('utf-8')")
        r = run_text([sys.executable, "-c", code], timeout=30)
        assert r.returncode == 0
        assert "验证成功" in (r.stdout or "")

    def test_encoding_is_utf8_regardless_of_locale(self, monkeypatch):
        """Guard the contract itself, not just today's observed behaviour."""
        assert CHILD_ENCODING == "utf-8"
        captured: dict = {}
        real_run = subprocess.run

        def spy(args, **kwargs):
            captured.update(kwargs)
            return real_run(args, **kwargs)

        monkeypatch.setattr("vulnclaw.utils.subprocess_text.subprocess.run", spy)
        run_text([sys.executable, "-c", "pass"], timeout=30)
        assert captured["encoding"] == "utf-8"
        assert captured["errors"] == "replace"
        assert captured["text"] is True

    def test_caller_cannot_reintroduce_the_locale_dependency(self):
        """text/encoding/errors are forced, so a caller passing them is harmless."""
        r = run_text(
            [sys.executable, "-c", _emit_bytes(r"b'\\x81 ok'")],
            text=False,  # would be bytes-mode if honoured
            encoding="cp936",
            errors="strict",
            timeout=30,
        )
        assert isinstance(r.stdout, str)
        assert "ok" in r.stdout

    def test_capture_output_is_only_defaulted(self, tmp_path):
        """A caller redirecting streams keeps control."""
        target = tmp_path / "out.txt"
        with open(target, "w", encoding="utf-8") as fh:
            r = run_text([sys.executable, "-c", "print('to-file')"], stdout=fh, timeout=30)
        assert r.returncode == 0
        assert target.read_text(encoding="utf-8").strip() == "to-file"

    def test_kwargs_pass_through(self, tmp_path):
        r = run_text(
            [sys.executable, "-c", "import os,sys; print(os.getcwd())"],
            cwd=str(tmp_path),
            timeout=30,
        )
        assert r.returncode == 0
        assert str(tmp_path) in (r.stdout or "")

    def test_timeout_still_raises(self):
        with pytest.raises(subprocess.TimeoutExpired):
            run_text([sys.executable, "-c", "import time; time.sleep(10)"], timeout=1)


class TestCombineOutput:
    def test_joins_both(self):
        r = subprocess.run(
            [sys.executable, "-c", "import sys; print('o'); print('e', file=sys.stderr)"],
            capture_output=True, text=True, encoding="utf-8", timeout=30,
        )
        combined = combine_output(r)
        assert "o" in combined and "e" in combined

    def test_none_streams_do_not_raise(self):
        """A bare `+` on None was the second half of the verifier defect."""
        r = subprocess.CompletedProcess(args=["x"], returncode=0, stdout=None, stderr=None)
        assert combine_output(r) == ""

    def test_one_none_stream(self):
        r = subprocess.CompletedProcess(args=["x"], returncode=0, stdout="out", stderr=None)
        assert combine_output(r) == "out"
        r2 = subprocess.CompletedProcess(args=["x"], returncode=0, stdout=None, stderr="err")
        assert combine_output(r2) == "err"


class TestVerifierEndToEnd:
    """The defect as it actually reached the user: a verified vuln marked unverified."""

    def test_confirmed_marker_survives_an_undecodable_byte(self):
        from vulnclaw.agent.exec_gate import get_execution_gate, reset_execution_gate
        from vulnclaw.report.verifier import VerificationResult, VerifierExecutor

        reset_execution_gate()
        get_execution_gate().install_sync_confirm_hook(lambda _req: True)

        poc = _emit_bytes(r"b'[CONFIRMED] sqli \x81 verified\n'")
        rc, output = VerifierExecutor.execute_poc(poc, timeout=30)
        verdict = VerifierExecutor.parse_result(output, rc)

        assert "[CONFIRMED]" in output, f"marker lost, output={output!r}"
        assert verdict == VerificationResult.VULN_CONFIRMED, (
            f"a confirmed PoC was classified {verdict} (rc={rc})"
        )
