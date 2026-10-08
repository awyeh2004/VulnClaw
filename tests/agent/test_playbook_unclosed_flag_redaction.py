"""Round-9 (2026-10-07) postmortem — redact UNTERMINATED flag literals.

``_fingerprint_flags`` only matched ``PREFIX{body}``, so a flag whose closing brace
never made it into the note stayed in cleartext. Found on a validated DASCTF note
whose ``fingerprint:`` carried ``flag{W0w_U_Ar3_V3ry_G00d_A7_C0unt1n9_`` — a real ELF
string constant, cut off by the ``strings`` output it was copied from. The read-path
gate reported the note clean, because "a flag with no closing brace" was not a shape
that existed: the store's leak detector and its scrubber shared the same blind spot.

The unclosed tier requires ``_looks_like_flag_body`` (and rejects
``_NON_FLAG_BRACE_WORDS`` prefixes) even for a KNOWN prefix, since an unclosed brace is
far more ambiguous than a closed one.
"""

import pytest

from vulnclaw.agent.playbook import _fingerprint_flags

UNCLOSED = "flag{W0w_U_Ar3_V3ry_G00d_A7_C0unt1n9_"


def test_unclosed_flag_mid_line_is_redacted():
    text = (
        "fingerprint: Linux ELF 'puzzle'; messages 'Congratulations! Your flag is: ' "
        f"/ '{UNCLOSED}'; target string 'VERYHARD' built as linked list"
    )
    out = _fingerprint_flags(text)
    assert "W0w_U_Ar3" not in out
    assert "A7_C0unt1n9" not in out
    assert "flag{…}" in out


def test_unclosed_flag_at_end_of_text_is_redacted():
    out = _fingerprint_flags(f"note: the constant is {UNCLOSED}")
    assert "W0w_U_Ar3" not in out
    assert out.endswith("flag{…}")


def test_unclosed_redaction_is_idempotent():
    """The read path relies on idempotence; applying twice must equal applying once."""
    once = _fingerprint_flags(f"a {UNCLOSED} b")
    assert _fingerprint_flags(once) == once


def test_unclosed_redaction_does_not_swallow_the_next_line():
    text = f"{UNCLOSED}\nstatus: validated"
    assert _fingerprint_flags(text) == "flag{…}\nstatus: validated"


@pytest.mark.parametrize(
    "snippet",
    [
        "body{color:red}",
        "else{return}",
        "function{returnvalue1234}",
        "media{screenonly}",
        "dict{keyvalue12}",
        # The 8-character floor: a 1-character body that carries a digit passes
        # `_looks_like_flag_body` on its own, and redacting it mangled this loop.
        "bash: for i in array{1..10}; do echo $i; done",
        # 7 characters with NO closing brace — under the unclosed-tier floor. (A
        # *closed* 7-character body is redacted by tier 2 by design; this one has no
        # brace to anchor on, so it stays.)
        "array{1234567 and then plain words",
        # A PHP POP chain from a real curated note: camelCase identifiers under braces,
        # no digit anywhere. Uppercase alone must not make these flag material —
        # `ReportRenderer{postProcessor:…` was mangled into `ReportRenderer{…}` before
        # the strong-signal rule went in.
        "4) POP chain: TemplateMetadata{renderer:ReportRenderer{postProcessor:"
        "ExportPostProcessor{archiver:LocalFileArchiver{storagePath:<path>,compressor:N}"
        ",nextProcessor:N}}}.",
    ],
)
def test_code_and_stylesheet_braces_are_untouched(snippet):
    assert _fingerprint_flags(snippet) == snippet


def test_closed_flag_redaction_is_unchanged():
    """No regression in tier 1/2 behaviour."""
    assert _fingerprint_flags("flag{abcdef123456}") == "flag{abcd…3456}"
    assert _fingerprint_flags("flag{abc}") == "flag{…}"


def test_masked_flag_form_is_stable():
    """An already-masked note must not be re-redacted into something else."""
    text = "flag{abcd…3456}"
    assert _fingerprint_flags(text) == text
