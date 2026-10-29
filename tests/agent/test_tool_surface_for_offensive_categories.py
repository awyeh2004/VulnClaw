"""The narrowed tool surface must carry the tools each bundle's own audience needs.

Measured 2026-10-29 (强网杯 prep): a pwn goal ("溢出这个 ELF，拿到 shell") matched
the `reverse` bundle because "elf" is its keyword, and that bundle had neither
`fetch` nor the background-cracker pair -- so a run that needs to pull a reference
or brute-force a canary/low ASLR bits could not see the tool at all. Same shape as
the 2026-10-28 analyser bug (ocr/pyc_analyze/pdf_analyze pruned on their own turf),
and the same class of silent failure: the model cannot reach for a tool that is
not in the schema.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent.builtin_tools import _infer_allowed_tools

#: Tools a narrowed run must still see, per goal shape. These are additions to
#: `_ALWAYS_KEEP_TOOLS`, which the bundle merges in automatically.
CASES = [
    (
        "溢出这个 ELF，拿到 shell",
        ["fetch", "bg_launch", "bg_result", "python_execute", "shell_command",
         "pwn_local_replay", "libc_lookup"],
    ),
    (
        "栈溢出 + ROP 打到远程",  # no "elf" / "逆向" word at all
        ["bg_launch", "fetch", "python_execute"],
    ),
    (
        "逆向 binary，找出正确的输入",
        ["fetch", "bg_launch", "ocr", "pyc_analyze", "pdf_analyze"],
    ),
    (
        "RSA 共模攻击，解出明文",
        ["crypto_decode", "python_execute"],
    ),
]


@pytest.mark.parametrize("goal,needed", CASES, ids=[c[0][:24] for c in CASES])
def test_bundle_carries_what_its_own_audience_needs(goal, needed):
    allowed = _infer_allowed_tools(goal)
    assert allowed is not None, f"{goal!r} should narrow, not keep everything"
    missing = [name for name in needed if name not in allowed]
    assert not missing, f"{goal!r} cannot see {missing}"


def test_crypto_goals_keep_fetch_pruned():
    """Pinned by tests/agent/test_builtin_tools.py: a decoding task has no network
    need, and the quiz branch exists because that default must not leak."""
    allowed = _infer_allowed_tools("解密这段 base64 密文")
    assert allowed is not None and "fetch" not in allowed


def test_pwn_and_reverse_bundles_are_the_same_set():
    """Deliberate today: which of the two matches first must not change the face."""
    pwn = _infer_allowed_tools("溢出这个 ELF，拿到 shell")
    reverse = _infer_allowed_tools("逆向这个 ELF，找出输入")
    assert pwn == reverse


def test_web_goals_keep_the_full_face():
    """No bundle claims a plain web goal any more: nothing is pruned."""
    assert _infer_allowed_tools("目标站 SQL 注入，拿 flag") is None


def test_misc_goals_keep_the_full_face():
    assert _infer_allowed_tools("附件是一张 PNG，找隐藏信息") is None