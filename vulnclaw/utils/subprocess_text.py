"""Decode a child process's output without trusting the parent's locale.

The hazard
----------
``subprocess.run(..., text=True)`` decodes the child's pipes with
``locale.getpreferredencoding()`` -- **cp936** on a Chinese Windows box. Any byte
sequence that is invalid for that codec makes the subprocess *reader thread* raise
``UnicodeDecodeError``. CPython swallows that exception, and the caller then sees:

    returncode == 0        (the child really did succeed)
    stdout     == None     (not "" -- None)

Measured, on a correct generated PoC whose banner contained one bad byte:

    [CONFIRMED] marker PoC, ASCII only     -> rc=0   output ok  -> VULN_CONFIRMED
    same PoC + b'\\x81 '                    -> rc=-3  output lost -> EXECUTION_ERROR

and the -3 came from a *second* landmine: ``result.stdout + result.stderr`` raises
``TypeError: unsupported operand type(s) for +: 'NoneType' and 'str'`` once the
decode has failed. So a verified vulnerability was reported as "the PoC failed to
run", with no error visible to the operator.

This is data-dependent, which is why it never showed up in tests: whether a given
byte is a valid cp936 sequence depends on the byte *and* its neighbour
(``b'\\xa8\\xa8'`` decodes fine, ``b'\\xa8 '`` does not). Same code, opposite
outcome.

What to do instead
------------------
Always pin the codec, and never let decoding decide success:

* :func:`run_text` passes ``encoding="utf-8"`` and ``errors="replace"``, so
  undecodable bytes become U+FFFD instead of destroying the whole stream, and
  stdout/stderr are always ``str`` (never ``None``);
* :func:`combine_output` concatenates None-safely, for callers that join them.

Rationale for UTF-8 and ``replace``: the alternative to "slightly mangled bytes"
is "no output at all", and agents act on output. ``errors="strict"`` would
reintroduce the failure; ``sys.stdout.encoding`` is not the child's encoding, so
guessing is exactly the bug.
"""

from __future__ import annotations

import subprocess
from typing import Any

__all__ = ["run_text", "combine_output", "CHILD_ENCODING"]

#: The codec every child of this process is asked for. See module docstring.
CHILD_ENCODING = "utf-8"


def run_text(
    argv: list[str] | str,
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]:
    """``subprocess.run`` with a pinned codec and never-None text streams.

    ``encoding``/``errors``/``text`` are forced: setting them is the entire point,
    so callers cannot accidentally reintroduce the locale dependency. Everything
    else (``timeout``, ``check``, ``cwd``, ``env``, ``shell``, stream redirection)
    is passed through untouched, and ``capture_output`` is only defaulted -- a
    caller that passes explicit ``stdout=``/``stderr=``/``stdin=`` keeps control.
    """
    kwargs.pop("text", None)
    kwargs.pop("universal_newlines", None)
    # Forced, not defaulted: these three ARE the contract, so a caller that passes
    # them gets them ignored rather than a TypeError from a duplicate keyword.
    kwargs.pop("encoding", None)
    kwargs.pop("errors", None)
    if not any(k in kwargs for k in ("capture_output", "stdout", "stderr")):
        kwargs["capture_output"] = True
    return subprocess.run(  # noqa: S603 - argv comes from the caller by design
        argv,
        text=True,
        encoding=CHILD_ENCODING,
        errors="replace",
        **kwargs,
    )


def combine_output(result: subprocess.CompletedProcess[str]) -> str:
    """Join stdout+stderr, None-safely.

    ``completed.stdout`` / ``.stderr`` are documented as possibly ``None`` (they
    are whenever the corresponding stream was not captured, and they were also
    ``None`` in the decode-failure case measured above). A bare ``+`` therefore
    turns a decoding problem into a ``TypeError`` somewhere else entirely, which
    is how the verifier ended up reporting EXECUTION_ERROR for a working PoC.
    """
    return (result.stdout or "") + (result.stderr or "")
