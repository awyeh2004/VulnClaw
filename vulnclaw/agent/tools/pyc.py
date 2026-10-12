"""pyc bytecode analysis (CTF reverse)."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext


# ── pyc 字节码分析工具（CTF REVERSE 高频）────────────────────────────────────

_PYC_TOOL_NAMES = {"pyc_analyze"}

_PYC_MAGICS = {
    0x0A0D0D55: (3, 5, 0), 0x0A0D0D56: (3, 5, 0),
    0x0A0D0D57: (3, 6, 0), 0x300D0D0A: (3, 6, 1),
    0x31: (3, 7, 0), 0x33: (3, 7, 3), 0x40: (3, 8, 0),
    0x41: (3, 8, 1), 0x42: (3, 8, 4), 0x4F: (3, 9, 0),
    0x55: (3, 9, 2), 0x5E: (3, 9, 5), 0x60: (3, 10, 0),
    0x61: (3, 11, 0), 0x63: (3, 11, 5),
    # 3.9's magic bytes (61 0d 0d 0a / 0x0A0D0D61) are shared with a few builds;
    # resolve ambiguity via xdis validation in _detect_pyc_magic.
    0x0A0D0D61: (3, 9, 0),
    0x0A0D0D62: (3, 12, 0), 0x0A0D0D63: (3, 12, 0),
}


def _detect_pyc_magic(raw: bytes) -> tuple[Optional[tuple[int, int, int]], bytes]:
    """Return (version, corrected_16_bytes_header) or (None, raw[:16]).
    Handles the common CTF trick of patching the first 4 magic bytes so the
    standard marshal loader rejects the file. Version detection prefers xdis's
    built-in magic table; our dict is only a fallback for unpatched headers."""
    head = raw[:16]
    if len(head) < 16:
        return None, head
    # Fast path: known magic + xdis validates the code object parses.
    magic_le = head[:4]
    try:
        from xdis.load import load_module as _xdis_load
        import tempfile
        import os as _os

        with tempfile.NamedTemporaryFile(suffix=".pyc", delete=False) as tf:
            tf.write(raw)
            tmp = tf.name
        try:
            ver, _ts, _mi, co, _py, _ss, _sh = _xdis_load(tmp)
            if co is not None:
                return ver, head
        except Exception:
            pass
        finally:
            if _os.path.exists(tmp):
                _os.unlink(tmp)
    except Exception:
        pass
    # Fallback: match the magic as little-endian int against the known table.
    magic_int = int.from_bytes(magic_le, "little")
    if magic_int in _PYC_MAGICS:
        return _PYC_MAGICS[magic_int], head
    rest = head[4:]
    for magic_int, ver in _PYC_MAGICS.items():
        cand = magic_int.to_bytes(4, "little") + rest
        if _pyc_marshal_ok(cand, raw):
            return ver, cand
    return None, head


def _pyc_marshal_ok(candidate_header: bytes, raw: bytes) -> bool:
    """Cheap check: does the marshal payload parse via xdis (cross-version)?
    Local marshal can only parse the running interpreter's bytecode version, so
    we rely on xdis, which understands 3.5+ across versions."""
    import tempfile
    import os as _os

    try:
        from xdis.load import load_module as _xdis_load
    except Exception:
        return False
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pyc", delete=False) as tf:
            tf.write(candidate_header + raw[16:])
            tmp = tf.name
        _ver, _ts, _mi, co, _py, _ss, _sh = _xdis_load(tmp)
        return co is not None
    except Exception:
        return False
    finally:
        if tmp and _os.path.exists(tmp):
            _os.unlink(tmp)


def _pyc_disasm_via_xdis(pyc_path: str) -> str:
    import io
    from xdis.disasm import disco
    from xdis.load import load_module

    version, ts, magic_int, co, ispypy, source_size, sip_hash = load_module(pyc_path)
    out = io.StringIO()
    try:
        disco(version, co, ts, out)
    except TypeError:
        disco(version, co, ts, out)
    return out.getvalue()


def _pyc_decompile_via_decompyle3(pyc_path: str) -> str:
    from decompyle3.main import decompile_file
    import io

    out = io.StringIO()
    decompile_file(pyc_path, outstream=out)
    return out.getvalue()


def _pyc_scan_consts(co, depth: int = 0, out: list[str] | None = None) -> list[str]:
    """Recursively collect printable constants / strings from a code object."""
    out = out if out is not None else []
    consts = getattr(co, "co_consts", ()) or ()
    for c in consts:
        if isinstance(c, str):
            if c.strip():
                out.append(c)
        elif hasattr(c, "co_consts"):
            _pyc_scan_consts(c, depth + 1, out)
    return out


def execute_pyc_analyze(agent: AgentContext, args: dict[str, Any]) -> str:
    """CTF 逆向助手:分析 pyc 字节码文件。

    自动处理被篡改的 magic 头（CTF 常见），提供反汇编/反编译/常量提取。
    """
    pyc_path = str(args.get("pyc_path", "")).strip()
    mode = str(args.get("mode", "auto")).strip().lower()
    if not pyc_path:
        return "[!] pyc_analyze requires 'pyc_path'"
    if not os.path.exists(pyc_path):
        return f"[!] pyc not found: {pyc_path}"

    raw = open(pyc_path, "rb").read()
    ver, fixed_head = _detect_pyc_magic(raw)
    magic_hex = raw[:4].hex()

    lines = [f"[pyc] path={pyc_path} size={len(raw)}B magic={magic_hex}"]
    if ver:
        lines.append(f"[pyc] detected python {ver[0]}.{ver[1]}.{ver[2]} (magic ok)")
    else:
        lines.append(f"[pyc] magic not recognized; trying fixed headers: {fixed_head[:4].hex()}")

    # 修复 magic 到临时文件
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".pyc", delete=False) as tf:
        fixed_path = tf.name
        if ver:
            fixed_path = pyc_path
        else:
            tf.write(fixed_head + raw[16:])

    try:
        if mode in {"auto", "disasm"}:
            try:
                dis = _pyc_disasm_via_xdis(fixed_path if not ver else pyc_path)
                lines.append(f"[pyc] disasm: {len(dis)} chars")
                lines.append(dis[:3000])
            except Exception as e:
                lines.append(f"[pyc] disasm failed: {str(e)[:120]}")

        if mode in {"auto", "decompile"}:
            try:
                src = _pyc_decompile_via_decompyle3(pyc_path)
                lines.append(f"[pyc] decompiled: {len(src)} chars")
                lines.append(src[:2000])
            except Exception as e:
                lines.append(f"[pyc] decompile failed: {str(e)[:120]}")

        if mode in {"auto", "consts"}:
            try:
                from xdis.load import load_module as _xdis_load
                _ver, _ts, _mi, co, _py, _ss, _sh = _xdis_load(pyc_path)
                consts = _pyc_scan_consts(co)
                lines.append(f"[pyc] consts/strings ({len(consts)}):")
                for c in consts[:40]:
                    lines.append(f"  {c!r}")
            except Exception as e:
                lines.append(f"[pyc] consts extraction failed: {str(e)[:120]}")
    finally:
        if fixed_path != pyc_path and os.path.exists(fixed_path):
            os.unlink(fixed_path)

    return "\n".join(lines)
