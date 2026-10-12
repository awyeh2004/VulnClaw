"""Subprocess helper shared by several tool families."""

from __future__ import annotations

from typing import Any


# ── subprocess 封装（避免重复代码）────────────────────────────────────────────────────

def run_subprocess_capture(
    cmd: str | list[str],
    shell: bool = False,
    cwd: str | None = None,
    timeout: int | None = None,
    encoding: str = "utf-8",
    errors: str = "ignore",
) -> dict[str, Any]:
    """安全的 subprocess 调用，统一返回格式。
    
    Returns:
        {
            "success": bool,
            "stdout": str,
            "stderr": str,
            "returncode": int,
            "timeout": bool
        }
    """
    import subprocess
    
    try:
        proc = subprocess.run(
            cmd,
            shell=shell,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding=encoding,
            errors=errors,
            timeout=timeout,
        )
        return {
            "success": proc.returncode == 0,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "returncode": proc.returncode,
            "timeout": False,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Command timed out after {timeout}s",
            "returncode": -1,
            "timeout": True,
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
            "timeout": False,
        }
