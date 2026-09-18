"""Deterministic local reproduction of pwn challenges via Docker.

Why: blind-firing exploits at the remote is expensive — single-connection
services, alarm() timeouts, one full-price LLM round per attempt. This tool
runs the challenge binary locally in a container whose distro matches the
binary's required glibc, so the solver iterates against 127.0.0.1 for free and
fires the real remote only once the exploit works.

The operator never enters a container: this is plumbing. Containers are named
per-binary, replaced on re-run, and removed by ``pwn_local_stop`` (or die with
``--rm`` when the daemon restarts).

Docker commands go through ``builtin_tools._spawn_captured`` (the already
reviewed spawn site) — this module introduces no new process-spawn call sites.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import shlex
import shutil
import socket
import tempfile
from pathlib import Path
from typing import Any

INSTALL_HINT = (
    "[pwn_local] docker not available — install Docker Desktop "
    "(https://www.docker.com/products/docker-desktop/), start it, then retry. "
    "Until then exploits must be blind-fired at the remote service."
)

_DAEMON_HINT = (
    "[pwn_local] docker daemon not reachable — start Docker Desktop and wait "
    "for it to report 'running', then retry."
)

# Max GLIBC symbol version required by the binary → distro tag whose archive
# ships it. Ordered ascending; anything newer than the last entry falls through
# to the default (22.04).
_GLIBC_IMAGE_MAP: list[tuple[tuple[int, int], str]] = [
    ((2, 23), "16.04"),
    ((2, 27), "18.04"),
    ((2, 31), "20.04"),
]
_DEFAULT_IMAGE_TAG = "22.04"

# (EOL tags kept for reference; apt repoint now uses the CN mirror for all tags)
# plain `apt-get update` on archive.ubuntu.com 404s for these.
_EOL_TAGS = {"16.04", "18.04", "20.04"}

# Docker Hub is unreachable from some networks (DNS poisoning); these mirror
# prefixes are used as fallbacks when a direct pull fails. Override with
# VULNCLAW_DOCKER_MIRRORS="m1,m2".
_DEFAULT_MIRRORS = [
    "docker.1ms.run",
    "docker.m.daocloud.io",
    "hub.rat.dev",
    "dockerproxy.net",
]

HELPER_IMAGE = "vulnclaw-pwn"


def detect_binary_info(data: bytes) -> dict[str, Any]:
    """Parse minimal ELF facts needed for image selection (no external tools).

    Returns arch (i386/amd64/other), dynamic (PT_INTERP present) and the max
    GLIBC_2.x symbol version string referenced by the binary.
    """
    arch = "other"
    if len(data) >= 18 and data[:4] == b"\x7fELF":
        ei_class, ei_data = data[4], data[5]
        if ei_class == 1 and ei_data == 1 and int.from_bytes(data[18:20], "little") == 3:
            arch = "i386"
        elif ei_class == 2 and ei_data == 1 and int.from_bytes(data[18:20], "little") == 62:
            arch = "amd64"
    dynamic = b"/lib/ld-linux" in data or b"/lib64/ld-linux" in data
    versions: list[tuple[int, int]] = []
    for m in re.finditer(rb"GLIBC_2\.(\d+)(?:\.(\d+))?", data):
        minor = int(m.group(2) or 0)
        versions.append((2, int(m.group(1))))
        if minor:
            versions.append((2, int(m.group(1)), minor))
    max_glibc = None
    for v in versions:
        key = (v[0], v[1], v[2] if len(v) > 2 else 0)
        if max_glibc is None or key > max_glibc:
            max_glibc = key
    return {
        "arch": arch,
        "dynamic": dynamic,
        "max_glibc": f"{max_glibc[0]}.{max_glibc[1]}" + (f".{max_glibc[2]}" if max_glibc and max_glibc[2] else "")
        if max_glibc
        else None,
        "max_glibc_tuple": (max_glibc[0], max_glibc[1]) if max_glibc else None,
    }


def image_tag_for(info: dict[str, Any]) -> str:
    """Pick the distro tag whose glibc satisfies the binary (or the default)."""
    if not info.get("dynamic"):
        return _DEFAULT_IMAGE_TAG  # static: any distro works
    required = info.get("max_glibc_tuple")
    if required is None:
        return _DEFAULT_IMAGE_TAG
    for ceiling, tag in _GLIBC_IMAGE_MAP:
        if required <= ceiling:
            return tag
    return _DEFAULT_IMAGE_TAG


def helper_image_name(tag: str) -> str:
    return f"{HELPER_IMAGE}:{tag}"


def helper_dockerfile(tag: str) -> str:
    """Distro image + socat + 32-bit runtime so both arches replay anywhere.

    apt sources are repointed to a mirror for every tag: EOL distros (16.04
    etc.) no longer exist on archive.ubuntu.com at all, and the mirror is
    reachable from CN networks with or without a VPN. Override with
    VULNCLAW_APT_MIRROR.
    """
    mirror = os.environ.get(
        "VULNCLAW_APT_MIRROR", "mirrors.aliyun.com/ubuntu"
    ).strip().rstrip("/")
    return (
        f"FROM ubuntu:{tag}\n"
        "ENV DEBIAN_FRONTEND=noninteractive\n"
        f"RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://{mirror}|g; "
        "s|http://security.ubuntu.com/ubuntu|"
        f"http://{mirror}|g' /etc/apt/sources.list && "
        "dpkg --add-architecture i386 && apt-get update && "
        "apt-get install -y --no-install-recommends socat libc6:i386 && "
        "rm -rf /var/lib/apt/lists/*\n"
    )


def container_name(binary_path: str) -> str:
    digest = hashlib.sha1(str(binary_path).encode("utf-8")).hexdigest()[:10]
    return f"{HELPER_IMAGE}-{digest}"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _spawn(argv: list[str], *, timeout_s: float) -> tuple[int, str, str]:
    from vulnclaw.agent.builtin_tools import _spawn_captured

    code, out, err, _timed_out = _spawn_captured(
        argv, cwd=str(Path.home()), timeout_s=timeout_s
    )
    return code, out, err


def _docker_or_hint() -> tuple[str, None] | tuple[None, str]:
    docker = shutil.which("docker")
    if not docker:
        return None, INSTALL_HINT
    code, _out, _err = _spawn([docker, "info", "--format", "{{.ServerVersion}}"], timeout_s=30)
    if code != 0:
        return None, _DAEMON_HINT
    return docker, None


def _run(cmd: list[str], *, timeout_s: float = 120) -> tuple[int, str, str]:
    docker, hint = _docker_or_hint()
    if hint:
        return 127, "", hint
    return _spawn([docker, *cmd], timeout_s=timeout_s)


def _mirror_list() -> list[str]:
    custom = os.environ.get("VULNCLAW_DOCKER_MIRRORS", "").strip()
    if custom:
        return [m.strip() for m in custom.split(",") if m.strip()]
    return list(_DEFAULT_MIRRORS)


def _pull_base_image(tag: str) -> tuple[bool, str]:
    """Pull library/ubuntu:<tag> directly, falling back to mirror prefixes.

    Returns (ok, error_message). Direct-first keeps VPN'd setups on the
    canonical image; mirrors cover networks where Hub is DNS-poisoned.
    """
    attempts: list[list[str]] = [["pull", f"library/ubuntu:{tag}"]]
    for mirror in _mirror_list():
        attempts.append(["pull", f"{mirror}/library/ubuntu:{tag}"])
    last_err = ""
    for cmd in attempts:
        code, _out, err = _run(cmd, timeout_s=600)
        if code == 0:
            if cmd[1].startswith("docker.io/") is False and "/" in cmd[1].split(":")[0]:
                # retag mirror image to the canonical name the Dockerfile FROM uses
                _run(["tag", cmd[1], f"ubuntu:{tag}"], timeout_s=30)
            return True, ""
        last_err = (err or "").strip()[-300:]
    return False, last_err


def _ensure_helper_image(tag: str) -> tuple[bool, str]:
    """Build the socat-enabled distro image once; skip when already present."""
    image = helper_image_name(tag)
    code, out, _err = _run(["images", "-q", image], timeout_s=30)
    if code == 0 and out.strip():
        return True, image
    # The build needs the ubuntu:<tag> base; Hub may be unreachable directly.
    code, out, _err = _run(["images", "-q", f"ubuntu:{tag}"], timeout_s=30)
    if not (code == 0 and out.strip()):
        ok, err = _pull_base_image(tag)
        if not ok:
            return False, (
                f"[pwn_local] cannot obtain base image ubuntu:{tag} "
                f"(direct + mirrors failed): {err}"
            )
    with tempfile.TemporaryDirectory() as td:
        df = Path(td) / "Dockerfile"
        df.write_text(helper_dockerfile(tag), encoding="utf-8")
        code, _out, err = _run(
            ["build", "-t", image, str(td)], timeout_s=600
        )
    if code != 0:
        return False, f"[pwn_local] helper image build failed: {err[-400:]}"
    return True, image


def _wait_port(port: int, timeout_s: float = 20.0) -> bool:
    import time

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        s = socket.socket()
        s.settimeout(1.0)
        try:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        finally:
            s.close()
        time.sleep(0.5)
    return False


def start_replay(binary_path: str, port: int | None = None) -> str:
    p = Path(binary_path)
    if not p.exists():
        return f"[pwn_local] binary not found: {binary_path}"
    data = p.read_bytes()
    info = detect_binary_info(data)
    tag = image_tag_for(info)

    ok, msg = _ensure_helper_image(tag)
    if not ok:
        return msg

    port = port or _free_port()
    name = container_name(str(p))
    # Self-heal: a leftover container from a previous run would keep the name.
    _run(["rm", "-f", name], timeout_s=30)
    mount_dir = str(p.parent)
    remote = f"/chall/{p.name}"
    cmd = (
        f"exec socat TCP-LISTEN:{port},reuseaddr,fork "
        f"EXEC:{shlex.quote(remote)}"
    )
    code, out, err = _run(
        [
            "run", "-d", "--rm", "--name", name,
            "-v", f"{mount_dir}:/chall:ro",
            "-p", f"127.0.0.1:{port}:{port}",
            helper_image_name(tag),
            "bash", "-c", cmd,
        ],
        timeout_s=60,
    )
    if code != 0:
        return f"[pwn_local] docker run failed: {(err or out)[-400:]}"
    if not _wait_port(port):
        return (
            f"[pwn_local] container started ({name}) but port {port} never came "
            "up — check the binary's runtime deps (docker logs " + name + ")"
        )
    return (
        f"[pwn_local] local replay ready: 127.0.0.1:{port} "
        f"(container {name}, image {helper_image_name(tag)}, arch {info['arch']}, "
        f"glibc {info['max_glibc'] or 'static'}). Develop and verify the exploit "
        "here; fire the real remote only once it works. Release with "
        "pwn_local_stop when done."
    )


def stop_replay(binary_path: str) -> str:
    name = container_name(binary_path)
    code, out, err = _run(["rm", "-f", name], timeout_s=30)
    if code != 0:
        return f"[pwn_local] stop failed: {(err or out)[-200:]}"
    return f"[pwn_local] released {name}."


async def execute_pwn_local_tool(agent: Any, tool_name: str, args: dict[str, Any]) -> str:
    if tool_name == "pwn_local_replay":
        binary_path = str(args.get("binary_path") or "").strip()
        if not binary_path:
            return "[!] pwn_local_replay requires binary_path"
        port = args.get("port")
        return await asyncio.to_thread(
            start_replay, binary_path, int(port) if port else None
        )
    if tool_name == "pwn_local_stop":
        binary_path = str(args.get("binary_path") or "").strip()
        if not binary_path:
            return "[!] pwn_local_stop requires binary_path"
        return await asyncio.to_thread(stop_replay, binary_path)
    return f"[!] Unknown pwn_local tool: {tool_name}"


def pwn_local_tool_schemas() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": "pwn_local_replay",
                "description": (
                    "Run a pwn challenge binary as a local TCP service in Docker "
                    "(distro auto-matched to the binary's glibc) and return "
                    "127.0.0.1:<port>. ALWAYS develop and verify the exploit "
                    "against this local replay first — remote services often "
                    "allow one short-lived connection; only fire the real remote "
                    "after the exploit works locally."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Absolute path to the challenge ELF.",
                        },
                        "port": {
                            "type": "integer",
                            "description": "Optional fixed local port; default auto-picked.",
                        },
                    },
                    "required": ["binary_path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "pwn_local_stop",
                "description": (
                    "Release the local replay container for a binary "
                    "(pair with pwn_local_replay — do not leave containers running)."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Same path passed to pwn_local_replay.",
                        },
                    },
                    "required": ["binary_path"],
                },
            },
        },
    ]
