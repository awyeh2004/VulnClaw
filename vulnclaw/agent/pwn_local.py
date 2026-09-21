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
import json
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

# Docker Hub is unreachable from some networks (DNS poisoning). Third-party
# registry mirrors are a *deliberate* trust decision, not a safe default:
# Docker does not verify image signatures, and the helper image's RUN steps
# execute inside whatever rootfs the mirror serves. They are therefore OFF by
# default — opt in per operator with:
#
#   VULNCLAW_DOCKER_MIRRORS="docker.1ms.run,docker.m.daocloud.io"
#
# Direct pulls from Docker Hub are always attempted first, so opting in costs
# nothing on networks where Hub is reachable.
_DEFAULT_MIRRORS: list[str] = []

# Kept for documentation/reference when an operator asks how to unblock Hub.
_KNOWN_MIRRORS = [
    "docker.1ms.run",
    "docker.m.daocloud.io",
    "hub.rat.dev",
    "dockerproxy.net",
]

_MIRROR_HINT = (
    "if Docker Hub is unreachable from this network (DNS poisoning), opt in to "
    "a third-party registry mirror explicitly with "
    'VULNCLAW_DOCKER_MIRRORS="docker.1ms.run" — note that Docker does not verify '
    "image signatures, and this build executes inside the pulled rootfs"
)

# apt mirror host/path only: it is interpolated into a `RUN sed` expression, so
# anything that could break out of the s/// command is rejected outright.
_APT_MIRROR_RE = re.compile(r"^[A-Za-z0-9.\-]+(?::\d+)?(?:/[A-Za-z0-9._\-]+)*$")
_DEFAULT_APT_MIRROR = "mirrors.aliyun.com/ubuntu"

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


def _apt_mirror() -> str:
    """Resolve VULNCLAW_APT_MIRROR, refusing anything unsafe to interpolate.

    The value lands inside a ``RUN sed -i 's|…|http://<mirror>|g'`` expression,
    so a malformed value (containing ``|``, quotes, ``;``, whitespace…) could
    inject build commands. An operator-supplied value is semi-trusted, but
    validating it costs nothing and keeps the Dockerfile well-formed.
    """
    raw = os.environ.get("VULNCLAW_APT_MIRROR", "").strip().rstrip("/")
    if not raw:
        return _DEFAULT_APT_MIRROR
    if not _APT_MIRROR_RE.match(raw):
        return _DEFAULT_APT_MIRROR
    return raw


def helper_dockerfile(tag: str) -> str:
    """Distro image + socat + 32-bit runtime so both arches replay anywhere.

    apt sources are repointed to a mirror for every tag: EOL distros (16.04
    etc.) no longer exist on archive.ubuntu.com at all, and the mirror is
    reachable from CN networks with or without a VPN. Override with
    VULNCLAW_APT_MIRROR (validated; falls back to the default when malformed).
    Ubuntu's apt signatures are still verified, so the mirror swap does not
    weaken image integrity — only availability.
    """
    mirror = _apt_mirror()
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
    """Deterministic container name for a binary.

    The path is normalized to an absolute one first: ``pwn_local_replay`` and
    ``pwn_local_stop`` must derive the *same* name from the same binary, or a
    relative path in one call would leak a running container.
    """
    try:
        normalized = str(Path(binary_path).expanduser().resolve())
    except (OSError, ValueError, RuntimeError):
        normalized = str(binary_path)
    digest = hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:10]
    return f"{HELPER_IMAGE}-{digest}"


# Container resource caps: a challenge binary is untrusted code, and socat's
# `fork` mode turns a fork bomb into a host-wide resource exhaustion. Override
# with VULNCLAW_PWN_MEMORY / VULNCLAW_PWN_CPUS / VULNCLAW_PWN_PIDS (values are
# validated — 0/-1 mean "unlimited" to docker and fall back to the default).
#
# Residual, accepted: the container keeps normal bridge networking. A published
# port requires a routable network, and `--network none`/`--internal` breaks the
# `-p 127.0.0.1:port:port` mapping this tool exists to provide, so a hostile
# challenge binary can still open outbound connections. Treat a challenge binary
# as something that can phone home.
_DEFAULT_MEMORY_LIMIT = "512m"
_DEFAULT_CPU_LIMIT = "1.0"
_DEFAULT_PIDS_LIMIT = "128"


def _positive_number(text: str) -> float | None:
    """Parse a docker size/count value, rejecting zero and negatives.

    Docker reads ``0`` (and ``-1``) as "no limit", so an unvalidated override
    silently disables the cap it was meant to tighten rather than loosening it.
    """
    match = re.match(r"^(\d+(?:\.\d+)?)\s*([kmg])?b?$", (text or "").strip().lower())
    if not match:
        return None
    value = float(match.group(1))
    return value if value > 0 else None


def _resource_limit_flags() -> list[str]:
    """Docker resource caps for the replay container.

    socat's ``fork`` mode turns a hostile challenge binary into host-wide
    resource exhaustion, so memory/CPU/PID caps are on by default. Overrides are
    validated: an invalid or non-positive value falls back to the default instead
    of becoming "unlimited".
    """

    def _checked(var: str, default: str) -> str:
        raw = (os.environ.get(var) or "").strip()
        if not raw:
            return default
        if _positive_number(raw) is None:
            return default
        return raw

    return [
        "--memory", _checked("VULNCLAW_PWN_MEMORY", _DEFAULT_MEMORY_LIMIT),
        "--cpus", _checked("VULNCLAW_PWN_CPUS", _DEFAULT_CPU_LIMIT),
        "--pids-limit", _checked("VULNCLAW_PWN_PIDS", _DEFAULT_PIDS_LIMIT),
    ]


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
    """Third-party registry mirrors to try after a direct pull fails.

    Empty unless the operator opted in via VULNCLAW_DOCKER_MIRRORS — see the
    comment on _DEFAULT_MIRRORS for why this is not a default.
    """
    custom = os.environ.get("VULNCLAW_DOCKER_MIRRORS", "").strip()
    if custom:
        return [m.strip() for m in custom.split(",") if m.strip()]
    return list(_DEFAULT_MIRRORS)


def _pull_base_image(tag: str) -> tuple[bool, str]:
    """Pull library/ubuntu:<tag> directly, then from opted-in mirrors.

    Returns (ok, error_message). Direct-first keeps VPN'd setups on the
    canonical image; mirrors cover networks where Hub is DNS-poisoned but must
    be opted into explicitly (unsigned rootfs pulled from a third party).
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
            suffix = "" if _mirror_list() else f" — {_MIRROR_HINT}"
            return False, (
                f"[pwn_local] cannot obtain base image ubuntu:{tag} "
                f"(direct pull failed): {err}{suffix}"
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
    p = Path(binary_path).expanduser()
    if not p.is_absolute():
        # A relative path would bind-mount cwd (or fail as an invalid volume
        # name); the tool contract asks for an absolute path.
        return (
            f"[pwn_local] binary_path must be absolute, got {binary_path!r} "
            f"(resolved: {p.resolve()})"
        )
    try:
        p = p.resolve()
    except (OSError, ValueError, RuntimeError) as exc:
        return f"[pwn_local] cannot resolve binary_path {binary_path!r}: {exc}"
    if not p.is_file():
        return f"[pwn_local] binary not found: {binary_path}"
    try:
        data = p.read_bytes()
    except OSError as exc:
        return f"[pwn_local] cannot read {p}: {exc}"
    if not data.startswith(b"\x7fELF"):
        # Only mount/execute something that is actually an ELF: without this
        # check any host file the agent names gets bound into the container.
        return (
            f"[pwn_local] {p} is not an ELF binary (bad magic) — refusing to "
            "mount it into the replay container"
        )
    info = detect_binary_info(data)
    digest = hashlib.sha256(data).hexdigest()
    tag = image_tag_for(info)

    ok, msg = _ensure_helper_image(tag)
    if not ok:
        return msg

    # Re-verify immediately before `docker run`. The checks above can be minutes
    # old (an image pull/build is allowed 600s) and docker resolves the
    # bind-mount path only when the container starts, so a file swapped in the
    # meantime would otherwise be the one that executes.
    try:
        current = p.read_bytes()
    except OSError as exc:
        return f"[pwn_local] cannot re-read {p} before start: {exc}"
    if not current.startswith(b"\x7fELF") or hashlib.sha256(current).hexdigest() != digest:
        return (
            f"[pwn_local] {p} changed between validation and container start — "
            "refusing to run it (the bind mount resolves the path at start time)"
        )

    port = port or _free_port()
    name = container_name(str(p))
    # Self-heal: a leftover container from a previous run would keep the name.
    _run(["rm", "-f", name], timeout_s=30)
    # Mount the binary itself, not its parent directory: a directory mount
    # exposes every sibling file to a root container for no benefit.
    remote = f"/chall/{p.name}"
    cmd = (
        f"exec socat TCP-LISTEN:{port},reuseaddr,fork "
        f"EXEC:{shlex.quote(remote)}"
    )
    code, out, err = _run(
        [
            "run", "-d", "--rm", "--name", name,
            *_resource_limit_flags(),
            "-v", f"{p}:{remote}:ro",
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
        f"glibc {info['max_glibc'] or 'static'}, sha256 {digest[:16]}). Develop and "
        "verify the exploit here; fire the real remote only once it works. "
        "Release with pwn_local_stop when done."
    )


def stop_replay(binary_path: str) -> str:
    name = container_name(binary_path)
    code, out, err = _run(["rm", "-f", name], timeout_s=30)
    if code != 0:
        return f"[pwn_local] stop failed: {(err or out)[-200:]}"
    return f"[pwn_local] released {name}."


def _parse_leaks(raw: Any) -> dict[str, int]:
    """Normalize the symbols argument: dict or 'name=0x..,name=0x..' string."""
    leaks: dict[str, int] = {}
    if isinstance(raw, dict):
        items = raw.items()
    elif isinstance(raw, str):
        items = []
        for part in raw.split(","):
            part = part.strip()
            if "=" in part:
                name, _, val = part.partition("=")
                items.append((name.strip(), val.strip()))
            elif part:
                items.append((part.strip(), ""))
    else:
        items = []
    for name, val in items:
        name = str(name).strip().strip('"')
        if not name or not val:
            continue
        try:
            leaks[name] = int(str(val), 16) if str(val).lower().startswith("0x") else int(str(val), 10)
        except ValueError:
            continue
    return leaks


def _arch_aliases(arch: str) -> set[str]:
    """Normalize the caller's arch argument into the spellings libc.rip uses."""
    a = (arch or "").strip().lower()
    if a in ("amd64", "x86_64", "x64", "x86-64", "64"):
        return {"amd64", "x86_64"}
    if a in ("i386", "i486", "i586", "i686", "x86", "386", "32"):
        return {"i386", "i686", "x86"}
    if a in ("arm64", "aarch64"):
        return {"arm64", "aarch64"}
    if a in ("armhf", "armel", "arm"):
        return {"armhf", "armel", "arm"}
    return {a} if a else set()


def _candidate_arch(cand: dict) -> str:
    """Best-effort arch of one libc.rip candidate ('' when undeterminable).

    libc.rip returns an explicit ``arch`` field for most builds; older entries
    only carry it inside the id (``libc6_2.27-3ubuntu1_amd64``). Both shapes are
    handled here so the filter does not silently no-op if the field is absent.
    """
    explicit = str(cand.get("arch") or "").strip().lower()
    if explicit:
        return explicit
    ident = f"{cand.get('id', '')} {cand.get('build', '')}".lower()
    for probe in ("amd64", "x86_64", "i386", "i686", "arm64", "aarch64",
                  "armhf", "armel", "mips", "ppc", "s390"):
        if probe in ident:
            return probe
    return ""


def _pick_libc_build(
    cands: list[dict], leaks: dict[str, int], arch: str = ""
) -> list[dict[str, Any]]:
    """Keep candidates where ALL leaked symbols share ONE page-aligned base.

    Returns [{id, base, system, download_url}] best (most symbols matched,
    lowest base) first. Requires >=1 symbol; libc.rip already narrows by the
    low 12 bits of each provided symbol, so alignment re-check is the gate.

    ``arch`` filters client-side: a candidate whose arch is *known and
    different* is dropped; a candidate whose arch cannot be determined is kept
    (filtering it out would silently lose valid matches on API changes).
    """
    wanted = _arch_aliases(arch)
    out: list[dict[str, Any]] = []
    for c in cands or []:
        syms = c.get("symbols") or {}
        if not isinstance(syms, dict):
            continue
        if wanted:
            found = _candidate_arch(c)
            if found and found not in wanted:
                continue
        base = None
        ok = True
        for name, addr in leaks.items():
            off = syms.get(name)
            if off is None:
                ok = False
                break
            try:
                off = int(off, 16)
            except (ValueError, TypeError):
                ok = False
                break
            b = addr - off
            if base is None:
                base = b
            elif b != base:
                ok = False
                break
        if not ok or base is None or base < 0 or base & 0xFFF:
            continue
        try:
            system = int(syms["system"], 16)
        except (KeyError, ValueError, TypeError):
            system = None
        out.append({
            "id": c.get("id", "?"),
            "base": base,
            "system": system,
            "download_url": c.get("download_url", ""),
        })
    out.sort(key=lambda x: (x["system"] is None, x["base"]))
    return out


def libc_lookup(leaks: dict[str, int], arch: str = "i386") -> str:
    """Query libc.rip and report builds consistent with the leaked addresses.

    ``arch`` is applied as a client-side filter (see ``_pick_libc_build``); the
    arch is *not* sent to libc.rip, whose /api/find contract is symbols-only.
    """
    if not leaks:
        return "[!] libc_lookup requires at least one leaked symbol address"
    import ssl
    import urllib.request

    body = json.dumps({"symbols": {k: hex(v) for k, v in leaks.items()}}).encode()
    req = urllib.request.Request(
        "https://libc.rip/api/find", data=body,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=25, context=ssl.create_default_context()) as resp:
        cands = json.loads(resp.read())
    matches = _pick_libc_build(cands, leaks, arch)
    arch_txt = f" (arch={arch})" if (arch or "").strip() else ""
    if not matches:
        total = len(cands) if isinstance(cands, list) else 0
        if total and (arch or "").strip():
            return (
                f"[libc_lookup] libc.rip returned {total} candidate(s) for "
                f"{ {k: hex(v) for k, v in leaks.items()} } but none match "
                f"arch={arch} with all leaks at one page-aligned base — retry "
                "with the other arch (i386/amd64) or leak more symbols"
            )
        return (
            f"[libc_lookup] no build in libc.rip puts ALL of "
            f"{ {k: hex(v) for k, v in leaks.items()} } at one page-aligned "
            "base — leak more symbols or the build is not in the DB"
        )
    lines = [f"[libc_lookup] {len(matches)} consistent build(s){arch_txt}:"]
    for m in matches[:5]:
        sys_txt = hex(m["system"]) if m["system"] is not None else "?"
        lines.append(
            f"  {m['id']} | base={m['base']:#x} | system={sys_txt}"
            + (f" | {m['download_url']}" if m["download_url"] else "")
        )
    if len(matches) == 1:
        lines.append(
            "unique match — compute system_addr = base + system and write it "
            "into a called GOT slot (strchr@got is a good default for menu "
            "services)"
        )
    return "\n".join(lines)


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
    if tool_name == "libc_lookup":
        leaks = _parse_leaks(args.get("symbols"))
        if not leaks:
            return "[!] libc_lookup requires symbols like {\"puts\": \"0xf7...\"}"
        arch = str(args.get("arch") or "i386").strip()
        return await asyncio.to_thread(libc_lookup, leaks, arch)
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
                            "description": (
                                "Absolute path to the challenge ELF. Must be an "
                                "absolute path (a relative one is refused) and "
                                "must be an ELF file — only that single file is "
                                "mounted into the container, read-only."
                            ),
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
        {
            "type": "function",
            "function": {
                "name": "libc_lookup",
                "description": (
                    "Identify a remote glibc build from leaked GOT symbol "
                    "addresses (puts/fgets/etc read out of the remote process). "
                    "Returns candidate builds that place every leaked symbol at "
                    "ONE page-aligned base, with each build's system() offset "
                    "and download URL. Feed 2+ symbols for a unique match."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "symbols": {
                            "type": "object",
                            "description": (
                                'Leaked symbol->runtime address map, e.g. '
                                '{"puts": "0xf7e48140", "fgets": "0xf7e38620"}.'
                            ),
                        },
                        "arch": {
                            "type": "string",
                            "description": (
                                "Architecture filter applied to the returned "
                                "builds: i386 (default) or amd64. Set it to the "
                                "challenge's arch so i386 and amd64 builds are "
                                "not mixed in one result."
                            ),
                        },
                    },
                    "required": ["symbols"],
                },
            },
        },
    ]
