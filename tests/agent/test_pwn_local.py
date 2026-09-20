"""pwn_local: deterministic Docker-backed local replay (pure logic parts)."""

from __future__ import annotations

import pytest

from vulnclaw.agent import pwn_local
from vulnclaw.agent.pwn_local import (
    _arch_aliases,
    _candidate_arch,
    _pick_libc_build,
)


def _elf(arch: int, machine: int, interp: bytes, glibc: bytes) -> bytes:
    head = b"\x7fELF" + bytes([arch, 1, 1, 0]) + b"\x00" * 8
    head += b"\x02\x00"  # e_type EXEC
    head += machine.to_bytes(2, "little")
    body = interp + glibc
    return head + body


def test_detect_64bit_dynamic_glibc_223():
    data = _elf(2, 62, b"/lib64/ld-linux-x86-64.so.2\x00", b"GLIBC_2.2.5GLIBC_2.23")
    info = pwn_local.detect_binary_info(data)
    assert info["arch"] == "amd64" and info["dynamic"] is True
    assert info["max_glibc"] == "2.23"


def test_detect_32bit_static():
    data = _elf(1, 3, b"", b"")  # i386, no interp
    info = pwn_local.detect_binary_info(data)
    assert info["arch"] == "i386" and info["dynamic"] is False


def test_image_tag_mapping():
    assert (
        pwn_local.image_tag_for({"dynamic": True, "max_glibc_tuple": (2, 23)}) == "16.04"
    )
    assert (
        pwn_local.image_tag_for({"dynamic": True, "max_glibc_tuple": (2, 27)}) == "18.04"
    )
    assert (
        pwn_local.image_tag_for({"dynamic": True, "max_glibc_tuple": (2, 31)}) == "20.04"
    )
    assert (
        pwn_local.image_tag_for({"dynamic": True, "max_glibc_tuple": (2, 35)}) == "22.04"
    )
    # static binaries run anywhere
    assert pwn_local.image_tag_for({"dynamic": False, "max_glibc_tuple": None}) == "22.04"


def test_helper_dockerfile_installs_32bit_runtime():
    df = pwn_local.helper_dockerfile("16.04")
    assert "FROM ubuntu:16.04" in df
    assert "libc6:i386" in df and "socat" in df


def test_container_name_stable_per_path():
    a = pwn_local.container_name(r"E:\x\challenge.elf")
    b = pwn_local.container_name(r"E:\x\challenge.elf")
    c = pwn_local.container_name(r"E:\x\other.elf")
    assert a == b and a != c and a.startswith("vulnclaw-pwn-")


def test_container_name_normalizes_relative_and_absolute():
    """replay and stop must agree on the name for the same binary."""
    import os

    rel = "challenge.elf"
    assert pwn_local.container_name(rel) == pwn_local.container_name(
        os.path.abspath(rel)
    )


def test_graceful_error_when_docker_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(pwn_local.shutil, "which", lambda _: None)
    out = pwn_local.start_replay(str(tmp_path / "nonexistent.elf"))
    assert "not found" in out  # file check fires before docker check
    assert "install Docker Desktop" not in out

    # Path validation is local and cheap, so it runs before the (possibly
    # multi-minute) image build — a valid ELF reaches the docker check.
    elf = tmp_path / "challenge.elf"
    elf.write_bytes(_elf(2, 62, b"/lib64/ld-linux-x86-64.so.2\x00", b"GLIBC_2.31"))
    out = pwn_local.start_replay(str(elf))
    assert "install Docker Desktop" in out


def test_start_replay_refuses_non_elf(monkeypatch, tmp_path):
    """Only a real ELF may be bind-mounted into the replay container."""
    monkeypatch.setattr(pwn_local.shutil, "which", lambda _: None)
    junk = tmp_path / "not-an-elf.bin"
    junk.write_bytes(b"#!/bin/sh\necho hi\n")
    out = pwn_local.start_replay(str(junk))
    assert "not an ELF" in out
    assert "install Docker Desktop" not in out


def test_start_replay_refuses_relative_path(monkeypatch):
    """A relative path would bind-mount cwd (or fail as a volume name)."""
    monkeypatch.setattr(pwn_local.shutil, "which", lambda _: None)
    out = pwn_local.start_replay("challenge.elf")
    assert "must be absolute" in out


def test_stop_with_docker_missing_is_graceful(monkeypatch):
    monkeypatch.setattr(pwn_local.shutil, "which", lambda _: None)
    out = pwn_local.stop_replay("whatever.elf")
    assert "install Docker Desktop" in out


def test_schemas_exist():
    names = [s["function"]["name"] for s in pwn_local.pwn_local_tool_schemas()]
    assert names == ["pwn_local_replay", "pwn_local_stop", "libc_lookup"]


def test_parse_leaks_forms():
    from vulnclaw.agent.pwn_local import _parse_leaks
    assert _parse_leaks({"puts": "0xf7e48140"}) == {"puts": 0xF7E48140}
    assert _parse_leaks('puts=0xf7e48140, fgets=4194304') == {
        "puts": 0xF7E48140, "fgets": 4194304}
    assert _parse_leaks("junk") == {}


def test_pick_libc_build_requires_single_base():
    from vulnclaw.agent.pwn_local import _pick_libc_build
    cands = [
        {"id": "good_i386", "download_url": "u1",
         "symbols": {"puts": "0x5e140", "fgets": "0x5c620", "system": "0x3ada0"}},
        {"id": "bad_diff", "download_url": "u2",
         "symbols": {"puts": "0x76140", "fgets": "0x747f0", "system": "0x4a4e0"}},
    ]
    leaks = {"puts": 0xF7DF9140, "fgets": 0xF7DF7620}
    out = _pick_libc_build(cands, leaks)
    assert [m["id"] for m in out] == ["good_i386"]
    assert out[0]["base"] == 0xF7DF9140 - 0x5E140
    assert out[0]["system"] == 0x3ADA0
    # unaligned candidates are dropped
    leaks2 = {"puts": 0xF7DF9141}
    assert _pick_libc_build(cands, leaks2) == []


def test_dispatch_includes_libc_lookup():
    import asyncio
    from vulnclaw.agent.pwn_local import execute_pwn_local_tool
    out = asyncio.run(execute_pwn_local_tool(None, "libc_lookup", {"symbols": {}}))
    assert "requires symbols" in out


# ── libc_lookup: the arch argument must actually filter ──────────────────


def test_candidate_arch_reads_field_and_id_fallback():
    assert _candidate_arch({"id": "x", "arch": "amd64"}) == "amd64"
    assert _candidate_arch({"id": "libc6_2.27-3ubuntu1_i386"}) == "i386"
    assert _candidate_arch({"id": "libc6_2.31-0ubuntu9.9_amd64"}) == "amd64"
    assert _candidate_arch({"id": "unknown-build"}) == ""


def test_arch_aliases_normalize_spellings():
    assert _arch_aliases("x86_64") == {"amd64", "x86_64"}
    assert _arch_aliases("i686") == {"i386", "i686", "x86"}
    assert _arch_aliases("amd64") == {"amd64", "x86_64"}
    assert _arch_aliases("") == set()


def _mixed_candidates():
    base = 0xF7E00000
    # Same leaked symbol resolves to the same base in both builds, so only the
    # arch differs — exactly the case the arch argument exists to break.
    return [
        {"id": "libc6_2.27-3ubuntu1_i386", "arch": "i386",
         "symbols": {"puts": hex(0x67340), "system": hex(0x3CD80)}},
        {"id": "libc6_2.27-3ubuntu1_amd64", "arch": "amd64",
         "symbols": {"puts": hex(0x67340), "system": hex(0x3CD80)}},
    ], {"puts": base + 0x67340}


def test_arch_filter_excludes_other_arch():
    cands, leaks = _mixed_candidates()
    i386 = [m["id"] for m in _pick_libc_build(cands, leaks, "i386")]
    amd64 = [m["id"] for m in _pick_libc_build(cands, leaks, "amd64")]
    assert i386 == ["libc6_2.27-3ubuntu1_i386"]
    assert amd64 == ["libc6_2.27-3ubuntu1_amd64"]


def test_arch_filter_accepts_alias_spellings():
    cands, leaks = _mixed_candidates()
    assert [m["id"] for m in _pick_libc_build(cands, leaks, "x86_64")] == [
        "libc6_2.27-3ubuntu1_amd64"
    ]


def test_no_arch_filter_keeps_everything():
    """Default/blank arch stays permissive (regression for existing callers)."""
    cands, leaks = _mixed_candidates()
    assert len(_pick_libc_build(cands, leaks, "")) == 2
    assert len(_pick_libc_build(cands, leaks)) == 2


def test_unknown_arch_candidates_are_kept():
    """An undeterminable arch is not proof of a mismatch."""
    cands = [{"id": "mystery-build", "symbols": {"puts": hex(0x67340)}}]
    leaks = {"puts": 0xF7E00000 + 0x67340}
    assert len(_pick_libc_build(cands, leaks, "amd64")) == 1


def test_libc_lookup_needs_no_network_for_empty_leaks():
    assert "requires at least one leaked" in pwn_local.libc_lookup({}, "amd64")


def test_libc_lookup_reports_arch_in_header(monkeypatch):
    """The arch actually used is visible in the output (no silent no-op)."""
    import json as _json

    cands = [{"id": "libc6_2.27-3ubuntu1_i386", "arch": "i386",
              "symbols": {"puts": hex(0x67340), "system": hex(0x3CD80)}}]

    class _Resp:
        def read(self):
            return _json.dumps(cands).encode()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(
        "urllib.request.urlopen", lambda *a, **k: _Resp(), raising=False
    )
    out = pwn_local.libc_lookup({"puts": 0xF7E00000 + 0x67340}, "i386")
    assert "arch=i386" in out
    assert "libc6_2.27-3ubuntu1_i386" in out


def test_libc_lookup_explains_arch_mismatch(monkeypatch):
    import json as _json

    cands = [{"id": "libc6_2.27-3ubuntu1_i386", "arch": "i386",
              "symbols": {"puts": hex(0x67340)}}]

    class _Resp:
        def read(self):
            return _json.dumps(cands).encode()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(
        "urllib.request.urlopen", lambda *a, **k: _Resp(), raising=False
    )
    out = pwn_local.libc_lookup({"puts": 0xF7E00000 + 0x67340}, "amd64")
    assert "none match arch=amd64" in out


# ── supply chain: third-party mirrors are opt-in, apt mirror is validated ──


def test_third_party_mirrors_are_off_by_default(monkeypatch):
    monkeypatch.delenv("VULNCLAW_DOCKER_MIRRORS", raising=False)
    assert pwn_local._mirror_list() == []
    attempts = []
    monkeypatch.setattr(
        pwn_local, "_run", lambda cmd, **kw: (attempts.append(cmd), (1, "", "boom"))[1]
    )
    ok, err = pwn_local._pull_base_image("22.04")
    assert ok is False
    # Exactly one attempt: the canonical Docker Hub pull, no third party.
    assert len(attempts) == 1
    assert attempts[0] == ["pull", "library/ubuntu:22.04"]


def test_third_party_mirrors_used_only_when_opted_in(monkeypatch):
    monkeypatch.setenv("VULNCLAW_DOCKER_MIRRORS", "mirror.example,docker.1ms.run")
    assert pwn_local._mirror_list() == ["mirror.example", "docker.1ms.run"]
    attempts = []
    monkeypatch.setattr(
        pwn_local, "_run", lambda cmd, **kw: (attempts.append(cmd), (1, "", "boom"))[1]
    )
    pwn_local._pull_base_image("22.04")
    assert attempts[0] == ["pull", "library/ubuntu:22.04"]
    assert attempts[1] == ["pull", "mirror.example/library/ubuntu:22.04"]
    assert attempts[2] == ["pull", "docker.1ms.run/library/ubuntu:22.04"]


@pytest.mark.parametrize(
    "bad",
    [
        'evil.com"; rm -rf /; echo "',
        "a|b",
        "x y",
        "host/$(id)",
        "host/`id`",
        "host/ubuntu\nRUN curl evil",
    ],
)
def test_apt_mirror_injection_is_rejected(monkeypatch, bad):
    monkeypatch.setenv("VULNCLAW_APT_MIRROR", bad)
    assert pwn_local._apt_mirror() == pwn_local._DEFAULT_APT_MIRROR
    # And the generated Dockerfile must not carry the payload.
    assert bad not in pwn_local.helper_dockerfile("22.04")


def test_apt_mirror_accepts_legitimate_host(monkeypatch):
    monkeypatch.setenv("VULNCLAW_APT_MIRROR", "mirrors.tuna.tsinghua.edu.cn/ubuntu")
    assert pwn_local._apt_mirror() == "mirrors.tuna.tsinghua.edu.cn/ubuntu"
    assert "mirrors.tuna.tsinghua.edu.cn/ubuntu" in pwn_local.helper_dockerfile("22.04")


def test_apt_mirror_falls_back_when_unset(monkeypatch):
    monkeypatch.delenv("VULNCLAW_APT_MIRROR", raising=False)
    assert pwn_local._apt_mirror() == pwn_local._DEFAULT_APT_MIRROR


# ── container resource caps ─────────────────────────────────────────────


def test_container_resource_limits_present_by_default(monkeypatch):
    for var in ("VULNCLAW_PWN_MEMORY", "VULNCLAW_PWN_CPUS", "VULNCLAW_PWN_PIDS"):
        monkeypatch.delenv(var, raising=False)
    flags = pwn_local._resource_limit_flags()
    assert "--memory" in flags and "--cpus" in flags and "--pids-limit" in flags


def test_container_resource_limits_are_overridable(monkeypatch):
    monkeypatch.setenv("VULNCLAW_PWN_MEMORY", "2g")
    monkeypatch.setenv("VULNCLAW_PWN_PIDS", "512")
    flags = pwn_local._resource_limit_flags()
    assert flags[flags.index("--memory") + 1] == "2g"
    assert flags[flags.index("--pids-limit") + 1] == "512"

