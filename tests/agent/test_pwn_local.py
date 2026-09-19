"""pwn_local: deterministic Docker-backed local replay (pure logic parts)."""

from __future__ import annotations

import pytest

from vulnclaw.agent import pwn_local


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


def test_graceful_error_when_docker_missing(monkeypatch):
    monkeypatch.setattr(pwn_local.shutil, "which", lambda _: None)
    out = pwn_local.start_replay("nonexistent.elf")
    assert "not found" in out  # file check fires before docker check
    from pathlib import Path

    fake = Path(__file__)
    out = pwn_local.start_replay(str(fake))
    assert "install Docker Desktop" in out


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
