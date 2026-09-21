"""remote_* safety: honest approvals, bounded scratch dirs, no silent clobber.

Round-4 review findings covered here:
  * the approval text advertised "read-only commands" while the collector also
    ran `rm -rf "$OUT"` on a model-chosen path and unpacked into a model-chosen
    local directory;
  * the collector left its script/archive/scratch dir on the target;
  * `extractall` (and `sftp.get` with mode 'wb') silently replaced local files;
  * the SFTP transfer had no timeout at all, so a black-holed peer hung the
    worker thread forever (asyncio.to_thread cannot be cancelled);
  * `accept_new` and `insecure` behaved identically, so every session was a
    fresh TOFU window.
"""

from __future__ import annotations

import io
import tarfile
import types
from pathlib import Path

import pytest

from vulnclaw.agent import remote


# ── helpers ─────────────────────────────────────────────────────────────


def _tar_bytes(entries, modes=None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for idx, (name, data) in enumerate(entries):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            if modes:
                info.mode = modes[idx]
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class _FakeSFTP:
    def __init__(self, payload=b"data", on_get=None):
        self.payload = payload
        self.on_get = on_get
        self.closed = False
        self.callback_seen = False

    def get_channel(self):
        return None

    def get(self, remotepath, localpath, callback=None):
        self.callback_seen = callback is not None
        if self.on_get is not None:
            self.on_get(callback)
        Path(localpath).write_bytes(self.payload)

    def close(self):
        self.closed = True


class _FakeClient:
    def __init__(self, sftp):
        self._sftp = sftp
        self.closed = False

    def open_sftp(self):
        return self._sftp

    def close(self):
        self.closed = True


# ── scratch dir validation (the `rm -rf "$OUT"` target) ─────────────────


@pytest.mark.parametrize(
    "value",
    ["/tmp/.ir-collect-123", "/var/tmp/.ir-collect-x", "/dev/shm/.ir-collect-a.b"],
)
def test_safe_scratch_dirs_are_accepted(value):
    path, err = remote._validate_remote_dir(value)
    assert err is None and path == value


@pytest.mark.parametrize(
    "value",
    [
        "/",
        "/etc",
        "/tmp",
        "/tmp/evil",
        "/tmp/../etc",
        "/home/user/.ir-collect-x",
        "/tmp/.ir-collect-a/b",
        "tmp/.ir-collect-a",
        "/tmp/.ir-collect-a;rm -rf /",
        "/tmp/.ir-collect-a b",
        "/tmp/.ir-collect-$HOME",
        "",
    ],
)
def test_unsafe_scratch_dirs_are_refused(value):
    path, err = remote._validate_remote_dir(value)
    assert path is None and err


def test_script_bounds_its_own_rm_rf():
    """Python-side validation plus an in-script guard (defence in depth)."""
    script = remote._collector_script("/tmp/.ir-collect-1")
    assert 'rm -rf "$OUT"' in script
    assert 'case "$OUT" in' in script
    assert "/tmp/.ir-collect-*|/var/tmp/.ir-collect-*|/dev/shm/.ir-collect-*" in script
    # The guard must precede the delete it protects.
    assert script.index('case "$OUT" in') < script.index('rm -rf "$OUT"')


def test_script_removes_its_own_uploaded_copy_unless_kept():
    removed = remote._collector_script("/tmp/.ir-collect-1")
    assert "rm -f /tmp/.ir-collect-1.sh" in removed
    kept = remote._collector_script("/tmp/.ir-collect-1", keep_remote=True)
    assert "rm -f /tmp/.ir-collect-1.sh" not in kept
    assert "keep_remote=true" in kept


# ── the approval text must describe what actually runs ──────────────────


def test_plan_discloses_the_destructive_steps():
    plan = remote.collect_plan(
        None, out_dir="/tmp/.ir-collect-1", local_dir="/tmp/out", keep_remote=False
    )
    assert "rm -rf" in plan.lower() or "delete that scratch dir" in plan
    assert "delete that scratch dir" in plan
    assert "/tmp/.ir-collect-1" in plan
    assert "not itself read-only" in plan
    assert "remove the uploaded script" in plan


def test_plan_names_the_local_unpack_dir():
    plan = remote.collect_plan(None, out_dir="/tmp/.ir-collect-1", local_dir="/data/ir/x")
    assert "/data/ir/x" in plan


def test_plan_flags_overwrite_only_when_enabled():
    without = remote.collect_plan(None, out_dir="/tmp/.ir-collect-1", local_dir="/d")
    assert "refused if occupied" in without
    with_ow = remote.collect_plan(
        None, out_dir="/tmp/.ir-collect-1", local_dir="/d", overwrite=True
    )
    assert "WILL be replaced" in with_ow


def test_plan_says_when_files_are_kept_on_the_target():
    plan = remote.collect_plan(
        None, out_dir="/tmp/.ir-collect-1", local_dir="/d", keep_remote=True
    )
    assert "keep_remote=true" in plan


def test_plan_still_lists_every_command():
    plan = remote.collect_plan(None, out_dir="/tmp/.ir-collect-1", local_dir="/d")
    for name, cmd in remote.collector_commands():
        assert f"[{name}]" in plan
        assert cmd in plan


# ── local extraction: no silent clobber, no drive-letter escape ─────────


@pytest.mark.parametrize(
    "name",
    [
        "C:/evil.txt",
        "C:evil.txt",
        "\\\\server\\share\\evil.txt",
        "/etc/evil",
        "../evil",
        "..\\evil",
        "a/../../evil",
    ],
)
def test_windows_and_posix_escapes_are_refused(tmp_path, name):
    ok, msg, _ = remote._extract_archive(_tar_bytes([(name, b"pwn")]), tmp_path / "o")
    assert ok is False
    assert "unsafe path" in msg


def test_extraction_refuses_to_overwrite_existing_files(tmp_path):
    dest = tmp_path / "o"
    dest.mkdir()
    victim = dest / "col" / "01-identity.txt"
    victim.parent.mkdir()
    victim.write_text("ORIGINAL", encoding="utf-8")

    ok, msg, _ = remote._extract_archive(
        _tar_bytes([("col/01-identity.txt", b"REPLACED")]), dest
    )
    assert ok is False
    assert "refusing to overwrite" in msg
    assert victim.read_text(encoding="utf-8") == "ORIGINAL"


def test_extraction_overwrites_when_explicitly_allowed(tmp_path):
    dest = tmp_path / "o"
    victim = dest / "col" / "01-identity.txt"
    victim.parent.mkdir(parents=True)
    victim.write_text("ORIGINAL", encoding="utf-8")

    ok, msg, _ = remote._extract_archive(
        _tar_bytes([("col/01-identity.txt", b"REPLACED")]), dest, overwrite=True
    )
    assert ok, msg
    assert victim.read_text(encoding="utf-8") == "REPLACED"


def test_setuid_bits_are_not_restored(tmp_path):
    """Evidence must never land as a setuid binary."""
    dest = tmp_path / "o"
    ok, msg, _ = remote._extract_archive(
        _tar_bytes([("col/run", b"#!/bin/sh\n")], modes=[0o4755]), dest
    )
    assert ok, msg
    mode = (dest / "col" / "run").stat().st_mode
    assert not mode & 0o4000
    assert not mode & 0o2000


def test_extraction_is_member_by_member_not_extractall(tmp_path, monkeypatch):
    """The pre-3.12 fallback used to be an unfiltered extractall()."""
    calls = []
    real_extract = tarfile.TarFile.extract

    def _spy(self, member, path="", set_attrs=True, *, filter=None, numeric_owner=False):
        calls.append(member.name)
        return real_extract(self, member, path, set_attrs, filter=filter,
                            numeric_owner=numeric_owner)

    monkeypatch.setattr(tarfile.TarFile, "extract", _spy)
    ok, _, _ = remote._extract_archive(
        _tar_bytes([("a.txt", b"x"), ("b.txt", b"y")]), tmp_path / "o"
    )
    assert ok
    assert calls == ["a.txt", "b.txt"]


# ── SFTP fetch: bounded, atomic, never a silent overwrite ───────────────


def _patch_client(monkeypatch, sftp):
    monkeypatch.setattr(remote, "_connect", lambda host, timeout: _FakeClient(sftp))


def test_fetch_refuses_to_replace_an_existing_file(tmp_path, monkeypatch):
    target = tmp_path / "evidence.bin"
    target.write_bytes(b"ORIGINAL")
    _patch_client(monkeypatch, _FakeSFTP(b"NEW"))

    ok, msg, size = remote.fetch_file(None, "h", "/remote/f", target)
    assert ok is False
    assert "already exists" in msg
    assert target.read_bytes() == b"ORIGINAL"


def test_fetch_replaces_only_when_allowed(tmp_path, monkeypatch):
    target = tmp_path / "evidence.bin"
    target.write_bytes(b"ORIGINAL")
    _patch_client(monkeypatch, _FakeSFTP(b"NEW"))

    ok, msg, size = remote.fetch_file(None, "h", "/remote/f", target, overwrite=True)
    assert ok, msg
    assert size == 3
    assert target.read_bytes() == b"NEW"


def test_fetch_passes_a_deadline_callback(tmp_path, monkeypatch):
    sftp = _FakeSFTP(b"NEW")
    _patch_client(monkeypatch, sftp)
    remote.fetch_file(None, "h", "/remote/f", tmp_path / "f.bin", timeout_s=30)
    assert sftp.callback_seen, "SFTP get() must carry a deadline callback"


def test_stalled_transfer_times_out_instead_of_hanging(tmp_path, monkeypatch):
    """A peer that stops sending must not block the worker thread forever."""
    import time as _time

    def _slow(callback):
        _time.sleep(1.3)  # longer than the clamped 1s budget
        callback(0, 10)  # the watchdog fires here

    sftp = _FakeSFTP(b"", on_get=_slow)
    _patch_client(monkeypatch, sftp)

    ok, msg, size = remote.fetch_file(
        None, "h", "/remote/big", tmp_path / "big.bin", timeout_s=1.0
    )
    assert ok is False
    assert "TimeoutError" in msg or "exceeded" in msg


def test_failed_fetch_leaves_no_partial_file(tmp_path, monkeypatch):
    target = tmp_path / "out.bin"

    class _Boom(_FakeSFTP):
        def get(self, remotepath, localpath, callback=None):
            Path(localpath).write_bytes(b"half a file")
            raise OSError("connection reset")

    _patch_client(monkeypatch, _Boom())
    ok, msg, size = remote.fetch_file(None, "h", "/remote/f", target)
    assert ok is False
    assert not target.exists()
    assert list(tmp_path.glob(".vulnclaw-fetch-*")) == []


# ── host-key policy: accept_new must actually remember ──────────────────


class _Policy:
    pass


class _RecordingSSHClient:
    def __init__(self):
        self.system_keys_loaded = False
        self.loaded: list[str] = []
        self.policy = ""
        self.saved: list[str] = []
        self.connect_kwargs: dict = {}

    def load_system_host_keys(self):
        self.system_keys_loaded = True

    def load_host_keys(self, path):
        self.loaded.append(path)

    def set_missing_host_key_policy(self, policy):
        self.policy = type(policy).__name__

    def connect(self, **kwargs):
        self.connect_kwargs = kwargs

    def save_host_keys(self, path):
        self.saved.append(path)

    def get_transport(self):
        return None


@pytest.fixture()
def fake_paramiko(monkeypatch):
    client = _RecordingSSHClient()
    module = types.SimpleNamespace(
        SSHClient=lambda: client,
        RejectPolicy=_Policy,
        AutoAddPolicy=_Policy,
    )
    monkeypatch.setattr(remote, "_import_paramiko", lambda: module)
    return client


def test_accept_new_records_the_key(monkeypatch, fake_paramiko, tmp_path):
    kh = tmp_path / "known_hosts"
    monkeypatch.setattr(remote, "_known_hosts_path", lambda: kh)
    remote._connect({"hostname": "h", "host_key_policy": "accept_new"}, 5.0)
    assert fake_paramiko.policy == "_Policy"  # AutoAddPolicy
    assert fake_paramiko.saved == [str(kh)], "TOFU must be persisted"


def test_insecure_does_not_record(monkeypatch, fake_paramiko, tmp_path):
    kh = tmp_path / "known_hosts"
    monkeypatch.setattr(remote, "_known_hosts_path", lambda: kh)
    remote._connect({"hostname": "h", "host_key_policy": "insecure"}, 5.0)
    assert fake_paramiko.saved == []


def test_recorded_keys_are_loaded_back(monkeypatch, fake_paramiko, tmp_path):
    """A recorded key is verified on the next session — that is the difference
    from `insecure`, which checked nothing."""
    kh = tmp_path / "known_hosts"
    kh.write_text("h ssh-rsa AAAAB3Nza\n", encoding="utf-8")
    monkeypatch.setattr(remote, "_known_hosts_path", lambda: kh)
    remote._connect({"hostname": "h", "host_key_policy": "accept_new"}, 5.0)
    assert fake_paramiko.loaded == [str(kh)]


def test_strict_policy_still_loads_system_keys(monkeypatch, fake_paramiko, tmp_path):
    monkeypatch.setattr(remote, "_known_hosts_path", lambda: tmp_path / "kh")
    remote._connect({"hostname": "h", "host_key_policy": "known_hosts"}, 5.0)
    assert fake_paramiko.system_keys_loaded
    assert fake_paramiko.saved == []


def test_default_policy_is_strict(fake_paramiko, tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "_known_hosts_path", lambda: tmp_path / "kh")
    remote._connect({"hostname": "h"}, 5.0)
    assert fake_paramiko.system_keys_loaded
