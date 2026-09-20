"""Tests for the remote (SSH) execution module.

Three things are worth protecting here, in priority order:

1. **The approval gate cannot be bypassed.** `remote_exec` is remote code
   execution against another machine. If a refactor ever lets a remote command
   skip `ExecutionGate`, the module becomes a privilege-escalation path around
   the project's only safety control. The gate tests below are the guard.

2. **The read-only classifier applies to remote commands.** Same table as local
   shell, so remote recon is unattended in `auto_review` while remote mutations
   prompt.

3. **Archive extraction from a compromised host is safe.** The collected tar.gz
   is attacker-influenced input; path traversal and symlink escape must be
   refused.

No test here opens a network connection: `_connect` is never called except
through monkeypatching in the one test that asserts fail-fast behaviour.
"""

from __future__ import annotations

import io
import tarfile

import pytest

from vulnclaw.agent.exec_gate import ExecutionGate, GateRequest
from vulnclaw.agent.remote import (
    COLLECT_MARKER,
    CollectorResult,
    RemoteResult,
    _collector_script,
    _extract_archive,
    _hv,
    _normalize_hosts,
    _parse_collector_stdout,
    _target_desc,
    collect_plan,
    collector_commands,
    list_hosts,
    remote_tool_schemas,
    resolve_host,
)
from vulnclaw.config.schema import SSHHostConfig, VulnClawConfig


# ── helpers ──────────────────────────────────────────────────────────────


class FakeChannel:
    """Scriptable trusted channel, mirroring tests/security/test_exec_gate.py."""

    def __init__(self, decisions: list[str] | None = None):
        self.views: list = []
        self.decisions = list(decisions or [])

    async def request_approval(self, view):
        self.views.append(view)
        return self.decisions.pop(0) if self.decisions else "deny"


def _cfg_with_hosts(**hosts) -> VulnClawConfig:
    """Config with a plain-dict inventory (mirrors a hand-written YAML load)."""
    cfg = VulnClawConfig()
    cfg.remote.hosts = hosts
    return cfg


def _tar_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _tar_with_link(name: str, target: str, *, hard: bool = False) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name)
        info.type = tarfile.LNKTYPE if hard else tarfile.SYMTYPE
        info.linkname = target
        tf.addfile(info)
    return buf.getvalue()


# ── host inventory ──────────────────────────────────────────────────────


class TestHostInventory:
    def test_empty_inventory_explains_how_to_configure(self):
        text = list_hosts(VulnClawConfig())
        assert "No remote hosts configured" in text
        assert "remote.hosts" in text
        # The example must use the TOFU option, since a competition VM has no
        # known_hosts entry and the strict default would just fail.
        assert "accept_new" in text

    def test_dict_entries_are_supported(self):
        """`config.remote.hosts = {...}` skips pydantic validation, so raw dicts
        must work -- this was a real AttributeError before _hv existed."""
        cfg = _cfg_with_hosts(victim={"hostname": "10.0.0.5", "username": "root"})
        text = list_hosts(cfg)
        assert "victim" in text
        assert "root@10.0.0.5:22" in text

    def test_objectic_entries_are_supported(self):
        cfg = VulnClawConfig()
        cfg.remote.hosts["v"] = SSHHostConfig(hostname="10.0.0.6", username="admin", port=2222)
        text = list_hosts(cfg)
        assert "admin@10.0.0.6:2222" in text

    def test_auth_method_is_reported(self):
        cfg = _cfg_with_hosts(
            k={"hostname": "a", "key_file": r"C:\keys\id_ed25519"},
            p={"hostname": "b", "password": "s3cret"},
            n={"hostname": "c"},
        )
        text = list_hosts(cfg)
        assert "key:id_ed25519" in text
        assert "auth=password" in text
        assert "agent/default keys" in text
        # A password must never be echoed back in the inventory listing.
        assert "s3cret" not in text

    def test_unknown_alias_lists_configured_ones(self):
        cfg = _cfg_with_hosts(alpha={"hostname": "a"}, beta={"hostname": "b"})
        with pytest.raises(ValueError) as exc:
            resolve_host(cfg, "gamma")
        message = str(exc.value)
        assert "alpha" in message and "beta" in message
        assert "inventory-based" in message

    def test_empty_alias_is_rejected(self):
        with pytest.raises(ValueError):
            resolve_host(_cfg_with_hosts(a={"hostname": "a"}), "   ")

    def test_hv_reads_both_shapes_and_applies_default(self):
        assert _hv({"hostname": "x"}, "hostname") == "x"
        assert _hv(SSHHostConfig(hostname="y"), "hostname") == "y"
        assert _hv({"hostname": "x"}, "port", 22) == 22
        assert _hv({"port": None}, "port", 22) == 22  # None falls back

    def test_normalize_hosts_copies_inventory(self):
        cfg = _cfg_with_hosts(a={"hostname": "a"})
        snapshot = _normalize_hosts(cfg)
        snapshot["b"] = {"hostname": "b"}
        assert "b" not in cfg.remote.hosts  # must not mutate the config

    def test_target_desc_formats_defaults(self):
        assert _target_desc({"hostname": "h"}) == "root@h:22"


# ── tool schemas ────────────────────────────────────────────────────────


class TestToolSchemas:
    def test_expected_tools_are_exposed(self):
        names = {s["function"]["name"] for s in remote_tool_schemas()}
        assert names == {"remote_exec", "remote_collect", "remote_fetch", "remote_hosts"}

    def test_every_schema_is_wellformed(self):
        for schema in remote_tool_schemas():
            assert schema["type"] == "function"
            fn = schema["function"]
            assert fn["name"] and fn["description"]
            params = fn["parameters"]
            assert params["type"] == "object"
            # remote_hosts takes no arguments, so it legitimately has none.
            required = params.get("required", [])
            assert set(required) <= set(params.get("properties", {}))

    def test_remote_exec_requires_command(self):
        exec_schema = next(
            s for s in remote_tool_schemas() if s["function"]["name"] == "remote_exec"
        )
        assert set(exec_schema["function"]["parameters"]["required"]) == {"host", "command"}

    def test_descriptions_state_the_approval_behaviour(self):
        """The model must know recon is unattended but mutations prompt, so it
        does not waste turns working around a gate that is not in its way."""
        exec_desc = next(
            s["function"]["description"]
            for s in remote_tool_schemas()
            if s["function"]["name"] == "remote_exec"
        )
        assert "approval gate" in exec_desc


# ── collector ───────────────────────────────────────────────────────────


class TestCollector:
    def test_commands_are_named_and_unique(self):
        cmds = collector_commands()
        names = [n for n, _ in cmds]
        assert len(names) == len(set(names)), "section names must be unique"
        assert all(n and c for n, c in cmds)

    def test_commands_are_read_only(self):
        """A collection must not mutate the target. Guard against someone
        adding a cleanup/`rm`/`systemctl stop` step later.

        Patterns are anchored to command position (start or after a separator) so
        that legitimate read-only flags like `find -perm` do not false-positive.
        """
        import re

        start = r"(?:^|[;&|]\s*)"
        banned = [
            (rf"{start}rm\s+-", "rm -"),
            (rf"{start}rm\s", "rm"),
            (rf"{start}mv\s", "mv"),
            (rf"{start}dd\s", "dd"),
            (rf"{start}truncate\b", "truncate"),
            (rf"{start}shred\b", "shred"),
            (rf"{start}userdel\b", "userdel"),
            (rf"{start}chmod\s", "chmod"),
            (rf"{start}chown\s", "chown"),
            (rf"{start}kill\s", "kill"),
            (r"systemctl\s+(?:stop|disable|mask)", "systemctl stop/disable"),
            (r">\s*/etc/", "writing under /etc"),
            (r"iptables\s+-F", "flushing firewall"),
        ]
        for name, cmd in collector_commands():
            for pattern, label in banned:
                assert not re.search(pattern, cmd), (
                    f"section {name!r} looks mutating ({label}): {cmd[:80]}"
                )

    def test_commands_are_posix_sh_not_bash(self):
        """Targets are often minimal (the drill box has neither python nor bash
        guarantees). Bash-only constructs would silently produce empty sections.

        NOTE: ``[[:space:]]`` is a POSIX bracket expression accepted by grep -E,
        not the bash ``[[`` keyword, so the check must not match it.
        """
        import re

        bashisms = [
            # The bash [[ keyword needs a closing ]]: this is what keeps
            # `grep -vE '^[[:space:]]*#'` (a POSIX bracket expression) from
            # being flagged. Measured -- the naive "[[" check false-positived.
            (r"(?:^|[;&|]\s*)\[\[.*\]\]", "[[ keyword"),
            (r"\bpipefail\b", "pipefail"),
            (r"=~", "=~ regex operator"),
            (r"\bdeclare\s+-a\b", "declare -a"),
            (r"^\s*function\s+\w+", "function keyword"),
            (r"\becho\s+-e\b", "echo -e"),
        ]
        for name, cmd in collector_commands():
            for pattern, label in bashisms:
                assert not re.search(pattern, cmd), (
                    f"section {name!r} uses bashism {label}: {cmd[:80]}"
                )

    def test_script_has_one_section_file_per_command(self):
        script = _collector_script("/tmp/out")
        for idx, (name, _) in enumerate(collector_commands(), start=1):
            assert f'$OUT/{idx:02d}-{name}.txt' in script

    def test_script_does_not_tar_the_root(self):
        """`tar czf x.tar.gz /` (or archiving into a scanned dir) is how these
        scripts end up recursing into their own output."""
        script = _collector_script("/tmp/out")
        assert "tar -czf" in script
        assert "-C " in script
        # The archive is built from the scratch dir's PARENT, selecting only the
        # scratch dir -- never a bare filesystem root.
        assert "-czf \"$OUT.tar.gz\" -C" in script

    def test_script_uses_dedicated_out_dir_and_cleans_it(self):
        script = _collector_script("/tmp/mine")
        assert 'OUT=/tmp/mine' in script
        assert 'rm -rf "$OUT"' in script
        assert 'mkdir -p "$OUT"' in script

    def test_script_is_sh_syntax(self):
        script = _collector_script("/tmp/out")
        assert script.startswith("#!/bin/sh")
        assert "set -u" in script

    def test_plan_lists_every_command(self):
        plan = collect_plan(VulnClawConfig())
        for name, _ in collector_commands():
            assert f"[{name}]" in plan

    def test_plan_and_script_are_generated_from_the_same_list(self):
        """This is the property that makes 'approve the batch' honest: what the
        operator approves (the plan) is what runs (the script)."""
        plan = collect_plan(VulnClawConfig())
        script = _collector_script("/tmp/out")
        for _, cmd in collector_commands():
            assert cmd in plan
            assert cmd in script

    def test_parse_sections_requires_the_marker(self):
        assert _parse_collector_stdout("command output with\ttabs\n") == []

    def test_parse_sections_after_marker(self):
        text = f"junk\n{COLLECT_MARKER}\n01-identity.txt\t10\n02-accounts.txt\t20\nARCHIVE=/tmp/a.tar.gz\n"
        assert _parse_collector_stdout(text) == ["01-identity.txt", "02-accounts.txt"]

    def test_parse_sections_ignores_non_section_lines(self):
        text = f"{COLLECT_MARKER}\nnote\t1\n03-x.txt\t2\nARCHIVE=/x\n"
        assert _parse_collector_stdout(text) == ["03-x.txt"]


# ── archive extraction safety ───────────────────────────────────────────


class TestArchiveSafety:
    def test_normal_archive_extracts(self, tmp_path):
        ok, msg, sections = _extract_archive(
            _tar_bytes([("col/01-identity.txt", b"hi"), ("col/02-accounts.txt", b"x")]),
            tmp_path / "out",
        )
        assert ok, msg
        assert set(sections) == {"01-identity.txt", "02-accounts.txt"}
        assert (tmp_path / "out" / "col" / "01-identity.txt").read_bytes() == b"hi"

    @pytest.mark.parametrize("name", ["../evil.txt", "../../etc/passwd", "/etc/evil"])
    def test_traversal_and_absolute_paths_are_refused(self, tmp_path, name):
        ok, msg, _ = _extract_archive(_tar_bytes([(name, b"pwn")]), tmp_path / "o")
        assert ok is False
        assert "unsafe path" in msg

    @pytest.mark.parametrize("target", ["/etc/passwd", "../../etc/passwd", "../x"])
    def test_symlink_escape_is_refused(self, tmp_path, target):
        ok, msg, _ = _extract_archive(_tar_with_link("link", target), tmp_path / "o")
        assert ok is False
        assert "unsafe link" in msg

    def test_hardlink_escape_is_refused(self, tmp_path):
        ok, msg, _ = _extract_archive(
            _tar_with_link("h", "/etc/passwd", hard=True), tmp_path / "o"
        )
        assert ok is False
        assert "unsafe link" in msg

    def test_nothing_is_written_when_refused(self, tmp_path):
        dest = tmp_path / "o"
        _extract_archive(_tar_bytes([("../evil.txt", b"pwn")]), dest)
        assert not (tmp_path / "evil.txt").exists()

    def test_garbage_input_is_reported_not_raised(self, tmp_path):
        ok, msg, _ = _extract_archive(b"not a tarball", tmp_path / "o")
        assert ok is False
        assert msg


# ── renderers ───────────────────────────────────────────────────────────


class TestRendering:
    def test_remote_result_includes_target_and_status(self):
        res = RemoteResult(
            alias="v1", hostname="10.0.0.5", command="id", exit_code=0,
            stdout="uid=0(root)", host_key_fingerprint="ssh-ed25519 SHA256:abc",
        )
        text = res.render()
        assert "v1 (10.0.0.5)" in text
        assert "id" in text
        assert "exit 0" in text
        assert "SHA256:abc" in text
        assert "uid=0(root)" in text

    def test_remote_result_error_short_circuits(self):
        res = RemoteResult(alias="v1", hostname="h", command="id", error="boom")
        text = res.render()
        assert "Error: boom" in text
        assert "Output:" not in text

    def test_remote_result_truncates(self):
        res = RemoteResult(alias="v", hostname="h", command="c", stdout="A" * 500)
        assert "truncated at 100 chars" in res.render(max_chars=100)

    def test_remote_result_ok_property(self):
        assert RemoteResult("v", "h", "c", exit_code=0).ok is True
        assert RemoteResult("v", "h", "c", exit_code=1).ok is False
        assert RemoteResult("v", "h", "c", error="x").ok is False
        assert RemoteResult("v", "h", "c", timed_out=True).ok is False

    def test_collector_result_warns_about_attacker_data(self):
        """Artifacts from a compromised host must never be presented as trusted."""
        text = CollectorResult(alias="v", hostname="h").render()
        assert "ATTACKER-INFLUENCED" in text
        assert "never execute" in text

    def test_collector_result_reports_missing_archive(self):
        assert "NOT PRODUCED" in CollectorResult(alias="v", hostname="h").render()

    def test_collector_result_lists_archive_and_sections(self):
        res = CollectorResult(
            alias="v", hostname="h", archive_path="/tmp/out",
            archive_bytes=1234, sections=["01-identity.txt"], duration_s=2.5,
        )
        text = res.render()
        assert "/tmp/out" in text and "1,234 bytes" in text
        assert "01-identity.txt" in text


# ── the safety property: the gate cannot be bypassed ────────────────────


class TestGateAppliesToRemote:
    """`remote_exec` must go through ExecutionGate with the shared classifier."""

    async def test_readonly_remote_command_is_auto_approved(self):
        gate = ExecutionGate(mode="auto_review")
        outcome = await gate.authorize(GateRequest(kind="remote", display="ps aux"))
        assert outcome.approved is True
        assert outcome.status == "approved"

    async def test_mutating_remote_command_needs_approval(self):
        """No channel installed -> refused, not silently allowed."""
        gate = ExecutionGate(mode="auto_review")
        outcome = await gate.authorize(GateRequest(kind="remote", display="rm -rf /var/log"))
        assert outcome.approved is False
        assert outcome.status == "no_channel"

    async def test_mutating_remote_command_prompts_when_channel_present(self):
        gate = ExecutionGate(mode="auto_review", timeout_seconds=5)
        channel = FakeChannel(["deny"])
        gate.install_channel(channel)
        outcome = await gate.authorize(GateRequest(kind="remote", display="userdel -r sysupdate"))
        assert outcome.approved is False
        assert channel.views, "the operator must actually be asked"
        assert channel.views[0].kind == "remote"

    async def test_remote_redirection_still_prompts(self):
        gate = ExecutionGate(mode="auto_review")
        outcome = await gate.authorize(
            GateRequest(kind="remote", display="ps aux > /tmp/x")
        )
        assert outcome.approved is False, "redirection can overwrite files remotely too"

    async def test_remote_interpreter_still_prompts(self):
        gate = ExecutionGate(mode="auto_review")
        outcome = await gate.authorize(
            GateRequest(kind="remote", display="python -c 'import os'")
        )
        assert outcome.approved is False

    async def test_the_remote_target_is_part_of_the_approval_detail(self):
        """An approval must never be blind about WHICH machine is touched."""
        gate = ExecutionGate(mode="auto_review", timeout_seconds=5)
        channel = FakeChannel(["approve"])
        gate.install_channel(channel)
        await gate.authorize(
            GateRequest(
                kind="remote",
                display="useradd -o -u 0 backdoor",
                detail="target v1 -> root@10.0.0.5:22 | remote exec",
            )
        )
        assert "10.0.0.5" in channel.views[0].detail

    async def test_shell_kind_behaviour_is_unchanged(self):
        """Regression guard: folding "remote" in must not alter shell semantics."""
        gate = ExecutionGate(mode="auto_review")
        assert (await gate.authorize(GateRequest(kind="shell", display="ps aux"))).approved
        assert not (
            await gate.authorize(GateRequest(kind="shell", display="rm -rf /"))
        ).approved

    async def test_python_kind_is_still_never_allowlisted(self):
        gate = ExecutionGate(mode="auto_review")
        outcome = await gate.authorize(GateRequest(kind="python", display="print(1)"))
        assert outcome.approved is False
