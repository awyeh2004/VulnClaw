"""Declared side effects per tool.

KubeTrail's ``collectors.SideEffects()`` plus ``runner.CollectorPlan`` answer a
question VulnClaw's run record could not: **what did this run actually do to the
target?** A production report today lists findings but cannot say whether the
run merely read a page or fired 400 brute-force attempts at a login form.

The declaration is deliberately separate from ``command_classifier.py``, which
answers a *different* question (may this command run unattended?). This table
answers "what class of change does invoking this tool make on the world", and it
is a property of the tool, not of the argument text.

Design notes
------------
- **Declared, not measured.** The entry is recorded before dispatch, so the
  record survives a tool that times out or crashes -- those are exactly the runs
  whose effects matter most. It is the same choice ``CollectorPlan`` makes.
- **Unknown tools are ``unclassified``, never ``safe``.** A new tool with no
  entry must not silently look harmless in the report. The test suite fails on
  any registered tool missing from the table, so this default should only ever
  apply to operator-supplied MCP tools.
- **``effect`` is a coarse class, not a log.** ``network_probe`` says the run
  touched the wire; it does not pretend to know how many requests.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Effect classes. Ordered from inert to hardest to undo.
FILE_READ = "file_read"
FILE_WRITE = "file_write"
LOCAL_STATE = "local_state_write"
PROCESS_EXEC = "process_exec"
NETWORK_PROBE = "network_probe"
AUTH_ATTEMPT = "auth_attempt"
REMOTE_EXEC = "remote_exec"
CONTAINER_START = "container_start"
PLATFORM_SUBMIT = "platform_submit"
UNCLASSIFIED = "unclassified"


@dataclass(frozen=True)
class ToolEffect:
    #: What the invocation does, coarse classes from the constants above.
    effects: tuple[str, ...]
    #: Whether the invocation can change state outside this machine's scratch
    #: area. ``True`` means the run's effects outlive it on the target -- the
    #: column an operator needs when deciding whether a run needs cleanup.
    touches_target: bool
    #: One-line note rendered next to the tool in the report ("" for the
    #: obvious ones).
    note: str = ""


def _e(*effects: str, touches: bool, note: str = "") -> ToolEffect:
    return ToolEffect(effects=effects, touches_target=touches, note=note)


#: Tool name -> declaration. Names match the schema/dispatch names exactly.
EFFECTS: dict[str, ToolEffect] = {
    # ── Local inspection: reads only ──────────────────────────────────
    "evidence_list": _e(FILE_READ, touches=False),
    "evidence_view": _e(FILE_READ, touches=False),
    "evidence_search": _e(FILE_READ, touches=False),
    "load_skill_reference": _e(FILE_READ, touches=False),
    "memory_search": _e(FILE_READ, touches=False),
    "vault_status": _e(FILE_READ, touches=False),
    "vault_search": _e(FILE_READ, touches=False),
    "blackboard_summary": _e(LOCAL_STATE, touches=False),
    "lookup_playbook": _e(FILE_READ, touches=False),
    "libc_lookup": _e(FILE_READ, touches=False),
    # ── Local reasoning state: writes only to this run's own store ────
    "report_finding": _e(LOCAL_STATE, touches=False, note="本地 finding，不是平台提交"),
    "blackboard_add_fact": _e(LOCAL_STATE, touches=False),
    "blackboard_record_answer": _e(LOCAL_STATE, touches=False),
    "blackboard_verify_fact": _e(LOCAL_STATE, touches=False),
    "blackboard_challenge_fact": _e(LOCAL_STATE, touches=False),
    "blackboard_add_intent": _e(LOCAL_STATE, touches=False),
    "blackboard_reject_intent": _e(LOCAL_STATE, touches=False),
    "blackboard_start_intent": _e(LOCAL_STATE, touches=False),
    "blackboard_review": _e(LOCAL_STATE, touches=False),
    "blackboard_set_lock": _e(LOCAL_STATE, touches=False),
    "blackboard_create_angle": _e(LOCAL_STATE, touches=False),
    "blackboard_hit_angle": _e(LOCAL_STATE, touches=False),
    "blackboard_miss_angle": _e(LOCAL_STATE, touches=False),
    "blackboard_create_tension": _e(LOCAL_STATE, touches=False),
    "blackboard_get_tensions": _e(FILE_READ, touches=False),
    "save_playbook": _e(LOCAL_STATE, touches=False),
    "vault_archive": _e(LOCAL_STATE, touches=False),
    "vault_restore": _e(FILE_READ, touches=False),
    "traffic_bind_evidence": _e(LOCAL_STATE, touches=False),
    "traffic_list": _e(FILE_READ, touches=False),
    "traffic_view": _e(FILE_READ, touches=False),
    # ── Local process execution (the gate decides whether it may run) ─
    "shell_command": _e(PROCESS_EXEC, FILE_WRITE, touches=True,
                        note="工作目录内执行，可能修改本机文件"),
    "python_execute": _e(PROCESS_EXEC, FILE_WRITE, touches=True),
    "source_extract": _e(FILE_READ, PROCESS_EXEC, touches=False),
    "runtime_diff_probe": _e(PROCESS_EXEC, touches=True),
    "crypto_decode": _e(PROCESS_EXEC, touches=False),
    "pwn_local_replay": _e(CONTAINER_START, PROCESS_EXEC, touches=False,
                           note="本地 Docker 容器内复现"),
    "pwn_local_stop": _e(CONTAINER_START, touches=False),
    # ── Network: touches the target ───────────────────────────────────
    "http_probe_batch": _e(NETWORK_PROBE, touches=True),
    "nmap_scan": _e(NETWORK_PROBE, touches=True),
    "dir_enum": _e(NETWORK_PROBE, touches=True),
    "subdomain_enum": _e(NETWORK_PROBE, touches=True),
    "js_recon": _e(NETWORK_PROBE, touches=True),
    "unauth_test": _e(NETWORK_PROBE, touches=True),
    "space_search": _e(NETWORK_PROBE, touches=False,
                       note="查外部空间测绘，不打靶标"),
    "traffic_repeat": _e(NETWORK_PROBE, touches=True, note="重放已记录的请求"),
    "brute_force_login": _e(NETWORK_PROBE, AUTH_ATTEMPT, touches=True,
                            note="对登录接口发起认证尝试"),
    # ── Remote execution over a declared host inventory ───────────────
    "remote_exec": _e(REMOTE_EXEC, touches=True),
    "remote_collect": _e(REMOTE_EXEC, FILE_READ, touches=True),
    "remote_fetch": _e(REMOTE_EXEC, FILE_READ, touches=True),
    "remote_hosts": _e(FILE_READ, touches=False),
    # ── Platform: submission is the one irreversible act in CTF mode ──
    "platform_submit": _e(PLATFORM_SUBMIT, touches=True, note="提交到平台，消耗尝试数"),
}

#: Everything a registered tool can be called by, for the completeness test.
#: Populated lazily from the schema builders so it cannot drift.
def registered_tool_names() -> set[str]:
    """Every tool name the model can call, from the schema source of truth."""

    names: set[str] = set()

    from vulnclaw.agent import builtin_tools

    def _collect(tool: dict) -> None:
        name = str((tool.get("function") or {}).get("name") or "")
        if name:
            names.add(name)

    try:
        from vulnclaw.agent.tool_schemas import append_builtin_tool_schemas

        append_builtin_tool_schemas(_collect)
    except Exception:  # noqa: BLE001 - the completeness test reports the gap
        pass
    for builder_name in (
        "pwn_local_tool_schemas",
        "remote_tool_schemas",
    ):
        try:
            module = getattr(builtin_tools, builder_name, None)
            if module is None:
                continue
            for schema in module():
                _collect(schema)
        except Exception:  # noqa: BLE001
            pass
    names.add(builtin_tools.REPORT_FINDING_TOOL_NAME)
    # Traffic/blackboard/playbook schemas are registered from their own modules.
    for module_path, attr in (
        ("vulnclaw.agent.blackboard", "tool_schemas"),
        ("vulnclaw.agent.playbook", "tool_schemas"),
    ):
        try:
            import importlib

            module = importlib.import_module(module_path)
            builder = getattr(module, attr, None)
            if builder is not None:
                for schema in builder():
                    _collect(schema)
        except Exception:  # noqa: BLE001
            pass
    return names


def effects_for(tool_name: str) -> ToolEffect:
    """Declaration for ``tool_name``; ``unclassified`` for anything unknown.

    Unknown must never render as harmless: an operator-supplied MCP tool that
    writes to the target and shows up as "no effects" would be worse than no
    column at all.
    """

    declared = EFFECTS.get(tool_name)
    if declared is not None:
        return declared
    if tool_name.startswith(("ctf2_", "gcs_", "platform_")):
        return _e(PLATFORM_SUBMIT, touches=True, note="平台工具（未逐项声明）")
    return _e(UNCLASSIFIED, touches=True, note="未声明副作用，按有影响对待")