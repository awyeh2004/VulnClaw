#!/usr/bin/env python3
"""Mechanical execution-boundary verifier for C-1/C-2 hardening.

Scans every module under ``vulnclaw/`` for process-spawn call sites and
checks each against a reviewed allowlist. Any *new* spawn site must be
added to the allowlist together with an owner and a purpose statement —
the script exits 1 otherwise, so review of new execution paths cannot be
skipped silently.

This is an architectural regression alarm, not a sandbox: it documents and
freezes the current attack surface. The model-reachable sites listed here
(shell_command / python_execute / PHP diff probe / generated-PoC verifier)
are the exact paths the ExecutionGate must cover.

Usage:
    python scripts/verify_execution_boundary.py            # scan vulnclaw/
    python scripts/verify_execution_boundary.py --json     # machine output
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_ROOT = REPO_ROOT / "vulnclaw"

# Callables that create (or can create) an OS process, plus the single shared
# funnel every ad-hoc text-mode subprocess call was collapsed into. Bare
# ``run_text`` must be scanned like a spawn: otherwise any new
# ``run_text(argv, shell=True)`` call site would be invisible to this audit,
# which is exactly the drift the audit exists to catch (round-5 C1).
_SPAWN_CALLS = {
    # subprocess module
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    # os family
    "os.system",
    "os.popen",
    "os.exec",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "os.posix_spawn",
    "os.posix_spawnp",
    # asyncio / multiprocessing / pty
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "multiprocessing.Process",
    "pty.spawn",
    "pty.fork",
    # the shared pinned-codec subprocess funnel
    "run_text",
}

# Reviewed baseline. Keyed by ``file:enclosing-scope:call:invariant-hash`` and
# carrying the number of call sites expected under that key.
#
# WHY NOT LINE NUMBERS: keys used to embed a line number, so inserting a line
# anywhere above a spawn site re-keyed it and the audit cried wolf. That
# happened five times (remote dispatch, cmd.exe quoting guard, GCS tool-face
# gating, an in-session edit, and the platform-tool refactor) for code that had
# not changed at all -- by the fifth, the note that used to sit here said to stop
# re-keying by hand and switch to the enclosing function or a content hash.
# This is that switch.
#
# What still fails the check (the guard keeps its teeth):
#   * a new scope, or a renamed one, containing a spawn call;
#   * a changed argv / call target (different invariant hash);
#   * one extra call site under a key whose count is already spent.
# What no longer fails: unrelated edits shifting line numbers, and moving a
# spawn site's code without changing it.
#
# "model-reachable" sites are exactly those the ExecutionGate must gate;
# "operator control plane" sites run fixed commands chosen by the local
# operator (doctor probes, TUI launcher).
ALLOWED_SPAWN_SITES: dict[str, dict[str, object]] = {
    # ── model-reachable: the ExecutionGate must cover these ──────────────
    "vulnclaw/agent/builtin_tools.py:_spawn_captured:subprocess.Popen:1eacb151": {
        "count": 1,
        "purpose": "shared gated process runner for shell/python/PHP execution",
    },
    "vulnclaw/agent/builtin_tools.py:_kill_process_tree:subprocess.run:0d8fbefe": {
        "count": 1,
        "purpose": "fixed Windows taskkill fallback for the gated process runner",
    },
    "vulnclaw/agent/builtin_tools.py:execute_nmap:run_text:23791bbb": {
        "count": 1,
        "purpose": "fixed Windows nmap path lookup (where.exe), via the pinned-codec funnel",
    },
    "vulnclaw/agent/builtin_tools.py:_run_nmap_argv:run_text:ddcaa122": {
        "count": 1,
        # model-reachable: called via asyncio.to_thread from execute_nmap;
        # argv stays the structured, schema-constrained nmap command (plus the
        # de-escalated retry) that the previous two inline subprocess.run
        # entries covered.
        "purpose": "structured argv nmap execution constrained by the nmap tool schema",
    },
    "vulnclaw/agent/builtin_tools.py:run_subprocess_capture:subprocess.run:f57fafd0": {
        "count": 1,
        "purpose": "run_subprocess_capture helper used by the pyc-analyze tool (PR #265-era module)",
    },
    "vulnclaw/report/verifier.py:VerifierExecutor.execute_poc:run_text:90b02123": {
        "count": 1,
        "purpose": "generated-PoC verification after synchronous ExecutionGate approval",
    },
    "vulnclaw/utils/subprocess_text.py:run_text:subprocess.run:8130d1f2": {
        "count": 1,
        "purpose": (
            "shared child-process runner with a pinned codec; the single funnel "
            "that every previously-ad-hoc subprocess.run(text=True) call now goes "
            "through. It introduces no execution path of its own -- callers keep "
            "their own ExecutionGate coverage -- it only stops the inherited "
            "locale from silently destroying child output."
        ),
    },
    # ── operator control plane: fixed commands chosen by the local operator ──
    "vulnclaw/cli/tui.py:run_tui:subprocess.call:31fb22ef": {
        "count": 1,
        "purpose": "operator control plane: native TUI binary launcher",
    },
    "vulnclaw/cli/tui.py:_command_version:run_text:eda38280": {
        "count": 1,
        "purpose": "operator control plane: fixed version diagnostic",
    },
    "vulnclaw/cli/tui.py:_read_system_clipboard:subprocess.run:000b7988": {
        "count": 1,
        "purpose": "operator control plane: Windows Get-Clipboard via powershell for /config paste",
    },
    "vulnclaw/cli/tui.py:_read_system_clipboard:subprocess.run:4650598c": {
        "count": 1,
        "purpose": "operator control plane: Unix pbpaste/wl-paste/xclip/xsel for /config paste",
    },
    "vulnclaw/cli/main.py:doctor:run_text:3409aa7f": {
        "count": 1,
        "purpose": "operator control plane: fixed Node.js version diagnostic",
    },
    # First-run setup wizard (merged from dev): operator-driven fixed argv
    # probes/installers; never model-reachable.
    "vulnclaw/cli/wizard.py:_WizardUi.clear:os.system:5cd31b04": {
        "count": 1,
        "purpose": "operator control plane: Windows terminal clear (cls)",
    },
    "vulnclaw/cli/wizard.py:_WizardUi.clear:os.system:3d6e81ea": {
        "count": 1,
        "purpose": "operator control plane: POSIX terminal clear (clear)",
    },
    "vulnclaw/cli/wizard.py:_java_major_version:run_text:078b11ec": {
        "count": 1,
        "purpose": "fixed java -version probe during wizard Java detection",
    },
    "vulnclaw/cli/wizard.py:ensure_java:run_text:eba5a3e8": {
        "count": 1,
        "purpose": "fixed winget install of Temurin JDK 17 package on user confirm",
    },
    "vulnclaw/cli/wizard.py:ensure_burp_mcp_jar:run_text:acf65aa5": {
        "count": 1,
        "purpose": "git clone of the constant PortSwigger mcp-server repo",
    },
    "vulnclaw/cli/wizard.py:ensure_burp_mcp_jar:run_text:c694af39": {
        "count": 1,
        "purpose": "gradlew embedProxyJar in the cloned constant repo (Windows shell)",
    },
    "vulnclaw/cli/wizard.py:ensure_burp_mcp_jar:run_text:65d5802e": {
        "count": 1,
        "purpose": "gradlew embedProxyJar in the cloned constant repo (POSIX argv)",
    },
    "vulnclaw/cli/wizard.py:launch_chrome_debug:subprocess.Popen:9ab7963f": {
        "count": 1,
        "purpose": "launch local Chrome with fixed argv for remote debugging",
    },
    "vulnclaw/cli/wizard.py:_open_url:subprocess.Popen:7f80d92e": {
        "count": 1,
        "purpose": "macOS open-URL launcher with fixed argv",
    },
    "vulnclaw/cli/wizard.py:_open_url:subprocess.Popen:8c0315af": {
        "count": 1,
        "purpose": "Linux xdg-open URL launcher with fixed argv",
    },
    "vulnclaw/cli/wizard.py:_open_path:subprocess.Popen:cbbbe138": {
        "count": 1,
        # Was mislabelled "Windows explorer" in the line-keyed allowlist; the
        # branch at 1116 is the Darwin one (Windows uses os.startfile).
        "purpose": "macOS open-path launcher with fixed argv",
    },
    "vulnclaw/cli/wizard.py:_open_path:subprocess.Popen:7961a112": {
        "count": 1,
        "purpose": "Linux xdg-open path launcher with fixed argv",
    },
    "vulnclaw/agent/network_scan.py:_wifi_interfaces:subprocess.run:5d0edc44": {
        "count": 1,
        "purpose": "fixed local wireless-interface diagnostic",
    },
    "vulnclaw/agent/network_scan.py:_interface_ipv4_network:subprocess.run:898b769c": {
        "count": 1,
        "purpose": "fixed local IPv4-interface diagnostic",
    },
}


@dataclass(frozen=True)
class SpawnSite:
    file: str
    line: int
    call: str
    scope: str
    invariant: str

    def key(self) -> str:
        """Stable allowlist key: no line number, so moved code stays reviewed.

        The previous key was ``file:line:call``, and every edit above a spawn
        site re-keyed it -- five rounds of hand re-registration for code that had
        not changed. The key is now the enclosing scope plus a hash of the call's
        own normalized source, so:

          * inserting lines / moving the function  -> same key  (no churn)
          * renaming the function                  -> new key   (review)
          * changing the argv or the call target   -> new key   (review)
        """
        return f"{self.file}:{self.scope}:{self.call}:{self.invariant}"

    def as_dict(self) -> dict[str, object]:
        return {
            "file": self.file,
            "line": self.line,
            "call": self.call,
            "scope": self.scope,
            "invariant": self.invariant,
        }


def _scope_of(tree: ast.AST) -> dict[int, str]:
    """Map every node id to the qualified name of its enclosing function.

    ``<module>`` for top-level calls, ``Cls.method`` for methods, and dotted
    names for nested defs, so a site's key says where it lives.
    """
    scopes: dict[int, str] = {}

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            name = prefix
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{prefix}.{child.name}" if prefix else child.name
            elif isinstance(child, ast.ClassDef):
                name = f"{prefix}.{child.name}" if prefix else child.name
            scopes[id(child)] = name
            visit(child, name)

    scopes[id(tree)] = "<module>"
    visit(tree, "")
    return scopes


def _call_invariant(call: ast.Call) -> str:
    """Short hash of the call with line/column noise stripped.

    ``ast.dump`` without attributes gives an exact structural fingerprint, which
    is what makes "the call still looks identical" checkable rather than a claim
    in a comment.
    """
    try:
        dumped = ast.dump(call, annotate_fields=False, include_attributes=False)
    except TypeError:  # pragma: no cover - Python without include_attributes
        dumped = ast.dump(call, annotate_fields=False)
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()[:8]


def _dotted_name(node: ast.AST) -> str | None:
    """Return 'a.b.c' for a pure attribute/name chain, else None."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _call_target(call: ast.Call) -> str | None:
    name = _dotted_name(call.func)
    if name is None:
        return None
    if name in _SPAWN_CALLS:
        return name
    # subprocess.getoutput("cmd") style is covered above; os.spawn* variants
    # with suffixes we did not enumerate still end in "spawn" via os.
    if name.startswith(("os.exec", "os.spawn")):
        return name
    return None


def scan_file(path: Path) -> list[SpawnSite]:
    # utf-8-sig accepts the BOM present in a few legacy modules. Real parse or
    # decode errors must fail CI rather than silently hiding every spawn in the
    # affected file.
    tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    rel = path.relative_to(REPO_ROOT).as_posix()
    scopes = _scope_of(tree)
    sites: list[SpawnSite] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            target = _call_target(node)
            if target is not None:
                sites.append(
                    SpawnSite(
                        file=rel,
                        line=node.lineno,
                        call=target,
                        scope=scopes.get(id(node), "<module>"),
                        invariant=_call_invariant(node),
                    )
                )
    return sites


def scan_tree() -> list[SpawnSite]:
    all_sites: list[SpawnSite] = []
    for path in sorted(SCAN_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        all_sites.extend(scan_file(path))
    return all_sites


def _partition_sites(
    sites: list[SpawnSite],
) -> tuple[list[SpawnSite], list[dict[str, object]]]:
    """Split scanned sites into reviewed ones and violations.

    A key is reviewed only while its call-site count is within the recorded
    budget, so adding a *second* spawn call next to an already-approved one is
    still a violation rather than riding along on the existing entry.

    Stale allowlist entries are violations too (round-5 C2): an entry whose key
    matched nothing in the tree is dead budget — it can silently absorb a
    structurally identical spawn if one is ever reintroduced, so it must be
    pruned at the same commit that removes the call site it used to cover.
    """
    grouped: dict[str, list[SpawnSite]] = {}
    for s in sites:
        grouped.setdefault(s.key(), []).append(s)

    reviewed: list[SpawnSite] = []
    violations: list[dict[str, object]] = []
    for key, rows in grouped.items():
        entry = ALLOWED_SPAWN_SITES.get(key)
        if entry is None:
            violations.extend({**r.as_dict(), "reason": "unreviewed key"} for r in rows)
            continue
        budget = int(entry["count"])  # type: ignore[arg-type]
        reviewed.extend(rows[:budget])
        if len(rows) > budget:
            violations.extend(
                {
                    **r.as_dict(),
                    "reason": f"key reviewed for {budget} site(s), found {len(rows)}",
                }
                for r in rows[budget:]
            )
    for key in sorted(set(ALLOWED_SPAWN_SITES) - set(grouped)):
        violations.append({"key": key, "reason": "stale allowlist entry (matches nothing)"})
    return reviewed, violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    args = parser.parse_args()

    sites = scan_tree()
    reviewed, violations = _partition_sites(sites)

    if args.json:
        print(
            json.dumps(
                {
                    "ok": not violations,
                    "reviewed_sites": [
                        {
                            **s.as_dict(),
                            "purpose": ALLOWED_SPAWN_SITES[s.key()]["purpose"],
                        }
                        for s in reviewed
                    ],
                    "violations": violations,
                    # Line numbers are reported per site but are deliberately NOT
                    # part of the key (see ALLOWED_SPAWN_SITES).
                    "allowlist": {
                        k: dict(v) for k, v in ALLOWED_SPAWN_SITES.items()
                    },
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0 if not violations else 1

    if violations:
        print("execution-boundary check FAILED — unreviewed/stale spawn entries:\n")
        for v in violations:
            if "key" in v and "file" not in v:  # stale allowlist entry
                print(f"  ALLOWLIST {v['key']}")
                print(f"      reason: {v.get('reason')}")
                continue
            print(f"  {v['file']}:{v['line']}  {v['call']}()  [{v.get('scope')}]")
            print(f"      key:    {v['file']}:{v.get('scope')}:{v['call']}:{v.get('invariant')}")
            print(f"      reason: {v.get('reason')}")
        print(
            "\nEvery new process-spawn call site must be reviewed and added to\n"
            "ALLOWED_SPAWN_SITES in scripts/verify_execution_boundary.py with an\n"
            "owner/purpose note before it can merge. The key is\n"
            "  file:enclosing-scope:call:invariant-hash\n"
            "so it survives line shifts; if only the line moved, nothing to do.\n"
            "Stale entries must be deleted in the same commit that removes the\n"
            "call site they covered — dead budget can silently absorb a\n"
            "reintroduced spawn.\n"
        )
        return 1

    print(
        f"execution-boundary OK — {len(sites)} spawn site(s), "
        f"all inside the reviewed allowlist."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
