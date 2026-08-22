"""Muteki-style multi-model swarm launcher for local challenge analysis.

Launches two heterogeneous solve agents (glm + ds) on the same challenge in
parallel, each sharing a blackboard file (facts/dead-ends) so findings from
one worker help the other. A lightweight reviewer loop watches both: if one
stops progressing (dead-loop), it is killed so the other can continue.

Usage:
    python launch_swarm.py <eid> [<eid> ...]
"""

import glob
import os
import re
import subprocess
import sys
import time

# Paths come from environment variables so this script is machine-agnostic.
#   VULNCLAW_SWARM_DIR  - repo root used as cwd + log output (default: this file's repo)
#   VULNCLAW_WORK_DIR   - challenge work root (attachments / swarm blackboard / writeups)
# Falls back to %USERPROFILE%\vulnclaw\work when the env var is unset.
WORKDIR = os.environ.get("VULNCLAW_SWARM_DIR", os.path.dirname(os.path.abspath(__file__)))
_WORK_ROOT = os.environ.get(
    "VULNCLAW_WORK_DIR", os.path.expandvars(r"%USERPROFILE%\vulnclaw\work")
)
BBASE = os.path.join(_WORK_ROOT, "swarm")
WRITEUP_DIR = os.path.join(_WORK_ROOT, "writeup")

MODELS = ["glm", "ds"]


def _blackboard_path(eid: str) -> str:
    os.makedirs(BBASE, exist_ok=True)
    return os.path.join(BBASE, f"{eid}.md")


def _init_blackboard(eid: str, prompt: str) -> str:
    path = _blackboard_path(eid)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Swarm blackboard: {eid}\n\n- Task: {prompt[:200]}\n- Facts: none yet\n- Dead ends: none\n")
    return path


def _read_blackboard(eid: str) -> str:
    path = _blackboard_path(eid)
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def _append_fact(eid: str, text: str) -> None:
    path = _blackboard_path(eid)
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"\n- Fact: {text}\n")
    except OSError:
        pass


def _append_dead_end(eid: str, text: str) -> None:
    path = _blackboard_path(eid)
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"\n- Dead end: {text}\n")
    except OSError:
        pass


def launch(eid: str, prompt: str) -> list[int]:
    board = _init_blackboard(eid, prompt)
    pids = []
    for model in MODELS:
        worker_prompt = (
            f"{prompt}\n\n【共享黑板】解题前先读 {board} 里的 facts/dead ends,"
            f"避免重复死路;发现新事实或死路时,用 python_execute 把内容 append 到该文件"
            f"(格式: - Fact: ... 或 - Dead end: ...)。这是多模型协作,你的发现会帮助另一模型。"
        )
        cmd = [
            sys.executable, "-m", "vulnclaw", "solve",
            f"local-{eid}", "--model", model,
            "--goal", "analyze the local challenge and output the flag",
            "--prompt", worker_prompt,
            "--writeup-dir", WRITEUP_DIR,
        ]
        log = open(os.path.join(WORKDIR, f"swarm_{eid}_{model}.log"), "wb")
        p = subprocess.Popen(
            cmd, cwd=WORKDIR, stdout=log, stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        pids.append(p.pid)
        print(f"[swarm] {eid} {model} pid={p.pid}")
    return pids


def _log_lines(path: str) -> int:
    try:
        with open(path, encoding="utf-8") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def review(eid: str, pids: list[int], idle_rounds_max: int = 6) -> None:
    """Watch workers; kill one stuck in a dead-loop so the other continues."""
    logs = [os.path.join(WORKDIR, f"swarm_{eid}_{m}.log") for m in MODELS]
    lines = [_log_lines(l) for l in logs]
    idle = [0, 0]
    while True:
        time.sleep(45)
        alive = [bool(__import__("os").path.exists(f"/proc/{p}")) if sys.platform != "win32" else bool(__import__("ctypes").windll.kernel32.OpenProcess(0x1000, False, p)) for p in pids]
        # simpler alive check via Get-Process
        new_lines = [_log_lines(l) for l in logs]
        for i in range(2):
            if alive[i] is False:
                continue
            if new_lines[i] == lines[i]:
                idle[i] += 1
            else:
                idle[i] = 0
            if idle[i] >= idle_rounds_max:
                print(f"[reviewer] {eid} {MODELS[i]} dead-loop, killing")
                subprocess.run(["taskkill", "/F", "/PID", str(pids[i])], capture_output=True)
                idle[i] = 0
        lines = new_lines
        if not any(alive):
            break


def _attachment_prompt(eid: str) -> str:
    """Build a prompt that points the worker at the downloaded attachment, using
    the configured work root (no hardcoded machine paths)."""
    attach_root = os.environ.get("VULNCLAW_ATTACH_DIR", os.path.join(_WORK_ROOT, "attachments"))
    # Try <work>/attachments/<eid>_* first, then <work>/<eid>.
    dirs = []
    if os.path.isdir(attach_root):
        dirs.extend(sorted(glob.glob(os.path.join(attach_root, f"{eid}_*"))))
    dirs.extend([os.path.join(_WORK_ROOT, eid)])
    existing = [d for d in dirs if os.path.isdir(d)]
    if existing:
        return f"本地题目 {eid},附件已解压到 {existing[0]},分析解出 flag"
    return f"本地题目 {eid},附件在 {attach_root},分析解出 flag"


def main() -> None:
    eids = sys.argv[1:]
    if not eids:
        print("usage: launch_swarm.py <eid> [<eid> ...]")
        sys.exit(1)
    prompts = {
        "10733": None,  # built dynamically below
        "10751": None,
    }
    for eid in eids:
        prompt = prompts.get(eid) or _attachment_prompt(eid)
        pids = launch(eid, prompt)
        # reviewer in background thread
        import threading
        threading.Thread(target=review, args=(eid, pids), daemon=True).start()


if __name__ == "__main__":
    main()