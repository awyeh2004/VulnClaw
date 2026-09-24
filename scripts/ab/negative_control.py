"""任务 1：同类迁移的冷/热配对重跑，读逐条命中与分数。

- COLD 目录每次重建为空（真空）；
- WARM 目录只种**手工技术笔记**（curated），不放自动笔记 —— 这样热跑里任何注入都必然
  来自"同类题迁移"，而不是同目标自动笔记；
- 三个同类兄弟题，各做冷/热一次；
- 从日志里抓 `[playbook] injected …` 行，得到"命中了什么、多少分、哪个键"。
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, ".")
from vulnclaw.ctf_platform import client as c

ROOT = Path(r"D:\GitClone\VulnClaw")
REPO = Path(__file__).resolve().parents[2]
LOGS = Path(".test-tmp/neg-logs")
PRACTICE = "2de971ac-26fe-448a-8719-01829e52c1d5"
MAX_STEPS = "30"
RUN_TIMEOUT_S = 600
TOKEN = ""

# 见 cold_warm_pair.py 里的同一条说明：种子与基准 config 已入库到 scripts/ab/seeds/，
# 不再依赖仓库外的 ab-config-*（那是上一轮会话的实验目录，不是入库资产）。
SEEDS = REPO / "scripts" / "ab" / "seeds"
COLD = REPO / ".test-tmp" / "abcfg-COLD"
WARM = REPO / ".test-tmp" / "abcfg-WARM"
SEED_FROM = SEEDS / "playbooks"
SEED = [
    "thinkphp-5-0-23-rce-captcha-route.md",
    "weblogic-cve-2017-10271-wls-wsat-xmldecoder-rce-.md",
    "dasctf-direct-ctf2-php-xxe-dom-php.md",
    "php-xxe-vulhub-php-xxe.md",
]

SIBLINGS = [
    ("[Weblogic]SSRF", "5fcc745e-4272-45cd-9f8f-435870e88199"),
]


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def goal_text(name: str, url: str) -> str:
    return (
        f"Target: {url}\n"
        f"This is a CTF challenge web service ({name}). Exploit it to obtain the flag.\n"
        f"The flag is stored inside the target container: usually an environment variable "
        f"named FLAG, or a file such as /flag. Report the exact flag value.\n"
        f"Do not attack the CTF platform itself; only this target is in scope."
    )


def build_cfg(cfg: Path, seed: bool) -> None:
    if cfg.exists():
        shutil.rmtree(cfg)
    cfg.mkdir(parents=True)
    shutil.copy2(SEEDS / "config.yaml", cfg / "config.yaml")
    books = cfg / "playbooks"
    books.mkdir(exist_ok=True)
    (cfg / "work").mkdir(exist_ok=True)
    if seed:
        for name in SEED:
            src = SEED_FROM / name
            if src.exists():
                shutil.copy2(src, books / name)
    log(f"    {cfg.name}: curated 笔记 {len(list(books.glob('*.md')))} 条")


def env_for(cfg: Path) -> dict:
    env = dict(os.environ)
    env.update({
        "PYTHONIOENCODING": "utf-8",
        "VULNCLAW_CONFIG_DIR": str(cfg),
        "VULNCLAW_CTF2_SESSION_TOKEN": TOKEN,
        "VULNCLAW_WORK_DIR": str(cfg / "work"),
        "VULNCLAW_LANG": "zh",
    })
    return env


async def start_env(cid: str) -> str:
    for attempt in range(8):
        try:
            await c.start_environment(PRACTICE, cid)
        except Exception as exc:  # noqa: BLE001
            log(f"    start {attempt + 1} 失败: {str(exc)[:70]}")
            await asyncio.sleep(6)
            continue
        deadline = time.time() + 150
        while time.time() < deadline:
            try:
                payload = await c.get_target(PRACTICE, cid)
            except Exception:  # noqa: BLE001
                payload = None
            node = payload.get("data") if isinstance(payload, dict) else payload
            if isinstance(node, dict) and str(node.get("status", "")).lower() in {"running", "ready"}:
                return str(node.get("access_url") or "")
            await asyncio.sleep(5)
    return ""


async def release(cid: str) -> None:
    for _ in range(3):
        try:
            await c.stop_target(PRACTICE, cid)
            return
        except Exception as exc:  # noqa: BLE001
            if "NOT_FOUND" in str(exc):
                return
            await asyncio.sleep(3)


def run_once(tag: str, cfg: Path, url: str, name: str) -> dict:
    LOGS.mkdir(parents=True, exist_ok=True)
    safe = name.replace("/", "_").replace("[", "").replace("]", "").replace(" ", "-")
    logfile = LOGS / f"{safe}-{tag}.log"
    target = url if url.startswith("http") else f"http://{url}"
    cmd = [sys.executable, "-X", "utf8", "-m", "vulnclaw", "solve", target,
           "--goal", goal_text(name, target), "--max-steps", MAX_STEPS]
    log(f"    {tag}: solve {target}")
    started = time.time()
    with open(logfile, "w", encoding="utf-8", errors="replace") as fh:
        fh.write(f"# {tag} cfg={cfg}\n")
        fh.flush()
        proc = subprocess.Popen(cmd, cwd=str(ROOT / "VulnClaw"), env=env_for(cfg),
                                stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        timed_out = False
        try:
            proc.wait(timeout=RUN_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            timed_out = True
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass
    elapsed = round(time.time() - started, 1)
    log(f"    {tag}: exit={proc.returncode} {elapsed}s")
    return {"tag": tag, "challenge": name, "seconds": elapsed, "exit": proc.returncode,
            "timed_out": timed_out, "log": str(logfile)}


async def main() -> None:
    global TOKEN
    TOKEN = c.session_token()
    if not TOKEN:
        log("无令牌"); return
    results = []
    for name, cid in SIBLINGS:
        log(f"=== {name} ===")
        for phase in ("cold", "warm"):
            build_cfg(COLD if phase == "cold" else WARM, seed=(phase == "warm"))
            await release(cid)
            url = await start_env(cid)
            if not url:
                log("    开靶机失败，跳过"); continue
            row = run_once(phase, COLD if phase == "cold" else WARM, url, name)
            row["phase"] = phase
            results.append(row)
            await asyncio.sleep(2)
            await release(cid)
            Path(".test-tmp/neg-results.json").write_text(
                json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
    log("=== 结束 ===")
    for r in results:
        log(f"  {r['challenge'][:28]:30s} {r['phase']:5s} {r['seconds']}s")


asyncio.run(main())
