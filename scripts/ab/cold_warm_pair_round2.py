"""冷/热配对重跑（本轮：新门槛 + 探测后重查）。

相对 `scripts/ab/cold_warm_pair.py` 的改动，逐条写清原因：

1. `COLD` / `WARM` 移到**工作区内**（`<repo>/.test-tmp/abcfg-*`）。原脚本写到
   `D:\\GitClone\\VulnClaw\\ab-config-*`（仓库之外），本会话沙箱拒绝在仓库外写入
   （实测 `PermissionError: D:\\GitClone\\VulnClaw\\ab-config-COLD\\_sandbox_probe.txt`），
   而 `VULNCLAW_CONFIG_DIR` 本来就只是个环境变量，换路径不影响被测代码。
2. 三组配对换成真实存在的题目 id（`list_practice_challenges` 实查 278 题得到），
   覆盖"同类不同 CVE"与"同框架不同漏洞类"两轴：
   - `[Weblogic]CVE-2017-10271`：种子笔记就是为它写的 → 最近距离的正对照
   - `[Weblogic]CVE-2018-2628`：同类不同 CVE → 交接文档记的跨题迁移场景
   - `[Weblogic]SSRF`：同框架不同漏洞类 → §4.4 点名的反向对照
3. `MAX_STEPS` 30、`RUN_TIMEOUT_S` 900：原值 600s 对 30 步偏紧，中途 taskkill 会让
   "时长"变成超时值而不是真实耗时。
4. 每臂把 `get_target` 的收尾确认写进 JSON（`target_after_release`）：交接文档 §4.3 要求
   收尾用 `get_target` 确认返回 null，否则靶机额度泄漏会污染后续配对。

用法：`python -X utf8 scripts/ab/cold_warm_pair_round2.py`
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

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO.parent
LOGS = REPO / ".test-tmp" / "rate-logs-r2"
RESULTS = REPO / ".test-tmp" / "rate-results-r2.json"
PRACTICE = "2de971ac-26fe-448a-8719-01829e52c1d5"
MAX_STEPS = "30"
RUN_TIMEOUT_S = 900
TOKEN = ""

COLD = REPO / ".test-tmp" / "abcfg-COLD"
WARM = REPO / ".test-tmp" / "abcfg-WARM"
SEED_FROM = ROOT / "ab-config-B" / "playbooks"
# 两条手工技术笔记 + 4 条自动笔记。自动笔记也放进来是为了让"注入了什么"可归因：
# `autonotes-*` 是**按目标**召回的（fingerprint 里带 URL 与整段题面），
# `*rce*captcha-route` / `weblogic-cve-*` 才是**跨题迁移**的那两条手工笔记。
# 不看这个区分，就没法说清"热臂变快"究竟是跨题迁移还是同一台靶机的历史笔记。
SEED = [
    "thinkphp-5-0-23-rce-captcha-route.md",
    "weblogic-cve-2017-10271-wls-wsat-xmldecoder-rce-.md",
    "autonotes-2de971ac-26fe-448a-8719-01829e52c1d5.md",
    "autonotes-direct-ctf2-dasctf-com-26368.md",
    "autonotes-direct-ctf2-dasctf-com-27087.md",
    "autonotes-direct-ctf2-dasctf-com-27865.md",
]

SIBLINGS = [
    ("[Weblogic]CVE-2017-10271", "da3de0ca-9f10-49c6-aa39-74bb4dbc6679"),
    ("[Weblogic]CVE-2018-2628", "a4276c0b-3c46-4ce8-9ca1-8b27d65601f4"),
    ("[Weblogic]SSRF", "5fcc745e-4272-45cd-9f8f-435870e88199"),
]

CFG_SRC = REPO / ".test-tmp" / "abcfg-base.yaml"


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
    shutil.copy2(CFG_SRC, cfg / "config.yaml")
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
    env.update(
        {
            "PYTHONIOENCODING": "utf-8",
            "VULNCLAW_CONFIG_DIR": str(cfg),
            "VULNCLAW_CTF2_SESSION_TOKEN": TOKEN,
            "VULNCLAW_WORK_DIR": str(cfg / "work"),
            "VULNCLAW_LANG": "zh",
        }
    )
    return env


async def start_env(cid: str) -> str:
    for attempt in range(8):
        try:
            await c.start_environment(PRACTICE, cid)
        except Exception as exc:  # noqa: BLE001
            log(f"    start {attempt + 1} 失败: {str(exc)[:90]}")
            await asyncio.sleep(6)
            continue
        deadline = time.time() + 180
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


async def target_state(cid: str) -> str:
    try:
        payload = await c.get_target(PRACTICE, cid)
    except Exception as exc:  # noqa: BLE001
        return f"error:{str(exc)[:40]}"
    node = payload.get("data") if isinstance(payload, dict) else payload
    if node is None:
        return "null"
    if isinstance(node, dict):
        return str(node.get("status") or "present")
    return str(node)[:40]


def run_once(tag: str, cfg: Path, url: str, name: str) -> dict:
    LOGS.mkdir(parents=True, exist_ok=True)
    safe = name.replace("/", "_").replace("[", "").replace("]", "").replace(" ", "-")
    logfile = LOGS / f"{safe}-{tag}.log"
    target = url if url.startswith("http") else f"http://{url}"
    cmd = [
        sys.executable, "-X", "utf8", "-m", "vulnclaw", "solve", target,
        "--goal", goal_text(name, target), "--max-steps", MAX_STEPS,
    ]
    log(f"    {tag}: solve {target}")
    started = time.time()
    with open(logfile, "w", encoding="utf-8", errors="replace") as fh:
        fh.write(f"# {tag} cfg={cfg}\n")
        fh.flush()
        proc = subprocess.Popen(
            cmd, cwd=str(REPO), env=env_for(cfg),
            stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        )
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
    return {
        "tag": tag, "challenge": name, "seconds": elapsed, "exit": proc.returncode,
        "timed_out": timed_out, "log": str(logfile), "url": target,
    }


def save(results: list[dict]) -> None:
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")


async def main() -> None:
    global TOKEN
    TOKEN = c.session_token()
    if not TOKEN:
        log("无令牌")
        return
    log(f"token len={len(TOKEN)}  repo={REPO}")
    results: list[dict] = []
    for name, cid in SIBLINGS:
        log(f"=== {name} ===")
        for phase in ("cold", "warm"):
            build_cfg(COLD if phase == "cold" else WARM, seed=(phase == "warm"))
            await release(cid)
            url = await start_env(cid)
            if not url:
                log("    开靶机失败，跳过")
                results.append({"challenge": name, "phase": phase, "error": "start_failed"})
                save(results)
                continue
            row = run_once(phase, COLD if phase == "cold" else WARM, url, name)
            row["phase"] = phase
            await asyncio.sleep(2)
            await release(cid)
            row["target_after_release"] = await target_state(cid)
            log(f"    {phase}: 释放后 get_target -> {row['target_after_release']}")
            results.append(row)
            save(results)
    log("=== 结束 ===")
    for r in results:
        if "seconds" in r:
            log(f"  {r['challenge'][:28]:30s} {r['phase']:5s} {r['seconds']}s solved_log")
    log(f"results -> {RESULTS}")


asyncio.run(main())
