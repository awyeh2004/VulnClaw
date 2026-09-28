"""Model-tier A/B: same drill question, fast tier vs deep tier.

Tier mapping (probed 2026-09-28 against api.deepseek.com, model deepseek-flash):
  fast = reasoning_effort 'none'  -> llm_utils omits the field entirely,
                                     model stays in default no-reasoning mode
  deep = reasoning_effort 'high'  -> top-level reasoning_effort=high

The two arms differ ONLY in VULNCLAW_LLM_REASONING_EFFORT (env override wired
in settings); config, target and prompt are identical, so the delta measures
the thinking overhead/benefit directly.

Usage (from repo root, CTF2 session token required like the other ab runners):
    python scripts/ab/model_tier_pair.py

Results append to .test-tmp/tier-results.json.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _drill_env import with_runtime_credentials  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
CFG = REPO / ".test-tmp" / "tier-cfg"
RESULTS = REPO / ".test-tmp" / "tier-results.json"
RUN_TIMEOUT_S = 1200

# The drill question: same shape as mock exams 1-2 (ransomware, port 2224).
TARGET = "127.0.0.1:2224"
GOAL = (
    "完成应急响应答题制排查：攻击者IP、首次入侵时间、入侵方式、勒索信文件名、"
    "被加密文件扩展名、加密算法、能否解密及依据、除root外的隐藏特权账号、"
    "持久化机制、清除与加固方案——每题独立作答并附证据"
)
PROMPT = (
    "这是应急响应实战赛（答题制，自动评分）。某公司服务器疑似被勒索软件入侵。"
    "你已获得该服务器 SSH 访问权：host 127.0.0.1 port 2224 user root password "
    "ir_drill_2026（先 remote_hosts 添加）。排查要点：日志/文件/账号/进程/持久化/网络六面。"
    "答案全部是文本，不是 flag；每题答案必须以 Q<n>: 开头记录为 finding"
    "（答案卡即 findings，评分只看得见 findings，黑板事实不算答案）；"
    "综合题（清除方案）单独成 finding 写步骤清单；路径用命令输出的原样形式，不许脑补。"
)

TIERS = {"fast": "none", "deep": "high"}


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def save(results: list[dict]) -> None:
    RESULTS.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")


def build_cfg(tier: str) -> Path:
    """Isolated config dir per arm; the drill key is injected at runtime, so the
    seeded config can carry empty credentials."""
    cfg = CFG / tier
    (cfg / "work").mkdir(parents=True, exist_ok=True)
    seed = Path(__file__).resolve().parent / "seeds" / "config-round2.yaml"
    if seed.exists() and not (cfg / "config.yaml").exists():
        (cfg / "config.yaml").write_text(seed.read_text(encoding="utf-8"), encoding="utf-8")
    log(f"    {tier}: config {cfg}")
    return cfg


def env_for(tier: str) -> dict:
    env = dict(os.environ)
    env.update(
        {
            "PYTHONIOENCODING": "utf-8",
            "VULNCLAW_CONFIG_DIR": str(CFG / tier),
            "VULNCLAW_LANG": "zh",
            # THE tier switch — the only difference between the two arms
            "VULNCLAW_LLM_REASONING_EFFORT": TIERS[tier],
        }
    )
    return with_runtime_credentials(env)


def run_once(tier: str) -> dict:
    started = time.time()
    out_path = REPO / ".test-tmp" / f"tier-run-{tier}.log"
    with open(out_path, "w", encoding="utf-8") as fh:
        proc = subprocess.Popen(
            [
                sys.executable, "-X", "utf8", "-m", "vulnclaw", "solve", TARGET,
                "--goal", GOAL, "--prompt", PROMPT,
            ],
            env=env_for(tier), stdout=fh, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, cwd=str(REPO),
        )
    try:
        proc.wait(timeout=RUN_TIMEOUT_S)
        seconds = round(time.time() - started)
        status = "done"
    except subprocess.TimeoutExpired:
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
        seconds = RUN_TIMEOUT_S
        status = "timeout"
    log(f"    {tier}: {status} {seconds}s  log={out_path.name}")
    return {"tier": tier, "seconds": seconds, "status": status, "log": str(out_path)}


def main() -> None:
    results: list[dict] = []
    for tier in ("fast", "deep"):
        log(f"=== {tier} (reasoning_effort={TIERS[tier]}) ===")
        build_cfg(tier)
        row = run_once(tier)
        results.append(row)
        save(results)
    log("=== done ===")
    for r in results:
        log(f"  {r['tier']:5} {r['seconds']}s {r['status']}")
    log(f"results -> {RESULTS}; grade each arm with score_run.py against the run dirs")


if __name__ == "__main__":
    main()
