"""解析本轮冷/热配对日志：注入/重查/被挡、步数、工具数、时长、解得、采纳代理。

相对 `scripts/ab/parse_run_logs.py` 的改动（本轮新增了日志行）：

* `[playbook] injected …` 行现在尾部会带 `; gated N below the 2-token overlap floor: slug=k,…`；
* 新增 `[playbook] refreshed …` 与 `[playbook] probe re-query …`（探测后重查）；
* 「解得」判据：平台提交被验证码挡着（429 risk_action='challenge'），所以用
  日志里是否出现动态 `CTF2{...}`（说明从靶机内部读到了 flag）作为代理，并且
  同时报出 `目标达成` 这一行是否存在，两个数字都写出来，不合并。

采纳代理：笔记里出现的特征词在该次运行日志里的出现次数。用来把「命中」与「被采用」
拆成两个数字（交接文档 §4.1）。
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LOGS = REPO / ".test-tmp" / "rate-logs-r2"
RESULTS = REPO / ".test-tmp" / "rate-results-r2.json"

TOOL_RE = re.compile(r"→ 调用工具:\s*([a-zA-Z0-9_]+)")
INJECT_RE = re.compile(r"\[playbook\] injected (.+)$", re.M)
REFRESH_RE = re.compile(r"\[playbook\] refreshed (.+)$", re.M)
REQUERY_RE = re.compile(r"\[playbook\] probe re-query \((.+?)\): (.+)$", re.M)
NOMATCH_RE = re.compile(r"\[playbook\] no prior notes matched \(queries: ([^)]+)\)")
GATED_RE = re.compile(r"gated (\d+) below the (\d+)-token overlap floor: ([^;\n]+)")
HIT_RE = re.compile(r"([\w\-\.]+) score=([\d.]+) \(([\w]+)([^)]*)\)")
FLAG_RE = re.compile(r"CTF2\{[0-9a-fA-F\-]{8,}\}")
STEPS_RE = re.compile(r"Thinking\.\.\.")

# 采纳代理词表：来自两条种子笔记里的**特征词**（路径 / 手法名），不是通用词。
WEBSHELL = ("wls-wsat", "xmldecoder", "bea_wls_internal", "coordinatorporttype",
            "processbuilder", "wls_utc", "ws_utc")
THINKPHP = ("captcha", "__construct", "invokefunction", "index.php?s=")


def proxy_counts(text: str) -> dict[str, int]:
    low = text.lower()
    return {
        "weblogic_note_words": sum(low.count(w.lower()) for w in WEBSHELL),
        "thinkphp_note_words": sum(low.count(w.lower()) for w in THINKPHP),
        "ssrf_words": low.count("ssrf"),
    }


def parse_hits(blob: str) -> list[dict]:
    hits = []
    for part in blob.split(";"):
        m = HIT_RE.search(part)
        if m:
            hits.append(
                {
                    "slug": m.group(1),
                    "score": float(m.group(2)),
                    "key": m.group(3),
                    "mismatch": "CLASS MISMATCH" in m.group(4),
                }
            )
    return hits


def gated_of(blob: str) -> list[str]:
    m = GATED_RE.search(blob)
    if not m:
        return []
    return [x.strip() for x in m.group(3).split(",") if x.strip()]


def parse(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    injected = [parse_hits(m.group(1)) for m in INJECT_RE.finditer(text)]
    refreshed = [parse_hits(m.group(1)) for m in REFRESH_RE.finditer(text)]
    gated: list[str] = []
    for m in GATED_RE.finditer(text):
        gated.extend(x.strip() for x in m.group(3).split(",") if x.strip())
    flags = FLAG_RE.findall(text)
    return {
        "file": path.name,
        "steps": len(STEPS_RE.findall(text)),
        "tools": len(TOOL_RE.findall(text)),
        "llm_errors": text.count("stopped after repeated"),
        "solved_line": "目标达成" in text,
        "flags_seen": len(flags),
        "injected": injected,
        "refreshed": refreshed,
        "requery": [m.group(1)[:60] + " -> " + m.group(2) for m in REQUERY_RE.finditer(text)],
        "gated": gated,
        "no_match": bool(NOMATCH_RE.search(text)),
        "curated_injected": any(
            h["slug"] and not h["slug"].startswith("autonotes")
            for group in injected + refreshed
            for h in group
        ),
        "proxy": proxy_counts(text),
    }


def main() -> None:
    secs: dict[str, float] = {}
    if RESULTS.exists():
        for row in json.loads(RESULTS.read_text(encoding="utf-8")):
            if "log" in row and "seconds" in row:
                secs[Path(row["log"]).stem] = row["seconds"]

    rows = [parse(p) for p in sorted(LOGS.glob("*.log"))]
    if not rows:
        print(f"no logs under {LOGS}")
        return
    for r in rows:
        r["seconds"] = secs.get(Path(r["file"]).stem)

    print(f"{'run':46s} {'达成':4s} {'解出':4s} {'步':>3s} {'工具':>4s} {'秒':>5s}  "
          f"{'WL词':>5s} {'TP词':>5s}  注入/重查")
    for r in rows:
        detail = ""
        if r["injected"] and r["injected"][0]:
            detail = "注入 " + ", ".join(
                f"{h['slug'][:34]}={h['score']}({h['key']})" for h in r["injected"][0]
            )
        elif r["no_match"]:
            detail = "无命中"
        if r["refreshed"]:
            detail += " | 重查后 " + ", ".join(
                f"{h['slug'][:34]}={h['score']}({h['key']})" for h in r["refreshed"][-1]
            )
        if r["gated"]:
            detail += f" | 被挡 {len(r['gated'])}: {', '.join(r['gated'][:3])}"
        secs_txt = f"{r['seconds']:.0f}" if r["seconds"] else "-"
        print(
            f"{r['file'][:46]:46s} {str(r['solved_line']):4s} {r['flags_seen']:>4d} "
            f"{r['steps']:>3d} {r['tools']:>4d} {secs_txt:>5s} "
            f"{r['proxy']['weblogic_note_words']:>5d} {r['proxy']['thinkphp_note_words']:>5d}  {detail}"
        )

    print("\n逐组配对：")
    groups: dict[str, dict[str, dict]] = {}
    for r in rows:
        base, _, arm = r["file"].rpartition("-")
        groups.setdefault(base, {})[arm.replace(".log", "")] = r
    for base, arms in groups.items():
        cold, warm = arms.get("cold"), arms.get("warm")
        if not (cold and warm):
            print(f"  {base}: 只有 {sorted(arms)}")
            continue
        print(f"  {base}")
        for tag, arm in (("cold", cold), ("warm", warm)):
            inj = arm["injected"][0] if arm["injected"] else []
            print(f"    {tag}: 步={arm['steps']:>3d} 工具={arm['tools']:>3d} 秒={arm['seconds']} "
                  f"达成={arm['solved_line']} 见到flag={arm['flags_seen']} "
                  f"注入={len(inj)}条{'(含手工)' if arm['curated_injected'] else ''} "
                  f"重查={len(arm['refreshed'])} 被挡={len(arm['gated'])} "
                  f"WL词={arm['proxy']['weblogic_note_words']} TP词={arm['proxy']['thinkphp_note_words']}")
        cs, ws = cold["seconds"], warm["seconds"]
        if cs and ws:
            print(f"    差值: 时长 {(ws - cs) / cs * 100:+.0f}%  步数 {warm['steps'] - cold['steps']:+d}  "
                  f"工具 {warm['tools'] - cold['tools']:+d}  "
                  f"WL词 {warm['proxy']['weblogic_note_words'] - cold['proxy']['weblogic_note_words']:+d}")

    out = REPO / ".test-tmp" / "rate-analysis-r2.json"
    out.write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\nanalysis -> {out}")


main()
