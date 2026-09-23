"""读逐条命中日志：同类迁移的命中率与效果量化。"""

from __future__ import annotations

import json
import re
from pathlib import Path

LOGS = Path(".test-tmp/rate-logs")
RESULTS = Path(".test-tmp/rate-results.json")
TOOL_RE = re.compile(r"→ 调用工具:\s*([a-zA-Z0-9_]+)")
INJECT_RE = re.compile(r"\[playbook\] injected (.+)$", re.M)
NOMATCH_RE = re.compile(r"\[playbook\] no prior notes matched \(queries: ([^)]+)\)")

secs = {}
if RESULTS.exists():
    for row in json.loads(RESULTS.read_text(encoding="utf-8")):
        secs[Path(row["log"]).stem] = row["seconds"]


def parse(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    tools = TOOL_RE.findall(text)
    inject = INJECT_RE.search(text)
    nomatch = NOMATCH_RE.search(text)
    hits = []
    if inject:
        for part in inject.group(1).split(";"):
            m = re.search(r"([\w\-\.]+) score=([\d.]+) \((\w+)\)", part)
            if m:
                hits.append({"slug": m.group(1), "score": float(m.group(2)), "key": m.group(3)})
    return {
        "file": path.name,
        "steps": text.count("Thinking..."),
        "tools": len(tools),
        "solved": "目标达成" in text,
        "hits": hits,
        "no_match": bool(nomatch),
        "queries": nomatch.group(1) if nomatch else "",
        "curated_hit": any(h["slug"] and not h["slug"].startswith("autonotes") for h in hits),
        "seconds": secs.get(path.stem),
    }


rows = [parse(p) for p in sorted(LOGS.glob("*.log"))]

print(f"{'run':48s} {'解得':4s} {'步':>3s} {'工具':>4s} {'秒':>5s}  注入")
for r in rows:
    secs_txt = f"{r['seconds']:.0f}" if r["seconds"] else "-"
    if r["hits"]:
        detail = ", ".join(f"{h['slug'][:30]}={h['score']}({h['key']})" for h in r["hits"])
    elif r["no_match"]:
        detail = f"无命中 (queries: {r['queries']})"
    else:
        detail = "（无注入行）"
    print(f"{r['file'][:48]:48s} {str(r['solved']):4s} {r['steps']:>3d} {r['tools']:>4d} "
          f"{secs_txt:>5s}  {detail}")

print()
print("配对对比：")
pairs: dict[str, dict] = {}
for r in rows:
    base = r["file"].rsplit("-", 1)[0]
    pairs.setdefault(base, {})[r["file"].rsplit("-", 1)[1].replace(".log", "")] = r
for base, arms in pairs.items():
    cold, warm = arms.get("cold"), arms.get("warm")
    if not (cold and warm):
        continue
    print(f"  {base}")
    print(f"    cold: 步={cold['steps']:>3d} 工具={cold['tools']:>3d} 秒={cold['seconds']} "
          f"注入={'有' if cold['hits'] else ('无' if cold['no_match'] else '?')}")
    print(f"    warm: 步={warm['steps']:>3d} 工具={warm['tools']:>3d} 秒={warm['seconds']} "
          f"注入={len(warm['hits'])} 条  curated={warm['curated_hit']}")
    if cold["seconds"] and warm["seconds"]:
        print(f"    时长 {(warm['seconds'] - cold['seconds']) / cold['seconds'] * 100:+.0f}%  "
              f"步数 {warm['steps'] - cold['steps']:+d}  工具 {warm['tools'] - cold['tools']:+d}")

warm_rows = [r for r in rows if r["file"].endswith("-warm.log")]
if warm_rows:
    hit = sum(1 for r in warm_rows if r["hits"])
    curated = sum(1 for r in warm_rows if r["curated_hit"])
    print()
    print(f"热跑命中率：{hit}/{len(warm_rows)} 有注入，{curated}/{len(warm_rows)} 命中的含手工笔记")

Path(".test-tmp/rate-analysis.json").write_text(
    json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
