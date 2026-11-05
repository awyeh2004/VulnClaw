#!/usr/bin/env python3
"""Build a single self-contained HTML "field capsule" from the skill library.

Why it exists: at an on-site competition the operator may only get a locked-down
machine and a browser -- no Python, no network beyond the platform, no way to run
VulnClaw. The knowledge that actually decides those challenges (the skill bodies
and the 700+ experience notes) is otherwise trapped in this repo and in
``~/.vulnclaw/playbooks``.

Output: ONE .html file with everything embedded (no CDN, no fetch -- ``file://``
blocks XHR), full-text search, filters, and copy buttons. Drop it on a USB stick.

    python -X utf8 scripts/build_field_capsule.py --out E:/vulnclaw/work/capsule.html
"""
from __future__ import annotations

import argparse
import html
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SKILLS_DIR = REPO / "vulnclaw" / "skills"


def _default_playbook_dir() -> Path:
    """Playbooks of THIS profile only.

    Delegates to ``vulnclaw.agent.playbook.PLAYBOOKS_DIR`` so the capsule and the
    auto-recall path can never disagree about which store belongs to this profile
    (CTF: ``<config>/playbooks``, production: ``<config>/playbooks-prod``).
    """
    try:
        from vulnclaw.agent.playbook import PLAYBOOKS_DIR

        return Path(PLAYBOOKS_DIR)
    except Exception:  # noqa: BLE001 - standalone use outside the package
        return Path.home() / ".vulnclaw" / "playbooks"

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.S)

#: 单文件胶囊要能从 U 盘双击打开、也要能从现场门户下载，所以不能带任何可执行的
#: webshell 原文：2026-10-31 实测，火绒 Web 扫描把带 ``<?php eval($_POST[...])``
#: 原文的知识包判成 ``Backdoor/PHP.TinyShell.h`` 并**直接阻止下载**，整个现场包
#: 都下不来。笔记本身是纯文本、不会执行，但 AV 只看字节特征。
#:
#: 处理方式是最小改写、可一眼还原：开标签的尖括号换成方括号（``<?php`` -> ``[?php``、
#: ``<?=`` -> ``[?=``、``<%@``/``<%`` -> ``[%@``/``[%``），函数名与括号之间加一个空格
#: （PHP/Java 都允许这种写法，删掉空格就是原文）。``<?xml`` 声明保持原样，XXE 类
#: 文档要能照抄。
#:
#: 作用域（2026-11-04 review）：只改"看起来可执行的 payload"所在的行/块，不再对整篇
#: 笔记做全局 ``replace``。旧实现对 ``eval(``/``system(`` 一律改写，把 ``model.eval()``、
#: ``os.system(...)``、普通模板语法都改坏了，胶囊里的示例无法直接复制运行。
_SHELL_TAG_SUBS: tuple[tuple[str, str], ...] = (
    ("<?php", "[?php"),
    ("<?PHP", "[?PHP"),
    ("<?=", "[?="),
    ("<%@", "[%@"),
    ("<%", "[%"),
    ("Runtime.getRuntime().exec", "Runtime.getRuntime().exec "),
    ("eval(", "eval ("),
    ("assert(", "assert ("),
    ("system(", "system ("),
    ("passthru(", "passthru ("),
    ("shell_exec(", "shell_exec ("),
)

#: 以 ``<?xml`` 开头的行不是 PHP 短标签（XML 声明要照抄），``(?!xml)`` 排除它。
_OPEN_TAG_RE = re.compile(r"<\?(?!xml)|<%@|<%", re.IGNORECASE)
_CLOSE_TAG_RE = re.compile(r"\?>|%>")
#: 一行里出现这些就基本可以确定是 webshell 交互代码（而非普通 API 示例）。
_PAYLOAD_CONTEXT_RE = re.compile(
    r"\$_(?:POST|GET|REQUEST|COOKIE|SERVER|FILES)\b|request\.getParameter|"
    r"Runtime\.getRuntime\(\)\.exec|php://input|base64_decode\s*\(",
    re.IGNORECASE,
)


def _defang_line(line: str) -> str:
    for old, new in _SHELL_TAG_SUBS:
        line = line.replace(old, new)
    return line


def _defang_shell_payloads(text: str) -> str:
    """Break executable webshell signatures so AV does not quarantine the capsule.

    Line-scoped on purpose: a line is rewritten when it opens a server-side
    template tag (``<?php``/``<?=``/``<%@``/``<%``), when it still sits inside such
    a block, or when it carries a webshell interaction marker (``$_POST``,
    ``request.getParameter``, …). Everything else -- ``model.eval()``,
    ``os.system()``, ordinary tutorial code -- is left byte-identical.
    """
    if not text:
        return text
    out: list[str] = []
    in_block = False
    for line in text.splitlines(keepends=True):
        opens = _OPEN_TAG_RE.search(line) is not None
        if opens or in_block or _PAYLOAD_CONTEXT_RE.search(line):
            out.append(_defang_line(line))
        else:
            out.append(line)
        if opens and not _CLOSE_TAG_RE.search(line):
            in_block = True
        elif in_block and _CLOSE_TAG_RE.search(line):
            in_block = False
    # XML 声明是正常内容（XXE 笔记要照抄），撤掉任何对它的误改。
    return "".join(out).replace("[?xml", "<?xml")



def _split_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Return (frontmatter key/value pairs, body). Tolerant of multiline values."""
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return {}, text
    meta: dict[str, str] = {}
    key = ""
    for line in match.group(1).splitlines():
        if not line.strip():
            continue
        if line[:1] in " \t" and key:
            meta[key] = f"{meta[key]} {line.strip()}".strip()
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            meta[key] = value.strip()
    return meta, text[match.end():]


def _collect_skills() -> list[dict]:
    docs: list[dict] = []
    for path in sorted(SKILLS_DIR.rglob("*.md")):
        rel = path.relative_to(SKILLS_DIR).as_posix()
        if "/references/" in rel:
            skill = rel.split("/references/")[0].split("/")[-1]
            kind = "reference"
        elif path.name == "SKILL.md":
            skill = rel.split("/")[0] if "/" in rel else rel
            kind = "skill"
        else:
            skill = rel.split("/")[0]
            kind = "note"
        text = path.read_text(encoding="utf-8", errors="replace")
        meta, body = _split_frontmatter(text)
        title = meta.get("name") or path.stem
        if kind == "reference":
            title = f"{skill} / {path.stem}"
        docs.append({
            "id": f"skill:{rel}",
            "kind": kind,
            "group": skill,
            "title": title,
            "meta": _defang_shell_payloads(meta.get("description", "")[:300]) if kind == "skill" else "",
            "body": _defang_shell_payloads(body.strip()),
        })
    return docs


def _collect_playbooks(playbook_dir: Path) -> list[dict]:
    docs: list[dict] = []
    if not playbook_dir.is_dir():
        return docs
    for path in sorted(playbook_dir.glob("*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        meta, body = _split_frontmatter(text)
        docs.append({
            "id": f"pb:{path.stem}",
            "kind": "playbook",
            "status": (meta.get("status") or "draft").lower(),
            "group": (meta.get("source") or "curated").lower(),
            "title": meta.get("name") or path.stem,
            "fingerprint": meta.get("fingerprint", ""),
            "body": _defang_shell_payloads(body.strip()),
        })
    return docs


TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VulnClaw 现场知识胶囊</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; font:14px/1.6 "Segoe UI","Microsoft YaHei",system-ui,sans-serif;
         background:#0f1115; color:#d7dbe0; }
  header { position:sticky; top:0; z-index:5; padding:10px 14px; background:#161a21;
           border-bottom:1px solid #262b35; display:flex; gap:10px; align-items:center;
           flex-wrap:wrap; }
  h1 { font-size:15px; margin:0 8px 0 0; font-weight:600; color:#8fd0ff; }
  input[type=search] { flex:1 1 320px; min-width:220px; padding:7px 10px; border-radius:6px;
           border:1px solid #2b313c; background:#0c0e12; color:#e6e9ec; font-size:14px; }
  select,button { padding:6px 9px; border-radius:6px; border:1px solid #2b313c;
           background:#1b212a; color:#cfd6de; font-size:13px; cursor:pointer; }
  #count { color:#7b8695; font-size:12px; margin-left:auto; }
  main { display:grid; grid-template-columns:270px 1fr; gap:0; min-height:calc(100vh - 54px); }
  nav { border-right:1px solid #262b35; padding:10px; overflow:auto; max-height:calc(100vh - 54px);
        position:sticky; top:54px; }
  nav a { display:block; padding:4px 8px; border-radius:5px; color:#aeb8c4; text-decoration:none;
          font-size:13px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  nav a:hover, nav a.on { background:#1d2530; color:#e8eef5; }
  nav .grp { margin:10px 0 3px; color:#5f6b7a; font-size:11px; text-transform:uppercase;
             letter-spacing:.06em; }
  section { padding:14px 18px; max-width:1000px; }
  article { border:1px solid #232a34; border-radius:8px; margin:0 0 14px; background:#141922; }
  article > h2 { font-size:14px; margin:0; padding:9px 12px; border-bottom:1px solid #232a34;
                 color:#9fd4ff; display:flex; gap:8px; align-items:baseline; flex-wrap:wrap; }
  .tag { font-size:11px; padding:1px 6px; border-radius:10px; border:1px solid #33404f;
         color:#8fa2b5; font-weight:400; }
  .tag.ok { border-color:#2f6f45; color:#7fd39b; }
  .tag.warn { border-color:#6f5a2f; color:#d9bd7f; }
  .fp { padding:6px 12px; color:#6f7d8c; font-size:12px; border-bottom:1px dashed #222a34; }
  pre { margin:0; padding:10px 12px; white-space:pre-wrap; word-break:break-word;
        font:12.5px/1.55 "Cascadia Mono",Consolas,monospace; color:#c8d2dc; }
  .empty { color:#6f7d8c; padding:30px 4px; }
  mark { background:#3a4a22; color:#e9f3c8; border-radius:2px; }
</style>
</head>
<body>
<header>
  <h1>VulnClaw 现场知识胶囊</h1>
  <input id="q" type="search" placeholder="搜索：blind watermark / LSB / CVE-2024 / 提示词注入 / SSTI …（Ctrl+K）" autocomplete="off">
  <select id="kind">
    <option value="">全部</option>
    <option value="playbook">经验笔记</option>
    <option value="skill">技能</option>
    <option value="reference">参考文档</option>
  </select>
  <select id="valid">
    <option value="">含 draft</option>
    <option value="validated">只看 validated</option>
  </select>
  <button id="clear">清空</button>
  <span id="count"></span>
</header>
<main>
  <nav id="nav"></nav>
  <section id="out"></section>
</main>
<script>
const DOCS = __DOCS__;
const NAV_GROUPS = __NAV__;
const idx = DOCS.map(d => ({
  id: d.id, kind: d.kind, title: d.title, group: d.group,
  status: d.status || "", fp: d.fingerprint || d.meta || "",
  hay: (d.title + "\\n" + (d.fingerprint || d.meta || "") + "\\n" + d.body).toLowerCase(),
}));
const bodyById = new Map(DOCS.map(d => [d.id, d.body]));
const q = document.getElementById("q");
const kindSel = document.getElementById("kind");
const validSel = document.getElementById("valid");
const out = document.getElementById("out");
const nav = document.getElementById("nav");
const count = document.getElementById("count");
const esc = s => s.replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));

function highlighted(doc) {
  // Light, deliberately dumb highlighter: only in the already-escaped title.
  const term = q.value.trim();
  if (!term) return esc(doc.title);
  const t = esc(doc.title);
  const re = new RegExp(term.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&"), "gi");
  return t.replace(re, m => "<mark>" + m + "</mark>");
}

function render() {
  const term = q.value.trim().toLowerCase();
  const kind = kindSel.value;
  const onlyValid = validSel.value === "validated";
  const rows = idx.filter(d =>
    (!kind || d.kind === kind) &&
    (!onlyValid || d.status === "validated") &&
    (!term || d.hay.includes(term))
  );
  // Value order: validated notes first, then skills, then everything else.
  const rank = d => (d.status === "validated" ? 0 : d.kind === "skill" ? 1 : 2);
  rows.sort((a, b) => rank(a) - rank(b) || a.title.localeCompare(b.title));
  count.textContent = rows.length + " / " + idx.length;

  const show = rows.slice(0, term ? 60 : 25);
  out.innerHTML = show.length ? show.map(d => {
    const tag = d.kind === "playbook"
      ? '<span class="tag ' + (d.status === "validated" ? "ok" : "warn") + '">' + (d.status || "draft") + "</span>"
      : '<span class="tag">' + d.kind + "</span>";
    const fp = d.fp ? '<div class="fp">' + esc(d.fp.slice(0, 400)) + "</div>" : "";
    return '<article id="' + d.id + '"><h2>' + highlighted(d) + tag +
           '<span class="tag">' + esc(d.group) + "</span></h2>" + fp +
           "<pre>" + esc(bodyById.get(d.id) || "") + "</pre></article>";
  }).join("") : '<p class="empty">没有匹配。换个关键词，或把筛选放宽。</p>';

  nav.innerHTML = NAV_GROUPS.map(g =>
    '<div class="grp">' + esc(g.label) + "</div>" +
    g.items.map(it => '<a href="#" data-term="' + esc(it.term) + '">' + esc(it.label) + "</a>").join("")
  ).join("");
}

nav.addEventListener("click", ev => {
  const a = ev.target.closest("a[data-term]");
  if (!a) return;
  ev.preventDefault();
  q.value = a.dataset.term;
  render();
});
q.addEventListener("input", render);
kindSel.addEventListener("change", render);
validSel.addEventListener("change", render);
document.getElementById("clear").onclick = () => { q.value = ""; kindSel.value = ""; validSel.value = ""; render(); };
document.addEventListener("keydown", ev => {
  if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "k") { ev.preventDefault(); q.focus(); }
});
render();
</script>
</body>
</html>
"""


def _nav(docs: list[dict]) -> list[dict]:
    """Sidebar shortcuts: the groups with the most content, plus headline recipes."""
    counts: dict[str, int] = {}
    for doc in docs:
        if doc["kind"] in {"skill", "reference"}:
            counts[doc["group"]] = counts.get(doc["group"], 0) + 1
    top = sorted(counts.items(), key=lambda kv: -kv[1])[:18]
    return [
        {"label": "技能组", "items": [{"label": name, "term": name} for name, _ in top]},
        {"label": "高频关键词", "items": [
            {"label": term, "term": term} for term in (
                "blind watermark", "LSB", "频谱", "CRC32", "鼠标流量", "流量分析",
                "prompt", "注入", "反序列化", "SSTI", "SQL", "JWT", "pickle",
                "RSA", "AES", "取证", "webshell", "提权", "盲水印",
            )
        ]},
    ]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(REPO / "field-capsule.html"))
    ap.add_argument(
        "--playbook-dir",
        default="",
        help=(
            "Playbook directory to embed (default: <VULNCLAW_CONFIG_DIR>/playbooks, "
            "so only the current profile's notes are included)"
        ),
    )
    args = ap.parse_args()

    playbook_dir = Path(args.playbook_dir) if args.playbook_dir else _default_playbook_dir()
    docs = _collect_playbooks(playbook_dir) + _collect_skills()
    if not docs:
        raise SystemExit("no documents collected -- check the source paths")

    payload = json.dumps(docs, ensure_ascii=False).replace("</", "<\\/")
    nav = json.dumps(_nav(docs), ensure_ascii=False)
    html_text = TEMPLATE.replace("__DOCS__", payload).replace("__NAV__", nav)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html_text, encoding="utf-8")

    validated = sum(1 for d in docs if d.get("status") == "validated")
    print(f"{out}  {out.stat().st_size/1e6:.1f} MB  "
          f"docs={len(docs)} (playbooks={sum(1 for d in docs if d['kind']=='playbook')}, "
          f"validated={validated}, skills={sum(1 for d in docs if d['kind']=='skill')}, "
          f"references={sum(1 for d in docs if d['kind']=='reference')}) "
          f"[playbooks: {playbook_dir}]")


if __name__ == "__main__":
    main()
