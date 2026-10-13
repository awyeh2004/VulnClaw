# 技术债清单

> 记录**已知但暂不修**的结构性问题。每条都带实测数字与"为什么暂不修"。
> 建立于 2026-10-10（赛前一天）。数字取自当日 `git ls-files` 全量实测，口径：**全部跟踪文件**。
>
> 纪律：本文件只**记录**，不代表已排期。修之前先复核数字——仓库在动，行数会漂。

---

## 规模基线（2026-10-10 实测）

| 区域 | 文件数 | 行数 | 占比 |
|---|---|---|---|
| `vulnclaw/`（核心代码） | 219 | 92,645 | 34% |
| `vulnclaw/skills/`（技能库） | 336 | 82,078 | 30% |
| `tests/` | 285 | 64,957 | 24% |
| `frontend/` | 49 | 11,110 | 4% |
| 仓库根 | 30 | 7,556 | 3% |
| 其他（配置/示例等） | 33 | 6,273 | 2% |
| `scripts/` | 28 | 4,475 | 2% |
| `docs/` | 4 | 392 | 0% |
| **合计** | **984** | **269,486** | |

**判断**：对一个"agent + 技能库"形态的项目，34% 核心 / 30% 技能 / 24% 测试是**正常分布**，
不是失控。真正反常的只有下面第 2 条那两个 5 千行文件。

---

## 1. 技能库 references 成组重复（13 组 / 4,167 行）—— ✅ 已修（2026-10-12，commit `86322a6`）

**修法（已落地）**：新增 `vulnclaw/skills/_shared/references/` 共享根 + frontmatter
`shared_references` 声明机制（`loader.py`）。技能只在自己 SKILL.md 里**声明**要用哪些共享名
（操作员写盘的静态清单，不是模型输入）；`resolve_skill_reference` 先查本技能
`references/`（原路径原逻辑），声明过的名字才回退到共享根，**共用同一套 containment 检查**
（resolve + 必须落在根内 + is_file），穿越面一个字没放松。本技能同名文件优先 = 本地可覆盖共享。

**迁移**（13 组全部完成，剩余重复 0 组）：web 域 3 文件（web-pentest /
web-security-advanced / secknowledge-skill）→ android 域 9 文件（android-pentest /
client-reverse）→ `upstream-source.md` ×34（全部 redteam-*-detail-pack）。

**防回潮**：`tests/skills/test_no_duplicate_references.py`——扫全部 `references/` 树
（含 `_shared`），任何两份逐字节相同即 fail；`tests/skills/test_shared_references.py`
钉住解析契约（未声明不可达 / own 覆盖共享 / 穿越仍拒 / 声明清洗）。

以下为原始记录（留存供对照）：


同一份内容在多个 skill 的 `references/` 下各存一份，**逐字节相同**（sha256 相等）：

| 重复 | 单份行数 | 可省 | 文件 | 分布 |
|---|---|---|---|---|
| **×3** | 582 | 1,164 | `web-logic-auth.md` | `secknowledge-skill` / `web-pentest` / `web-security-advanced` |
| ×2 | 906 | 906 | `web-injection.md` | `web-pentest` / `web-security-advanced` |
| ×3 | 348 | 696 | `web-modern-protocols.md` | `secknowledge-skill` / `web-pentest` / `web-security-advanced` |
| ×2 | 229 | 229 | `android-external-url-runtime-first-workflow.md` | `android-pentest` / `client-reverse` |
| ×2 | 220 | 220 | `android-signing-and-crypto-workflow.md` | 同上 |
| ×2 | 207 | 207 | `android-ui-driven-observation-and-packet-loop.md` | 同上 |
| ×34 | 6 | 198 | `upstream-source.md` | 34 个 `redteam-*-detail-pack` 等包各一份 |
| ×2 | 167 | 167 | `android-authorized-app-pentest-sop.md` | `android-pentest` / `client-reverse` |
| ×2 | 119 | 119 | `android-network-layer-testing-quick-reference.md` | 同上 |
| ×2 | 115 | 115 | `android-signature-reverse-template.md` | 同上 |
| ×2 | 55 | 55 | `android-dynamic-hooking-and-replay.md` | 同上 |
| ×2 | 48 | 48 | `android-static-triage-and-callflow.md` | 同上 |
| ×2 | 43 | 43 | `android-native-signature-analysis.md` | 同上 |

**两个最集中的重复面**：

- `web-pentest` 与 `web-security-advanced` 的 `references/` 有 **3 个同名文件，且三份全部逐字节相同**
  （`web-injection` 906 + `web-logic-auth` 582 + `web-modern-protocols` 348 = **1,836 行**）。
- `android-pentest` 与 `client-reverse` 的 `references/` **9 份逐字节相同**（合计 1,203 行）。

**为什么存在**：技能是独立加载单元，`references/` 必须自包含（`loader.py` 的目录约定：
`<skill_name>/SKILL.md + <skill_name>/references/`）。这是**有意冗余**，但代价真实：
改一处要改三处，且已经漂移过（见 `CONTRIBUTING.md` §6.2「唯一来源纪律」——
flag 正则副本曾漂移到 3/17）。

**为什么暂不修**：⚠️ **去重不能靠软链接**——`resolve_skill_reference()` 会对候选路径做
`resolve()`（**展开符号链接**）并检查"结果必须落在本 skill 的 `references_dir` 之内"，
所以指向别的 skill 的软链会被拒绝。这条 containment 是防路径穿越的
（`load_skill_reference` 的入参 `ref_name` 由模型提供，`../../.vulnclaw/config.yaml` 是真实攻击面），
不能为了让路给去重而放松。真要修得先给加载层加"共享引用"机制，属**改安全边界附近的行为**，
不适合赛前动。

**修法（赛后）**：先做 `web-pentest` / `web-security-advanced`（省 1,836 行，且两者是同一域的两个
版本、最易漂移）；再做 `android-pentest` / `client-reverse`（9 份）。改完必须跑
`tests/` 里技能加载相关用例。

---

## 2. 两个"上帝文件"（各 5 千行）—— ✅ 已拆完（2026-10-12）

> **2026-10-12 更新**：两个上帝文件都已拆完（见下"拆分进度"），以下原始记录留存供对照。

**拆分进度（2026-10-12，aw 分支，未推）**：

- ✅ **`builtin_tools.py` 5,473 → 2,853 行**：按工具族拆成 `vulnclaw/agent/tools/` 子包——
  `shell_exec.py`（shell_command 族）/ `python_exec.py` / `nmap.py` / `http_probe.py` /
  `brute_force.py` / `runtime_diff.py` / `ocr.py` / `pyc.py` / `pdf.py` /
  `subprocess_util.py` / `_shared.py`（跨族 `_runtime_config`）。`builtin_tools.py` 保留
  gating/policy/dispatch 与 schema 注册，并**原样 re-export 每个搬走的名字（含私有名）**，
  旧 import 路径与测试的属性访问全部不变。**每族一笔提交**（8 笔），每笔跑全量。
  - ⚠️ 两个非显然的坑（下次拆别的族会再遇到）：① 搬走的代码原来吃 `builtin_tools.py` 顶部的
    stdlib import，搬完就 `NameError`——新模块必须补自己的 import；②
    `scripts/verify_execution_boundary.py` 的 `ALLOWED_SPAWN_SITES` 键含文件路径，搬迁会让
    旧键 stale、新键未登记——**必须同笔提交里删旧加新**（该守卫专门逼人复查每个 spawn 点）。
  - `_bg_*`（后台任务族）**刻意不拆**：有模块级可变状态（`_bg_tasks` dict / `_bg_seq` 经
    `global` 重绑 / `_bg_lock`），测试按属性访问并 `clear()`，拆了会产生孤儿副本——属单独设计任务。
- ✅ **`cli/main.py` 5,355 → 845 行**：拆成 `cli/repl.py`（1,891）+ `commands_run.py`（1,476）+
  `commands_platform.py`（741）+ `commands_admin.py`（467）+ `commands_config.py`（242），
  `main.py` 只留 typer 入口与装配。原"拆时顺手修 `_print_cli_manual` 双定义"已随之完成
  （`52d7689` 删旧定义，现 1 个定义 + 3 个调用点）。
- ⚠️ **拆分遗留（后续清理项，round19 审计发现）**：`cli/_helpers.py`（690 行，带 UTF-8 BOM）
  与 `cli/__init__.py` 存在约 16 个同名 helper 双定义（搬迁期中间态，早于 main.py 拆分窗口）。
  当前各调用点各取其一、无行为冲突；合并前先跑 `tests/cli/` 全量，顺手去 BOM。

以下为原始记录（留存供对照）：

| 行数 | 文件 |
|---|---|
| **5,473** | `vulnclaw/agent/builtin_tools.py` |
| **5,355** | `vulnclaw/cli/main.py` |
| 2,930 | `vulnclaw/cli/tui.py` |
| 2,725 | `vulnclaw/agent/solver.py` |

`builtin_tools.py` 一个文件承载 shell / python / nmap / fetch / `http_probe_batch` / 后台任务 /
OCR / pyc / pdf / 证据 / 报告 等十余种工具的执行逻辑；`main.py` 里 REPL 主循环、全部 typer
子命令、配置 CLI 混在一起。

**为什么暂不修**：这是**重构而非清理**——改错一处就会命中赛时要用的主路径。而且**已经拆过一轮**
（`remote.py`、`recon_tools.py`、`exec_gate.py`、`constraint_policy.py` 都是从它们里独立出来的），
说明方向对、只是没做完。

**修法（赛后）**：`builtin_tools.py` 按工具族拆（`tools/shell.py`、`tools/http.py`、`tools/ir.py`…），
`main.py` 按"REPL / 子命令注册 / 配置"三分。每步跑全量回归
（当前基线：`python -X utf8 -m pytest -q` → **4902 passed / 17 skipped**）。

---

## 3. 非问题（记录以免后人重复怀疑）

- **`tests/` 占 24%（64,957 行）**：对 9.2 万行核心代码，测试/代码 ≈ 70%，属**健康**，不是臃肿。
- **`vulnclaw/skills/` 占 30%**：技能库是产品资产（内容即能力），不是代码债。
- **仓库根 30 个文件**：其中 8 个是赛前作战卡（`IR-*.md`）与合规记录，属**临时资产**，赛后可归档。
  移出时注意：**它们已在 git 历史里，光删最新提交不够**（要改历史或接受它们留在历史中）。

---

## 附：本清单的来历

2026-10-10 用户问"项目是不是有点臃肿"，实测后写下。同日已完成的清理：删
`PLAYBOOK-REUSE-HANDOFF.md` / `PLAYBOOK-REUSE-RESULT.md`（642 行，通用经验提炼进
`CONTRIBUTING.md` §六，commit `d0c477a`）。

**那次是零风险的文档清理；本清单里的两条要动结构，故分开记录、赛前不动。**
