# VulnClaw — 给 AI 会话的落盘与环境约定

> 本文件面向在本仓库工作的 AI 会话（任何客户端）。**开工前先读这一节**，
> 尤其是关于磁盘路径的部分——写错位置会迅速吃满 C 盘。
> 详细踩坑记录见 `CONTRIBUTING.md` §六。

---

## 一、磁盘：临时产物一律进 E 盘

**本机 C 盘只剩 12G，E 盘 56G。禁止把附件、解压目录、脚本暂存写进 C 盘。**

### 两条独立路径，必须都覆盖

| 产物 | 落点 | 配置项 |
|---|---|---|
| `shell_command` / `python_execute` 的脚本与工作目录 | `<solve_work_root>/<run_id>/` | `config.yaml` → `session.solve_work_root`（已配 `E:\vulnclaw\work`） |
| 平台附件下载（`attachment_dir()`） | `$VULNCLAW_WORK_DIR/attachments` | 用户级环境变量 `VULNCLAW_WORK_DIR=E:\vulnclaw\work` |

**坑**：`vulnclaw/platforms/attachments.py` 里 `work_dir()` 的默认值是
`Path.home()/"vulnclaw"/"work"`，**不读 `solve_work_root`**。
只配了 config 时，agent 下载的附件照样落在 `C:\Users\<user>\vulnclaw\work`。
两处都要设，缺一个就会重新往 C 盘写。

**自检命令**（新环境里先跑一次）：

```bash
cd <repo> && python -c "from vulnclaw.platforms.attachments import work_dir, attachment_dir; print(work_dir()); print(attachment_dir())"
# 期望输出以 E:\vulnclaw 开头；出现 C:\Users\... 说明环境变量没生效
```

### 2026-10-17 清理后的位置变化

历史数据已从 C 盘迁出，**查旧 run 不要去 `.vulnclaw\runs`**：

| 内容 | 现在的位置 |
|---|---|
| 旧 `runs/` `sessions/` `targets/` + 散落日志脚本 | `E:\vulnclaw\dot-vulnclaw-archive\` |
| 旧 C 盘临时目录（ctf/ctf2/work/tmp/vulnclaw 等） | `E:\vulnclaw\c-drive-archive\ctf-temp-dirs-20261017.tar.gz` |

`C:\Users\<user>\.vulnclaw` 现在只有约 3 MB：`config.yaml` + 历史备份、`playbooks/`、
`skills/`、`kb/`、`known_hosts`、`switch-llm.sh`、`web_token`、`solve_locks/`。

`--resume` / `target-state` 只认原地路径，不认归档目录。要读历史请直接读归档。

### C 盘满过一次（2026-10-18），TEMP 已重定向

刷题时出现过 `temp filesystem is full (2MB free)` —— C 盘 100%，只有 2.7 MB 可用。
两条临时数据的来源和现状：

| 来源 | 处理 |
|---|---|
| `%TEMP%`（默认 `C:\Users\<user>\AppData\Local\Temp`） | **用户级 TEMP/TMP 已改到 `E:\vulnclaw\tmp`**；同时清了 2.1 GB 旧临时文件 |
| `.vulnclaw\runs` + `sessions`（每次跑题都涨） | 今日 41+41 个已归档到 `E:\vulnclaw\dot-vulnclaw-archive\20261018-grind\` |

**但这些变量对新进程才生效，而子进程继承父进程的环境**：一个在你改设置之前就开着的
终端，会把**旧的 C 盘值**继续传给每个子进程（实测：注册表已是 E 盘，
`python -c "import tempfile; print(tempfile.gettempdir())"` 仍返回 C 盘）。

所以要跑耗磁盘的任务，用这个 wrapper（它强制覆盖 TEMP/TMP + `VULNCLAW_WORK_DIR`）：

```bash
E:\vulnclaw\vulnclaw-e.cmd ctf2 <challenge_id> <practice_id> --max-steps 40
# 实测：经它启动的 python 里 tempfile.gettempdir() == E:\vulnclaw\tmp
```

`C:\Users\<user>\AppData` 仍占 76 GB，那是系统目录，不要在里面 rm -rf。
可安全清理的是 `AppData\Local\Temp`（超过 1 天的文件）。

---

## 二、环境变量生效时机

`VULNCLAW_WORK_DIR` 是**用户级**环境变量（已写入 `HKCU\Environment`，实测
`reg query "HKCU\Environment" /v VULNCLAW_WORK_DIR` → `E:\vulnclaw\work`）。

它**只对新启动的进程生效**。设置之前就开着的终端读不到，在里面跑仍然看到它指向 C 盘
（实测：同一台机器上，注册表已有值而旧 shell 的 `os.environ` 仍为 `None`）。
判断是否生效以新进程实测为准：

```bash
python -c "import os; print(os.environ.get('VULNCLAW_WORK_DIR'))"
```

空值不是配置错误，是当前终端没继承；换一个新终端再跑。

---

## 三、批量跑题时的两个资源坑

### 3.1 solve 锁残留

进程被强杀（`taskkill`、超时、终端关闭）后 `solve_locks/*.lock` 不会自动清，
下次启动会被误判为 "another solve run is active for this target" 并直接以 `steps=0` 退出。

排查：

```bash
cat ~/.vulnclaw/solve_locks/*.lock   # 看 pid
tasklist //FI "IMAGENAME eq python.exe"   # pid 还活着吗
# 确认已死 → 删锁
rm -f ~/.vulnclaw/solve_locks/*.lock ~/.vulnclaw/solve_locks/*.lock.guard
```

### 3.2 平台环境配额不自动释放

CTF2 agent 配额 `max_environments=1`。某道题被 stall guard 交还（`waiting for user input`）
或运行失败后，**它开的环境仍然占着配额**，下一题会报：

```
agent_environment_limit — This Agent already runs its maximum number of environments.
```

换题前先释放：

```bash
# 用 MCP 调，需要原题的 practice_ground_id + challenge_id
ctf2_user_delete_practice_id_challenges_challengeid_environment
```

找不出是哪道题占着时，用 `ctf2_get_environment` 遍历最近跑过的 challenge_id，
`status=running` 的那个就是。

---

## 四、跑题时的角色分工（实测有效的做法）

- **让 VulnClaw 自己解，不要替它解。** 人工代打会掩盖框架缺陷：2026-10-17 有人手工解了
  12 道，后来验证 agent 自己能解其中大部分（平台返回 `ALREADY_SOLVED`），纯属白干。
- 观察它的日志找**卡点**，给提示或改代码，而不是接管。
- 提交后**必须核对平台返回**：`accepted: true` 才算数。owner PAT 与 MCP agent token
  是**两套记分板**，用 owner token 提交不计入 agent 分数。

### 4.1 正式赛（competition）与练习场（practice）走的是两条路

实测 2026-10-23（1024 快闪赛调试赛，4/4 解出、180 分）：

- `vulnclaw ctf2 <pid> <cid>` **只认 practice**。比赛题不能这样起：适配器的
  `read_challenge` 不区分 `ref.kind`，一律调 practice 路由 → 404；而且 REST 对
  比赛路由直接返回 `403 agent_scope_forbidden` —— **比赛能力只开放给 MCP**。
- 比赛的起法是 `solve` + 在 goal 里点名 MCP 工具：

  ```bash
  vulnclaw solve "ctf2:competition:<cmp_id>:<stage_id>:<challenge_id>" \
    --goal "…start its environment with ctf2_start_competition_environment and poll
            ctf2_get_competition_environment until usable… then submit with
            ctf2_submit_competition_flag (confirmation=true). Flag format DASCTF{...}."
  ```

- 比赛工具（`ctf2_list_competition_challenges` 等）**必须同时传 `competition_id`
  和 `stage_id`**，只传一个会 `INVALID_REQUEST`。stage id 从
  `ctf2_get_competition` 的 `stages[].audience == "agent"` 里取。
- **选择题**：`submission_type` 在题目列表与单题读取里都会返回。遇到 `choice` 时
  不是传 `flag` 而是传 `choice: ["A"]`（`single_choice`/`true_false` 一个字母，
  `multiple_choice` 全部正确字母）。**选项顺序每人不同**，只能按自己 `choice.options`
  里的字母，别照抄题解。

### 4.2 计分时间窗：到点前挂起、到点自动提交

1024 快闪赛有两条按**提交时刻**计分的规则，而且它们需要**两个不同的出发时刻**：

| 窗口 | 时刻 | 为什么是这个时候 |
|---|---|---|
| 首血 | 19:10:24（闪电战开窗） | 窗口内得分翻倍，一血按"谁先到"判 ⇒ 越早越好 |
| 卡点 | 19:24:00–19:24:59 | 带内满分、其他时间一半 ⇒ 必须落在带内，早发无用 |

配置（两选一）：

```bash
# 环境变量（推荐，比赛现场改一行就行）
export VULNCLAW_COMPETITION__SUBMIT_WINDOWS="firstblood@19:10:24,peak@19:24:00+59"
export VULNCLAW_COMPETITION__SUBMIT_WINDOW_END=2026-10-24T20:00:00
```

```yaml
# 或写进 config.yaml
competition:
  submit_windows:
    - {name: firstblood, at: "2026-10-24T19:10:24"}
    - {name: peak,       at: "2026-10-24T19:24:00", until: "2026-10-24T19:24:59"}
  submit_default_window: peak
```

设了窗口之后，提交调用**不立即发送**：完整参数落盘
（`<config>/submit_hold/queue.json`），后台线程在到期时刻自动发出，模型收到
`queued: true`（不是失败）。行为细节：

- 不指定窗口时选**最近一个尚未关闭**的窗口 —— 19:23 找到的 flag 仍进得了 19:24 带；
- 队列**落盘**，找到 flag 的 run 退出了也照样发；
- 同一 payload 折叠成一条（选择题只有 1 次机会）；
- 每项按**自己的**窗口关闭：首血项不会被卡点窗口的终点误杀；
- 过了窗口终点一律不发，改为丢弃并记录原因（往关闭的入口提交算"非有效操作"）；
- 首血提前量 0.3s、卡点 0.8s，tick 间隔 0.05s；
- 完全不设 = 立即提交，行为不变。

**注意**：这个机制只负责"到时才发"。19:24 那一刻没解出题，队列里就没东西可发。

---

## 五、完成门与 stall guard 是有意设计，不要"优化"掉

- `_completion_gate`（`agent/solver.py`）：答案里的 flag 必须能在已记录证据中找到，防猜。
- `_completion_lock_gate`（`solver.py:547`）：答案正确后仍要求补 LOCK + fact + ANGLE。
  会让 agent 多花 1–2 轮，但 2026-10-11 应急赛靠它保住了答案不落盘。
- `_path_progress_fingerprint`（`solver.py:638`）：**故意不把"新证据"计入进展**。
  `tests/agent/test_path_stall_guard.py` 开头记录了实测依据：一个跑偏的 run 每小时
  产出 53 次工具结果、大量证据却毫无进展。想改之前先读那个测试的注释。

stall guard 的动作是**交还给人**（`waiting for user input`），不是硬杀。CLI 只显示
`⊘ 未达成`，容易误判成"崩了"，实际是它在等一个提示。

---

## 六、仓库纪律

- CTF 杂物不要留在仓库根；附件统一放 `E:\vulnclaw\work\`。
- 提交前 `git status` 查并行会话的未提交改动（本仓库常有多个会话同时工作）。
- 全量测试（5117 条）：

  ```bash
  python -X utf8 -m pytest -q -n 4        # 约 4–5 分钟，安全
  python -X utf8 -m pytest -q             # 单进程 14 分 11 秒
  ```

  **⚠️ `-n 必须保守，别按 CPU 核数开。** 2026-10-19 实测：本机 32 核、16 GB 内存，
  跑 `-n 8` 时 `tests/agent/test_ocr_vision.py` 真的调用 easyocr，每个 worker 各自
  加载一份 torch + OCR 模型（数百 MB），8 份叠加把内存顶满，整机卡死。选 `-n 4`
  以内，且**不要同时跑别的分析任务**（并发的 python 会再叠一份）。内存紧张时用单进程。

  单进程慢在完全没有并行，不是测试太多：统计过每个目录，最慢的是 agent 1590 条，
  但没有哪个目录能整批删掉——2026-09 写的 `test_playbook_overlap_gate.py` 在
  2026-10-19 拦下过一次错误的召回改动，旧测试恰好是护栏。日常改哪个模块就跑哪个目录
  （改 playbook 只跑 `-k playbook`，约 10–20 秒），一天收尾跑一次全量。
- 并发下偶发：`tests/config/test_token_provider.py::test_chatgpt_login_and_refresh`
  在早期的单进程全量里失败过一次，单独跑与并行全量都通过。见到它失败先单独重跑再判断。
- **`.test-tmp/` 会随测试增长**（每次跑测试新建上百个目录，conftest 只清 12 小时前的）。
  磁盘紧张时直接 `rm -rf .test-tmp`，测试会重建。
- `.ir-tools/` 是本地取证工具包（1.1 GB，已 gitignore），不在仓库内容里，**不要删**——
  应急响应题依赖它。

## 七、2026-10-18 文档清理

10-11 应急赛的现场作战卡已归档，仓库根不再保留：

| 原文件 | 现位置 |
|---|---|
| `IR-RUNBOOK.md` / `IR-PRECHECK.md` / `IR-FIELD-CARD.md` / `IR-PROMPTS.md` | `E:\vulnclaw\archive\ir-competition-cards-20261018\` |
| `IR-PENTEST-CARD.md` / `IR-PENTEST-HANCLOUD.md` / `IR-WP-TEMPLATE.md` | 同上 |
| `AUDIT-2026-10-08.md` / `PLAYBOOK-SHORTLIST.md` | 同上 |

9 份共 268 KB。仓库根 md 从 604 KB 降到 340 KB。**这些文件仍在 git 历史里**，
需要时 `git show <sha>:IR-RUNBOOK.md` 可取回，或读 E 盘归档。

注意：`PLAYBOOK-SHORTLIST.md` 里的 311 篇 playbook 精选清单已随之移出。若还要按清单
手动贴 playbook，去归档目录取。
