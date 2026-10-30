# VulnClaw — 给 AI 会话的落盘与环境约定

> 本文件面向在本仓库工作的 AI 会话（任何客户端）。**开工前先读这一节**，
> 尤其是磁盘路径部分。详细踩坑记录见 `CONTRIBUTING.md` §六。

---

## 一、磁盘：临时产物一律进 E 盘

**本机 C 盘小、E 盘大。禁止把附件、解压目录、脚本暂存写进 C 盘。**

### 两条独立路径，必须都覆盖

| 产物 | 落点 | 配置项 |
|---|---|---|
| `shell_command` / `python_execute` 的脚本与工作目录 | `<solve_work_root>/<run_id>/` | `config.yaml` → `session.solve_work_root`（本机 `E:\vulnclaw\work`） |
| 平台附件下载（`attachment_dir()`） | `$VULNCLAW_WORK_DIR/attachments` | 用户级环境变量 `VULNCLAW_WORK_DIR=E:\vulnclaw\work` |

**坑**：`vulnclaw/platforms/attachments.py` 的 `work_dir()` 默认是
`Path.home()/"vulnclaw"/"work"`，**不读 `solve_work_root`**。只配 config 时附件仍会落到
`C:\Users\<user>\vulnclaw\work`；两处都要设。

**自检**（新环境先跑一次）：

```bash
cd <repo> && python -c "from vulnclaw.platforms.attachments import work_dir, attachment_dir; print(work_dir()); print(attachment_dir())"
# 期望以 E:\vulnclaw 开头；出现 C:\Users\... 说明环境变量没生效
```

### TEMP 与历史数据

- `%TEMP%` / `%TMP%` 已改到 `E:\vulnclaw\tmp`，但**只对新进程生效**；旧终端
  仍会把 C 盘值传给子进程。耗磁盘任务用 wrapper（强制覆盖 TEMP/TMP +
  `VULNCLAW_WORK_DIR`）：

  ```bash
  E:\vulnclaw\vulnclaw-e.cmd <args>
  # 实测经它启动的 python 里 tempfile.gettempdir() == E:\vulnclaw\tmp
  ```

- 历史 run / session 在 `E:\vulnclaw\dot-vulnclaw-archive\`；
  `--resume` / `target-state` **只认原地路径**，不认归档目录。
- `E:\vulnclaw\tmp` 是**共享 TEMP**，不是 VulnClaw 专属目录：只清确认属于
  VulnClaw 的 `*.events.ndjson` 和 run `.log`，**绝不按扩展名全局删**
  （`.log/.tmp/.dll/.exe` 大量是别的程序的运行时文件）。
- `C:\Users\<user>\AppData` 是系统目录，不要 `rm -rf`；可安全清理的是
  `AppData\Local\Temp` 里超过 1 天的文件。

---

## 二、环境变量生效时机

`VULNCLAW_WORK_DIR` 是**用户级**环境变量（`HKCU\Environment`），**只对新启动的进程生效**。
设置之前就开着的终端读不到；判断是否生效以新进程实测为准：

```bash
python -c "import os; print(os.environ.get('VULNCLAW_WORK_DIR'))"
```

空值不是配置错误，是当前终端没继承；换新终端再跑。

---

## 三、批量跑题时的资源坑

### 3.1 solve 锁残留

进程被强杀（`taskkill`、超时、终端关闭）后 `solve_locks/*.lock` 不会自动清，
下次启动会被误判为 "another solve run is active for this target" 并以 `steps=0` 退出。

```bash
cat ~/.vulnclaw/solve_locks/*.lock   # 看 pid
tasklist //FI "IMAGENAME eq python.exe"
# 确认已死 → 删锁
rm -f ~/.vulnclaw/solve_locks/*.lock ~/.vulnclaw/solve_locks/*.lock.guard
```

### 3.2 平台环境配额不自动释放

CTF2 agent 配额 `max_environments=1`。题目被 stall guard 交还或运行失败后，
它开的环境仍占配额，下一题会报：

```text
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

## 四、跑题时的角色分工

- **让 VulnClaw 自己解，不要替它解。** 人工代打会掩盖框架缺陷；观察日志找卡点，
  给提示或改代码，而不是接管。
- 提交后**必须核对平台返回**：`accepted: true` 才算数。owner PAT 与 MCP agent token
  是**两套记分板**，用 owner token 提交不计入 agent 分数。

### 4.1 正式赛与练习场走两条路

- `vulnclaw ctf2 <pid> <cid>` **只认 practice**；比赛题不能这样起（适配器
  `read_challenge` 不区分 `ref.kind`，REST 对比赛路由返回 `403 agent_scope_forbidden`）。
- 比赛走 `solve` + 在 goal 里点名 MCP 工具：
  `ctf2_start_competition_environment` / `ctf2_get_competition_environment` /
  `ctf2_submit_competition_flag`。
- 比赛工具（`ctf2_list_competition_challenges` 等）**必须同时传 `competition_id`
  和 `stage_id`**，只传一个会 `INVALID_REQUEST`；stage id 从 `ctf2_get_competition`
  的 `stages[].audience == "agent"` 取。
- **选择题**：`submission_type=choice` 时传 `choice: ["A"]`（单选/判断一个字母，
  多选全部正确字母）；选项顺序每人不同，只按自己的 `choice.options`。

### 4.2 计分时间窗

按提交时刻计分的比赛可配 `competition.submit_windows`：提交调用不立即发送，
完整参数落盘，后台线程到到期时刻自动发出（模型收到 `queued: true`，不是失败）。
`submit_window_challenges` 非空时只有指定题等窗口，其余解出即发。
细节见 `vulnclaw/config/schema.py` 的 `CompetitionConfig` 与
`vulnclaw/ctf_platform/submit_hold.py`。

---

## 五、完成门与 stall guard 是有意设计，不要"优化"掉

- `_completion_gate`（`agent/solver.py`）：答案里的 flag 必须能在已记录证据中找到，防猜。
- `_completion_lock_gate`（`solver.py`）：答案正确后仍要求补 LOCK + fact + ANGLE；
  会让 agent 多花 1–2 轮，但这是防止答案不落盘的设计。
- `_path_progress_fingerprint`（`solver.py`）：**故意不把"新证据"计入进展**。
  `tests/agent/test_path_stall_guard.py` 开头记录了实测依据：一个跑偏的 run 每小时
  产出 53 次工具结果、大量证据却毫无进展。想改之前先读那个测试的注释。

stall guard 的动作是**交还给人**（`waiting for user input`），不是硬杀。CLI 只显示
`⊘ 未达成`，容易误判成"崩了"，实际是它在等一个提示。

---

## 六、仓库纪律

- CTF 杂物不要留在仓库根；附件统一放 `E:\vulnclaw\work\`。
- 提交前 `git status` 查并行会话的未提交改动（本仓库常有多个会话同时工作）。
- 全量测试：

  ```bash
  python -X utf8 -m pytest -q -n 4        # 约 4–5 分钟，安全
  python -X utf8 -m pytest -q             # 单进程较慢
  ```

  **⚠️ `-n` 必须保守，别按 CPU 核数开。** 本机 32 核 / 16 GB 内存；
  `tests/agent/test_ocr_vision.py` 真调 easyocr，每个 worker 各载一份 torch + OCR 模型，
  `-n 8` 会把内存顶满。选 `-n 4` 以内，且不要同时跑别的分析任务。

  日常改哪个模块就跑哪个目录（改 playbook 只跑 `-k playbook`），一天收尾跑一次全量。
- `.test-tmp/` 随测试增长，磁盘紧张时 `rm -rf .test-tmp`，测试会重建。
- `.ir-tools/` 是本地取证工具包（已 gitignore），**不要删**——应急响应题依赖它。
- 并发下偶发 OCR / token-provider 类测试抖动；见到失败先单独重跑，再判断是否真回归。
  **2026-10-30 校正**：OCR 那条抖动的真因是测试钉死外部路径
  `E:\vulnclaw\test\`（已改为 `tests/fixtures/ocr/` + `tmp_path`），不是并发本身。

### 6.1 easyocr 走 GPU 的前提（只影响速度，不影响功能）

`execute_ocr` 会先问 `torch.cuda.is_available()` 再决定 easyocr 用不用 GPU，
所以**不需要任何配置**：

| 机器 | torch 构建 | 效果 |
|---|---|---|
| 有 NVIDIA 卡 | `torch==2.11.0+cu128` 等 CUDA 版 | 1440×900 截图约 1.4s，占显存约 0.5 GB |
| 没卡 / 装了 CPU 版 | `torch==...+cpu` | 同一张图约 4.8s；easyocr 自动退 CPU，不报错 |

换 CUDA 版的命令（Windows，注意别让 pip 顺手升级 numpy）：

```bash
python -m pip install --no-deps --index-url https://download.pytorch.org/whl/cu128 \
  torch==2.11.0+cu128 torchvision==0.26.0+cu128
```

官方 CDN 在本机只有 ~0.4 MB/s；国内镜像 `mirrors.aliyun.com/pytorch-wheels/cu128/`
约 0.4 MB/s、`mirror.sjtu.edu.cn/pytorch-wheels/cu128/` 约 2 MB/s，多连接分段下载
可到 ~9 MB/s（实测脚本见 `E:\vulnclaw\tmp\dlw.py`）。

