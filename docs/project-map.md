# VulnClaw 项目地图

> 定位：AI 驱动的渗透测试 / CTF 解题 CLI（`vulnclaw`，v0.3.9，Python ≥3.10，typer + FastAPI）。
> 本文档描述 aw 分支当前形态（含平台适配层、solve 引擎与安全边界），供会话/成员快速定位代码。

## 1. 顶层包地图（`vulnclaw/`，共 20 个子包 ~10.3 万行）

| 包 | 职责 | 关键文件 |
|---|---|---|
| `agent/` | **核心**：solve 引擎、LLM 客户端、全部工具实现、子代理、上下文管理 | `solver.py`(3951L)、`builtin_tools.py`(3105L)、`llm_client.py`(1764L)、`agent_state.py`(1237L)、`remote.py` |
| `cli/` | 用户入口：typer 应用、TUI、向导、配置面板 | `tui.py`(2942L)、`main.py`(855L)、`wizard.py`、`config_panel.py` |
| `platforms/` | **平台适配层**（新）：CTF 平台的中立抽象，6 动词统一工具面 | `base.py`(Protocol)、`ctf2.py`、`gcs.py`、`registry.py`、`tools.py` |
| `ctf_platform/` | CTF2 (DASCTF) 旧集成（正被 platforms/ 取代） | — |
| `gcs_platform/` | 西湖论剑 agent API 集成（同上） | — |
| `web/` | Web UI 后端（FastAPI），复用同一核心 | `app.py` |
| `mcp/` | MCP 协议集成：内置 server 注册、生命周期、路由 | `lifecycle.py`(2459L) |
| `skills/` | 知识技能库：59 个 specialized + core 方法论 7 篇 | `dispatcher.py`、`routing.py`、`loader.py` |
| `config/` | 配置模型与加载（yaml + env） | `schema.py`(1303L)、`settings.py` |
| `kb/` | 安全知识库（CVE/技巧/工具情报，中文感知检索） | — |
| `intel/` | 情报模块（移植自 HackBot：CVE、OSINT、拓扑、修复规则） | `remediation_rules.py` |
| `report/` | 结构化报告生成 + PoC 验证 | `generator.py`、`verifier.py` |
| `codescan/` | 本地源码安全审计 | — |
| `traffic/` | 沙箱原生 HTTP 流量证据存储（`maintenance.py` = GC 的受约束入口） | `maintenance.py` |
| `retest/` | 复测已上报的结论（A1，借鉴 ARTEX）：冻结快照 + 三选一结论 + 唯一的处置翻转点 | `store.py`、`service.py` |
| `target_state/` | 目标级状态持久化（快照/回滚） | `store.py` |
| `plugins/` | 漏洞检测插件机制（registry + runtime + web 视图） | — |
| `i18n/`、`utils/`、`warstories/` | 国际化 / 共享 httpx client / 实战复盘案例（md） | — |

## 2. 三条运行主线（关系图）

```
                    ┌── CLI (typer) ── vulnclaw solve|ctf2|gcs|competition|go …
                    │        └─ TUI / REPL / wizard
用户 ───────────────┤
                    └── Web UI (FastAPI, /api/*) ── 任务异步运行 + SSE 流
                            │
                            ▼
              agent/solver.py —— solve 主循环（黑板模型）
              ├─ llm_client.py      多厂商 LLM（流式/重试/计费感知）
              ├─ agent_state.py     证据/发现黑板 + AutoNotes 沉淀
              ├─ context*.py        上下文预算与压缩
              ├─ playbook.py        解题 playbook 复用/沉淀（~/.vulnclaw/playbooks）
              ├─ subagent/          叶子代理（team 并行分身，禁危险工具）
              │
              ▼ 工具调用（tool_schemas.py 定义 → builtin_tools.py 实现）
   ┌─ 本地工具：shell_command / python_execute / http_probe_batch / nmap_scan /
   │   crypto_decode / brute_force_login / dir_enum / vault_* / evidence_* /
   │   memory_search / pwn_local（Docker 复现）/ remote_*（SSH 采集执行）
   │
   └─ 平台工具（platforms/tools.py 统一面）：
       platform_list / read / start_env / read_env / stop_env / submit  ← 6 核心动词
       (+ capability 可选：submissions / event_info / notices / overview)
                    │ ref 令牌（禁止裸 id，防猜平台）
                    ▼
       PlatformAdapter Protocol（base.py）
       ├─ Ctf2Adapter（platforms/ctf2.py，DASCTF）
       └─ GcsAdapter（platforms/gcs.py，西湖论剑，默认不注册）
```

**安全边界贯穿所有执行路径**：
- `agent/exec_gate.py` — 执行审批门（进程级单例，channel 协商：approve/refuse）
- `agent/command_classifier.py` — Windows/Linux 命令分级（只读白名单 vs 变更动词）
- `scripts/verify_execution_boundary.py` — spawn 位点审计（作用域+不变量哈希白名单，CI 门）
- `platforms/submit_guard.py` — flag 提交防误触
- `hackerone_scope.py` / `constraint_policy.py` — 授权范围与主机/路径约束（URL 级强制）
- `agent/tools/shell_exec.py` — 解释器隔离：python 载荷落在 `<scratch>/.vulnclaw-scripts`，工作目录只 append 到 sys.path 末尾；工作目录里有同名 stdlib 文件时给出可操作提示

## 3. CLI 命令面（`vulnclaw/cli/main.py`，typer）

| 命令 | 功能 |
|---|---|
| `run` / `solve` | 启动 agent 会话 / 深度解题（模型主导循环，token 熔断+单实例锁） |
| `ctf2` / `gcs` / `competition` | 平台会话（CTF2 / 西湖论剑 / 比赛模式抢分策略） |
| `solve-all` | 跨题并发解题：每道题一个子进程，`--concurrency` / `--limit` / `--timeout-min`；比赛时先铺满广度 |
| `where` | 哪些题从没跑过：读本地 run 历史回答平台答不了的"试过没解出"，附已花调用数 |
| `go` | 单条指令直达（快速意图执行） |
| `persistent` | 持久会话 |
| `recon` / `scan` / `network-scan` / `exploit` | 侦察 / 扫描 / 网络扫描 / 利用 |
| `report` | 报告生成 |
| `retest` | 复测一条已上报的 finding（发起 / 结案 / `--list` / `--sweep`，A1） |
| `evidence` | 证据维护：`gc`（回收孤立 blob，`--dry-run`）/ `unbind` / `reorder`（默认只看不写，`--write` 才落盘） |
| `manual` (`man`) | 内置手册查询 |
| `init` / `login` / `logout` / `doctor` | 初始化 / 登录 / 诊断 |
| `learn` / `feedback` | 知识沉淀 / 反馈 |
| `repl` / `tui` / `web` | 交互 REPL / 终端 UI / Web UI |
| 子应用 `config` `kb` `experience` `target-state` `plugins` | 配置/知识库/经验/目标状态/插件管理 |

## 4. Web REST API（`vulnclaw/web/app.py`，FastAPI，前缀 `/api`）

- 健康/配置：`GET /health` `GET|POST /config` `GET /mcp` `GET /constraint-audit` `GET /providers` `POST /provider-models`
- 任务：`GET /tasks` `POST /tasks/run` `GET /tasks/{id}` `POST /tasks/{id}/stop` `GET /tasks/{id}/stream`（SSE）
- 目标状态：`GET /targets` `GET /targets/{path}` `/raw` `/snapshots` `GET /target-preview/{path}` `GET /target-diff/{path}` `POST /targets/{path}/rollback` `DELETE /targets/{path}`
- 报告：`GET /reports` `GET /reports/content` `GET /reports/download` `POST /reports/target`
- 静态：`GET /`（Web UI 单页）+ SPA fallback

## 5. agent 工具面（模型可调用）

本地工具（`agent/tool_schemas.py` 注册，`builtin_tools.py` 实现，约 25+ 个）：
`load_skill_reference` `evidence_list/view/search` `source_extract` `runtime_diff_probe` `shell_command` `http_probe_batch` `python_execute` `crypto_decode` `nmap_scan` `brute_force_login` `space_search` `subdomain_enum` `js_recon` `unauth_test` `dir_enum` `vault_archive/restore/search/status` `memory_search` + `pwn_local_*`（Docker 本地复现）+ `remote_*`（SSH hosts/exec/collect/fetch）

平台工具（`platforms/tools.py`，按注册适配器启用）：见上文 6 核心动词。
工具面裁剪：goal 感知（quiz/IR/pwn 等场景裁剪无关工具，`_infer_allowed_tools`）+ `agent/tool_registry.py` 能力卡（本机外部工具注入系统提示）。

## 6. 知识资产（模型按需加载）

- `skills/specialized/`（54 个）：incident-response（含出题方教材 book/ 15 文件）、competition-mode（CTF+IR 答题制策略）、ctf-web/crypto/misc、redteam-*-detail-pack、hackerone、knowledge-quiz 等
- `skills/core/`（7 篇方法论）：recon / vuln-discovery / exploitation / post-exploitation / reporting / waf-bypass / pentest-flow
- `kb/`：CVE / 攻击技巧 / 工具情报（带中文感知检索）
- `~/.vulnclaw/playbooks/`：解题 playbook 库（~80 条，启动注入 + 结束沉淀）
- `warstories/`：实战复盘案例（md）
- `agent/distiller.py`：跨会话经验蒸馏（experience）

## 7. 配置与落盘

- 配置：`~/.vulnclaw/config.yaml` → `config/schema.py`（VulnClawConfig：session/safety/mcp/providers…）
  - 关键 session 项：`solve_max_model_tokens`（成本熔断，默认 6M）、`solve_work_root`（per-solve scratch 目录，本机 `E:\vulnclaw\work`，run_id 子目录）
- 数据：`~/.vulnclaw/`（config/kb/playbooks/runs）、`E:\vulnclaw\work\<run_id>\`（解题草稿）、`E:\vulnclaw\tools\`（外部工具链：sqlmap/hashcat/john/ffuf/gobuster/binwalk/exiftool/ROPgadget）
- IR 备赛资产：`E:\vulnclaw\work\ir_prep\ir_drill.py`（靶场驱动）、`ir_drills/<场景>/`（webshell/cryptomining + answers.json）、`ir-collection/`（采集产物，gitignored）

## 8. 测试与质量门（`tests/`，301 个测试文件 / 5825 个用例）

`tests/agent`（核心循环+工具）、`tests/security`（spawn 边界/gate）、`tests/platforms`（适配层 A/B 对照）、`tests/cli` `tests/web` `tests/mcp` `tests/skills`（路由/加载安全）等。
质量门：`scripts/verify_execution_boundary.py`（spawn 白名单）、`verify_dist_artifacts.py`（发布产物）、全量回归约 6 分钟。
