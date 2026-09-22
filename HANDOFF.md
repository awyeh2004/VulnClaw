# 交接文档 — VulnClaw 赛前准备

> 面向：接手的人 / 外层 agent。写于 2026-09-22。
> **本文取代此前所有交接材料**：旧的 `.test-tmp/HANDOFF.md` 已随 `.test-tmp/` 清理删除，
> 且它**从未进过版本库**（`git log` 无记录），内容不可恢复 —— 有效部分已并入本文与
> `IR-RUNBOOK.md`。
>
> 标记约定：
> `[实测]` 本机验证过并有实证；`[推断]` 有依据未验证；`[待定]` 需要你决定；`[阻塞]` 缺外部信息

---

## 0. 一句话状态

**工程主体完成，测试全绿（3590 passed / 0 failed），没有已知的未修产品缺陷。**
剩下的都是"要你拍板"或"必须到现场才能定"的事。

| 项 | 值 |
|---|---|
| 分支 | `aw`，**领先 `origin/main` 19 个提交**（未推送；推送由你操作） |
| `upstream/main` | 原作者上游，落后 43 个提交 —— 另一条线，与比赛无关 |
| 工作区 | 仅 `frontend/vite.config.ts` 有你的未提交改动 |
| 测试 | `python -m pytest tests -q` → 3590 passed / 20 skipped |
| 执行边界守卫 | `python scripts/verify_execution_boundary.py` → 18 个 spawn 站点全在 allowlist |
| 比赛 | 2026-10-11，天津；渗透 50% + 应急响应 50%；允许 agent 做题 |

---

## 1. ⚠️ 我必须先纠正的三处错误陈述

这三条是我此前说过、但**经核实是错的**。留着会误导后续判断，所以单独列在最前。

### 1.1 「看门狗由 15.7 小时冻结暴露」—— 错

那次是**电脑息屏/休眠导致断连**，不是代码卡死。它证明不了看门狗的必要性。

看门狗**仍然保留**，但理由换成可实证的：旧设计的完成条件是搜日志文本标记
（`d.find('目标达成')`），而实测该字节日志里 UTF-8 与 GBK 下**都不存在**（双重编码
乱码），所以那个条件**永远不可能为真**，看门狗实际只靠 stall 定时器兜底。

⚠️ 顺带教训：**一个永远不会触发的检查比没有检查更糟** —— 它让系统看起来是健康的，
且事后无法区分"查过了没问题"和"检查本身是死的"。

### 1.2 「代理修复接入了 9 处 httpx」—— 错

实测核对源码后：代理工厂只接入了 **4 处**：

| 站点 | 谁做的 |
|---|---|
| `gcs_platform/gateway_proxy.py:91`（转发到比赛 LLM 网关） | 我 |
| `agent/builtin_tools.py:2738`（http_probe_batch） | 我 |
| `agent/builtin_tools.py:3523`（登录表单，异步） | 我 |
| `agent/builtin_tools.py:2730` 按 spec 拆分客户端（混合批次） | **你** |

**其余裸 `httpx.Client` 大多是故意的**，不要"顺手统一"：

| 站点 | 为什么保持原样 |
|---|---|
| `agent/recon_tools.py:310`（FOFA/Shodan 等） | 公网 API，**需要**系统代理 |
| `intel/cve.py` · `intel/osint.py` | 公网情报 API |
| `ctf_platform/client.py` · `gcs_platform/client.py` | dasctf.com，公网 |
| `traffic/replay.py` | 调用方显式传 `transport`/`proxies` |

⚠️ **唯一确认的遗漏**：`mcp/lifecycle.py:1490` 与 `:1501`（MCP HTTP 取 cookie）。
MCP server 可能是 `127.0.0.1`，当前会被系统代理劫持。低优先但真实，见 §5。

### 1.3 「`.test-tmp/HANDOFF.md` 里那句归因要更正」—— 前提就不成立

我去查了 `IR-RUNBOOK.md` 全文，**它本来就没引用那个 15.7 小时**。所以只需改脚本自身
docstring，不需要改 RUNBOOK。当时我说"要更正 RUNBOOK"是基于记忆而非核查。

---

## 2. 本轮实际修掉的缺陷（都有实证 + 对抗性验证）

四个都属**"现场极难当场定位"**的类型：静默丢结果、静默挂死、非确定性失败。

### 2.1 `4168cae` 原子写入：Windows 共享冲突会丢状态

**症状**：`test_agent_graph.py` 单独连跑 8 次挂 3 次；跨全量 5 次跑出 **4 种不同的失败集合**。

**根因** `[实测]`：

```
PermissionError: [WinError 5] 拒绝访问。
  '.../agents/graph.json.tmp' -> '.../agents/graph.json'
  os.replace(self, target)
```

`os.replace` 是原子的，但 Windows 上当目标文件正被其他进程短暂持有（**杀软实时扫描**、
并发读者）会拒绝。失败时机取决于机器时序 → 每次落在不同用例上；现场则是**静默丢状态**。

**关键**：正确答案早在库里，**只用在一处** —— `platforms/submit_guard.py` 的
`_atomic_write` 早就注明并处理了这个冲突（重试 5 次 + 线性退避）。其余 **6 处**
各自实现"临时文件 + 原子替换"，全都没重试。

**改法**：`vulnclaw/utils/atomic_write.py` 作为唯一实现；`submit_guard` 与
`run_context` 的两份重复实现收敛掉。顺带修 `agent_graph._persist_event` **缺 fsync**
（该类不变式是"graph.json 恒等于 events.jsonl 的折叠"，事件先写却未 fsync，崩溃时会让
`resume()` 抛 `GraphInconsistencyError`）。

**验证**：`test_agent_graph.py` 连跑 20 次 **0 失败**；全量**连续 3 次全绿**。
对抗性：换回裸 `os.replace` → 新测试 **3 个失败**。

### 2.2 `0f6b920` 子进程编码：已验证的漏洞被误报为"未验证"

**这个最严重**（这是我判断，理由在下面）。全仓 9 处 `subprocess.run(text=True)` 未固定
编码 → 按父进程 locale（中文 Windows = **cp936**）解码。

**实证** `[实测]`（真实 `VerifierExecutor` + `parse_result`）：

```
正确的 PoC，纯 ASCII 输出        -> rc=0   -> VULN_CONFIRMED   ✓
同一 PoC，输出含一个 0x81 字节    -> rc=-3  -> EXECUTION_ERROR  ✗
                                    '[CONFIRMED]' 标记消失
```

**双重机制**：
1. 非法字节让 subprocess 的**读线程**抛 `UnicodeDecodeError`，CPython 吞掉 → `stdout` 变 **None**（不是 `""`）
2. 随后 `result.stdout + result.stderr` 抛 `TypeError: NoneType + str` → 被兜成 `-3`

而 `parse_result` 的注释明说 `-3` 是"执行环境问题，而非目标返回 403/404"。
**所以验证器把已确认的漏洞丢掉了，全程无任何报错** —— 而"未经验证的漏洞 = 误报 =
不写入报告"正是该模块存在的全部理由。

**为什么从没被测出**：**依赖数据**。某字节能否过 cp936 取决于它和邻居 ——
`b'\xa8\xa8'` 是合法双字节（解码成 `è`），`b'\xa8 '` 不是。我第一次构造的证明就"通过"了，
换字节才复现。

**改法**：`vulnclaw/utils/subprocess_text.py`（`run_text` 强制
`encoding="utf-8"` + `errors="replace"`；`combine_output` 做 None 安全拼接），接入 9 处。
顺带清掉 3 处同源缺陷（详见提交信息）。

**验证**：新增 12 个用例含端到端"D带非法字节的 `[CONFIRMED]` PoC 仍须判
`VULN_CONFIRMED`"。对抗性：去掉 `encoding=` → **4 个用例失败**。

### 2.3 `160d768` i18n 全局状态泄漏：非确定性测试失败

`vulnclaw.i18n` 持进程级 `_translator`，而 `reset_execution_gate` /
`reset_guard` / `reset_bootstrap` 都有，**唯独 i18n 没有复位入口**。全仓 170+ 处
`init_i18n` 调用，多处不还原（最明确的是 `tests/cli/test_config_panel_render.py` 的
`_render()`，每条用例 `init_i18n("en")` 却从不复位）。

**改法**：补 `reset_i18n()`（对齐既有命名）；`conftest.py` 加 autouse fixture
**快照并还原翻译器对象本身**（不是语言码），不依赖用例配合。

### 2.4 `ef76284` 看门狗改为面向 agent

读者是外层 agent（输出当上下文用），不是人。复核后发现三处不达标：

1. **文档论证基础是错的** —— 撤掉 15.7 小时（见 §1.1）
2. **`NEEDS_INPUT` 只说状态不说做什么** → 现在末尾直接给
   `ACTION: the agent is waiting on you. Answer it in the session, then re-check
   this run. Do NOT record this run as finished.`
3. **可发现性为零** → `--help` 加 epilog（三种模式示例 + 别自己循环调 `--status` +
   全部 6 种结局含义）；`IR-RUNBOOK.md` 新增一节

⚠️ **`run.json` 的 `completed` 不等于任务做完** —— 实测遇到过进程正常退出、但
`agent_state.completed=False` 且 `pending_questions` 非空（agent 停在问操作员）。
只看 `run.json` 会**关掉一个正等着你回复的 run**。该情形报 `NEEDS_INPUT`。

### 2.5 `bb6569a` / `c989c06` / `04f0d79` —— 你的提交，基于我的发现做得更彻底

| 提交 | 内容 | 说明 |
|---|---|---|
| `c989c06` | 能力卡 IR 段加**意图门** | 我只注册了工具，你补上"什么时候该显示"。`IR_INTENT_KEYWORDS` 防住"按工具设关键词"的误注入（如「登录」注入 FullEventLogView），并修掉我提的 `服务`/`服务器` 误命中 |
| `bb6569a` | `http_probe_batch` **混合批次按需拆客户端** | 我的 `targets=` 只在"全部目标都需直连"时生效，你处理了混合场景 |
| `04f0d79` | 被忽略垃圾可见性 + 测试沙箱自动清理 | `tmp-*` 会无限增长（实测又涨到 1084 个），你从机制上治 |

**⚠️ 依赖关系**：`e03b224`（我：IR 注册表 + 只遍历 `_REGISTRY` 的修复）在前，
`c989c06`（你：意图门）在后。revert 或 cherry-pick 时注意顺序。

---

## 3. 比赛前必须处理

### 3.1 待你操作

| # | 事项 | 现状 |
|---|---|---|
| 1 | **push 19 个提交** | 唯一的真实单点风险 —— 只存在于本机 |
| 2 | 删 `tsec_bench/` 源目录 | 已归档 `G:\tool\archive\tsecbench-2026-09-13`（57 文件，SHA256 逐个校验通过）。源 58 文件原样未动 |

**push 的三个坑**（`[实测]`）：

```
aw -> origin:refs/heads/main      ← aw 跟踪的是 origin/main，不是同名分支
```

- 直接 `git push` 会把 `aw` 推到 `origin/main`（若这是你要的，就对了）
- **绝不要 `--force`** —— 本地 `main` 另有 43 个提交不在 `aw` 里
- GitHub **直连不通**，但**经 Hiddify 代理（`127.0.0.1:12334`）是通的**（HTTP 200 实测）

### 3.2 你说了等赛前最后一次再定

| # | 事项 | 现状 |
|---|---|---|
| 3 | 出站范围白名单 / 超范围确认 | `[阻塞]` 需赛场靶机网段 |
| 4 | `full_access` vs `auto_review` | 现为 `full_access`（全部自动放行） |
| 5 | Go 装不装 | 取决于赛题是否含 Linux 内存镜像 |

---

## 4. 你会用到的两样东西

### 4.1 活性看门狗 `scripts/run_watchdog.py`

```bash
# 三选一，别同时开两个（会重复通知）
python scripts/run_watchdog.py --run <name> --status          # 偷看一次，~10 行
python scripts/run_watchdog.py --run <name> --follow          # 变化才打一行
python scripts/run_watchdog.py --run <name> --follow --quiet  # 后台盯梢，只在有事时说话
```

⚠️ **别自己循环调 `--status`**：N 次检查 = N 次工具调用 + N 个状态块。轮询循环在脚本
进程里，所以第三种模式**一次后台调用**就覆盖全过程。`--help` 末尾是完整说明。

### 4.2 IR 工具箱（30+ 工具，1 GB）

```powershell
. .ir-tools\env.ps1           # PowerShell；cmd 用 env.cmd
python .ir-tools\verify-ir.py # 自检
```

⚠️ **`.ir-tools/` 被 gitignore** —— 现场从 clone 起步时它**不在**。需要从移动硬盘
`G:\tool\ir-toolkit` 拷，或改 `VULNCLAW_TOOLS_DIR` 指向它。

⚠️ 工具是"探到才算数"：`vulnclaw/agent/tool_registry.py` 的 `_candidate_roots()`
已把 `<repo>/.ir-tools` 列为最低优先级探测根（我加的）。16 个 IR 工具实测
**16/16 探测成功**，会进 agent 的能力卡。

---

## 5. 已知未修 / 低优先

| # | 事项 | 影响 | 备注 |
|---|---|---|---|
| 1 | `mcp/lifecycle.py:1490,1501` 未接入代理工厂 | MCP server 是 `127.0.0.1` 时被系统代理劫持 | 唯一确认的代理遗漏，见 §1.2 |
| 2 | `_match` 子串匹配 | nmap 关键词 `服务` 命中 `服务器` | 精度瑕疵非正确性；你已用意图门压制 |
| 3 | `intel/osint.py` WHOIS 曾无读超时 | 已修 | 提交信息里我错误引用了 15.7 小时（见 §1.1），但**修复本身成立**：`create_connection(timeout=)` 只约束连接，不约束 `recv` 循环。实测对静默服务器现 2.02 秒返回 |
| 4 | `.gitignore` 瘦身 | 未应用 | 候选文件已随清理丢失。当时结论：规则数只减 10%，收益在"按类型封堵"而非行数。当前 0 个未忽略风险文件，**不急** |
| 5 | `tsec_bench` 是什么 | 回答一个疑问 | **不是 6 小时测试**：51 道题、单项超时上限 3600 秒（2 道正好卡住）、耗时中位数 110 秒、45 solved、总分 12800、靶机 `10.0.172.x`（腾讯内网/VPN） |
| 6 | 河马 HWS / PCHunter | 结论：**不装** | Windows-only，教材无 rootkit 场景，火绒 HipsDaemon 会删它 |

---

## 6. 可复用操作

### CTF2 起靶机 / 打题 `[实测]`

```bash
ctf2_start_environment practice_id=<PID> challenge_id=<CID>
# ⭐ 轮询直到 status=running —— starting 的响应是残缺的！
ctf2_get_target practice_id=<PID> challenge_id=<CID>
ctf2_stop_environment practice_id=<PID> challenge_id=<CID>   # 记得释放
```

⚠️ **CTF2 的 pwn 靶机是 TLS 包装的**：裸 socket 会"连上后静默 EOF"，看起来和"利用失败"
一模一样。⚠️ 出现 `[ TARGET NOT FOUND ]` 说明靶机过期，**重启靶机，别去调 payload**。

### 已解出的两题（战果记录）

| 题 | flag |
|---|---|
| SSTI (N1BOOK) | `CTF2{36cec5fa-1bba-4efb-bbfc-0271533523ce}` |
| stack (Pwn) | `n1book{851939e4e90b864b8d20fe6228564522}` |

### 环境坑（都踩过，别再踩）

| 坑 | 现象 | 处理 |
|---|---|---|
| 配置目录硬编码 | `--runs-dir` 管不了 `targets/`，写不进直接崩 | 用 `VULNCLAW_CONFIG_DIR` 整体重定向 |
| 中文 Windows 编码 | 跨进程读输出：`UnicodeDecodeError` 在读线程里被吞，调用方拿到**空 stdout** | **一律显式 `encoding=`**（见 §2.2） |
| 原子写入 | Windows 上裸 `os.replace` 间歇性 `WinError 5` | 用 `vulnclaw.utils.atomic_write`（见 §2.1） |
| PowerShell 编辑文本 | `Set-Content -Encoding utf8` 加 BOM 且 `Get-Content -Raw` 按 GBK 读 → **曾毁掉一个 950 行文件** | 用 Python 或编辑器写文件 |
| PowerShell heredoc | `python - <<'PY'` 不支持 | 写成临时 `.py` 再跑 |
| PowerShell 引号 | `"$PWD\"`、`$_ -join`、嵌套引号反复报"缺少终止符" | 别用；改用 Python 脚本（本会话踩了 4 次） |

### 验证命令

```bash
python -m pytest tests -q                          # 期望 3590 passed
python scripts/verify_execution_boundary.py        # 期望 exit 0，18 站点
python .ir-tools/verify-ir.py                      # IR 能力自检
python scripts/run_watchdog.py --run <name> --status
```

---

## 7. 文件索引

| 路径 | 内容 |
|---|---|
| `IR-RUNBOOK.md`（仓库根，已跟踪） | ⭐ 应急响应能力速查：调用方式、自检、工具箱、SSH 远程实操、CTF2 实战 |
| `vulnclaw/skills/specialized/incident-response/` | `SKILL.md` + `references/` 9 文件 + `references/events/` 6 篇（webshell / cryptomining / ransomware / web-defacement / ddos / data-leak）+ `book/` 出题方教材全文 16 文件 |
| `vulnclaw/platforms/` | 平台适配层：base/normalize/refs/registry/render/submit_guard/ctf2/gcs/tools/bootstrap |
| `vulnclaw/utils/` | `atomic_write.py`、`http_client.py`、`subprocess_text.py`（本轮新增的三个共享模块） |
| `vulnclaw/agent/tool_registry.py` | 能力卡：25 个工具条目（含 16 个 IR 工具）+ 意图门 |
| `scripts/run_watchdog.py` | 活性看门狗 |
| `scripts/verify_execution_boundary.py` | spawn 站点 allowlist（key = `file:scope:call:invariant`） |
| `.ir-tools/`（gitignored） | IR 工具箱 30+ 工具，1 GB；移动硬盘副本 `G:\tool\ir-toolkit` |
| `G:\tool\archive\tsecbench-2026-09-13` | tsec_bench 归档（57 文件，SHA256 校验通过） |
| `ir-collection/`（gitignored） | `remote_collect` 采集落地（35 文件） |
| `~/.vulnclaw/` | 真实运行状态：`runs/` `targets/` `sessions/` `kb/` `config.yaml` |
| `.test-tmp/`（gitignored） | 测试沙箱。⚠️ 里面的东西**不进版本库也不可靠**，别把交接材料放这里 |

---

## 8. 我建议的下一步顺序

1. **push 19 个提交** —— 唯一真实单点风险，其余最坏只是少点便利
2. 删 `tsec_bench/`（已归档验证过）
3. （可选）修 §5.1 的 MCP 代理遗漏 —— 15 分钟的事
4. 赛前一天：定 §3.2 的三项（出站白名单、权限模式、Go）

⚠️ **一致性提醒**：`.test-tmp/` 里的东西**随时会消失**（你上次清理就删掉了 HANDOFF）。
需要长期保留的材料一律放 `IR-RUNBOOK.md` 或仓库内其他已跟踪文件。
