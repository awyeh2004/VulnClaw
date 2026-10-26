# 技术债清单

> 记录**已知但暂不修**的结构性问题。每条都带实测数字与"为什么暂不修"。
> 建立于 2026-10-10（赛前一天）。数字取自当日 `git ls-files` 全量实测，口径：**全部跟踪文件**。
>
> 纪律：本文件只**记录**，不代表已排期。修之前先复核数字——仓库在动，行数会漂。
> **已修完的条目在提交时从这里删掉**（git 历史里查得到），本文件只留未做的。

---

## 2026-10-24 1024 快闪赛暴露的缺陷（已修，待提交）

赛前 HEAD 的提交窗口功能有四处在实战里失效或差点失效。全部已修 + 有回归测试
（`tests/ctf_platform/test_submit_hold.py`，419 项相关套件通过）；**尚未提交**。

### 1. 调度线程从未启动（最严重）

`_start_submit_scheduler` 只构造了 `SubmitScheduler`，**没调 `.start()`**。队列看着
已排队（item 有未来的 `fire_at`），实际没有线程 tick：19:10:24 与 19:24:00 两次
都没开火。当晚卡点题是 19:24:35 手工补发的（仍在 19:24:00–19:24:59 带内，拿满分）。
测试 `test_the_factory_spawns_a_ticking_thread` 已做变异验证（去掉 `.start()`
必红）。工作区的另一版实现（带持久化/文件锁）已有 `.start()`，HEAD 没有。

### 2. 卡点窗口的 0.8s 提前量把请求送出带外

`_lead_for` 对非首血窗口返回 `_FIRE_LEAD_SECONDS`（0.8s），与它自己的 docstring
矛盾：19:24:00 的卡点会 19:23:59.2 发出，落在带外只算一半。改为 0.0（准点发，
调用本身的准备耗时已让它晚几百毫秒，60s 带宽足够吸收）。首血仍 0.3s。

### 3. 队列无法按题筛选

`should_hold()` 是全局的：配了窗口就**所有题**都压到窗口，而现场要求是"只有卡点题
等 19:24，其余解出即发"。新增 `submit_window_challenges`（env
`VULNCLAW_COMPETITION__SUBMIT_WINDOW_CHALLENGES`）+ `SubmitHoldQueue.covers()`；
不在名单里的提交直接放行。

### 4. 队列没法被"死掉的上一个 run"接手

调度器只在**本进程自己**提交时才启动，而 run 通常交完就退出（实测每题 2 分钟），
于是落盘的 flag 没有线程去发。新增 `_ensure_held_scheduler()`：任何一次 MCP
`call_tool` 都会补启一次调度器（每进程一次）。这同时是 AGENTS.md 里"队列落盘，
run 退出了也照样发"承诺的实现缺口。

### 5. `queued` 文案被渲染层吞掉（模型以为提交失败）

`builtin_tools` 对 `ok:true` 但没有 `content` 的结果返回 `[tool:x] completed`，
把 `queued/fire_at/message` 全丢了。模型只看到 45 字节的 "completed"，于是一路
重试、还投了一条 `DASCTF{deliberately_wrong_probe_0}` 的探针进队列。改为回落到
`message`。

---

## 2026-10-19 交接：待办清单

按优先级排列。每条都写清了"为什么还没做"和"先决条件"，避免下一个人重复调查。

### A. 8 条模板句笔记的**写入端**根因（检索端已修）

**现状**：检索端已修（challenge id + 长哈希保留，520 条笔记 token 集零碰撞，
自召回@3 88.3% → 98.7%）。但**写入端仍会产出同形指纹**：当 goal 不含题目名时
（如裸的 `capture the flag 解出附件 flag（misc forensics 取证 incident response）`），
`capture_run_notes` 存下的键仍没有判别力。

**已验证失败的两条路，别再试**：

1. **按正文稀有度拓宽**：从笔记 body 里挑"全库最稀有"的词补进 fingerprint。
   实测挑出的是 `ai` / `accepted` / `acts` 这类散文里的通用英文，不是题目需要的手法。
   → "稀有"不等于"重要"。
2. **用平台元数据补**：让 `_platform_identity_hint` 把题名/类别/附件名补进键。
   在 ctf2 ref 已有 challenge uuid 之后这个分支是**死代码**（id 本身已具判别力），
   而对手工构造的 goal 又拿不到 hint。

**2026-10-24 已落结构化身份（待提交）**：frontmatter 新增 `identity_version` /
`target_ref` / `target_hash`（ctf2 完整引用 + sha256[:16]），capture 自动填、
lookup 在 token 打分之外做**精确引用提权**（同 ref ⇒ 分数地板 0.6，先于 min_score
过滤）。旧笔记无字段按 version 0 加载、召回不变（迁移即兼容）。回归
`tests/agent/test_playbook_identity_fields.py`（10 例：往返/旧笔记迁移/同形指纹
tie-break/零 token 重叠仍召回/错误引用不提权/capture 落盘）。

**残余**：`attachment_sha256[]`、`source_snapshot_id` 尚未作为身份字段存储
（下载侧 sha256 已产出（见 G），字段化待下一轮）；goal 不含平台引用且非 ctf2 的
run（手工 web 题）仍只有 token 身份。

### B. stall guard 在模型仍在收敛时交还 run

**实测**（2026-10-19，robomunication，16 步 / 116 次工具调用）：第 10–16 步仍在
逼近（元素边界修正 → 逐 10 ms 频率 → 字典覆盖率 1.00），但因为没有新的"已裁决
角度"，`path_stall_streak` 涨到 7，交还。

**根因是刻意的取舍，不是 bug**：`_path_progress_fingerprint`（`solver.py`）
**故意不把"新证据"计入进展**。依据记录在 `tests/agent/test_path_stall_guard.py`
开头：一个跑偏的 run 每小时产出 53 次工具结果、大量证据却毫无进展。想改之前先读
那段注释。

**可能的出路**（都需实测，不能拍脑袋）：给"证据在收敛"一个可判定的形状
（例如连续 N 轮的可打印率/覆盖率单调上升），而不是"有新证据"这种会骗过判据的
粗糙信号。

**2026-10-24 已加观测 + replay 工具（待提交），决策未动**：solver 每轮 emit
`turn_metrics`（`_turn_text_metrics`，纯函数，有形状测试）；
`scripts/replay_turn_metrics.py` 消费两代日志（新代 turn_metrics 直读，旧代
agent_observation 降级为 proxy 并明确标注不可作测量）。**首次全量扫描
（73 个 run）**：0 个含真实 telemetry、72 个 proxy-only——proxy 的 reason 字段
多为空（ratio 序列 0/1 二值），证实假设只能等新代日志积累，**在 telemetry replay
给出证据前不许把 printable-ratio 接进任何 guard 决策**
（`_path_progress_fingerprint` 不计新证据是有实测依据的防绕过设计，别动）。
工具回归：`tests/meta/test_replay_turn_metrics.py`（3 例）。

### C. 目标范围硬门只装在 HTTP 探测族上（2026-10-16 BILISRC 实战）

**症状**：设了 target 后 `http_probe_batch` 对范围外主机 fail-closed
（`[constraint_violation] Host s1.hdslb.com is outside allowed scope`），但同一场
run 里 `python_execute` 的裸 `requests` **完全不受同一闸约束**——e005/e006 就这样
抓下 s1.hdslb.com 上的 1.9 MB JS。模型自己在 thinking 里察觉到不对称、按"严格模式"
自我收手，**但那是模型纪律，不是硬门**。

**另一面**：闸的口径是"单 target 主机"，既比授权范围窄、又比真实攻击面宽。口令
明确授权"抓含 CDN 域的公开静态 JS"时，正规工具反而拦住授权动作，只能靠 python
绕路。**模型行为不稳定**：同一口令下有的轮次绕闸把正事做完，有的轮次判"严格模式
优先"、拒绝绕过，于是核心步骤被跳过、退化为猜已知端点。

**为什么暂不修**：真正的修法是网络层收口（拦 socket），对 `python_execute` 这种
通用能力太重，且要先定策略模型（deny-list 硬拦 / 资产面 allow-list + 操作者显式
放行 / 仅告警记录）——属"改安全边界"，须单独一轮设计。

**便宜的先手——2026-10-24 已做（待提交）**：`python_execute` / `shell_command`
双闸加了 fail-closed 两层：

1. **denied_hosts/blocked_hosts 文本扫描**：约束里的 blocked 主机与
   `safety.denied_hosts` 硬黑名单（直接读 config，未装 scope 的 run 也生效），
   出现在 code/command 文本里即拒绝；CIDR 条目跳过（是地址规则不是文本标记）。
2. **动态网络目标 fail-closed**：run 带任务约束时，python 侧 AST 判定
   HTTP 客户端调用的 URL 实参——拼接/f-string/未知名/env/文件读一律拒（模块级
   常量链与 `urllib.request.Request(字面量)` 包装仍放行）；shell 侧对
   curl/wget/iwr/irm：URL 片段无字面 host、或无字面 URL 却含 `$VAR`/`$(...)`/
   反引号/`%VAR%` 一律拒，无 scheme 的字面目标（`curl host/x`）也补进 scope 检查。
   有干净字面 URL 时动态头（`-H "$AUTH"`）不误伤。无约束的本地 run 行为不变。
   回归：`tests/agent/test_dynamic_target_scope.py`（18 例）。

**2026-10-24 已补 C2-Python（待提交）**：`_egress_scope_preamble` 给 staged
载荷预置 `sys.addaudithook`——`socket.getaddrinfo` 按 allowed/blocked 全查、
`socket.connect` 查 blocked/端口（裸 IP 不做 allowed 名单比对，残余已注释），
钩子装上即不可卸载。Python 侧出站从"字符串扫描"升级为**进程内网络层拦截**
（别名/库内部/文件读的目标都过闸）。回归：
`tests/agent/test_dynamic_target_scope.py::TestPythonEgressAuditHook`（6 例，
真实子进程、违规在联网前抛出）。

**残余**：① shell 侧仍只有字符串扫描（shell 进程装不了 Python 审计钩子，
OS 级 egress 代理/WFP 才是终局）；② 直连 ctypes/winsock 绕过审计事件；
③ curl 多 URL 操作数时 `$URL` 混在干净字面 URL 旁边仍漏（取舍已注释）；
④ MCP 通用 dispatch 是否有自身 scope 门证据不足。

**同类残余（未清）**：`blocked_group_patterns` 的"不要测 <数字开头域>"仍会把 `8`
装进 blocked_ports（无害但同族；`allowed_ports` 已在 2026-10-16 用 `(?![\d.])`
前瞻修掉）。

**已测未修（2026-10-17）**：范围解析器把 **shell 变量当 host 的一部分**——
`https://www.ys7.com/order/x.html?order_id=$i` 被判
`Host www.ys7.com$i is outside allowed scope` 而误拒。修法=URL host 解析在
`$` / `{}` 处截断，或对含变量占位的 URL 报"需字面 URL"的明确提示。

### D. 中文短语被 bigram 切出假唯一词

**2026-10-24 已修（待提交）**：`_CJK_STOP`（17 个 df≥10% 模板 bigram）落地，
`_tokenize` 打分面改用 `_cjk_signal_tokens`（过滤停用 bigram），**空集兜底路径保留
未过滤的 `_cjk_tokens`**（与 ASCII unfiltered 兜底同则）。回归
`tests/agent/test_playbook_cjk_stoplist.py`（7 例）钉住：停用 bigram 不再参与打分、
"据泄"形态的模板句笔记不再注入无关题、真实目标笔记照常召回、兜底路径可用。
playbook 全套 308 通过。

**残余（跨词碎片，公开问题）**：把模板词**直接连写**（`题目提交得到`）会产生
`目提/交得` 这类跨界 bigram，不在 17 个停用词内、也无法枚举全。真实库的高频形态
是带分隔的（停用词表按实测 df 选出），连写属人为构造；彻底解仍是分词，继续挂账。

`_cjk_tokens` 用相邻两字切分，于是 `荷兰宽带数据泄露` 产生 `据泄` 这种跨词碎片，
它在全库只出现一次 → 被判为"判别力极强"。实测后果：一条 IR 排查清单
（`ir-triage-checklist-ten-drills`，0.231 分）被注入到一道路由器配置解密题里，
一模一样的注入在三次 run 中都出现。

**2026-10-24 语料实测**（599 篇笔记，445 篇含中文，12,813 个不同 bigram）：
df 最高的 bigram 全是模板套话——`提交` 22.2%、`得到` 18.0%、`题目` 16.4%、
`证据` 15.0%、`答案` 13.7%、`注意` 13.5%、`到的/包上/请包` 13%（"请在提交包上
包含…"的跨词碎片）、`记录` 12.4%、`文件` 12.2%、`字节/返回/数据/确认` ~11%。
df≥10% 的 bigram 共 **17 个**；df=1（仅单篇）的有 **8,837 个（69%）**。

**未做且别轻做**：IDF 乘法评分（2026-10-18 试过并**撤回**，别重蹈）。

### E. 新工具/新能力只验证了工具本身，尚未在真实题目里触发

**能力覆盖矩阵**（2026-10-24 整理；"结论"列的含义：没触发≠坏了，只是缺题型命中）：

| 能力 | 单测/闭环 | 本地 fixture | 真实题型命中 | 结论 |
|---|---|---|---|---|
| F5 隐写 | 嵌入→提取逐字节一致（含 JDK 24 `--add-exports`） | ✅ | ❌ | 能力在，待题 |
| pyzbar 二维码 | QR 往返一致 | ✅ | ❌ | 同上 |
| easyocr | 可识别；形近字会替换（`flag{easyocr_ok}`→`flagleasyccr_ok}`） | ✅ | ❌ | 同上 |
| cve_lookup 别名回退 | `log4shell`→CVE-2021-44228 (10.0) | ✅ | ❌ | 同上 |
| exploit_intel | KEV/nuclei + 跨 loop 并发回归（2026-10-24） | ✅ | ❌ | 代码已测，实战未验 |

**2026-10-24 已落 manifest（待提交）**：`tests/fixtures/capabilities/manifest.yaml`
（机器可读矩阵：unit_test / fixture / external_deps / closed_loop / real_hit）+
元测试 `tests/meta/test_capability_manifest.py`（引用路径存在性、pytest 节点可
收集性、QR fixture 往返）。**QR 确定性样本已入库**
（`tests/fixtures/capabilities/qr_sample.png`，payload 断言，pyzbar 缺失时 skip）。
F5/OCR 的 fixture 仍缺（需 F5.jar/JDK 与外部 PNG，manifest 里如实标注）。
1024 快闪赛 9 题一道都没碰到这几项，属题型分布，不是能力缺陷；
"未验证"列的消除仍要靠真实题型命中。

### F. 磁盘：`E:\vulnclaw\tmp` 会持续增长

**2026-10-24 复测**（口径：`os.walk` 递归全量，按顶层目录与扩展名拆分）：
共 **4,908 个文件 / 1,296,059,046 bytes（约 1.21 GiB）**。但拆开看，
**VulnClaw 自己只占约 25 MiB**（73 个 `*.events.ndjson` ≈ 0.95 MiB + 131 个
run 短名 `.log` ≈ 24.4 MiB）；大头是**别的程序借道共享 TEMP** 产生的：
`oopz` ≈ 276 MiB、`PCL` ≈ 103 MiB、6 个 ≈ 84 MiB 的安装解压目录、`VS` ≈ 36 MiB、
两个 `pip-unpack-*` 各 ≈ 33 MiB、`WinRAR.exe.WebView2` ≈ 16 MiB（.dll 484 MiB、
.exe 209 MiB、.jar 81 MiB 等）。历史快照"394 MB"（2026-10-19，28 个 events +
若干 log）口径不同且已过期，勿再引用。

**推论**：① 清理必须按"确认属于 VulnClaw 的 `*.events.ndjson` / run `.log`、
按修改时间归档后删除"做，**绝不按扩展名全局删**（`.log/.tmp/.dll` 里大量是他
程序运行时）；② `E:\vulnclaw\tmp` 是共享 TEMP，不是 VulnClaw 专属目录——
`E:` 剩 30G / `C:` 剩 25G 的压力主要来自 oopz/PCL/VS 等，归因别找错对象；
③ 顺手能安全清的只有那 ~25 MiB 旧日志，收益主要是文档不再骗人。

**2026-10-24 已执行归档（移动未删除）**：当日复测 VulnClaw 自有日志共 157 份 /
16.05 MiB，**全部 ≤6 天**（7 天窗口零合格）。按 3 天保留执行：85 份 / 9.37 MiB
移入 `E:\vulnclaw\tmp-log-archive-20261024-3d\`（可恢复），近 3 天 72 份（含
1024 正赛全部 run）保留原位，0 份被进程锁定。共享 TEMP 的大头（oopz/PCL/VS 等）
未动、也不该由仓库纪律授权去动。

### G. 大附件题会把 token 预算烧在"反复读同一份数据"上

**实测**（2026-10-21，菜刀666）：附件解出 pcap 后，run 在 19 步内用掉 **6.03 M
tokens**（上限 6 M），被 `token_budget_exceeded` 终止。161 次工具调用里绝大部分是
对同一份 2.3 MB 数据反复切片、解码、再用 `evidence_view` 读回，每次都要把长文本
重新送进上下文。

**这不是模型跑偏**：它已经定位到 `->|` + zip + `|<-` 的菜刀传输格式，方向正确，只是
单轮成本太高。

**2026-10-24 已修（待提交）**，分两半：

- **读取端**（`agent_state.py`）：`evidence_view` 单次硬上限 32,768 字符（更大
  的显式 limit 一律截断）；`limit<=0` 不再表示"全部"而是拒绝；每条 evidence
  每 run 累计读取预算 262,144 字符（`evidence_view_spend`，`reset_for_goal`
  清零），耗尽后要求改用 `evidence_search` 或脚本提炼；>128 KiB 的大证据首个
  窗口附带改用搜索/脚本的提示。原始内容仍完整保留供 `evidence_search`，证据门
  不受影响。工具 schema 文案同步更新。
- **下载端**（`platforms/attachments.py`）：流式下载设硬上限（默认 1 GiB，
  `VULNCLAW_MAX_ATTACHMENT_MB` 可调）——声明 size 超限在**联网前**拒绝，未声明
  size 的流**中途**超限即中止并丢弃；流式计算 sha256 随结果返回；平台声明的
  md5 现在**真的会校验**（此前从未校验，不匹配即丢弃重报）。

**残余**：阈值（32K/256K/128K/1GiB）是拍的工程值，需要在下一场取证题上复测
菜刀666 形态确认不再触发 `token_budget_exceeded` 且不误伤正常取证。

### H. 批量跑题时"拿到答案"必须立刻可见（操作纪律，非代码缺陷）

2026-10-21 实测教训：早先的 `batch_seq.sh` 要等整批跑完才输出，而且只 grep
`CTF2{...}`。结果 ErrorFlask 那题实际已被平台接受
（`flag{Y0u_@re_3enset1ve_4bout_deb8g}`），日志里却看不到 —— 看起来像失败，白白
多等了一轮。

现在脚本：**每道题结束立刻打一行**（exit code / accepted 标记 / 抓到的 flag / 停止
原因），同时匹配 `CTF2{...}` 与 `flag{...}`（这个平台两种都有），并排除
`CTF2{...}` 这类模板占位符。脚本在 `E:\vulnclaw\batch_seq.sh`。

原则：要长跑时**一题一个后台任务**，让 harness 在每题结束时通知，而不是自己轮询整批。

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
不是失控。

---

## 5. 非问题（记录以免后人重复怀疑）

- **`tests/` 占 24%（64,957 行）**：对 9.2 万行核心代码，测试/代码 ≈ 70%，属**健康**，不是臃肿。
  且 2026-10-19 实证：2026-09 写的 `test_playbook_overlap_gate.py` 拦下过一次错误的
  召回改动（单 token 唯一豁免会把框架词匹配放过去）——旧测试恰好是护栏。
- **`vulnclaw/skills/` 占 30%**：技能库是产品资产（内容即能力），不是代码债。
- **全量测试慢**：不是测试太多，是完全没有并行。`pytest-xdist` 已装，`-n 2` 约 3 分钟
  （**不要按核数开**：`test_ocr_vision.py` 真调 easyocr，每个 worker 各载一份 torch
  模型，`-n 8` 会把 16 GB 内存顶满 —— 2026-10-19 实测事故）。

---

## 附：本清单的来历

2026-10-10 用户问"项目是不是有点臃肿"，实测后写下。同日已完成的清理：删
`PLAYBOOK-REUSE-HANDOFF.md` / `PLAYBOOK-REUSE-RESULT.md`（642 行，通用经验提炼进
`CONTRIBUTING.md` §六，commit `d0c477a`）。

**那次是零风险的文档清理；本清单里的条目要动结构，故分开记录。**
