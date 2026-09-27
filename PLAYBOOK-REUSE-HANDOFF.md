# 笔记复用链 — 交接文档

**给接手的会话**：这份文档是自包含的。你**看不到**写它那轮的对话，所以下面把背景、
已完成的改动、待办事项、验收标准、以及踩过的坑都写全了。请先读完「0. 一分钟摘要」
和「5. 纪律与陷阱」再动代码。

- 文档位置：仓库根目录（`docs/` 被 .gitignore 忽略，所以不放那里）
- 写于：2026-09-23 夜
- **本文档对应的代码 HEAD：`a300d4f`**（文档本身随后作为 `d655e79` 提交；从 `a300d4f` 或更新的
  HEAD 起步都可以，用 `git log --oneline -8` 自己确认）
- 全量测试基线：**3885 passed / 20 skipped**（`python -X utf8 -m pytest -q --ignore=tests/web`，约 6-8 分钟）
- ~~⚠️ 仓库根目录的 `HANDOFF.md` 属于**另一个并发会话**（有未提交改动），**不要动它**~~
  —— **已删除（2026-09-25，作者决定）**：那份交接文档的内容与数字已过期（审计 D2：称领先
  `origin/main` 29 提交，实际 7；"工作区干净"与自身未提交矛盾），删除即 D2 的处理方式。
  本文档自身的数字同样以"写于 2026-09-23 夜"为准，引用前先 `git log` 核对 HEAD。

---

## 0. 一分钟摘要

**这套机制做什么**：把历史上解题写下的笔记，按"目标指纹 / 题目类别"检索出来，自动注入
solve 的系统提示，让新题复用旧经验。

**这轮做了什么**：给它加了两个查询键、命中日志、手工笔记名额预约、漏洞类判别。

**下一步要做什么（本文档的正题）**：

1. **把"开局用题名查一次"改成"开局召回 + 首次探测后用实测页面特征重查并替换简报"**；
2. **给"仅框架命中"加门槛（至少 2 个不同 token 重叠）**，消灭"单 token 查询满分命中"。

**为什么做这两件**：`Playbook.score` 是词袋重合率，衡量的是**召回**不是**相关性**。
实测：查询只有 1 个 token（`"Weblogic"`）时，任何 Weblogic 笔记都得满分 1.0，命中率
4/4 但其中**没有相关性信息**。这两条改动是当前性价比最高的准确度改进。

---

## 1. 背景：这套链现在长什么样

### 1.1 数据与文件

笔记（playbook）= `~/.vulnclaw/playbooks/<slug>.md`，带回填式 frontmatter：

```
---
name: <人类可读名，常含框架与漏洞类，如 "Weblogic CVE-2017-10271 (wls-wsat XMLDecoder RCE)">
fingerprint: <自由文本查询键，可能是模型写的手法描述，也可能只是目标串>
status: validated | draft
source: curated | auto          # 本轮新增
updated_at: <ISO>
---
<body: 模型写的 LOCK / CONFIRMED / ANGLES 等>
```

- `source: auto` —— `capture_run_notes()` 自动落的笔记（名字固定以 `AutoNotes` 开头）
- `source: curated` —— 模型主动调 `save_playbook` 写的技术笔记
- **旧库兼容**：没有 `source` 字段的按名字前缀 `AutoNotes` 判为 auto（实测真实库 4 自动 / 4 手工，判定全对）

### 1.2 代码地图

全部在 `vulnclaw/agent/playbook.py` 与 `vulnclaw/agent/solver.py`：

| 位置 | 作用 |
|---|---|
| `playbook._tokenize` | 分词：小写、按非字母数字切、去停用词、**丢纯数字与长度<2 的 token** |
| `playbook.Playbook.score` | **查询 token 被笔记包含的比例**（不是 Jaccard，短查询更容易满分） |
| `playbook.lookup_playbook(fp, limit, min_score)` | 单键检索，返回行含 `name/slug/status/source/score/fingerprint/steps` |
| `playbook.challenge_class_signature(goal)` | 抽取"题目种类"身份：方括号标签 + CVE + category/difficulty + 引号题名 + **漏洞类** |
| `playbook.vulnerability_classes(text)` | 闭集词表抽漏洞类（纯字符串匹配，无模型调用） |
| `playbook._VULN_CLASS_PATTERNS` | 词表本体（ssrf/deserialization/sqli/rce/xxe/file_read/upload/ssti/auth_bypass/steganography/crypto/reverse/pwn，含中文标签） |
| `playbook._LOOKUP_SCAN_LIMIT = 50` | 逐键取候选的上限，**必须大于调用方 limit**（见陷阱 5.7） |
| `playbook.lookup_playbook_multi(queries, limit, min_score)` | 多键查询、按 slug 合并保留最高分、标注 `query_kind` / `vuln_classes` / `vuln_class_agrees`，排序 = 类一致 > 分数 > validated |
| `playbook._reserve_curated_representation(rows, limit)` | curated 预约：前 limit 条一条手工笔记都没有时，最后一格让给分最高的手工笔记 |
| `playbook.save_playbook(..., source=)` | 落盘，写 `source` 进 frontmatter |
| `playbook.capture_run_notes(...)` | 自动笔记，写 `source=auto` |
| `solver._inject_prior_playbooks(origin, goal, runtime, stream_sink, emit)` | **注入入口**，返回命中数；设置 `runtime.prior_playbook_brief`；发 `playbook_injected` 事件 + 操作者 notice |
| `solver._system_prompt` | 每轮读 `runtime.prior_playbook_brief` 拼进提示词 |
| `solver._notify_operator(stream_sink, msg)` | 打到操作者可见的 console（`stream_sink.on_notice`） |

**调用点**：`solver._solve_impl` 内，进入主循环之前（搜 `_inject_prior_playbooks`），包在
`try/except` 里，失败静默。**目前整轮只调用一次。**

### 1.3 注入到提示词的文本（当前措辞，别改弱）

`runtime.prior_playbook_brief` 大致长这样：

```
# Prior-run notes (auto-matched: this target, or the same challenge class)
[playbook] N match(es):
- ✅ validated score=… :: <name>
  steps: <笔记正文>
How to use these notes:
- The challenge's OWN stated vulnerability class wins. A note matched by challenge
  class is a SIBLING challenge, not this one: <带上了 2026-09-23 那次被带偏的实例>
- Before adopting a sibling note's path, VERIFY its stated premise on THIS target
  (hit the endpoint it names, confirm the version/route it relies on). If the premise
  does not hold on this instance, discard that path and attack the vulnerability the
  challenge actually asks for.
- Replay only steps you have confirmed still apply. Flag values are fingerprinted …
```

**这三条约束是"把相关性判断交给模型"的关键**，改动时不要删；测试
`tests/agent/test_playbook_vuln_class.py::test_injection_wording_puts_the_challenge_class_first`
会盯住它。

---

## 2. 这轮已完成（含提交号）

| 提交 | 内容 |
|---|---|
| `0752308` | 模型面向消融开关（`session.reasoning_graph_enabled` / `tool_card_enabled`）+ `python_execute` 载荷脚本改落运行 scratch 目录 |
| `fe30522` | 平台开出的靶机域名登记进运行作用域（修"整轮白跑"） |
| `84e921a` | 主 solve 提示词补"同一条消息里的多个工具调用会并发执行" |
| `854818a` | 笔记复用加 class 键 + 命中条目与分数打进运行日志 |
| `36f664f` | curated 预约（自动笔记不得挤掉手工笔记） |
| `a300d4f` | **漏洞类判别 + "本题漏洞类优先"的使用约束**（本次交接的直接前置） |

对应的测试文件（改动时都要跑）：

- `tests/agent/test_playbook_class_reuse.py`
- `tests/agent/test_playbook_curated_priority.py`
- `tests/agent/test_playbook_vuln_class.py`
- `tests/agent/test_playbook_auto_reuse.py`
- `tests/agent/test_model_ablation_knobs.py`
- `tests/agent/test_prompt_tool_batching.py`

---

## 3. 待办（本文档的正题）

### 任务 1：探测后用**实测特征**重查并替换简报

**现状**：开局的查询是题名（`challenge_class_signature(goal)`），信息量极低 —— 真实写法
`([Weblogic]SSRF)` 下签名只有 `'Weblogic'`（+ 漏洞类后为 `'Weblogic ssrf'`）。整轮不会
再评估，只有模型自己去调 `lookup_playbook` 工具才可能更新。

**要做的**：

1. 在**首次拿到真实响应之后**（建议触发条件：第一次出现带 HTTP 响应/页面标题的工具结果，
   或黑板收到第一条 CONFIRMED 事实/LOCK）**再查一次**，查询串用**实测特征**：
   - 页面标题、`Server` / `X-Powered-By` 头、响应里出现的路径与非通用参数名、表单字段名。
   - **可直接复用现成 helper**（`vulnclaw/agent/builtin_tools.py`）：
     `_extract_html_title(body)`、`_extract_endpoints(raw)`、`_extract_html_surfaces(raw)`、
     `_http_body_signals(body, limit)`、`_source_signal_lines(source)`。
     不要另写一套抽取逻辑（这个仓库有"唯一来源"纪律）。
2. 用新查询跑 `lookup_playbook_multi`，**若结果与当前注入的不同**（条目集合或最高分变化
   超过阈值），**替换** `runtime.prior_playbook_brief`，并：
   - `emit("playbook_refreshed", {"hits": [...]})`（与 `playbook_injected` 同结构）；
   - `_notify_operator(stream_sink, "[playbook] refreshed: <slug> score=… (<key>) …")`，
     让"换条目"这件事在运行日志里可见 —— 这是验收的关键证据。
3. **约束**：最多重查 N 次（建议 1-2 次）；只在**特征确实变化**时换（否则白白抖动提示词）；
   简报总长要有上限；任何异常都不得中断 solve（沿用现有 try/except 风格）。
4. **不要**为了重查而阻塞首轮请求：首次探测前照旧用开局签名注入（召回兜底）。

**验收**：
- 新建测试：给定伪造的"首次探测结果"（含 title/header/path），断言重查发生过、简报被替换、
  事件与 notice 都带了新条目；
- 断言"特征没变时不替换"（避免每次探测都抖动提示词）；
- 断言异常/空结果时保留旧简报。

### 任务 2：给"仅框架命中"加门槛

**现状**：单 token 查询对同框架任何笔记都是 1.0 分（实测）。查询至少要 2 个不同 token 与
**笔记**重叠，才算一次 class 级命中。

**要做的**：

- 在 `lookup_playbook_multi` 里对 `query_kind == "class"` 的命中加最小重叠门槛（建议 2）；
  实现上可以在 `lookup_playbook` 返回行里带上重叠 token 数（或新增一个内部函数返回
  `(score, overlap_tokens)`），**不要**用 `score` 反推（分数受查询长度影响）。
- 门槛只在"查询是短签名"时生效还是普遍生效，由你判断，但**必须在测试里写清所选语义**。
- **注意召回代价**：门槛会砍掉一部分命中，这是有意的；但要在日志里能看出"被门槛挡掉了
  哪些"，否则以后没人知道为什么某题没有注入。建议 notice 里输出被挡条目与重叠数。

**验收**：
- 回归测试：`"Weblogic"` 单词查询**不得**对同框架笔记判为 class 命中；
- 测试：2 token 以上重叠仍正常命中；
- 测试：被挡条目在 notice/事件里可见。

---

## 4. 怎么测（协议与工具）

### 4.1 协议（照这个来，别自己发明）

- **配对设计**：同一道题跑两次 —— `cold`（配置目录空笔记） vs `warm`（只放**手工技术笔记**，
  不放自动笔记，这样任何注入都必然来自跨题迁移）。每臂**各开一台新靶机**。
- **样本量**：**至少 3 组配对**（6 次运行），并且报告**每组**的差值，不要只报聚合 —— 这轮
  实测 4 组里 1 组反而变慢（+23%），聚合会掩盖它。
- **必须记录的字段**（每臂）：
  - `[playbook] injected/refreshed …` 行（slug、score、哪个键、是否 CLASS MISMATCH）
  - 步数（日志里 `Thinking...` 出现次数）、工具调用数（`→ 调用工具:` 行数）、墙钟秒数、是否解出
  - **采纳代理**（新增，务必做）：笔记里出现的特征词（路径、手法名）在该次运行日志里的
    出现次数。用来把"命中"和"被采用"分成两个数字。
- **统计自觉**：**同代码不同次运行的方差可以到 33%-100%**（实测：同一份代码只改两个开关的
  三个臂给出 60/74/80 次工具调用、3/3 vs 2/3）。所以 n=3 只能给信号，**不能下结论**；
  文档/汇报里必须写明这一点。

### 4.2 实验工装（**已耐久化，优先用这些**）

`.test-tmp/` 被 gitignore，且 **pytest 的 conftest 会清理其中超过 12 小时的顶层条目**，
所以关键脚本已拷到 **`scripts/ab/`（已入库）**，用法与约束见 `scripts/ab/README.md`：

- `scripts/ab/cold_warm_pair.py` —— 冷/热配对运行器（开靶机、跑 solve、释放、写结果 JSON）
- `scripts/ab/negative_control.py` —— 反向对照（同框架不同漏洞类）
- `scripts/ab/parse_run_logs.py` —— 日志解析（命中行、步数、工具数、逐组差值）

`.test-tmp/` 里还有（**可能会被清掉，需要就先拷走**）：`run_ab.py` / `run_ab_agent.py` /
`run_ablation.py` / `measure_ablation_static.py` / `analyse_ab*.py` / `attribute_steps.py`，
以及结果 JSON（`ab-*.json` / `class-*.json` / `rate-*.json` / `neg-*.json`）与日志目录
（`ab-logs/`、`ab-agent-logs/`、`ablation-logs/`、`class-logs/`、`rate-logs/`、`neg-logs/`）。
历史日志（很有参考价值，尤其 `neg-logs/WeblogicSSRF-*.log` 那次被带偏的现场）建议先拷到
`scripts/ab/` 之外一个你自己的目录。若已被清理，可按 `scripts/ab/` 的脚本重跑复现。

对照用的两棵代码树与隔离配置目录在仓库**之外**（`D:\GitClone\VulnClaw\` 下）：
`vc-baseline-0919`（09-19 版整棵树，用 `git archive` 导出）、`ab-config-A/B/B1/B2/WARM/COLD`。

### 4.3 平台与凭据的硬约束（踩过）

- CTF2 凭据只有**浏览器登录态换来的 session JWT**（`vulnclaw.ctf_platform.client.session_token()`，
  会去读本地 Edge/Chrome profile）。**没有 Open API key**，所以不要写到需要
  `X-CTF2-API-Key` 的路径上。
- **并发靶机上限 3 台**；`start_environment` 是**异步排队**（返回 `task_id`，要轮询
  `get_target` 到 `running`）；短时间连开会被 **429 RATE_LIMIT_EXCEEDED**（要退避重试）。
- **靶机用完必须 `stop_target` 释放**；收尾时用 `get_target` 确认返回 `null`。
- **提交 flag 会撞平台验证码**（HTTP 429 `risk_action='challenge'`），所以"提交成功"通常
  拿不到；不要把它当判据，用"是否从靶机内部读到动态 `CTF2{uuid}`" + 你自己的核验。
- 容器题的 flag 是**按实例动态**的，且要在 `stop` 之前提交；实例有效期约 1 小时。
- 落点主机已对 `E:\vulnclaw\` 加了杀软排除（用户做的）。在此之前，杀软会把生成的 JSP
  webshell 载荷按启发式隔离（实测 6 条 `HEUR:Backdoor/JSP.WebShell.a`），删掉"写完还没执行"
  的脚本，导致运行花几回合自诊断 `python_execute` 是不是坏了。若又看到这类现象，先查
  `C:\ProgramData\Huorong\Sysdiag\log.db`（SQLite，表 `HrLogV3_60`，`detail` JSON 里有
  `recname`/`pathname`/`p_cmdline`）与 `Quarantine/`，不要凭猜。

### 4.4 选题

`2de971ac-26fe-448a-8719-01829e52c1d5` 是 BUUCTF 练习场（278 题，全部要容器、无附件）。
同类兄弟题好用的有：ThinkPHP（`5.0.23-Rce` / `5-Rce` / `2-Rce` / `IN SQL INJECTION`）、
Weblogic（`CVE-2017-10271` / `CVE-2018-2628` / `Weak Password` / `SSRF`）、struts2（s2-001/005/007/008/013/045）。

**做反向对照时一定要带上 `[Weblogic]SSRF`**（题 id `5fcc745e-4272-45cd-9f8f-435870e88199`）：
它当初就是暴露"同框架不同漏洞类被误注入"的那道题。

---

## 5. 纪律与陷阱

### 5.1 表述纪律（这轮反复吃过亏）

- **先量后说**。这轮至少三次"先把机制讲圆再去测，结果与讲的不一样"：① 说"确定性命中永不
  触发"（实测旧键照样命中，撤回）；② 说"class 键会提高命中率"（实测 0.727 vs 0.727）；
  ③ 说"关掉推理图能提速"（实测更慢，B2 还丢题）。
- 汇报时把 **[实测]** 与 **[推断]** 分开，**主动写出没做/没验的部分**。
- 已知的、**不要重复走**的结论：
  - 推理图/能力卡**不是**效率损失来源（消融后更慢：利用调用 29→41→68）；
  - "当前版本比 09-19 慢 2.3 倍"**不成立**（同代码方差同量级），已撤回；
  - 同代码不同次运行方差 33%-100%，n=1 的任何对比都不足以下结论。

### 5.2 这个仓库的既有不变量（别破坏）

- flag 必须**脱敏后再落盘**（`_fingerprint_flags`，`>8` 个则 `first4…last4`）。改 `playbook.py`
  时不要把明文 flag 写回去。
- `_ALWAYS_KEEP_TOOLS` 与平台核心工具：平台工具必须能存活 schema 裁剪。
- 审计类字段（`source`、`vuln_classes`）要"沉默不算矛盾"：没声明的不要当成反对证据。
- **唯一来源**纪律：抽取/解析逻辑复用已有 helper，别再写第二份（这仓库有前车之鉴：
  flag 正则副本漂移、`_ALWAYS_KEEP_TOOLS` 手写清单漂移）。

### 5.3 PowerShell / Windows

- `echo` 在 pwsh 里是 `Write-Output` 别名，**裸 `echo` 会报缺少参数**；用 `""` 或写完整 cmdlet。
- **不要**给 python 命令加 `2>&1`：一旦 MCP/子进程往 stderr 写东西，PowerShell 会抛
  **NativeCommandError 并制造假的 exit 1**。
- 中文提交信息用 `git commit -F <文件>`；不要用 here-string 拼。
- `Get-Content` / `Measure-Object -Line` 会误读 UTF-8，**用 Python 读**。
- `git show rev:path > file` 在 PowerShell 里会写成 **UTF-16**（Python 读会报 null byte）；
  用 Python 写字节：`Path(p).write_bytes(subprocess.run([...],capture_output=True).stdout)`。
- 跑脚本时加 `-X utf8` 并设 `$env:PYTHONIOENCODING="utf-8"`，否则中文日志会乱码。
- 出题面里有 6 个文件带 UTF-8 BOM，`ast.parse` 需要 `encoding="utf-8-sig"`。

### 5.4 模型常犯的两个环境错误（摩擦点，可顺手治）

- 在 Windows 上爱用 Unix 管道：`curl ... | head -40` → `CommandNotFoundException`，白费一步
  （实测出现在 `[ThinkPHP]2-Rce` 那次）。可考虑在提示词或命令分类器里提示"当前 shell 是
  PowerShell"。
- 用 `requests` 时若目标自签证书，记得 `verify=False`（`python_execute` 的 preamble 已经处理）。

### 5.5 这仓库的协作状态

**有另一个会话在并发提交**。所以：

- ~~不要动 `HANDOFF.md`~~（该文件已于 2026-09-25 删除，见文首说明）；
- 提交前先 `git status`，只 `git add` 你自己的文件；
- 改动 `exec_gate.py` / 边界扫描器 allowlist / `command_classifier.py` 前，先看那是不是它的
  地盘（`scripts/verify_execution_boundary.py` 的 key 与调用点强耦合）。
- 执行边界扫描器：改完跑 `python scripts/verify_execution_boundary.py`，应为
  `27 spawn site(s), all inside the reviewed allowlist`。

### 5.6 测试与提交习惯

- 全量：`python -X utf8 -m pytest -q --ignore=tests/web`（6-8 分钟）。
- 中文提交信息用 `-F <文件>`，正文写清：实测证据、改了什么、**已知局限**、测试计数变化。
- 数字要**数准**再写（这轮把 9 个测试写成 10 个、把 3873 写成 3874，都被自己抓到过）。

### 5.7 本次改动里踩过的两个自伤 bug（同类陷阱还在附近）

1. **逐键查询时就按 `limit` 截断**，导致手工笔记在 curated 预约规则看到它之前就被丢掉 →
   改为逐键多取候选（`_LOOKUP_SCAN_LIMIT=50`）、合并排序后再预约、最后才按 limit 截断。
2. **预约函数在"库里只有自动笔记"时返回了未截断的全表**（`limit=2` 回了 3 条）→ 所有返回
   路径都必须遵守 `limit`。

改 `lookup_playbook_multi` / `_reserve_curated_representation` 时，**先把这两条当回归测试
写上**。

---

## 6. 完成标准（Definition of Done）

1. 任务 1、任务 2 各有测试覆盖（含上面点名的回归用例），全量测试绿；
2. 运行日志里能直接看到：注入了什么、分数、哪个键、是否 CLASS MISMATCH、**是否被重查替换**、
   以及被门槛挡掉的条目；
3. 至少 3 组冷/热配对的实测数据，**逐组**列出：命中条目、采纳代理、步数/工具/时长变化；
4. 一份诚实的结论段落：**哪些是实测、哪些是推断**；明确写出 `score` 度量的是召回而非相关性，
   以及 n=3 不足以下结论；
5. 提交信息里写清已知局限。
