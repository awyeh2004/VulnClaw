# 更新日志

---

<details open>
<summary><strong>Unreleased</strong> — 第五轮审计：副驾 target 第四道来源、<code>config set</code> 的 fail-open、<code>config get</code> 的 dict 键</summary>

- **修（中）：copilot 下 `chat` 不再从粘贴里认领 target** — 前三道门（`_repl_no_auto` / `_mined_target_for_session` / `_target_after_agent_result`）只治了 REPL 的 `current_target` 变量，而 `AgentCore.chat` 另有一条**独立**认领路径（`core.py:684` 的 `target or self._detect_target(user_input)`）。实测：`VULNCLAW_REPL_NO_AUTO=1` 下同一段抹了地址的 IR 粘贴，提示词仍出现 `当前渗透测试目标: access.log`，且 `~/.vulnclaw/targets/<key>/state.json` 被重写。新增 `_copilot_pins_target()`（同一 env 门）把 `chat` 的认领也钉住——**显式传入的 target 仍生效、已设 target 保留，未设 env 时逐字节不变**。
- **修（中·fail-open）：`config set platforms.<name>.enabled false` 不再把开关打开** — 第四轮记的"`config set platforms.*` 抛 traceback"只修了一半：遍历仍用 `getattr`，而 `platforms` 是 Pydantic `extra="allow"` 模型、段名在配置里尚不存在时照样 `AttributeError`。修好遍历后新暴露更糟的一半：新建段无既有值可推断类型，`"false"` 以**字符串**落盘，而读端 `registry._config_enabled` 是 `bool(entry.get("enabled"))` —— `bool("false") == True`，**把"关掉平台工具面"反着打开**。`settings.py` 现新增 `_config_child()` / `_config_extra_allowed()` / `_coerce_scalar_literal()`，`set_config_value` 覆盖"新建 extra 段"这条路径并落布尔。
- **修（低）：`vulnclaw config get` 支持 dict/extra 键** — 原本是裸 `getattr` 链，`config get platforms.ctf2.enabled`、`mcp.servers.chrome-devtools.enabled` 直接 traceback 穿出 CLI（而 `config/schema.py:1048` 的注释恰恰推荐这些键）。新增 `settings.get_config_value()`（与 `set` 共用遍历），未知键 → 干净报错 + 退出码 2。
- **修（低）：`vulnclaw retest --verdict fixed` 的提示不再像落盘** — 第四轮第 8 条按选项 ② 收口：提示改为「已记入复测记录，未写回 findings.json」。**行为不变**（不写回是模块 docstring 声明的有意设计），只纠正表述。
- **文档** — `AUDIT-2026-10-08.md` 新增《第五轮》，含三条发现的证据、探针实测与"未改的行为（有意）"说明；本仓库根新增 [`PLAYBOOK-SHORTLIST.md`](PLAYBOOK-SHORTLIST.md)（赛前 playbook 手贴短清单，311 篇 → 精选 ~45 篇）。
- **测试** — `tests/cli/test_user_intent.py::TestCopilotPinsChatTarget` 5 例、`tests/cli/test_config_get.py` 5 例、`tests/retest/test_retest_cli.py` +2 例。`tests/cli + tests/config + tests/mcp + tests/agent` → **2150 passed / 7 skipped**。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — <code>copilot.cmd</code> 第三层：<code>COPILOT_DENY</code> 硬黑名单（日志证明）<code>fetch</code> 不在审批闸内</summary>

- **新：`copilot.cmd` 支持 `set COPILOT_DENY=<host>`** — 该主机进**硬黑名单**（`VULNCLAW_SAFETY_DENIED_HOSTS`）。起因是一次渗透副驾演练的终端日志（`E:\vulnclaw\log.txt`，5616 行）被逐条拆开：同一句"不要调用任何工具"，IR 演练 **0 次**工具调用、渗透演练 **10 次**（`blackboard_add_fact`×1 / `python_execute`×1 / `shell_command`×1 / **`fetch`×6**）。其中 `python_execute`（它想自己 curl 目标）**被审批闸弹窗拒掉** ✅、`shell_command`（在本机写马）**被人放行** ⚠️、而 **6 次 `fetch` 全部无提示通过** ❌ —— **审批闸不覆盖 `fetch`/`http_probe_batch`**，模型又会从粘贴文本里挖出主机进 allowed，所以提示词是唯一挡它的东西。硬黑名单是唯一能挡住 `fetch` 的一层。
- **坑（顺带修）**：`VULNCLAW_SAFETY_DENIED_HOSTS` 是**覆盖**语义而非追加 —— 直接用它设目标会**顶掉 `tp.qianxin.com`**（计分平台黑名单）。`copilot.cmd` 因此把 `tp.qianxin.com` 追回列表。实测：未设 → `['tp.qianxin.com']`；设 `127.0.0.1` → `['127.0.0.1', 'tp.qianxin.com']`。启动器仍为**纯 ASCII**（非 ASCII 字节数 0），`--version` 透传正常。
- **文档** — `IR-PROMPTS.md` 新增 §0.1「机制层：提示词不是唯一防线」，把上表（提示词 / auto_review / 硬黑名单三层各自的实测效果）与标准启动写法写进去。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 新增 <code>IR-PROMPTS.md</code>：现场提示词卡（四个槽 + 四种场景模板 + 八句纠偏）</summary>

- **新增 [`IR-PROMPTS.md`](IR-PROMPTS.md)：现场提示词卡** — 把散落在 runbook §五、现场卡 §2、`copilot.cmd` 横幅与彩排结论里的"消息该怎么写"收成一张照抄卡。核心是**四个槽**：① 执行点/环境（不写 → 它按 bash 给多行命令，cmd 逐行报错）② 角色+目标（不写 → 切 AUTO 自跑或答成报告）③ 范围（副驾模式下作用域闸完全失效，边界只剩这句话）④ 输出契约（"不要调用任何工具"这一句实测把 16 次工具调用压到 0 次）。另含：IR 副驾模板（含 Windows 目标变体）、渗透副驾模板（含"先抄工具清单"与"当前上下文"行）、**渗透 agent 直连**的 `--goal`/`--prompt` 写法与 `ssh -D` 隧道版、强制技能路由表（`/incident-response` 等，confidence 1.0 vs 隐式 0.11–0.2）、**八句纠偏短句**、WP 提示词、**反面清单**（"随便看看"/"帮我提交 flag"/贴答案卡/裸启动粘大段输出/在副驾里做爆破…）、以及 30 秒开场清单。
- **文档** — `IR-FIELD-CARD.md` 头部加指针。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 新 <code>VULNCLAW_REPL_NO_AUTO=1</code>：副驾模式有了机制级开关（粘贴不再把 REPL 拖进自主循环，也不再认领 target）</summary>

- **新：`VULNCLAW_REPL_NO_AUTO=1` 把 REPL 钉在单轮 chat（copilot 模式）** — 2026-10-09 彩排暴露的**代码级**根因：`_should_auto_pentest` 的末段是"只要输入里能抽出**本地路径型 target** 就直接 `return True`"（`_extract_target_from_input` + `_is_local_path_target`），而 IR 的粘贴内容里全是 `/usr/sbin/cron`、`/var/www/html/uploads`、`/tmp/.x/.kworker`，甚至一行 cron `*/3 * * * *` 都会被抽成 target `/3`（实测）⇒ **每一次粘贴都重新进 AUTO 自主循环**，抹 IP 与事后打 `chat`（要求整条输入恰好等于 `chat`/`manual`/`单轮`/`手动`，且须在 AUTO 激活后单独发送）都拦不住它自跑。修法是在函数最前面加一道 env 门 `_repl_no_auto()`：命中时**在任何分支之前** `return False`。副驾会话统一 `$env:VULNCLAW_REPL_NO_AUTO='1'; vulnclaw`；**env 未设时行为逐字节不变**。实测：同一段 IR 粘贴，未设 → `should_auto(None)=True`，设了 → `False`。
- **同一道门也关掉"从粘贴内容里认领 target"** — 第三轮彩排发现即使不进 AUTO，REPL 仍从粘贴里抽出 `/usr/sbin/cron` 当会话目标（提示符 `vulnclaw /usr/sbin/cron | Recon>`）。新增 `_mined_target_for_session()`：copilot 模式下**不挖目标**（`return None`），调用点由 `_extract_target_from_input(user_input)` 改为它（`cli/main.py` 的 target 切换/首次认领分支之前）。要指定目标时**显式**用 `target` 命令即可（flag-skill 那条路径不受影响）。实测：同一段粘贴，未设 → `mined='/3'`，设了 → `None`。
- **第三个来源（第四轮彩排暴露）：agent 回合回报的 target 也要挡** — 前两道门都生效（无 AUTO、无 Turn 计数、`Tools: none`），但提示符仍是 **`vulnclaw access.log \| Recon>`**：单轮 chat 的 `after_result()` 里原本是 `if result.target: current_target = result.target`，而 agent 会把自己从粘贴里挖到的 `access.log` / `/usr/sbin/cron` 当作 target 报回来。新增 `_target_after_agent_result(current, reported)`：copilot 模式**保持操作者的 target 不变**（`return current`），非 copilot 仍是原来的 `reported or current`（"只在 agent 报了才覆盖"）。
- **新：仓库根 [`copilot.cmd`](copilot.cmd) —— 副驾模式一行启动器** — 把三道防线钉在一个双击即用的脚本里：`VULNCLAW_REPL_NO_AUTO=1`（单轮 chat + 不认领 target）、`VULNCLAW_SAFETY_PERMISSION_MODE=auto_review`（只读免批；`python_execute` / `shell_command` 弹窗，副驾模式下直接拒 —— 提示词失效时的兜底）、以及把三条现场规则打在屏幕上（抹地址 / 模板必带"不要调用任何工具" / 提示符应为 `vulnclaw Ready>`）。参数透传（`copilot.cmd --version` → `0.3.9`，退出码 0）。
  ⚠️ **踩过的坑**：初版把中文说明写在 `.cmd` 里 —— cmd 按 GBK 读 UTF-8 无 BOM，注释与 `echo` 全被当成命令执行（`'CLAW_REPL_NO_AUTO' is not recognized` …）。**`.cmd` 一律纯 ASCII**，中文只放 `.md` 文档。实测两条 env 覆盖均生效：`VULNCLAW_SAFETY_PERMISSION_MODE` 未设 → `full_access`、设了 → `auto_review`（`load_config().safety.permission_mode`）。
- **测试** — `tests/cli/test_user_intent.py::TestReplNoAutoOptOut` 现 **9 例**：① **先钉住前提**——未设 env 时该粘贴确实触发 AUTO 且抽出的 target 是 `/3`（这条就是本特性存在的理由，防止以后有人改回默认静默失效）；② 设了 env 后粘贴/带 target/`start recon`/ctf2 平台句一律 `False`；③ truthy 拼写 `1/true/TRUE/True/yes/on/" 1 "` 全部生效；④ `""/0/false/no/off/maybe/2` 一律保持默认行为；⑤ copilot 下粘贴与普通 URL 都不再被认领为目标；⑥ 未设 env 时普通挖掘路径（URL → target、闲聊 → None）不变；⑦⑧ copilot 下 agent 回报的 `access.log` 不被采纳，未设 env 时仍按原规则采纳（`reported or current`）。`tests/cli` 全量 **458 passed**（0 failed）。
- **文档** — `IR-RUNBOOK.md` §五 彩排小节把"两条出路"改成"① 已实现（一张表说明关掉的两件事 + 启动器三层 + 第三轮实测）+ ② 兜底用法"；`IR-FIELD-CARD.md` §2 开场动作第 ③ 条改为"一律用 `copilot.cmd` 启动"（含手敲等价物与 Ctrl+C→`chat` 兜底）。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 副驾模式彩排（10/9 夜）：默认 REPL 会自己动手，四条前置纪律写进 runbook</summary>

- **文档（实测教训）** — 一次真人彩排（裸启动 `vulnclaw`，粘一段**假**的"网页终端输出"，其中含测试 IP）暴露四件在赛场算事故的行为，已写进 `IR-RUNBOOK.md` §五「主路径 = 副驾模式」下的新小节「副驾模式彩排结果」：① ⭐ **它从粘贴内容里抓出 URL 当 target 并切进 AUTO 自主模式**（提示符 `vulnclaw Ready>` → `vulnclaw http://203.0.113.7 | Ready | AUTO>`，日志 `[*] Entering autonomous pentest mode`，随后真发了三条 HTTP 探测、18.7 s 超时）——**贴原文等于把目标 IP 交给它自己去打**；② **主动去连 `remote.hosts` 里配置的三台演练容器**（victim/victim-crypto/victim-ransom，逐个 `remote_exec`）——赛前若把跳板机填进清单，它会直接 SSH 上去，正是红线"远程操控"的灰区；③ **乱调平台工具**（`platform_list` 列出 7 个 CTF2 练习场，`platform_list {"ref":"ctf2:daily"}` → `403 agent_scope_forbidden`）；④ **在笔记本上全盘搜索**（`Get-ChildItem C:\ -Recurse` → 60 s 超时 + 工具降级标记）。它给出的"命令 + 判据"（`cat -A` 看马 / `ls -laR /tmp/.x` / `grep -rIn 'flag{'`）是对的，但同时把**自己加载的技能文档内容**当成未解决的 pinned fact，与 ASK/证据闸门来回较劲两轮，最终 `Not achieved — steps=2`。
- **文档（由此定的四条前置纪律）** — ① 贴之前把输出里的 IP / URL / 域名一律抹成 `<target>`；② 粘完立刻打 `chat`（也认 `单轮`/`手动`/`exit auto`）退出 AUTO；③ `vulnclaw config set platforms.ctf2.enabled false`（必要时 `platforms.gcs.enabled false`）关掉平台工具面；④ 副驾会话用会话级 `VULNCLAW_SAFETY_PERMISSION_MODE=auto_review`（弹窗可拒），全局 `full_access` 只留给"agent 驱动打跳板机"。比赛当天另需清理 `remote.hosts`（现为三台本地演练容器）。
- **落地（同日）** — ①②已写进 `IR-RUNBOOK.md` §五 的副驾 prompt 模板（模板本体改成 `<target>` 占位 + "只输出命令、不要调用任何工具"）与 `IR-FIELD-CARD.md` §2 的开场动作；③已实际关闭并**用项目自己的加载器验证**：`platforms.ctf2.enabled=false` / `platforms.gcs.enabled=false` → `_config_enabled` 双双 `False`、`configured_adapters()` 返回 `[]`（平台工具面消失），备份 `~/.vulnclaw/config.yaml.bak-20261009-platforms`。
- **发现（未修，待你决定）** — **`vulnclaw config set` / `config get` 对 `platforms.*` 这类嵌套键会直接抛 traceback**（`set_config_value` 走 `getattr(config.platforms, 'ctf2')` 时炸，`settings.py:243`；`config get` 同因报错，`cli/main.py:3670` / `:3685`），而 `config/schema.py:1048` 的注释恰恰说 `extra="allow"` 就是为了让 `platforms.gcs.enabled: true` 生效 —— **文档指的路走不通，只能手改 YAML**。本次即手改（先备份、改完用加载器校验、失败自动回滚）。
- **第二轮彩排（同日，抹掉 IP + 模板加"不要调用任何工具"）** — 结果一半一半：✅ **工具调用 0 次**（第一轮 16 次）、✅ 平台工具不再出现、✅ 五轮都明确拒绝编造 flag、✅ 第 3 轮给出最优命令（`cp /proc/9137/exe` + `/proc/9137/{cmdline,environ,fd}` + `strings` —— 对"已删除的存活进程"正解）；❌ 但 `chat` 没能退出 AUTO（识别要求整条输入**恰好等于** `chat`/`manual`/`exit auto`/`单轮`/`手动` 且在 AUTO 激活后单独发送，`cli/main.py:977-983`），且它把 target 认成了 **`/usr/sbin/cron`**。**根因（代码级）**：让它进 AUTO 的不是 IP 而是**路径** —— `_should_auto_pentest` 末段只要从输入里抽出**本地路径型 target** 就 `return True`（`cli/main.py:4651-4655`），而 IR 输出里全是 `/usr/sbin/cron`、`/var/www/html/uploads`、`/tmp/.x/.kworker` ⇒ **每次粘贴都会重新进 AUTO**，"抹 IP + 事后打 chat"只能压住它动手、压不住它自跑。⇒ 两条出路已写进 `IR-RUNBOOK.md`：①（推荐）加 env 门 `VULNCLAW_REPL_NO_AUTO=1` 让 `_should_auto_pentest` 直接 `return False`（默认零影响 + 补回归测试）；②不改代码就用"粘 → Ctrl+C → 单独发 `chat`"兜底。`IR-FIELD-CARD.md` §2 同步更正开场动作（并把"不要调用任何工具"列为必带句）。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 赛前命令更正：<code>--only-host</code> 不在 <code>solve</code> 上（文档里那条"主路径命令"会直接报错）</summary>

- **修（文档，实测发现）** — `IR-RUNBOOK.md` §五「插上网线后的 30 秒动作」与 §五 任务 prompt 模板、`IR-FIELD-CARD.md` §3 模式 B、`IR-PENTEST-CARD.md` §0 都写着 `vulnclaw solve <target> --only-host <CIDR>`，**实测直接报 `No such option: --only-host`**（`vulnclaw solve --help` 无此开关、`vulnclaw run --help` 有）。带 `--only-host` 的命令只有 **`run` / `recon` / `scan` / `network-scan` / `exploit` / `persistent` / `tui`**（`cli/main.py` 各命令签名；`solve` 与 `go` 都没有）。四处文档改为 `vulnclaw run … --only-host …` 并加实测注记。
- **顺带记下的一条边界** — 别指望把网段写进题面绕过去：核心从任务文本解析 `Only test host X` 用的正则是 `[a-z0-9.-]+`（`agent/input_analysis.py:408-414`），**`10.20.0.0/16` 会被截断成 `10.20.0.0`**（退化成单主机精确匹配，网段失效）。要在 `solve` 上带作用域，只能走 **TUI `/scope`**（存进 `session.tui_scope_only_host`，TUI 起任务时会带 `--only-host`）或 **Web 任务台**（`only_host` 字段 → `task_service` 的 `allowed_hosts`）。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 新增 <code>IR-PENTEST-CARD.md</code>（渗透段粘贴即用命令卡），补上赛前缺口 P1-4 的一半</summary>

- **新增 `IR-PENTEST-CARD.md`：渗透段现场命令卡** — 补 §五点五 **P1-4「没有可直接粘贴的短命令卡」**的渗透一半（应急一半仍待出）。设计约束就是现场约束：**每条 ≤120 字符**（网页终端可能不支持长粘贴，超长的给 base64 两步法 `echo <b64> | base64 -d > x.sh`），每条命令标**来源**（`[原生]` 攻击机必有 / `[工具库]` 平台内置工具库下载后可用、**现场照抄实际清单** / `[本机]` 只在笔记本离线用），并按"现场会不会踩"写坑（`-sS` 要 root 故一律 `-sT`、`sqlmap` 太吵先手工三连、`linpeas` 别一上来全量、mimikatz 会留日志、Windows 上 `curl` 是 alias 必须写 `curl.exe`）。章节顺序=现场顺序：§1 60 秒侦察 → §2 Web 打点（目录/`.git`/备份/注入三连/弱口令）→ §3 反弹与传文件 → §4 Linux 提权 → §5 Windows 提权与凭据 → §6 横向与隧道 → §7 本机破解 → §8 判读解码与找 flag 落点 → §9 攻击机是 Windows 的对照表 → §10 五条纪律（只碰下发靶机 / flag 本人提交 / 输出原文贴回 / 11:30 停开新题 / 留证据）。
- **文档** — `IR-RUNBOOK.md` §五点五 P1-4 标记为**渗透段已交付、应急段待出**；`IR-FIELD-CARD.md` 头部加一行指向新卡。
- **更正（同日）：P1-4 的判据本身是错的** — 该条写"IR references 里全是分面长文档，没有任何'粘贴即用'的短清单"，但**两张应急段粘贴卡早就在技能 references 里**：`incident-response/references/paste-cards-linux.md`（100 行 / 45 条命令）与 `paste-cards-windows.md`（107 行 / 40 条）—— 卡自己的开头就写着"为什么有这张卡：IR references 里全是分面长文档，而平台网页终端可能不支持长粘贴"。**教训：写缺口前先搜一遍 references。** 现在两边都齐了（应急=技能里的两张卡，渗透=`IR-PENTEST-CARD.md`），P1-4 标为已闭合；`IR-FIELD-CARD.md` 与 `IR-PENTEST-CARD.md` 各加一行互指。
- **修（技能文档）：Windows 粘贴卡最后一条 140 字符命令超标** — 原 `powershell -c "gci C:\ -Recurse … -Include *.txt,*.log,*.bak …"` 140 字符，且正是卡里自己实测过的"递归扫全盘 271 秒"陷阱。改成两条窄范围等价命令（`$env:TEMP` 与 `C:\inetpub`，用 `-R`/`-Inc`/`% FullName` 缩写），各自 **≤120 字符**。实测三张粘贴卡现在**超 120 字符的行数均为 0**。
- **补（同日）：卡里加 §0「先定执行点与 OS」** —— 初版默认"命令在 Linux 攻击机上敲"，但现场有三个执行点（**你的 Windows 笔记本** / 平台攻击机 / 跳板机，后两者 **OS 未确认**，朱禹只说不保证是 Windows）。§0 给判定表（控制台里 `uname -a` vs `ver`/`whoami`）+ **30 秒可达性判定**（`Test-NetConnection` / `curl.exe`：通 → 侦察在笔记本上由 agent 驱动、闸门有效；不通 → 控制台里人打字、闸门失效）+ **边界一句**：从笔记本发包是本机操作（默认可用），**agent SSH 登进跳板机替你操作才是红线灰区**（`remote_exec`，别当主路径）。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 10/9 赛前培训纪要（元宝纪要）并入 runbook / 作业卡：分值差异、非线性解锁、平台入口与两处待澄清</summary>

- **文档** — `IR-RUNBOOK.md` §五 表补 10/9 培训纪要里此前**没记**的赛事事实：**不同 flag 分值不同**（分诊时把分值写进状态表，按"分值 ÷ 预计耗时"排序）、**工位随机分配 + 各队伍独立环境 + 严禁跨组交流**、入口是**点【进入演练】**且规则文档**自行查阅**（官方后续另发详细说明）、**上午只开渗透场景**（应急段之前别去找 IR 题）、界面**右上角倒计时**（= 现场唯一可信时钟）；**应急场景**补 **高校网站故障背景（运维视角）/ 任务附件给拓扑与登录方式 / 初始只开放部分节点控制台权限 / 非线性解锁（高亮·灰度）/ 官方适时发提示**。
- **文档** — 同节新增「⚠️ 10/9 培训纪要带来的三点待澄清」，并写明**该纪要是腾讯会议"元宝纪要"的 AI 提炼、不是逐字稿**，三条按待确认处理：① 纪要称"本地大模型对跳板机的调用能力至关重要"，与红线"禁止远程操控 / 非有效操作视为弃赛"**表述张力** → 必须问清 **agent 经 SSH（`remote_exec`/`remote_collect`/`remote_fetch`）驱动跳板机算不算被禁的"远程操作"**，答复前主路径仍是副驾模式（同时记下 `IR-FIELD-CARD.md`"AI 辅助已确认合规"与 §五点五 P0-1"没人问过"这处**文档内部矛盾**，以群内答复为准一起改）；② 纪要演示渗透拓扑时把**攻击机**称为跳板机 → 现场确认与 IR 跳板机**是不是同一台**；③ **非线性解锁** → §九"顺序解锁 ⇒ 到点必跳"收敛为"**线性链到点必跳、非线性节点可与主链并行**"。
- **文档** — 待确认表第 8 条（账号题集）补纪要信号：**各队伍独立环境** ⇒ 队内更像"一套环境 + 多账号"，§9.3 **B 档（双线 2+2）能否用仍待现场验证**。
- **文档** — `IR-FIELD-CARD.md`：开场清单加"**进入演练 → 先读规则文档 → 下载任务附件 → 记分值 → 留意高亮/灰度 → 工位随机禁跨组**"，倒计时写成唯一可信时钟；解锁一条改为**线性/非线性两分**；合规现状加一行"**纪要口径待核**"；现场待验证表加**第 7 行**（攻击机 vs 跳板机、SSH 驱动是否属"远程操作"），第 6 行补纪要信号。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 证据维护落地：GC 终于有人调（run 收尾 + <code>vulnclaw evidence gc</code>），解绑/重排有了暴露面</summary>

- **修（缺口 1）：`EvidenceStore.collect()` 在生产代码里**没有**任何调用方 —— 孤立 blob 只增不减** — 2026-10-09 复核。实现本身一直是对的（只删「没有任何索引行引用 + 超过 grace」的 blob），缺的是**调度**和**边界**：`run_dir=None` 会落到 `CONFIG_DIR/evidence` 这个跨 run 的全局根，一次误删就是别人的证据。新增 `vulnclaw/traffic/maintenance.py`：`collect_run_evidence(run_dir)` 只作用于**显式给定的单个 run**、best-effort 永不抛、**拒绝 `run_dir=None`**；索引不存在或**有坏行**时直接返回 `[]`（引用集不完整时"无人引用"的判断不可信，宁可少删 —— blob 只是占磁盘，删错就是证据丢失）。调度点：`orchestrator` 在 `mark_run_status(..., "completed")` 的**同一分支**调用（紧邻既有的 distillation 调度），默认 24h 宽限（报告刚渲完还能读到证据），回收条数写进 run 事件 `evidence_gc`。
- **新（缺口 2）：`vulnclaw evidence` 子命令组** — 三个动作都只在显式给定的 run 目录 / findings 文件上生效：`gc [--grace-days N] [--dry-run]`（dry-run 走 `plan_run_evidence_gc`，与真删共用同一条谓词，不会各自漂移）、`unbind <finding> --snapshot …`、`reorder <finding> --handles h1,h2`。**解绑/重排默认只看不写**，`--write` 才落盘 —— 这两个动作会削弱报告的证据面 / 改变引用顺序，不该一条命令就跑掉。谓词只留一份：`EvidenceStore.stale_digests()`（`collect()` 改为复用它）；findings 读写抽到 `cli/findings_io.py`（`retest` 与 `evidence` 共用同一套定位/落盘规则，原子写）。
- **复核发现（未改代码，等拍板）** — `unbind_finding_evidence()` 的 docstring 说"即使没匹配上也 bump `evidence_version`"，实现只在真删掉绑定时才 bump（`vulnclaw/traffic/binding.py`）。CLI 因此必须自己把"没有匹配到"打出来，否则调用方从版本号看不出这次请求被考虑过。改哪边会动绑定语义，留作赛后决定。
- **测试** — `tests/traffic/test_evidence_gc_schedule.py` 12 例（无 run 上下文绝不删全局 / 无索引不删 / **坏索引不删** / 引用再老也留 / 只作用于本 run / dry-run 与真删一致 / 收尾异常不外抛 / 源码级钉子：调度点必须与 completed 分支同函数）+ `tests/cli/test_evidence_cmd.py` 9 例；连带 `tests/traffic` + `tests/cli` + `tests/retest` 实测 **615 passed**（0 failed）。
- **文档** — `docs/project-map.md` 补 `evidence` 命令与 `traffic/maintenance.py`。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 复测（A1）：<code>vulnclaw retest</code> —— 已上报的结论可以被复核，但改处置状态只有一个入口</summary>

- **新：复测工作流（A1，借鉴 ARTEX 的 `finding_retests` / `retester` 语义，不抄代码）** — 2026-10-09。此前 finding 一旦上报就是单向的：报告上写着"已验证 / 待验证"，**没有任何机制回答"打补丁之后这条还成立吗"**，处置状态也没有第二个来源能改。新增 `vulnclaw/retest/`（`store.py` 文件式会话存储、`service.py` 语义内核）、`vulnclaw retest` 子命令、`retester` 叶子角色。四条不变量照 ARTEX 的设计意图（而非它的 Go+PostgreSQL 实现）：
  ① **一个 finding 只有一条复测会话** —— 重复发起返回既有记录，不新开、不覆盖已冻结的快照；进程重启遗留的 `running` 由 `--sweep` 封成 `stopped`，**不自动重放**（对齐 ARTEX 的 orphan sweep）。
  ② **结论三选一 `reproduced` / `fixed` / `inconclusive`，只有第一轮能写结论** —— 后续追问轮只追加记录，`RetestConflictError` 拒绝覆盖第一轮结论；**只有 `completed + fixed` 才把 `lifecycle_status` 翻成 `fixed`**，`reproduced` / `inconclusive` 只留痕、不改状态。
  ③ **发起即冻结快照** —— finding 指纹 + `evidence_version` + 原任务约束（scope / methods），复测期间 finding 被改写也不改变本轮的判定依据。
  ④ **报告门槛不动** —— `is_report_included` 仍只看 `verification_status`：复测改变的是**处置状态**，不是验证状态。`retest_history` 随 finding 进 `findings.json`，`summary` 新增 `fixed` 桶（`intel/findings.py` 早已把 `fixed` 当终态，词表本就对齐）。
- **`retester` 角色**（叶子代理）—— 只读 + 探测工具面（无 `shell_command` / `python_execute` / `agent_run` / 提权），prompt 明令"不重跑原任务、不扩大 scope、不碰其他 finding"；`build_retest_brief()` 把约束、三选一结论与"最小定向复测"写进交给它的话术里。
- **CLI 默认不写回 run 目录** —— `vulnclaw retest <finding-id> --findings <findings.json|run 目录> [--verdict V] [--note …] [--constraints k=v,…]`、`--list`、`--sweep`；状态权威在复测存储里，CLI 只读已发布的 `findings.json` 定位 finding，**避免把运行产物改成另一种样子**。
- **测试** — `tests/retest/` **33 passed**（store 不变量 10 / service 语义 8 / CLI 接线 5 / 角色 5 / 报告纯增量 4，含 1 参数化）；连带 `tests/report` + `tests/cli` + `tests/config` + `tests/agent/test_roles.py` + `tests/agent/test_spawn_role_mapping.py` 实测 **731 passed**（0 failed）。
- **文档** — `docs/project-map.md` 补 `retest/` 模块表与 CLI 命令表。
- **未做（下一步）** — Web 端点（`/api/findings/{id}/retest`）与报告正文的"历次复测"段落；两者都需要一个 findings 注册表，留到 A1 第二轮。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — flag 完整性：开括号必须在真实输出里找到配对的闭括号（不许自己补 <code>}</code>）</summary>

- **完成闸新增 flag 完整性判据：开括号必须观测到闭括号** — 2026-10-09 彩排真实事故：一道六段碎片题只拼出五段，模型**自己把缺的 `}` 补上**，候选于是既匹配 flag 正则、又"看起来有证据支撑" —— 它已把那个串写进黑板，而黑板的 tool result 本身落入证据面（`_flag_token_grounded` 的 `flag in evidence_text`），**等于自己给自己担保** —— 结果被当作答案报出，**平台判错**。新增 `agent/ctf_mode.flag_completeness_issues()`，两条刻意收窄的判据：① 答案里出现已知前缀的开括号 token、而全文找不到 `}`（`_FLAG_RE` 本就要求闭括号，所以缺尾段的候选根本不会被提取 —— 缺的是"把这件事说出来"）；② 完整候选的 UUID body 末段不足 12 位（8-4-4-4-6 不可能是完整 UUID）。`_completion_gate` 在 grounding 比对**之前**用它拒绝，理由写明"尾段从未被观测到，不要自己补括号"。⚠️ 判据**不能**写成"整串必须在工具输出里逐字符出现过"：正解本身就是拼装出来的，从不在任何单次输出里完整出现 —— 这条边界写在函数注释里。**测试**：`tests/agent/test_completion_gate.py` 新增 4 例（五段拼装即使"有证据"也被拒 / 完整 UUID 仍放行 / 无闭括号的措辞 / 6 个反例证明判据收窄 + 脱敏指纹形不误伤）；`tests/agent` **1425 passed**（+1 既有环境性失败）。**文档**：`IR-RUNBOOK.md` §五"提交前自查"补"括号必须配对 + 自我接地"两条，并注明拼装是允许的。

</details>

<details open>
<summary><strong>Unreleased</strong> — CLI 报告找回本 run 证据（run_id 反查 + --run-dir）；SSH 纳入硬黑名单 + target 文件名净化统一</summary>

- **修：`vulnclaw report <session.json>` 拿不到本 run 的取证仓库，还把"证据就在那儿"误报成"证据没了"** — 2026-10-09 彩排实测（受控实验，同一个 run 各渲一次）：**A 路** `report(session)`（= CLI；`generate_report_from_file()` **不传 `run_dir`**）正文**不内联**、两条引用被写成 **"⚠ 已绑定但正文不可读取（快照已不在索引中）"**、且不产出 `evidence_bundles`；**B 路** `report(session, run_dir=…)`（agent/orchestrator 路）正文 + 响应体正常内联、bundles 正常生成。**根因比表面深一层**：`vulnclaw solve` 从前**根本没把 run 写进会话**（`session.run_id` 为空 —— 只有 subagent 那条路会生成 `run_id`），"从会话找回 run"这条链在源头就是断的。修法两层：① `orchestrator` 在注入 `agent.run_dir` 的同一处把 `run.json` 的 `run_id` 写进 `session_state.run_id`（已有值不覆盖，兼容 resume）；② 新增 `run_context.find_run_dir_by_run_id()`（best-effort：无 id / 无 root / 无匹配一律 `None`，不抛 —— 调用方是拿它**改善默认值**，不是校验 run）+ `generate_report_from_file(session_path, run_dir=None)` 先反查再渲染 + `vulnclaw report` 新增 `--run-dir`（显式优先，不被反查推翻）。**实测**：新 run 的会话 `session.run_id` == 该 run 的 `run.json.run_id`，反查命中 run 目录；单测 4 例（正文内联 / 显式优先 / 反查 best-effort / 无 run 仍能出报告且保留"不可读取"提示）。⚠️ **渗透题同样中招**，不只 IR —— §9.2 让用 `report <session.json> --pdf` 交 WP，交出去的报告会自述证据不可读。
- **撤销（同日移除）：把 IR 答案卡渲成交付物的 `vulnclaw wp`** — 2026-10-09 曾加入 `vulnclaw wp <session.json> [--out] [--template] [--pdf]`，当晚评估后**删除**：命令、`vulnclaw/report/ir_wp.py`、`tests/report/test_ir_wp.py` 一并移除（`WP` 回到 `IR-WP-TEMPLATE.md` 人肉填的路线）。**报告跳过答案卡这条设计不变**：`blackboard_record_answer` 落的 `vuln_type="ir-answer"` 卡片不能被当漏洞渲染（round-10 finding #1），对应的回归用例已迁到 `tests/report/test_report.py::test_report_body_omits_answer_cards`。
- **文档** — `IR-RUNBOOK.md` §八 补记彩排 A 半结果（105 秒 / 5-6 分 / 用时分解）并附"同日已修"表（① 的 `wp` 方案同日撤回，改回 `IR-WP-TEMPLATE.md` 人肉填），§9.2 的 15:00–15:20 出 WP 步骤回到 `IR-WP-TEMPLATE.md` 骨架 + `report --run-dir`；`IR-FIELD-CARD.md` 收工清单同步。
- **文档** — §八 再补**渗透半彩排**（CTF2 练习场真靶机 BUU LFI COURSE 1，`completed` / 1 轮 / ≈0.09M token）：记下 **session 过期时的 Open API 绕法**（题目 id 从 `~/.vulnclaw/playbooks/` 的 `ctf2:practice:<pid>:<cid>` 引用捞 → `start_environment` 起靶机 → `get_environment` 取 `access_url`（`get_target` 是 session-only，401）→ `stop_target` 释放）；**交付链实测**：`report` 出 0 findings（flag 只因 LLM 第 4 节摘要才出现，77 行）；同日渲过的 `wp` 结构化版本（148 行）所用命令**已移除**，数字仅留作复盘；**`evidence_bundles` 不生成的原因是 agent 全程没调 `traffic_bind_evidence`**（纪律问题，非代码问题）；并标注"1 轮命中不算冷解 —— playbook 3 天前就有"。§9.2 与作业卡同步为"**IR 题的 WP 走 `IR-WP-TEMPLATE.md` 人肉填**，只有评估型 run 才用 `report`"。
- **修（事后审查）：SSH 远端工具纳入硬黑名单 + `target` 派生的文件名收敛为单一规则** —— 回看 2026-10-09 那批提交（`c6929e5` 加硬黑名单、`4b4eba4` 加 SSH 邻近的证据工具，两边没互看）时发现的两处，**只读审查 → 定点修**：
  ① **`remote_exec` / `remote_collect` / `remote_fetch` 是唯一不查 `blocked_hosts` 的 egress** —— `fetch` / `traffic_repeat` / `http_probe_batch` / recon / `nmap` 全都过 `enforce_host_path_constraints`，于是 `safety.denied_hosts`（= 计分平台 `tp.qianxin.com`）在 SSH 这条路上是空的。现在在 alias→hostname 解析之后、任何工具分支之前校验，**alias 与解析出的真实主机名双写都查**；**只查 blocked 侧**——`allowed_hosts` 表达的是靶场范围，而 SSH 清单里本就可能有范围外的跳板机/堡垒机，"绝不许碰"要一路到底，"只许这些"从来没打算管清单。
  ② **由 `session.target` 派生文件名的三份拷贝走样**：`.replace("/", "_").replace(":", "_")` 链**漏了 `\`** ⇒ Windows 上路径型 target（本机 378 个会话 / 222 个 distinct target 中 **7 个**是 Windows 路径，如 `C:\Users\…\a9c4…zip`）把会话与报告写进 `SESSIONS_DIR\<名字>\Users\…` 的嵌套目录，而 `report_service.list_reports()` 的非递归 `*.md` glob **根本看不见**；Web 那份 ASCII-only 正则虽然安全，却把 `/证据` 打成一行下划线。现在统一到 `vulnclaw/utils/fs_names.py::safe_name_component()`，会话存档 / 两个报告默认名 / Web 报告**四处共用**：保留非 ASCII、盖住 `<>:"/\|?*` 与控制字符、剥掉两端点号空格、避开 Windows 保留设备名（`CON`/`NUL`/`COM1`…）、80 字符封顶。
  回归：`tests/utils/test_fs_names.py`（19 例）、`tests/agent/test_session_save_path.py`（4 例）、`tests/security/test_remote_exec.py::TestBlockedHostsCoverSsh`（5 例）、报告与 Web 各 1 例。

</details>

<details open>
<summary><strong>Unreleased</strong> — 赛前分工按 4 人定稿（runbook §9.3）+ 作业卡同步</summary>

- **文档** — `IR-RUNBOOK.md` §九 按**实际队制 4 人**定稿（该节原规则：人数一确定就把另外两档删掉，故删除"①单人 / ②双人"）：**A 档（默认）= 主链 3 人（主攻 / 记录+计时+提交核对 / 素材+WP）+ 复核线 1 人**；**B 档（备选）= 双线 2+2**（前提是现场确认"4 个账号能各做不同的题"，否则别用）。顺带修掉草案里一处**自相矛盾**：原"**统一由他人提交** flag"与同节"**一人一个账号**"冲突 —— 别人的账号里交不了你的 flag，故改为**发现者本人在自己账号上提交 + 记录员只做提交核对**（台账登记 + 锚点逐题点名），只有赛方允许共用单一账号时才回到"一人统一提交"。分诊改为 4 人并行（仍守"开赛 10 分钟内不许开打"）。新增**现场待确认第 8 条**（4 个账号的题集 / 能否共用单账号），§八 P1-8 标记关闭。`IR-FIELD-CARD.md` 同步：提交纪律加"4 人版"两条、现场待验证表加第 6 行（现场只看那一页）。

</details>

<details open>
<summary><strong>Unreleased</strong> — 证据改为 per-run 目录（写读同锚、删除跨 run 兜底读）</summary>

- **证据存储改为 per-run：写入与读取都由 run 目录锚定，读侧不再跨 run 兜底** — 此前抓包日志与固定证据落在 **process-wide** 的 `CONFIG_DIR/evidence`（可被 `VULNCLAW_EVIDENCE_DIR` 覆盖），而读侧在目标 run 目录为空时**静默兜底**到该全局树，于是「没有自己证据的 run」会把**上一个 run 的抓包**当成自己的 proof 渲染进报告 —— 同进程多 run（批量扫描 / 并发）下这条泄漏尤其致命。现在：① 写侧 `resolve_traffic_store` / `resolve_evidence_store`（`vulnclaw/traffic/paths.py`，经 `agent/builtin_tools.py` 的 `traffic_capture` / `traffic_bind` 使用）优先取 `agent.run_dir`（由 `orchestrator` 在 checkpoint 前注入 `run_context.run_dir`），落到 `<run_dir>/evidence/traffic`；② 读侧 `resolve_report_*_store` 与工具侧**共用同一 seam**，但语义是**显式 `run_dir` 即权威** —— 该 run 没有抓包就读到空，绝不再回落到 config 默认（D2）；③ `generate_report(session, output_path=..., run_dir=...)` 新增 `run_dir` 参数，把**报告落点**与**证据位置**解耦（`output_path` 只决定报告写哪；修掉「报告写到 `SESSIONS_DIR` 就再也读不到本 run 证据」的坑，D3）；④ 扫描（headless）路径与 `RunContext` 路径共用同一套 run 目录骨架，此前 `_create_run_layout` 已含 `evidence/`，现抽为公共幂等函数 `run_context.ensure_run_layout`，扫描路径在生成 run 目录后同样补齐 `evidence/`（D4）。**实测**：`tests/traffic/test_evidence_report.py` 新增 A/B 双 run **同进程** 隔离用例（B 报告不得出现 A 的 host、请求行、响应体标记与快照 id；两个 run 的响应体刻意取不同值，以免内容寻址的快照摘要撞车造成误判）、`tests/traffic/test_report_export.py` 补「显式 run_dir 不读 config 默认」「缺 run_dir 不内联邻近 run」两条、`tests/cli/test_cli_noninteractive.py` 新增「扫描产物的报告/summary 落在 agent 自己写的 run 目录、且该目录含 `evidence/`」断言；`tests/run/test_headless.py` 补 `ensure_run_layout` 骨架用例。回归 `tests/{traffic,report,run,cli}` 全绿。
- **文档** — `vulnclaw/traffic/paths.py` 模块 docstring 去掉「Until the run-directory PRD lands…」的临时说明，改为描述 per-run 权威解析（显式 `run_dir` 确定性、无跨 run 兜底；仅无 run 上下文时用 config 默认）。

</details>

<details open>
<summary><strong>Unreleased</strong> — 硬黑名单（计分平台永不可测）+ CIDR 网段作用域 + 显式出口代理（SOCKS5/HTTP）+ 现场作业卡</summary>

- **新增显式出口代理：让靶场流量走自建隧道（SOCKS5 / HTTP）** — 补上赛前 Q1 的代码级缺口：`http_client` 对私网/回环目标强制 `trust_env=False` 是**为挡系统代理**而设，却也把 `ssh -D` 建的隧道一并挡掉了。现在 `network.http_proxy`（或 `VULNCLAW_HTTP_PROXY`）可指定出口代理，target-facing 工具按 `proxy=resolve_egress_proxy(config)` 接入（`fetch`（含 TLS 重试分支）、`http_probe_batch`、`brute_force_login`、`traffic_repeat`）；**LLM 网关 / 情报 API / 远端 MCP 刻意不接入**，免得把评测与情报流量误送进靶场隧道。语义：① 显式代理对**私网目标同样生效**（这正是隧道的目的，`trust_env` 表达不了）；② **回环目标仍直连** —— 隧道对端会把 `127.0.0.1` 读成它自己；③ 强制 `trust_env=False`，实测可盖过 `HTTP_PROXY`/`ALL_PROXY`/`NO_PROXY=*`；④ 未知 scheme 直接报错（httpx 只认 http/https/socks5/socks5h，不认 socks4）。**实测**（httpx 0.28.1，`tests/utils/test_http_client_egress_proxy.py` 用进程内 SOCKS5 服务器 + 不可解析域名固化成断言）：`socks5://` 交给代理的是**主机名**（`ATYP=3`），DNS 在代理端解析 → **作用域闸仍看到真实 host**，`--only-host` / `blocked_hosts` 在隧道下继续有判别力（这是必须用 `ssh -D` 而非 `ssh -L` 的原因：`-L` 下 agent 只能请求 `127.0.0.1`，闸门失去判别力）；`socks5h://` 在 httpcore <1.0.9 是**裸 `KeyError: b'socks5h'`**（本机 1.0.2 崩、临时 venv 1.0.9 通过，报错点离代理 URL 很远）→ 统一改写成 `socks5://`（两边都是远端解析，实测行为相同，≠ curl）；缺 `socksio` 时点名 `vulnclaw[socks]` 而不是静默失败（`pyproject.toml` 新增该 extra）。
- **新增 `IR-FIELD-CARD.md`：现场作业卡（一页）** — 决赛当天用的动作清单（runbook 存判据与证据，卡只在现场用）：开场 30 分钟 checklist（含**开赛 30 分钟后禁止入场**、全程录屏 9:30–15:30）、每题的分岔判断（控制台题 → 副驾模式；VPN/直连题 → agent 驱动）、副驾四条纪律 + prompt 模板、提交纪律（链式解锁 + **提交由人做**）、收工清单、现场待验证 5 问。隧道一条按刚落地的能力写成"必须 `-D` 不能 `-L`"。
- **执行类工具的重复调用预算 30 → 10** — 2026-10-08 成本复盘：一条**已解出**的 run（`batch-1005t-01`，SETCTF，5.21M token / 117 请求 / 135 次工具调用，平均 42.9K prompt 每次）里，**11 次重复调用**（7 组重复参数，含 4 次完全相同的 `python_execute`）+ 15 次失败调用（python 12）+ 1 次空转 + 2 次被证据闸门拒掉的 FINAL ≈ **12% 的请求是纯冗余**；而执行类工具的"同结果重复"预算是 30 次，这条通道在限时比赛里太宽。改为 **10**（`_REPEAT_TOOL_LIMITS` 与 `session.repeat_tool_limits` 默认表同步，`fetch: 50` 保持不变——有状态题要反复取同一端点观察变化）。**为什么安全**：round-22 那次"整场丢掉工具"的失效来自**按调用次数**计数；现在按**结果签名**计数并在结果变化时归零，所以 10 只收紧"连续十次完全相同结果"这一种情形。回归：`tests/agent/test_tool_repeat_guard.py` 新增 `TestShippedDefaultBudget`（默认即 10 / 10 次相同结果触发 / 10 次递进结果不受影响），原 30 次递进结果回放用例保持通过。本机 `~/.vulnclaw/config.yaml` 同步：`competition.stall_turns: 8 → 6`、`session.repeat_tool_limits.python_execute/shell_command: 30 → 10`（备份 `config.yaml.bak-20261008c`）。
- **新增 `safety.denied_hosts`：任何运行都不许测的主机** — 赛前需要一条"这个 host 无论任务作用域怎么写都不能碰"的表达（决赛计分平台 `tp.qianxin.com`，通知七(三)严禁攻击竞赛平台/赛事系统/第三方服务）。此前项目只有**作用域**开关（allowed/blocked hosts + strict），没有全局禁测面，而作用域的来源有四条（CLI 参数、Web 任务 API、自然语言解析、平台交接），任一条能把它写进 `allowed_hosts` 就等于没拦。实现：`AgentCore._reset_runtime_state` 与 `apply_task_constraints` 在安装约束前调用 `_harden_constraints()` 并入 `blocked_hosts`（`TaskConstraints.add_blocked_hosts()` 去重、保序、幂等，因为约束对象在每次上下文重置时被反复加固）；`task_service.build_scope_constraints` 刻意**保持纯函数**（不读配置），否则同一份任务负载会在不同机器上产生不同作用域。`enforce_host_path_constraints` **先查 allowed 后查 blocked**，故重加进 allowed 无法翻案；匹配复用 `host_in_scope` 的域名作用域语义（`tp.qianxin.com` 覆盖其子域，`tp.qianxin.com.evil.test` / `evil-tp.qianxin.com` 不误伤）。环境变量：`VULNCLAW_SAFETY_DENIED_HOSTS`（逗号或换行分隔）。
- **`host_in_scope` 支持 CIDR，并修掉一个静默失效的私网拦截** — 赛场给出的"靶场网段"此前无法表达：裸 IP 模式是**精确匹配**，没有前缀/网段形式。现在 `10.20.0.0/16` 这类模式按网段匹配（仅当地址字面量对网段，主机名永不落入网段，不做 DNS 解析；家族不同不匹配；畸形/含斜杠的主机名模式被跳过而非吞掉整条列表）。同时修掉本地文件型任务的私网守卫：它原本写 `"10."` / `"192.168."` / `"172.16."`…，在精确匹配下**永远匹配不上**（实测 `host_in_scope("192.168.1.9", ["192.168."]) is False`），改为 CIDR 后该守卫才真正生效。
- **文档** — `IR-RUNBOOK.md` 新增"五点五、赛前缺口清单（10/10 复核用）"：把 2026-10-08 实测出的未补缺口按 P0/P1/P2 分级并附证据（AI 辅助合规未问、录屏与磁盘空间（C: 15.5 GB / D: 17.9 GB 可用）、**LLM 凭据单点：`llm.api_keys` 仅 1 条、zhipu key 已失效**（单次失败硬题实测烧 3.14M prompt + 0.16M completion tokens / 70 请求，`solve_max_model_tokens` 现值 6M）、无"可粘贴短命令卡"、`chrome-devtools` MCP 实为 placeholder 且从未下载（`_npx` 缓存为空）、`report --pdf` 缺 weasyprint 而 `python-docx` 可用、无端到端彩排、时间盒与分工未定、`remote_*` 未真机验证且 paramiko 仅 2.8.1（rsa-sha2 需 2.9+）、`uvx` 缺失、burp/ctf2 MCP placeholder）。
- **比赛策略 skill 补两条** — `competition-mode`：①**提交的例外**——赛事禁止 agent 联平台/要求人工提交时（判据：赛方明令 + 平台地址被 `safety.denied_hosts` 拉黑），只交付 flag 并给证据，不打开 `competition.allow_flag_submission`；②**名次权重（一血/二血/三血）**——速度优先于深度、先做零环境依赖题、链式解锁时一题一交付。
- **文档** — `IR-RUNBOOK.md` 第五节再补 10/9 赛前培训（朱禹）确认的赛事事实：日程（8:30 签到 / 9:30–12:00 渗透 / 12:20–15:30 应急 / 15:30 颁奖，**开赛 30 分钟后禁止入场**）、**一血/二血/三血速度权重**、平台操作路径（任务中心 → 拓扑 → 右键攻击机控制台 → 内置账号密码）、**链式解锁**、**内置工具库供下载**、现场网线（可连比赛环境与互联网）、**部分题需 VPN 登录 + 提交演练报告（WP）**、违规四条（跨组交流 / 攻击平台 / **C2 类非有效登录或远程操作** / **全程录屏 9:30–15:30**）；新增"自动化边界"表（平台与跳板机一律人操作、本机分析与 VPN 类题目 agent 可驱动）与 WP/一血两项交付物说明；待确认清单收敛为 7 项并标注朱禹的三条群内待办。
- **文档（同日更早一批）** — 补记接入形态（官方网线 → **跳板机** → 靶场）、IR 作答形式（**经跳板机远程排查 + 找隐藏 flag**）、**平台内置工具库**（本机工具退回离线/兜底；工具清单写进 `remote.hosts.<alias>.note` 供 `remote_hosts` 渲染；附任务 prompt 模板）、**题目链式解锁**（flag 必须提交但**提交由人做**，agent 只交付不提交，goal 措辞已给）、**操作入口=平台网页端右键开终端**（确认后 `remote_*` 从主路径**降级为备选**，主路径改为"人打字 + agent 出命令"的**副驾模式**，含四条纪律与 prompt 模板）、**攻击机系统未知**（现场先定性的探测表 + `remote_collect` 仅 POSIX 的硬事实）与**"隧道 / 浏览器驱动 agent"两个问题的技术结论**（跳板机一人一连的席位冲突；`http_client.py` 对私网/回环目标刻意 `trust_env=False` 导致 SOCKS 不生效、`-L` 转发下作用域闸只看到 `127.0.0.1`；`chrome-devtools` MCP 虽已启用但自动操作平台 UI 属高风险，中间路线=人粘贴、agent 只生成）；网络可达性节补充"国内实测可达，要问的是国外与公网出口"。
- **新增 IR 找 flag 落点清单** — `skills/specialized/incident-response/references/flag-landing-spots.md`：赛方材料明确"要找隐藏的 flag"后补的**解题交付卡**（五步作业顺序：内容搜 → 时间圈定 → 进程/环境 → 服务侧 → 变形解码；Linux/Windows 落点表；已删除文件、磁盘未分配区、数据库、日志、ADS；编码变形对照；常见坑与"搜不到时怎么体面收尾"）。`SKILL.md` 的"常见提问 → 检索路径"与参考文档索引各加一条；`.ir-tools/verify-ir.py` 自检 **PASS=97 FAIL=0**。
- **`remote_collect` 在 Windows 目标上给出可执行的下一步** — 攻击机/跳板机的系统不由赛方公布，而 `remote_collect` 发的是 POSIX `sh` 脚本（`#!/bin/sh` + `tar`），在 Windows 上每一步都失败、现场只看得到"no archive produced"。新增 `_windows_target_hint(stderr)`：仅当 stderr 里出现 cmd.exe 自有诊断（`is not recognized as an internal or external command` / `The system cannot find the path specified` / `was unexpected at this time`）时，才在报错后追加"目标像 Windows cmd，请改用 `remote_exec`（cmd/PowerShell 语法）+ `remote_fetch`"；POSIX 端的一般失败（`tar: not found`、`Permission denied`）不会触发，避免把操作者引到错方向。测试见 `tests/security/test_remote_collector_integrity.py::TestWindowsTargetHint`。
- **新增 OA / 产品化 Web 系统 → webshell 卡片** — `skills/specialized/web-security-advanced/references/web-oa-webshell.md`：赛题明确"获取 OA 系统漏洞并植入 webshell"后补的**渗透交付卡**（产品指纹表（泛微/致远/通达/蓝凌…，要求两条互相印证）、能出 shell 的漏洞族、上传后缀与解析差异（白名单/黑名单/多后缀/`;`/`%00`/Tomcat `;jsessionid=`）、上传目录可访问性、无回显三法（回显/时间盲/带外）、落马后取证与"按 `flag-landing-spots.md` 找 flag"顺序、7 个高频坑）。`web-security-advanced/SKILL.md` 的场景路由与参考索引、`web-pentest/SKILL.md` 的文件上传条目各加指针。
- **测试** — 新增 `tests/security/test_hard_denied_hosts.py`（13 例：合并、子域、相似域不误伤、allowed 不能翻案、重复加固幂等、无黑名单时行为不变、运行重置路径仍禁测、Web 任务约束在安装点被加固、builder 保持纯函数、env 覆盖、条目归一化）；`tests/config/test_host_scope.py` 增 CIDR 组（网段内/外、主机名不解析、畸形段、家族混用、host bits）；新增 `tests/cli/test_local_path_egress_scope.py`（私网/回环真被拦、公网不受影响、URL 目标不走本地路径分支）。全量回归 **4569 passed / 20 skipped**。

</details>

<details open>
<summary><strong>Unreleased</strong> — round-9 审查修复（平台身份查询移出事件循环 / 题名兜底 / quiz 谓词）</summary>

- **修复平台身份查询阻塞事件循环（round-9 事故）** — 无身份 goal 会向平台补查一次挑战元数据，原实现在 `async` 求解路径上直接 `pool.submit(...).result(timeout=_PLATFORM_HINT_TIMEOUT)`：worker 线程只兜住了 socket，等待仍发生在**调用线程**，而唯一生产调用者就是 solve 协程，于是每个无身份 run 都把事件循环（及同循环上的兄弟协程）卡住最多 8 秒 —— 而原 docstring 恰恰声称"worker 线程保证 inside-an-event-loop 的调用者不会 stall solve"。现将阻塞读取抽为 `_fetch_platform_identity()`，新增 `_platform_identity_hint_async()` 用 `asyncio.wait_for(asyncio.to_thread(...))` 把查询移出循环（保持有界、不抛、每 ref 每进程只查一次三条契约）；求解路径在调用注入器前解析好 `identity_hint` 传入，注入器收到 `None` 时仍回落阻塞形态——9 处同步调用点的契约不变。副作用：生产路径不再每个 ref 新建一个 `ThreadPoolExecutor`。判定条件单点化为 `_goal_is_identity_free()`，生产调用点与注入器分支共用，避免各自漂移。
- **任务句题名降级为兜底，避免挤掉对口笔记** — 平台启动句题名（`用 ctf2 工具解练习场 <pid> 的题目 <cid>：<name>。`）此前会并入**已有**类签名。以 224 条真实 goal + 真实笔记库实测（每个候选设计都跑真实 `lookup_playbook_multi`，查询列表与 `_inject_prior_playbooks` 一致 = target fingerprint + class）：并入后 11 条目标的查询结果集改变，其中 `[GeoServer] CVE-2024-36401` 丢掉对口的 `geoserver-cve-2024-36401-wfs-jxpath-rce`，被 `ir-triage-checklist-ten-drills` 顶掉——因为 `Playbook.score` 是"查询词被笔记命中的比例"，查询变长只会降分，而平台任务句原文恰好一字不差地出现在 auto 笔记里，curated 笔记因此被挤出 `limit=2`。改为**仅当签名为空时才用题名**后：那 5 条真正有价值的收益全部保留（变异凯撒→`mutated-caesar`、Quoted-printable→`quoted-printable-ctf2-crypto-easy`、丢失的MD5→`md5-lost-md5`、传感器→`sensor-manchester-ook`、一眼就解密→`base64`），已识别目标拿到的查询与改动前逐字相同，结果集结构上不可能改变（identical 208→214，churn 11→5，回归 0）；改完用已实现的代码复测得到同样的 5/0/214。
- **quiz 分支的 flag 需求判定统一为词边界** — `_completion_gate` 的 quiz 短路仍内联 `flag|getshell|shell` 子串匹配，`shell ⊂ webshell` 让「知识竞赛答题：webshell 文件路径排查…」这类 quiz 形态目标跳过 quiz 路径、落到 flag 检查，再被 "FINAL did not cite evidence ids or quote recorded evidence" 拒掉。改用与 `_implicit_flag_completion` 同一个 `_EXPLICIT_FLAG_DEMAND_RE`（实测该形态下新=放行、旧=拒绝）。
- **回归用例（+11 个节点）** — `test_playbook_goal_identity.py` 增 5 例：用"每 20ms 走一步的兄弟协程"钉住"查询期间 loop 未被占用"（**该用例第一版是无效的**：窗口写在兄弟协程体内，只会在查询结束后才开始计时，对同步阻塞也能通过；用故意同步阻塞的变体反测（期望失败）时误过才发现，窗口移到查询之前，旧实现下 tick=0）、异步形态的不抛/失败也 memo 契约、传 hint 时不得再走阻塞形态、传 `None` 时回落同步形态、`_goal_is_identity_free` 与注入器分支一致；`test_goal_wants_flag_boundary.py` 补 3 条**逐字取自真实语料**的主机型目标（`http://<hex>.http-ctf2.dasctf.com:80`，旧子串谓词靠 `ctf ⊂ ctf2` 把 362 条会话首目标里的 69 条判成"要 flag"）与 1 条 quiz+webshell 用例，把有意收窄写死，避免将来被当成 bug 改回子串匹配。
- **round-9 原改动随组提交** — 未闭合 flag 脱敏第三层 `_FLAG_UNCLOSED_RE`（覆盖 `strings` 截断等"没有 `}`"的形态；当前 293 篇库实测零误伤，`base64{...}` 类构造性误伤仍存但无真实样本）；`_CLASS_TASK_NAME_RE` 识别平台任务句题名（39 条含"题目"的真实目标命中 35 条）；`scripts/audit_playbooks.py`、`scripts/verify_playbook_migration.py` 两个只读审计脚本；`_goal_wants_flag` 词边界化（362 条会话首目标中 72 条翻转，其中 69 条为主机型目标）。
- **测试** — `tests/agent tests/platforms tests/ctf_platform`：**2067 passed / 7 skipped / 1 failed**（唯一失败为本机裸 `python` 为 Store 存根导致的 `test_bg_tasks.py::test_bg_launch_and_result_lifecycle`，改动前即固定失败；改动前基线 2056 passed，+11 即本次新增节点）。

</details>

<details>
<summary><strong>Unreleased</strong> — 语言支持（bilingual UI）</summary>

- **新增英文 / 中文双语界面** — 默认语言改为英文（无法识别环境信号时不再落到中文）。CLI/REPL 工具调用行、状态横幅、solve 报告标题、知识库状态、上下文截断提示、LLM 重试/恢复提示与推理状态块均随当前语言输出；zh 模式下输出保持逐字节不变。切换方式：REPL `/language` 命令、`VULNCLAW_LANG=zh|en` 环境变量、`session.language` 配置。
- **修复 `/language` 命令输出** — 移除确认文本前的多余 ASCII 字母 `f`。
- **Agent 英文关键词支持** — finding parser、阶段检测、CTF 判定、输入分析、认证墙、技能分发与 MCP 路由等识别表补充英文等价信号词，英文提示下子 agent 的发现分类、阶段迁移与技能注入与中文模式一致。
- **知识库状态本地化** — KB 初始化/降级/禁用详情随当前语言输出。

</details>

<details open>
<summary><strong>Unreleased</strong> — 知识竞赛（理论题）支持</summary>

- **新增知识竞赛/理论题直答能力** — solve 引擎新增知识题识别（知识竞赛/理论题/选择题/判断题等关键词 + A./B./C./D. 选项模式），命中后注入 Knowledge Quiz Mode 指令：先抓题入证据、按平台格式作答、不确定用排除法、禁止对答题平台做扫描/注入/爆破。完成闸门为知识题目标走专属分支：不再强制 FINAL 携带 flag 或引用证据词（原闸门会让"答案：A"类最终答复永久拒绝死循环），仅要求题目先抓入证据、声称的 flag 仍需证据落地。
- **新增 `knowledge-quiz` 专项 Skill** — 识别信号、六步答题工作流、分题型对策 playbook（单选否定问法/多选策略/判断题绝对化表述/填空标准术语）与网络安全法律法规高频考点基线 `cn-cybersec-law-baseline.md`（四部核心法律时间线、网安法要点、等保 2.0、应急响应 PDCERF/事件四级、国密算法、刑法涉网罪名、常见端口）。dispatcher 路由新增知识竞赛/理论题/法规名/quiz 等中英文关键词。
- **新增超纲题人工兜底策略** — 超出模型知识的题目（当年时事、比赛主题/届数、训练截止后新发布文件）不猜测：以 `🔴 超纲题` 红标标记题号/题干/选项并附资料线索（可能出处文件、检索关键词、skill reference、平台公告页），继续做完其余题目；超纲题未答时扣卷不交，全场做完后 `ASK_USER:` 请用户作答，拿到答案合并后再做唯一一次最终提交。
- **知识题防误换靶与续跑保活（CLI）** — 新增 `_should_switch_target`：粘贴题目文本中引用的 IP/域名（如"192.168.1.1 属于哪类地址"）不再触发目标切换重置会话上下文；`_should_auto_pentest` 自动模式触发词补充"答题/知识竞赛"；Ctrl+C 中断后按回车续跑时恢复 prompt 附带任务类型标记，知识题指令与闸门豁免跨中断保留。
- **更新比赛模式策略** — competition-mode 明确知识竞赛环节最先做：零环境依赖、不受靶机过载影响、答完即锁定得分，是单位时间得分率最高的题型。
- **修复存量测试失败** — `test_solver.py` 的 `_Agent` mock 补齐 `runtime` 属性（solve playbook 机制引入的回归，修复后该文件测试时长从 ~113s 降至 ~2s）；`test_tool_parallel.py` 内联返回用例载荷从 5000 字符降至预览阈值（3500）以内，保留"小结果默认内联"的测试意图。
- **知识题门禁与护栏审计修复** — 完成闸门的 quiz 短路仅在 goal 未显式要求 flag/shell 时生效（"答题拿flag"类混合目标回落到 flag 落地校验，杜绝无 flag 提前判完成）；新增 `_quiz_questions_inline` 内联题目判定（≥3 个选项标记或"（ ）"填空），题目直接粘贴在任务文本时不再要求先抓取证据（原逻辑会指向不可能执行的动作并烧尽 max_steps）；`_should_switch_target` 按目标形态切分——quiz 文本中出现的完整 URL 视为真实换靶（"改打 http://x"），裸 IP/域名诱饵维持豁免；续跑任务类型后缀改走 i18n（`cli.resume_quiz_suffix`）。
- **工具裁剪与完成路径全量审计修复** — `_infer_allowed_tools` 为知识题目标保底 web 工具束：技术型题面（含 RSA/AES/端口等词）不再把 `fetch` 从工具 schema 裁掉（原 crypto bundle 首位命中会导致 quiz 指令要求的工具不存在）；`_implicit_flag_completion` 改为仅在 goal 显式要求 flag/shell 时触发，纯答题 goal 不再被页面证据中的 flag 形态字符串隐式判完成；premature-ASK_USER 守卫对 quiz 目标豁免——quiz 页面证据（表单/输入框）必触发 near-miss 启发，原守卫会把"超纲题转交用户"的既定流程随"资料/搜索"措辞永久拦截；`_quiz_questions_inline` 补判断题格式（对/错、正确/错误）与"无 URL 即内联"兜底。
- **quiz 启发式边界收紧（第三轮审计修复）** — 内联判定去掉过宽的"无 URL 即内联"兜底：改为要求实际题干内容（问句/选项/填空/对错格式），防止 `target` 命令给 URL、goal 仅"开始答题"时不读题即通过门禁；`_QUIZ_KEYWORDS` 移除裸"答题"（"对 XX 答题系统做渗透测试"是攻击任务，quiz 判定会同时翻转门禁豁免/ASK_USER 豁免/禁攻击指令三项行为；自动模式触发词表保留"答题"）；换靶守卫的 URL 分支需伴随"改打/切换到/换成"类显式换靶动词才重置会话（题干引用"判断题：https://x 是…"不再误清上下文）；`_infer_allowed_tools` 的 quiz 分支改为模块级导入并移除裸吞异常（当前无循环导入，回归会在导入期显式暴露）。
- **quiz 门禁第五轮审计修复(续)** — A2 提示判据与 URL 判据统一为 "://" 形态(HTTP 字样不再误指可抓取页面); 单行粘贴的编号卷子恢复内联识别(编号允许行中匹配, 问号共现条件保留, F1 规则列表防护不变)。
- **速查表脱敏** — benchmark-driving 的 TSecBench API 速查表内网 IP/预检地址替换为占位符(同 commit B1 红线自查)。
- **gitignore 补充** — DataCon 一次性解题产物(brute*/test_sha*/brute_flag/poll*/scan_full/disasm/out)不再有误提交风险。
- **quiz 内联判定第四轮审计修复** — 问号不再作为题干内联信号（"知识竞赛？开始答题"是指令不是题，原判定可让未读题的 FINAL 通过门禁）；无 URL 且无结构标记的内联题面，门禁拒绝消息改为指引"向用户要题面 URL 或粘贴题目"，不再指向不可能执行的 fetch（消除烧尽 max_steps 的死循环残余）。

</details>

<details open>
<summary><strong>v0.3.8</strong> — sub-agent fan-out + cold/hot memory + context budget</summary>

- **新增模型驱动的并行子 Agent 扇出** — 默认 solve 引擎新增 `spawn_subagents` 工具，主模型可在一轮内提交多个独立、自包含的攻击方向并发探索；子循环继承目标约束与已有证据，禁用递归扇出并采用单次/并发/每次 solve 生命周期预算。子证据合并回父状态时统一重分配 `eNNN`，同步修正 claim、pin、progress signal 和 tool-call 引用；CLI 新增 fan-out 生命周期事件展示。
- **新增 TUI 子代理实时监控面板** — Textual TUI 执行任务时通过带随机会话令牌的私有 JSON 行协议接收 `spawn/start/progress/finish/batch_done` 事件，按批次实时展示每个子代理的角色、状态、步数、目标或最新进展；每次执行使用独立 `run_id`、输出队列和事件 token，旧 worker 的迟到输出、结束哨兵及定时器不会污染或提前终止新任务。普通 CLI 日志保持不变，窄终端仍可从原始日志查看事件。
- **新增冷热记忆分离** — 会话历史超过 48 条消息或 32K token 时，旧消息自动归档到冷记忆 JSONL 分片（每 64MB 轮转，最多 8 分片），热上下文仅保留近期完整工具交换组；新增 `memory_search` 工具从冷记忆按关键词检索带上下文的片段。`ContextManager` 新增 `max_tokens`/`search_max_chars` 配置，大工具输出超预算时自动归档并替换为冷记忆指针+预览。`/compact` 改用 `group_tool_exchanges` 按工具交换组原子切分，不再拆散 assistant `tool_calls` 与对应 `tool` 消息。`_trim()` 改为 token+条数双重安全网，不再直接丢弃最早消息。
- **新增统一上下文预算与结构化压缩** — `context_budget.py` 提供 `prepare_context()` 唯一预算入口，覆盖所有 LLM 调用路径（`call_llm`/`call_llm_auto`/`call_llm_stream`/`call_llm_auto_stream`/`structured_call`/team planner/adviser/report summary）。预算公式：`usable = max_context_tokens - output_reserve`，trigger=usable×0.70，target=usable×0.55；工具 schema token 计入预算。压缩时按不可拆分工具组分组、保留最近 N 组、其余生成确定性 `[context digest v1]` 摘要（含 target/scope/verified_claims/pinned_facts/evidence 引用），原子回写 `ContextManager.replace_history_with_digest`。审计事件记录前后 token/原因/组数/evidence IDs，敏感字段（authorization/cookie/api_key）自动脱敏。新增 `ContextBudget`/`ContextCompactionResult`/`ContextDigest`/`ContextCompactionEvent` 类型。配置：`context_auto_compact=true`（默认启用）、`context_compact_trigger_ratio=0.70`、`context_compact_target_ratio=0.55`、`context_recent_message_groups=12`、`context_summary_max_tokens=3500`、`context_output_reserve_tokens=0`（自动取 min(max_tokens,8192)）、`context_compaction_mode=structured`、`context_compaction_audit_enabled=true`。旧 `solve_auto_compact`/`solve_compact_trigger_ratio` 标 deprecated，未显式设置新字段时自动迁移。
- **修复子 Agent 合并边界与审计完整性** — 父状态合并子 Agent 证据及辅助历史时继续遵守各项硬容量上限并清理淘汰引用；`spawn_subagents` 作为本地调度元工具不再被误判为 scan，子会话的约束违规消息与结构化事件会完整合并；所有子 Agent 预算/容量配置拒绝零值和负数。仅当子 Agent 在进入 `child_solve`（即启动 LLM/工具）之前的工厂/种子/setup 阶段失败时才退还其生命周期预算（确定零成本）；一旦进入 `child_solve` 即计入预算，避免昂贵的后期失败悄悄回收扇出广度。`max_concurrent` 文档提示：使用 chrome-devtools/burp 等外部 stdio MCP 时应设为 1，避免并发子 Agent 共享单条 stdio 会话交错。
- **加固子 Agent 扇出安全与子进程生命周期** — `SubagentConfig` 全部数值项补上界 `le=`（`max_depth` 硬顶为 2，防止逐层预算叠乘导致扇出指数爆炸），越界的 `VULNCLAW_SUBAGENT_*` 环境变量改为拒绝并告警而非静默丢弃；修复子证据合并后 `duplicate_of` 在源证据被容量截断丢弃时残留指向子侧 id 的悬挂引用（改为清空，避免后续随 `evidence_seq` 增长误解析到无关证据）；TUI 输出日志对来自子进程的不可信内容（子代理 `goal`/`NO_PATH` 复述等）先转义再写入 `markup=True` 面板，杜绝 `[/quote]` 等未闭合标签触发 `MarkupError` 击穿 TUI，或 `[link=]`/`[red]` 注入操作员终端；子进程中断/切换/退出改为 `terminate→wait→kill` 三段式并在退出时统一清理，子进程为 `SIGTERM` 注册与 `SIGINT` 一致的清理入口，避免遗留 MCP/nmap 孙进程被孤儿化。
- **重构工具循环上下文管理** — `call_llm_auto`/`call_llm_auto_stream` 不再每轮截断全部历史，而是构建稳定前缀（system prompt + 有界历史 + 任务指令）+ 可变工具循环尾部；仅在尾部超过高水位（默认 32K）时压缩至目标（26K），保留稳定前缀和近期完整工具交换组，减少不必要的上下文丢失。流式调用改为 `asyncio.to_thread` 包装同步 provider stream，避免子代理并发时阻塞事件循环。
- **Skill 参考资料化架构** — skill resolver 现在只向 prompt 注入可选参考索引（skill 名称、描述、reference 文件列表和路由原因），不再自动注入 primary skill 正文、默认 `pentest-flow` 剧本或 WAF 绕过知识。`load_skill_reference` 被定义为模型自主选择的参考资料读取工具，返回内容不再视为强制流程、阶段计划或工具调度。
- **纠偏层去命令化** — solve 系统提示和 correction layer 改为输出 diagnostic notes：只描述工具健康、重复调用、same-body、parser/filter、POP 链等证据状态，不再直接命令模型“必须使用某工具/某 payload/某验证顺序”。`NO_PATH`/`ASK_USER` 闸门只说明未解决的高信号证据，不替模型规划下一步。
- **架构调整 active context 证据工作集** — 大工具输出仍完整写入 `AgentState.evidence`，但默认不再把完整 HTML/body/stdout/stderr 重复塞进模型 active context；模型可见 tool transcript 使用 bounded high-signal preview，包含 raw size/hash、关键行、表单/参数、endpoint、源码 sink/filter、flag-like token 和请求面摘要。新增 `evidence_search` 用于在 raw evidence 中按关键词/正则查找精确片段；`evidence_view` 继续用于分页查看原始证据。相同 raw 输出再次出现时只注入 `same_as=eXXX` 引用，减少 context rot，同时不牺牲证据闸门、报告和按需回查的完整性。

- **修复 PHP5 反序列化差分误判** — `http_probe_batch` 现在会把响应头写入证据并默认关闭 TLS 校验，`runtime_diff_probe` 可从 `X-Powered-By: PHP/5.x` 推断目标运行时；遇到 `O:+n:` / `C:+n:` 这类 signed length 候选时，会明确标记为必须远程验证，防止模型把本地新版 PHP 的 `unserialize_ok=false` 误判成远程不可利用。
- **增强 PHP POP 链高信号记忆** — 看到 `unserialize`、魔术方法和 `eval/assert/system/exec` 等 sink 同时出现时，会固定“魔术方法入口对象 → sink 对象”的对象图提示，避免模型只序列化 sink 类而漏掉真正触发链。
- **强化 `fetch` HTTPS 兼容性** — 即使模型显式传入 `verify_tls=true`，证书链校验失败时也会自动以 `verify_tls=false` 重试一次，并在工具结果中标注，减少 CTF/lab 站点因本机 CA 问题浪费一次模型回合。
- **强化外部题解类 `ASK_USER` 闸门** — 当 flag/shell 目标仍有 parser/filter、源码 sink、请求面等高信号证据时，模型重复询问“是否查看公开题解/外部资料”会持续被拒绝；真正的授权、凭证、范围问题仍允许询问用户。
- **新增 `runtime_diff_probe` 运行时差分探测工具** — 模型在遇到“正则/字符串过滤器 → 运行时解析器/解释器”的边界时，可按需批量生成并验证 parser-accepted/filter-missed 候选；当前支持通用 regex 检查和 PHP serialize/unserialize 本地差分，并会提示目标/本地运行时版本不一致风险。
- **新增 `ASK_USER` 近成功防误停闸门** — 当目标仍要求 flag/shell 且已有源码 sink、parser/filter 边界、本地 proof、请求面等高信号证据时，不接受模型过早询问“是否查看外部题解/公开思路”，而是把拒绝原因反馈给模型继续做本地差分、精确编码或远程验证。
- **增强 parser/filter 纠偏记忆** — correction layer 会固定 `preg_match`/regex/blacklist 与 `unserialize`、模板、表达式、XML/JSON 等运行时解析器之间的边界事实，并提示优先用小规模差分实验代替大范围 payload 猜测。
- **重构默认 solve 引擎为模型主导模式** — 删除旧 `ResearchState` / 研究方向 / plan-action-observe 生命周期；solve 现在像 Claude Code/Codex 一样由模型自行决定下一步、工具调用、`FINAL:` 完成、`ASK_USER:` 询问或 `NO_PATH:` 终止。
- **新增 `AgentState` 证据记忆** — 工具结果统一写入 `AgentState.evidence` 并完整保留 raw；active context 默认使用高信号预览，新增 `evidence_list` / `evidence_search` / `evidence_view` 让模型按需回看历史证据。
- **改为 Codex-style 工具 transcript** — solve 工具调用后会把 assistant `tool_calls` 与 `role=tool` 结果追加进模型上下文，并继续采样；只有 provider 拒绝 tool transcript 时才降级为完整工具文本，避免旧的 `Summarizing...` 摘要污染上下文。
- **新增 `shell_command` 内置工具** — 模型可按需运行本地 `php -r`、`curl`、`rg`/`Select-String` 等命令做精确验证；默认完整返回 stdout/stderr，可用 `max_output_chars` 主动裁剪。
- **新增源码自动还原能力** — `fetch` / `http_probe_batch` 遇到 `highlight_file`、HTML 高亮源码和混杂 HTML/JS body 时，会自动在 raw body 前追加 clean source；`source_extract` 仍可按需重读历史 evidence 并提取危险 sink、服务器端源码线索、表单、input 与 endpoint 信号。修复高亮源码 `<span>` 被误当成换行导致源码 token 化、模型无法准确读代码的问题。
- **新增轻量纠偏层** — 记录工具耗时、失败降级、重复调用、请求面、same-body/响应差异和新发现信号，作为 AgentState prompt hint 提供给模型；纠偏层不做阶段规划、不主动安排工具。
- **新增高信号证据固定** — 从工具原始输出中提取源码 SQL、HTML 表单/input、PHP/API 链接和 JavaScript endpoint 构造，写入长期可见 pinned facts，避免后续 HTTP 试错把真实入口淹没；SQL 源码场景会提示模型优先从服务端表达式推导 payload，并在 comment 结尾失败时尝试 no-comment 小步变体。
- **新增 `http_probe_batch` 内置工具** — 一次比较多组 URL/参数/header/body/raw URL 变体，返回状态码、长度、hash、title、关键 body 信号、实际请求面、完整 body 和 same-body 分组；`max_body_chars` 只有显式设为正数时才裁剪。复杂 Cookie/精确编码 payload 推荐使用 `headers.Cookie`，输出会展示模型实际发送的 method/URL/params/headers/cookies/body/json。
- **新增 `NO_PATH` 近成功防误停闸门** — 当源码 sink、表单/参数、请求面、本地 proof、same-body/响应差异等高信号证据仍未耗尽时，solve 会拒绝模型因单次 payload 无回显或远端 same-body 就提前停止，并把“验证 method/URL/headers/cookies/body、编码、触发条件和替代回显通道”的纠偏提示反馈给模型继续行动。
- **增强 `fetch` 本地工具** — 默认 GET，支持 HTTP/HTTPS、自定义 method/headers/params/cookies/body/data/form/json、timeout/follow_redirects/verify_tls/max_body_chars；默认返回完整响应 body，CTF/靶场 HTTPS 默认不校验证书，减少模型退回 `python_execute` 手写请求的 token 消耗。
- **工具输出改为 raw evidence + active preview** — `python_execute` / `shell_command` / HTTP 工具默认完整保存 raw stdout/stderr/body 到 `AgentState.evidence`；大输出进入模型上下文时改为 bounded high-signal preview，显式配置正数上限时仍可在工具层主动裁剪 raw 输出。
- **修复终端 payload 渲染崩溃** — 工具输出、工具参数和 solve 观察摘要改为 Rich 纯文本渲染，避免 SQL payload 中的 `[/**/]`、`[xxx]` 被误解析为 Rich markup 标签。
- **修复证据查看空转问题** — `evidence_view` / `evidence_list` 现在会写入 AgentState 工具调用记录；重复读取同一 evidence 覆盖范围会被短路，连续多轮只有证据查看且没有新增 evidence 时触发 stall guard，避免模型把预算耗在反复翻同一批日志上。
- **保留 `python_execute` 原始证据** — `python_execute` 的完整 stdout/stderr 会写入 AgentState；小输出可直接进入 active context，大输出使用高信号预览，`python_execute_max_output_chars` 显式设为正数时才在工具层裁剪 raw 输出。
- **保留并强化证据闸门** — `FINAL:` 声称的 flag/结论必须由真实工具输出支撑或引用证据编号；不满足时不会假完成，而是把拒绝原因反馈给模型继续探索。
- **新增 solve 自动复盘报告** — 目标达成后基于 `AgentState` 确定性生成 Markdown 报告并默认打印，包含解题思路、关键证据、复现请求包、curl、响应片段和证据索引；新增 `session.solve_auto_report` / `session.solve_report_show` 配置。
- **上下文压缩改为显式/必要时触发** — solve 默认保留正常历史；仅在上下文接近上限、用户执行 `/compact` 或显式启用自动压缩时压缩。
- **工具改为可用能力清单** — 目录扫描、JS 收集、空间测绘、nmap、skill 读取等只作为工具暴露，框架不再按阶段模板主动安排。
- **工具失败不再打崩 solve** — MCP/browser 初始化失败、AnyIO cancel-scope 清理噪声等会作为工具失败证据返回给模型，模型可继续改用其他工具。
- **进度显示改为 Turn** — CLI 不再显示 `Step x/N`，`solve_max_steps` 明确为防失控安全预算，不作为模型工作流轮数；默认安全预算从 80 提高到 240，避免慢模型在接近答案时被过早截断。
- **导入授权红队 Skill** — 吸收 `codex-redteam-mode` 的授权红队 detail packs 到 `vulnclaw/skills/specialized/`；jailbreak、拒绝绕过、会话 patch 等破限内容未导入。
- **新增 SQL 注入实战知识条目** — 基于 fushuling《SQL注入一命通关!》二次整理 `web-sqli-fushuling-one-pass.md`，并接入 `secknowledge-skill` 路由和内置 KB seed。

</details>

---

<details>
<summary><strong>v0.4.1</strong> — 并行探索 + 记忆引擎 + 信息收集工具链 + MCP streamable-http</summary>

- **多方向并行探索** — solve 引擎支持同时探索多个方向（默认 max_parallel=3），单个方向异常不影响其他，每个方向有独立的证据缓冲区和工具调用记录。
- **agent 记忆引擎** — 共享研究状态新增工具调用日志（跨方向可见），reason 阶段显式列出已放弃方向并禁止重复提出，explore 上下文带"已执行工具"摘要；checkpoint 机制在图状态没变时跳过 reason 避免空转；已放弃方向做 Jaccard 去重兜底。
- **结论判定优化** — 放宽了"有进展"的标准（发现新接口、确认未授权都算推进），不再轻易丢弃有价值的发现；最后一步增加证据复核，防止误判丢弃实际有数据返回的探索。
- **完成判定否定闸门** — 模型在 complete 字段里写"未达到完成标准"等否定结论时不会再被误判为已完成；显式要求 complete=true 布尔值 + evidence fact 引用。
- **JS 信息收集（js_recon）** — 抓取页面及全部 JS 文件，提取 API 路径 / 关联域名 / 硬编码密钥；动态发现 PascalCase 实体名并与 base path + CRUD 动词排列组合推断隐藏接口；收集到的接口自动做 GET+POST 未授权探测。
- **未授权探测（unauth_test）** — 批量无凭据请求，按状态码/响应体/内容类型判定；支持有/无 token 差分对比确认未授权；自动跳过 delete/save/sms 等破坏性接口。
- **目录枚举（dir_enum）** — 并发字典爆破，带 404 基线与全局伪装 200 识别（随机路径返回 200 自动停止），状态码与响应长度过滤。
- **空间测绘（space_search）** — FOFA / Hunter / Quake / Shodan / ZoomEye / 0.zone 六引擎统一查询，engine=all 时并发查询所有已配置 key 的引擎。
- **子域名枚举（subdomain_enum）** — 空间测绘被动聚合 + 内置字典 DNS 爆破，自动去重。
- **MCP streamable-http 支持** — 支持 Chrome DevTools MCP 等 HTTP 传输的 MCP 服务器；惰性连接（启动时不占 session slot）；首次调用时自动建连 + 工具发现；连接失败降级为 service_unavailable 不影响 solve 循环。
- **Chrome MCP 工具名修正** — 占位工具改为真实 Chrome MCP 工具名（chrome_navigate / chrome_read_page / chrome_pentest_* 等）。
- 工具返回 undefined 标记为失败而非静默成功；事实序号 / 方向序号在 session 恢复后正确续接；新增 ReconConfig 配置区块与 solve_max_parallel 配置项。

</details>

<details>
<summary><strong>v0.4.0</strong> — 核心：自主引擎从「固定轮数工作流」重构为「目标驱动求解」</summary>

- **新增目标驱动求解引擎（默认）** — 基于已验证事实、研究方向与证据记录的计划/行动循环，以「目标达成 / 研究方向耗尽 / 安全预算」为终止条件，结构上杜绝"原地打转"；新增 `vulnclaw solve` 命令，`run`/REPL 自主模式默认改走该引擎（`session.engine=rounds` 可回退旧逻辑）。
- **新增证据级反幻觉闸门** — 录制所有真实工具输出作为唯一可信证据；声称的 flag/完成必须在真实输出里逐字符出现才被采信，否则判定幻觉并继续探索；拿到验证过的 flag 即时收敛。
- **新增结构化推理 + 自适应反思** — 已知事实（带置信度）/约束/攻击链结构化沉淀并注入提示词；失败自动归类并按 L0–L4 渐进升级 payload 绕过策略，persistent 模式跨周期保留失败记忆。
- **新增漏洞检测插件体系** — 低耦合插件运行时 + 内置只读 Web 插件（安全响应头 / JWT / JS 端点），结果可去重合并进 findings 与报告链路；新增 `vulnclaw plugins list/info/run` 命令。
- **修复 #45 工具被误约束** — 动作约束不再把 HTTP 方法（OPTIONS/POST）或使用 `requests` 误判为「利用」；只有实际攻击载荷（SQLi/RCE/路径穿越等）才算 exploit；`load_skill_reference`/`crypto_decode` 等纯本地工具豁免范围约束。
- 新增 `session.engine` / `solve_*` / `reflexion_*` / `plugin_*` 等配置项，均支持环境变量注入。

</details>
