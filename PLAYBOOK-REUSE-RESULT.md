# 笔记复用链 · 本轮结果（接 PLAYBOOK-REUSE-HANDOFF.md 的两项待办）

- 代码：`vulnclaw/agent/playbook.py`、`vulnclaw/agent/playbook_refresh.py`（新增）、
  `vulnclaw/agent/solver.py`
- 测试：`tests/agent/test_playbook_overlap_gate.py`（新增，20 条）、
  `tests/agent/test_playbook_probe_refresh.py`（新增，32 条）、
  `tests/agent/test_playbook_vuln_class.py`（按新语义改写）
- 工装：`scripts/ab/cold_warm_pair_round2.py`、`scripts/ab/parse_run_logs_round2.py`（新增）
- 纪律：**先量后说**；下面严格分开 **[实测]** 与 **[推断]**，并列出**没做的部分**

---

## 0. 摘要

两项待办都做完，并且**都靠实测纠过至少一个真 bug**——两个 bug 都不是想出来的，是跑出来的：

1. **任务 2 的门槛第一版把跨题迁移整体清零**：门只数笔记 `fingerprint` 的 token，而手工笔记的
   判别信息在 `name` 里。278 道真实题面实测：手工笔记注入 **0/278**。改成按"笔记声明的身份"
   （fingerprint+name+slug）计数后回到 **16/278**，且反向对照 `[Weblogic]SSRF` 仍被正确挡住。
2. **任务 1 的重查第一版是死代码**：只认 `http_probe_batch`/`fetch` 这类制式探测工具，而模型在
   真实运行里**从不调用它们**（实测一个 run：`python_execute` 8 次、`shell_command` 5 次、
   制式工具 0 次；日志里 `body:` 与 `response_headers=` 各 0 次）。修好后重查在真实运行里
   确实触发了（见 §3）。

冷/热配对 **3 组跑完**（6 臂、每臂独立新靶机、收尾 `get_target` 全部 `null`）：

| 组 | 冷（无笔记） | 热（2 手工 + 4 自动） | 差值 |
|---|---|---|---|
| `[Weblogic]CVE-2017-10271` | 237.3s 解出（9 步） | **46.5s 解出**（11 步） | 时长 **-80%** |
| `[Weblogic]CVE-2018-2628`（同类不同 CVE） | 超时 23352s 未解（22 步） | **166.8s 解出**（14 步） | 删除失外 -99% |
| `[Weblogic]SSRF`（反向对照） | 279.1s 解出（20 步） | 295.3s 解出（23 步） | 时长 **+6%**，零注入 |

n=3，**只能给信号**（同代码方差 33%-100%，见 §5）。

**本轮还撤回了自己的一条结论**：上一版报告说"平台套话 token 让无关笔记对任何题面都满分命中"，
复算后不成立——那只在**短题面**下发生，产品的完整 goal 模板（37 个查询 token）会把它稀释到
`min_score` 以下，实测 278 道题 × 两份真实库都是 0 次假命中。详见 §1 的更正表。

**顺带发现并已修**（§6）：home 库里有一条自动笔记的 fingerprint 存成 `'E:'`（成因：那一轮 target
就是 `'E:'`，而 `Path('E:').exists()` 为 True / `is_file()` 为 False，既补不了 sha256 也拦不住），
它对所有目标串都召回不了（12 种组合实测 `score=0.000`）——与"确定性复用"契约直接冲突。
现在 `capture_run_notes` 落盘前会检查这条笔记**是否可能被任何查询查到**：查不到就先用 goal 拓宽
key，拓宽后仍查不到才拒绝落盘。同节还记了一个会骗人的观测陷阱：`read` 工具会把路径里的
`\v`/`\b` 当转义渲染，涉及反斜杠路径的证据必须做字节级校验。

---

## 1. 任务 2：仅框架命中的最小重叠门槛

**实现**：`playbook.MIN_OVERLAP_TOKENS = 2`。`lookup_playbook` 每行新增 `overlap_tokens`
（查询 token 与笔记**声明身份**的不同 token 交集数，**不由 score 反推**——score 是"查询 token
被笔记包含的比例"、受查询长度影响：实测 12-token 查询命中 2 个 token 只有 0.167，用分数当门
会误杀真命中）。门槛在 `lookup_playbook_multi` 的合并结果上生效，对 `target`/`class` 一视同仁；
`lookup_playbook`（模型自己调的单键原语）不过门，保留全量召回。被挡条目经 `out_blocked=`
返回并进日志。

**选定语义（写进测试）**：门 = "查询侧**任意一个键**与该笔记重叠 ≥2 个不同 token"，
重叠算在 `Playbook.identity_tokens() = fingerprint + name + slug` 上。

### [实测] 278 道真实题面 × 真实手工笔记的画像

评测集：练习场 `2de971ac…` **全部 278 道题**题面（各配假端口）；笔记库 `ab-config-B/playbooks`
（4 手工 + 4 自动）。

| 计数面 | 有任意注入的题 | **有手工笔记注入的题** | 有被门挡掉的题 |
|---|---|---|---|
| 只数 `fingerprint`（第一版） | 1/278 | **0/278** | 26/278 |
| `fingerprint + name + slug`（现版） | 16/278 | **16/278** | 13/278 |

逐条笔记（候选 → 过门/被挡，现版）：`weblogic-cve-2017-10271-…` 候选 11 → 过门 9 / 被挡 2；
`thinkphp-5-0-23-rce-captcha-route` 候选 14 → 过门 6 / 被挡 8。

### [实测] 修复前后逐题差别（交接文档点名的三道）

| 题 | 只数 fingerprint | 现版 |
|---|---|---|
| `[Weblogic]CVE-2017-10271` | 被挡（重叠 1） | 注入（class，overlap=2，score=0.5） |
| `[Weblogic]CVE-2018-2628` | 被挡 | 注入同一条（class，overlap=2） |
| `[Weblogic]SSRF` | 被挡 | **仍被挡**（overlap=1）——反向对照保住 |
| `[ThinkPHP]2-Rce` / `5.0.23-Rce` | 被挡 | 注入（class，overlap=2） |

**[推断]** 成因：手工笔记的 fingerprint 是**目标形状**的（`Weblogic 10.3.6 -
/wls-wsat/CoordinatorPortType returns 'Web Services WSAT10Service' listing; /console/
redirects to login ...`），判别性名字只在 `name`。而 `lookup_playbook_multi` 里**同一个函数**
早就写明"身份要从 name/slug 读"（854818a/a300d4f 修的同类 bug）——这是同一缺陷的二次复发。
已加 3 条测试钉住。

### [实测·更正] 套话 token 假命中：**在真实题面形状下不成立**（上一版报告写错了）

上一版报告写"平台套话 token 让一条无关自动笔记对**任何**题面都拿 0.556/重叠 5 排第一"。
按同一纪律复算后**撤回这句**，因为 0.556 只出现在**短题面**上：

| 查询形状（`target` 键 = `target_fingerprint(origin, goal)`） | query token 数 | `autonotes-b9bbb32f-…` 的 score | 重叠 | 是否为候选（`min_score=0.15`） |
|---|---|---|---|---|
| `Solve CTF2 challenge [Weblogic]SSRF (category Real, difficulty Easy)` | 9 | **0.556** | 5（全是套话） | 是 |
| `Solve CTF2 challenge '[Weblogic]CVE-2017-10271' (…) on practice 2de971ac` | 12 | **0.583** | 7（全是套话） | 是 |
| 产品实际的完整 goal 模板（`Target: …` + flag 说明 + 范围约束） | **37** | **0.054** | 2（`ctf2`、`flag`） | **否，进不了候选** |
| `This is a CTF challenge web service ([Weblogic]SSRF). Exploit it.` | 10 | 0.100 | 1 | 否 |

也就是说：**`_STOP` 里的 `ctf2` 漏了一个套话 token，但产品实际使用的 goal 模板长度足以把它稀释到
`min_score` 以下**，那条笔记在真实运行里根本不会成为候选（`ghost_injection` 在 278 道题 × 两份
真实笔记库上实测都是 **0**）。所以这条**不需要修 `_STOP`**，上一版把它列为"下一步"是错的。

**[推断]** 只有在题面被裁剪成"一行题名"的调用方（例如自定义 goal 的脚本、短题名字典）下，
套话假命中才会真的出现。本仓库的 `scripts/ab/` 工装用的就是短格式之一，所以交接文档里的
0.556 是真实测出来的——只是它不是产品路径的形状。**若将来有人把 goal 改短，这条会回来**，
届时应加 `_STOP` 词条并重新画像。

---

## 2. 任务 1：首次探测后用实测特征重查并替换简报

**实现**：新增 `vulnclaw/agent/playbook_refresh.py`

- `probe_signature(evidence)`：只从**已记录的证据**取特征（不碰网络、不调模型），复用
  `builtin_tools` 现成 helper（`_extract_html_title` / `_extract_endpoints` /
  `_extract_html_surfaces` / `_http_body_signals`），另补 `Server`/`X-Powered-By` 头与
  路径/参数名。**没有另写一套抽取逻辑。**
- token 级去重 + 封顶 `MAX_PROBE_TOKENS=18`。**[实测]** 不封顶时 40 链接页面生成 80 个查询
  token，真实命中掉到 ~0.02（低于 `min_score=0.15`）→ 恰好在信息最丰富的页面上"重查什么都找不到"。
- 两道"这是不是真页面"的闸（**都是实测踩出来的**）：
  1. 必须至少有一个**强特征**（页面标题 / `Server`·`X-Powered-By` 头 / 带斜杠的路径）。
     **[实测]** 回放真实运行的工具输出：无页面无路径的那些产生
     `'Python execution result trusted-local status elapsed sleep'` 这种查询——纯工具管道信息，
     用它换简报比不换更差。
  2. 签名里至少要有 2 个**非模板词**。**[实测]** 运行里第一条 HTTP 结果是未授权错误页，
     标题 `Error 404--Not Found` 分词后全是 `error/not/found/title/color/helvetica/black`；
     它是真页面、有真 `<title>`，却不标识任何题目。
- `should_replace()`：判据**只看条目集合**（同批笔记分数变化/换序都不换简报）。
- solver：`_inject_prior_playbooks`（开局、题名键、**不阻塞首轮请求**，保留为召回兜底）拆出
  共用的 `_format_prior_playbook_brief` / `_lookup_prior_playbooks`；主循环每步（新证据落库后、
  下一次 `_system_prompt` 之前）调用 `_refresh_prior_playbooks_after_probe`，**最多 2 次**，
  只在"证据未读过 + 特征变过 + 答案变了"时替换，全部 best-effort。
- 日志：`emit("playbook_refreshed", {hits, query, replaced, reason})` +
  `[playbook] refreshed <slug> score=… (probe key: …; replaced …)`，以及
  `[playbook] probe re-query (…): <为什么没换>` 与
  `gated N below the 2-token overlap floor: <slug>=<overlap>`。
- **三条使用约束原样保留**（`test_injection_wording_puts_the_challenge_class_first` 盯着）。

### [实测] 测试

- `test_playbook_overlap_gate.py` **20 条**（含 §5.7 两个自伤 bug 的回归、门槛语义、被挡可见、
  身份面语义）
- `test_playbook_probe_refresh.py` **32 条**（含**真跑 solve 主循环**的端到端；含
  "`python_execute` 输出可读"、"`shell_command` curl 输出可读"、"工具管道输出不产生查询"、
  "服务器错误页不产生查询"、"真标题不被误伤"）
- `test_playbook_auto_reuse.py` **+2 条**（"笔记必须能被自己的 fingerprint 召回"，见 §6）
- 笔记链 6 个文件 **107 passed**
- `tests/agent` **1051 passed / 7 skipped / 0 failed**；其余 18 个测试目录
  **2855 passed / 13 skipped / 0 failed**；`verify_execution_boundary.py` → **27 spawn sites**

> 说明：本轮前半段沙箱是 `workspace-write`，当时有 6 个环境失败（`E:\vulnclaw\` 写入被拒、
> 禁止管道 stdio），已在**未改动的基线树**上用 `git stash` 逐个复现确认与本改动无关；
> 会话中途文件策略改为 `danger-full-access` 后这 6 个失败全部消失，现在是 0 failed。

---

## 3. 冷/热配对实测（3 组，这是本轮的正题交付）

工装：`scripts/ab/cold_warm_pair_round2.py`（真实题目 id、隔离配置目录、每臂新开靶机、
跑完 `stop_target` 并用 `get_target` 确认；`RUN_TIMEOUT_S=900`）。
解析：`scripts/ab/parse_run_logs_round2.py`。

**热臂笔记库**：2 条手工技术笔记（`weblogic-cve-2017-10271-wls-wsat-xmldecoder-rce-`、
`thinkphp-5-0-23-rce-captcha-route`）+ 4 条自动笔记。放自动笔记是为了让"注入了什么"可归因：
自动笔记是**按目标**召回的，手工笔记才是**跨题迁移**的那两条。

### [实测] 逐组结果（每臂都报，不做聚合）

| 组 | 臂 | 秒 | 步 | 工具 | 达成 | 见到动态 `CTF2{uuid}` | 注入 | 重查 | 被挡 |
|---|---|---|---|---|---|---|---|---|---|
| **CVE-2017-10271** | cold | 237.3 | 9 | 15 | ✅ | 14 | 无命中 | 1 次（保留旧简报）+ 1 次换 | 0 |
| | warm | **46.5** | 11 | 22 | ✅ | 19 | `weblogic-cve-2017-10271-…` score=0.5 (class) | 1 次换（0.188 probe ×2） | 0 |
| **CVE-2018-2628** | cold | **23352.0（超时）** | 22 | 29 | ❌ | 0 | 无命中 | 0 次生效 | 0 |
| | warm | **166.8** | 14 | 24 | ✅ | 17 | 同上 score=0.5 (class) | 1 次换 | 0 |
| **SSRF**（反向对照） | cold | 279.1 | 20 | 23 | ✅ | 19 | 无命中 | 1 次（保留旧简报） | 0 |
| | warm | 295.3 | 23 | 31 | ✅ | 25 | **无命中** | 3 次（全部保留旧简报） | **1**（`weblogic-cve-2017-10271-…` overlap=1） |

**采纳代理**（笔记特征词在运行日志里的出现次数）：注入发生的那两臂一致上升
（CVE-2017-10271：128→173；CVE-2018-2628：64→192）；**反向对照里下降**（122→81）——
这正是"没注入、没被带偏"的形态。

### [实测] 三条结论

1. **跨题迁移成立且幅度大**：CVE-2018-2628 那一组，热臂用**另一道 CVE**（CVE-2017-10271）的
   笔记在 166.8s 解出；冷臂同一道题 22 步后仍未解出，被 6.5 小时超时杀掉。
   CVE-2017-10271 那一组同题自迁移：237.3s → 46.5s（-80%）。
2. **反向对照按设计生效**：`[Weblogic]SSRF` 热臂**零注入**，且日志明确写出
   `gated 1 below the 2-token overlap floor: weblogic-cve-2017-10271-wls-wsat-xmldecoder-rce-=1`
   —— 这条正是交接文档记录过"把 SSRF 带偏"的笔记（当时它拿满分 1.0），现在被门槛挡在门外。
   该臂时长 +6%、步数 +3（同代码方差量级内，且它本来就没注入）。
3. **重查在真实运行里生效**：日志里有 `[playbook] probe re-query (console LoginForm wls-wsat
   CoordinatorPortType …)` 与 `[playbook] refreshed … (probe key: uddiexplorer
   SearchPublicRegistries bea_wls_internal …)`，也有"查询没命中→保留旧简报"的判定。
   **修 bug 前这一行永远不会出现**（实测：修前热臂 `Re-matched AFTER` 计数 0、`refreshed` 计数 0）。

### [实测] 必须写明的保留

- **CVE-2018-2628 冷臂不是"慢"，是死路/环境所致离群**：靶机本身正常（日志里正确识别
  `Oracle WebLogic 10.3.6.0 with T3 enabled — matches CVE-2018-2628`），但模型转向**在本机
  递归找 ysoserial**（`Get-ChildItem -Recurse -Filter *ysoserial*`），单条 `shell_command`
  实测 18555ms。所以那一组的时长差（-99%）**主要是删失造成的，不能当作收益**。
- **步数/工具数在 CVE-2017-10271 组反而热臂更多**（+2 步 / +7 工具），与时长 -80% 相反 ——
  再次说明单看一个指标会得出相反结论。
- 冷臂里模型扫描了**宿主机文件系统**（日志中读到 `package-lock.json`、`Untitled.ipynb`、
  以及 pytest 临时目录里的夹具笔记）；这对"本机 vs 靶机"的边界是需要单独处理的问题，
  本轮未处理。

---

## 4. 没做的部分（明确声明）

1. **n=3 不足以下结论**：同代码不同次运行方差可达 33%-100%（交接文档 §4.1 实测）。上表逐组
   报了差值，但 CVE-2018-2628 那组冷臂是删失值，真正的有效配对只有 2 组半。
2. **套话 token 不修了**（见 §1 更正）：在产品的真实 goal 形状下它不是问题，实测为 0 次假命中。
3. **重查的第二个信息源（黑板 LOCK / CONFIRMED facts）没接入**：本轮只用实测的探测证据，
   以免把未实测来源混进"先量后说"的改动。
4. **平台 flag 提交仍被验证码挡**（429 `risk_action='challenge'`），所以判据是"日志里出现
   动态 `CTF2{uuid}`"+"`目标达成`"两个数字，**没有**用平台判题结果。
5. **冷臂扫描宿主机**这一点没修（见 §3 保留）。
6. **`fetch` 之外的 MCP 工具输出格式未逐一验证**：现版对任意工具文本做"找 title / 找头 /
   找带斜杠路径"，未识别就返回空（安全降级），但没有为每种 MCP 工具写夹具。
7. **旧库里那条坏条目没删**（见 §6）：`autonotes-babyfengshui-33c3-2016` 的 fingerprint 仍是
   `'E:'`。**新的落盘闸只防将来，不改旧数据**——旧条目要么留着（它靠 name 里的
   `babyfengshui` 还能被"按题名查"的路径召回），要么由人决定迁移/删除，本轮没动它。
8. **纯中文目标/题面形成不了 key**：`_tokenize` 只认 ASCII 字母数字，`'中文目标'` →
   `set()`、`'企业合同审批系统 本地文件包含'` → `set()`。所以：
   * 新的落盘闸对"中文 goal + 退化 target"会**拒绝落盘**（旧行为是静默写一条死笔记）——
     这是把缺陷暴露出来，不是修好它；
   * 但中文**笔记**不受影响：库里 8 + 70 条笔记的 `identity_tokens` **没有一条为空**
     （它们都带英文名或技术词），只是"用中文查询"永远查不到。
   引入中文分词（或对 CJK 走 2-gram）是独立且更大的改动，本轮没做。

---

## 6. 顺带发现：一条永远召回不了的自动笔记

**[实测]** home 库里 `autonotes-babyfengshui-33c3-2016` 存下来的 fingerprint 是 `'E:'` ——
一个裸的 Windows 盘符片段。后果：

* `tokens()` 为空（`_tokenize` 会丢掉长度 <2 的 token），于是 `score()` 对**任何**查询都返回 0.0；
* 拿 4 个目标串 × 3 个 goal 共 12 种组合核验，**全部 `score=0.000`、召回 `False`**，包括它当初
  被捕获时那台目标（`E:\vulnclaw\work\babyfengshui_33c3_2016`）和它里面的二进制路径；
* 它与本模块开头的契约（"deterministic reuse：同一道题下次运行要能找到笔记"）直接冲突：
  这条笔记在库里只占位置，永远不会把任何东西带过去。

**这不是本轮改动引入的**（本轮没有动 `capture_run_notes`），但它属于同一条复用链，而且
**测试没有覆盖**：原有的 roundtrip 测试在同一次调用里捕获并查找、且用的是格式良好的目标串，
所以照不出这种笔记。已补 `TestEveryNoteCanBeFoundAgain`：捕获后断言 `tokens()` 非空、且能被
自己记录的 fingerprint 召回（4 种目标形状各测一遍），另有一条用例把 `'E:'` 这种退化形状的
当前行为写死，给将来修它的人一个靶子。

**[推断]** 成因已定位到"谁写的"：`target_fingerprint` 只在 `Path(o).exists() and is_file()`
时补 sha256，否则**原样返回 target 字符串**；用 10 种候选串实测，只有 target 本身是 `'E:'`
时才会得到 `fp='E:'`。所以那一轮（2026-09-18）的 target 就是 `'E:'`。
而 `Path('E:').exists()` 在 Windows 上为 **True**、`is_file()` 为 **False** —— 一个只有盘符的
路径既"存在"又不是文件，因此既拿不到 sha256 也不会被拦下。

**[实测] 一个会骗人的观测方式（记录备查）**：用 `read` 工具看那条笔记的 frontmatter 时，
`fingerprint:` 那一行显示成 `E:ulnclaw\workabyfengshuiabyfengshui_33c3_2016 pwn heap …`，
看起来是"路径丢了反斜杠"；而用 Python 读**字节**得到的真实值是 `'E:'`（长度 2）。
差异来自 `read` 把那一行里的 `\v`、`\b` 当转义序列渲染。**涉及反斜杠路径的证据一律用字节级校验**
（`ascii(value)` / `len(value)`），否则会得出相反结论——本轮就先被它骗了一次。

**[推断]** 修法（**已在本轮实现**，见下）：`capture_run_notes` 落盘前检查这条笔记**是否可能被
任何查询查到**——判据不是"fingerprint 有没有 token"（太严，会把 `http://t/` 这类
查得到的笔记也拒掉，实测把两个既有测试弄红），而是把该笔记自己的身份 token 拼成"最有利的查询"
再算一次 `score`：连它都得 0 分，才说明没有任何查询能查到这条笔记。

### [实测] 已实现的落盘闸与其边界

`capture_run_notes` 现在走 `_recallable_fingerprint()`：target 派生的 fingerprint 可查 →
原样存；不可查但加上 goal 后可查 → 存拓宽后的 key（保住这一轮的结论）；两者都不可查 → 拒绝落盘。

用 10 种 target × 6 种 goal 的**穷尽网格**核对：

* 被拒绝的 12 种组合**全部**是"target 与 goal 的 token 集合都为空"（`'E:'`/`'E:\'`/`'http://t/'`/
  `'t'`/`'a'`/`''`/`'  '` × `''`/`'g'`/`'中文目标'`）——名副其实，没有任何查询能查到它们；
* 其余 48 种组合全部落盘且**实测可召回**（用自己的 fingerprint 与同一轮的 `target_fingerprint`
  两种查法都命中），包括真实那条 `target='E:'` + 技术词 goal 的场景；
* 真实库审计：`ab-config-B`(8) 与 home(70) 两份库，`identity_tokens` 为空的笔记 **0 条**；
  `fingerprint` 本身 token 为空的只有那 1 条 `'E:'`（它靠 name 尚能被"按题名查"召回）。

**[实测] 代价**：闸会让"退化 target + 纯中文/单字符 goal"的组合不再落盘——旧行为是静默写一条
**永远查不到**的死笔记。也就是说这一轮把缺陷**暴露**成"不写"，而不是修好中文可召回性（见 §4.8）。

---

## 5. 方法学提醒（照交接文档 §5.1）

- §1 的所有数字是**静态召回测量**（同一批题面 + 同一批笔记，确定性可复现），不受运行方差影响；
- §3 的步数/时长/工具数是**运行结果**，n=3，且一组冷臂删失 → **只能给信号**；
- 本轮两个最重要的发现（门槛只数 fingerprint、重查只认制式工具）都不是推理出来的，是
  **跑出来的**：前者来自"278 道题面 × 真实笔记"的全量画像，后者来自回放真实运行日志里的
  工具输出。这也是为什么每一条修复都配了钉住它的测试。
