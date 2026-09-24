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

### [实测] 门槛仍未解决的更大一类假命中（重要局限）

另一台机器的 70 条笔记库里，`autonotes-b9bbb32f-…` 对**任何** CTF2 题面都拿 0.556、重叠 5：

```
note tokens  : [..., category, ctf2, difficulty, easy, practice, reverse, solve]
query tokens : [category, ctf2, difficulty, direct, easy, real, solve, ssrf, weblogic]
overlap      = {category, ctf2, difficulty, easy, solve}   # 全部是平台套话
```

题面模板 `"Solve CTF2 challenge [...] (category X, difficulty Y) on practice Z"` 分词后贡献
5 个 token，自动笔记 fingerprint 里也带同一段套话 → **与题目内容无关的笔记稳定拿 0.556 排第一**
（`[Crypto]AES-ECB` 实测同样命中）。即 ≥2 token 门杀掉**单 token**退化，**多 token 套话**退化仍在。

**[推断]** 修法：把 `solve/ctf2/challenge/category/difficulty/easy/practice/real` 加进 `_STOP`
或在算重叠前剔除。**本轮没做**：它会全局改 `score` 语义，值得单独一轮 + 单独实测。

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
- 笔记链 6 个文件 **105 passed**
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
2. **套话 token 的修法没做**（见 §1 末），留给下一轮单独做 + 单独实测。
3. **重查的第二个信息源（黑板 LOCK / CONFIRMED facts）没接入**：本轮只用实测的探测证据，
   以免把未实测来源混进"先量后说"的改动。
4. **平台 flag 提交仍被验证码挡**（429 `risk_action='challenge'`），所以判据是"日志里出现
   动态 `CTF2{uuid}`"+"`目标达成`"两个数字，**没有**用平台判题结果。
5. **冷臂扫描宿主机**这一点没修（见 §3 保留）。
6. **`fetch` 之外的 MCP 工具输出格式未逐一验证**：现版对任意工具文本做"找 title / 找头 /
   找带斜杠路径"，未识别就返回空（安全降级），但没有为每种 MCP 工具写夹具。

---

## 5. 方法学提醒（照交接文档 §5.1）

- §1 的所有数字是**静态召回测量**（同一批题面 + 同一批笔记，确定性可复现），不受运行方差影响；
- §3 的步数/时长/工具数是**运行结果**，n=3，且一组冷臂删失 → **只能给信号**；
- 本轮两个最重要的发现（门槛只数 fingerprint、重查只认制式工具）都不是推理出来的，是
  **跑出来的**：前者来自"278 道题面 × 真实笔记"的全量画像，后者来自回放真实运行日志里的
  工具输出。这也是为什么每一条修复都配了钉住它的测试。
