# 笔记复用链 · 本轮结果（接 PLAYBOOK-REUSE-HANDOFF.md 的两项待办）

- 改动范围：`vulnclaw/agent/playbook.py`、`vulnclaw/agent/playbook_refresh.py`（新增）、
  `vulnclaw/agent/solver.py`，测试 3 个文件（2 新增 / 1 改写语义）
- 纪律：**先量后说**；下面严格分开 **[实测]** 与 **[推断]**，并列出**没做的部分**

---

## 1. 任务 2：仅框架命中的最小重叠门槛

**实现**：`playbook.MIN_OVERLAP_TOKENS = 2`。`lookup_playbook` 每行新增
`overlap_tokens`（查询 token 与**笔记 token** 的不同 token 交集数，**不由 score 反推**，
因为 score 是"查询 token 被笔记包含的比例"、受查询长度影响）。门槛在
`lookup_playbook_multi` 的合并结果上生效，因此对 `target` / `class` 两种键一视同仁
（单 token 的 target 查询同样是退化形状）；被挡条目通过 `out_blocked=` 返回，进运行日志。

**选定语义（写在测试里）**：门是"查询侧**任意一个键**与该笔记重叠 ≥2 个不同 token"。
`lookup_playbook`（模型自己调的单键原语）**不过门**，保留全量召回。

### [实测] 门槛在真实笔记库（70 条，`~/.vulnclaw/playbooks`）上的召回代价与收益

| 查询（真实 CTF2 题面写法） | 门槛前候选 | 门槛后注入 | 被挡 |
|---|---|---|---|
| `[Weblogic]SSRF` | 3 | 1 | `encrypted-flask`（1 token） |
| `[Weblogic]CVE-2017-10271` | 3 | 1 | `vm2-3-9-17-cve-2023-37466-...`（1 token） |
| `[ThinkPHP]5.0.23-Rce` | 4 | 1 | `encrypted-flask`、`encrypted-flask-n1book`（各 1 token） |
| `[struts2]s2-045` | 2 | 1 | 0 |
| `([Weblogic]SSRF)`（题名仅此） | 3 | 2 | `encrypted-flask`（1 token） |

即：门槛砍掉的是**跨框架/跨漏洞类的单 token 碰撞**（题目问 Weblogic，候选是 Flask；
问 thinkphp，候选还是 Flask）。这正是交接文档 §0 点名的退化情形。

### [实测] 门槛**没有**解决的更大一类假命中（重要局限）

真实库里 `autonotes-b9bbb32f-…` 这条自动笔记对**任何** CTF2 题面都拿 0.556、重叠 5：

```
note tokens  : [..., category, ctf2, difficulty, easy, on, practice, reverse, solve]
query tokens : [category, ctf2, difficulty, direct, easy, real, solve, ssrf, weblogic]
overlap      = {category, ctf2, difficulty, easy, solve}   # 全部是平台套话
```

题面模板 `"Solve CTF2 challenge [...] (category X, difficulty Y) on practice Z"` 被
`_tokenize` 分词后贡献了 5 个 token；由于笔记的 fingerprint 里也带同一段套话，于是
**与题目内容无关的笔记稳定拿 0.556 并排第一**（换成 `[Crypto]AES-ECB` 一样命中，
实测 4 条候选里 1 条纯靠套话过门）。也就是说：本轮的 ≥2 token 门杀掉了**单 token**
退化，但**多 token 套话退化**仍在。

**[推断]** 修法很小：把这批平台套话（`solve/ctf2/challenge/category/difficulty/easy/
medium/hard/practice/real`）加进 `_STOP`，或在算重叠前剔除。**本轮没做**，因为它会
全局改变 `score` 语义（`_STOP` 影响所有查询与所有笔记），值得单独一轮 + 单独的实测，
和"门槛"混在一起会让两者的效果无法归因。**这恰好也是注入简报里那三条使用约束继续
必需的理由**：gate 管召回形状，相关性仍由模型带靶机验证。

---

## 2. 任务 1：首次探测后用实测特征重查并替换简报

**实现**：新增 `vulnclaw/agent/playbook_refresh.py`

- `probe_signature(evidence)`：只从**已记录的 HTTP 证据**里取特征（不碰网络、不调模型），
  复用 `builtin_tools` 现成 helper：`_extract_html_title`、`_extract_endpoints`、
  `_extract_html_surfaces`、`_http_body_signals`；再补 `Server` / `X-Powered-By`
  响应头与路径/参数名。**没有另写一套抽取逻辑。**
- token 级去重 + 封顶 `MAX_PROBE_TOKENS=18`。**实测**：不封顶时一个 40 链接的页面
  生成 80 个查询 token，真实命中被打到 ~0.02（`min_score=0.15` 以下）→ 恰好在信息最
  丰富的页面上"重查什么都找不到"。
- `should_replace()`：判据**只看条目集合**（同批笔记分数变化/换序都不换简报）。
- solver：`_inject_prior_playbooks`（开局，题名键，**不阻塞首轮请求**，逻辑保留为召回兜底）
  拆出共用的 `_format_prior_playbook_brief` / `_lookup_prior_playbooks`；
  主循环内每步（新证据落库后、下一次 `_system_prompt` 之前）调用
  `_refresh_prior_playbooks_after_probe`，**最多 2 次**（`_PLAYBOOK_REFRESH_LIMIT`），
  只在"证据未读过 + 特征变过 + 答案变了"时替换，全部 best-effort（异常只丢重查）。
- 日志：`emit("playbook_refreshed", {hits, query, replaced, reason})` +
  `[playbook] refreshed <slug> score=… (query_kind) (probe key: …; replaced …; reason)`
  + 被门槛挡掉的 `gated … <slug>=<overlap>`。
- **三条使用约束原样保留**（`test_injection_wording_puts_the_challenge_class_first` 盯着）。

### [实测] 测试

- 新增 `tests/agent/test_playbook_overlap_gate.py`（19 条，含 §5.7 两个自伤 bug 的回归）
- 新增 `tests/agent/test_playbook_probe_refresh.py`（25 条，含**真跑 solve 主循环**的
  端到端：第 1 步无证据不重查 → 第 2 步拿到探测结果 → 简报被替换、事件与 notice 都出现；
  以及"重查抛异常不中断 solve"）
- 改写 `tests/agent/test_playbook_vuln_class.py`：**语义变了**——`([Weblogic]SSRF)` 不再
  命中 Weblogic 反序列化笔记（原用例断言"降权不排除"，现在是"过不了门就不注入"）。
  已按新语义重写并补 `test_the_framework_only_note_is_now_blocked_outright` 记录该决定。
- 笔记链 6 个文件合计 **96 passed**；`tests/agent` 整目录 **1038 passed / 7 skipped /
  4 failed**；其余目录（cli/config/ctf_platform/…/utils）**2853 passed / 13 skipped /
  2 failed**。

### [实测] 那 6 个 failure 与本次改动无关

`git stash` 后在**未改动的基线树**上单独跑，6 个全部同样失败：

| 测试 | 失败原因（基线复现） |
|---|---|
| `test_builtin_tools.py::…test_timeout_messages_discard_partial_output` | 环境 |
| `test_builtin_tools.py::…test_runtime_diff_probe_warns_on_target_php_version_mismatch` | 环境 |
| `test_builtin_tools.py::…test_runtime_diff_probe_emits_php5_remote_candidate_…` | 环境 |
| `test_ocr_vision.py::test_ocr_vision_fallback_fires_when_local_fails` | `PermissionError: E:\vulnclaw\test\empty_test.png`（本会话沙箱只允许写工作区） |
| `test_mcp_lifecycle.py::test_persistent_stdio_shutdown_has_no_cross_task_error` | 沙箱禁止管道 stdio |
| `test_spawn_hardening.py::…test_taskkill_fallback_when_job_creation_fails` | `child pid missing from output`（同上） |

`python scripts/verify_execution_boundary.py` → **27 spawn site(s), all inside the
reviewed allowlist**（与基线一致）。

### [实测] 重查在本机真实库上的效果 = **无变化**

用真实 Weblogic 控制台页面构造探测证据（title/Server/X-Powered-By/`/wls-wsat/…`/
`/uddiexplorer/…`/`j_username`）得到 14 token 的查询，在本机 70 条笔记的库上
**没有带来任何新命中**（仍然是开局那条 `autonotes-b9bbb32f-…`）。

**[推断]** 原因：本机库里根本没有 Weblogic/ThinkPHP 笔记，所以"用实测特征重查"
无处可施。**因此"重查能提升解题"这件事在本轮没有任何实测支撑**，只有机制级的
单测证据（重查会发生、会替换、会进日志）。要验证收益必须在有对应笔记的靶机上跑配对。

---

## 3. 没做的部分（明确声明）

1. **冷/热配对实测（交接文档 §4.1 / §6.3）没做。** 需要至少 3 组 × 2 臂 = 6 次真实
   solve + 每臂新开靶机 + 逐臂 `stop_target`。本会话未获得平台凭据可用性的确认、
   也没有把 6 次运行跑完的预算；**本轮结论全部来自单测与本机静态测量，没有一次真实
   solve 数据**。按 §5.1，n=1 且非同靶机的对比本来也不足以下结论。
2. **套话 token 的修法没做**（见 §1 末），留给下一轮单独做。
3. **重查的第二个信息源（黑板 LOCK / CONFIRMED facts）没接入。** 交接文档 §3 任务 1 提到
   它可作为触发条件；本轮只用**实测的探测证据**，因为把模型自述的散文混进一个
   "先量后说"的改动会让效果无法归因（模块 docstring 里写明了这个取舍）。
4. **`fetch` / `python_execute` 的响应体解析只做了保守支持**：`probe_signature` 认
   `http_probe_batch` 的制式输出（`body:` 标记 + `response_headers=`），其它工具名在
   `HTTP_EVIDENCE_TOOLS` 里但若输出格式不同则取不到特征 → 返回空查询 → 不重查（安全降级）。

---

## 4. 一句话结论

**实测**：≥2 token 门在真实 70 条笔记库上确实消灭了"单 token 跨框架满分命中"
（每个真实题面砍掉 0-2 条 1-token 碰撞），代价是这些笔记不再注入；重查机制在单测层面
端到端可用（含主循环接线、事件、notice、预算、异常兜底），但在本机库上**没有可测收益**。
**实测的更大漏洞**：平台套话 token 让一条无关自动笔记稳定拿 0.556 排第一，≥2 token 门
挡不住它 —— 这也是"命中≠有用、相关性必须由模型带靶机验证"必须继续成立的原因。
**未做**：3 组冷/热配对实测（因此本改动**没有真实解题收益数据**）。
