# VulnClaw 机制联动（共享参考）

本文件用于把 skill 的领域方法与 VulnClaw 的黑板、攻击面、证据和收尾机制接起来。skill 负责“怎么测”，本文件负责“状态怎么记、什么时候收面、什么算证据”。

## 1. 基本循环

```text
LOCK → ANGLES → INTENT → EVIDENCE/FACT → REVIEW → HIT/MISS → FINDING
```

1. `blackboard_set_lock`：写清目标、边界、成功条件。生产审计写“已确认的读/写/执行/越权”；CTF 写题面理解和 flag 位置假设。
2. `blackboard_create_angle`：把攻击面拆成独立 ANGLE。不要只开一个“测试目标”的总 ANGLE。
3. `blackboard_add_intent` + `blackboard_start_intent`：每个具体测试方向一条 intent；失败用 `blackboard_reject_intent`。
4. `evidence_*`：请求/响应、日志、截图、命令输出先入证据。
5. `blackboard_add_fact(description, evidence_ref=...)`：有 witness 才是 CONFIRMED；没有 evidence 是 candidate。不要手动把 candidate 写成 confirmed。
6. `blackboard_verify_fact`：只在 evidence 里确实能看到描述时调用。
7. `blackboard_hit_angle` / `blackboard_miss_angle`：每个 ANGLE 必须有结论，不能悬空。
8. `blackboard_review` / `blackboard_summary`：每 3–5 步或换面前读一次，避免重复 dead end。
9. `report_finding` / `submit_gate`：生产报告必须过证据门；CTF 的 `blackboard_record_answer` 不要用在生产审计。

## 2. 攻击面 / WebMap

- Web/API/本地 HTTP：`web_map_add(url, method, params, content_type, notes)`，
  关系用 `web_map_link(from_url, to_url, kind, notes)`，决策前 `web_map_summary`。
- 非 Web 面（IPC、文件、协议、MCP Apps、更新器）：用 `blackboard_create_angle` 建 ANGLE，
  不要硬塞进 WebMap。
- 并行 surface wave：`extract_attack_surfaces` 从 `session.recon_data`
  （`network_services` / `subdomains` / `paths`）和 findings 提取；发现路径/子域/服务后
  尽早落到 `recon_data` 或 WebMap，不要只留在对话里。
- 每个 surface 仍要独立 ANGLE；root 只保留 LOCK、汇总和未决 TENSION。

## 3. 证据与状态

- Fact 描述必须包含可在 evidence 中被 witness 的具体字符串（状态码、路径、日志行、JSON 字段）。
- 代码与运行时冲突：`blackboard_create_tension` 记录“代码看起来允许 vs 运行时拒绝/放行”，再做一次可复现验证。
- 只有 candidate 时不能写“已复现”；报告里明确“已确认/未确认/链式假设”。
- 测试产生的临时文件、服务、调试端口要清理；证据保留但不含真实 token/用户数据。

## 4. 其他机制

- **playbook**：新目标先 `lookup_playbook`；确认后 `save_playbook` 保存可复用 recipe，
  但先脱敏（不放 token、用户路径、真实域名/账号）。`playbook_refresh` 自动维护，不要手改。
- **reflexion**：同一路径连续失败两次，`blackboard_miss_angle` + 新 ANGLE；不要重复同一 payload。
- **task_mode**：goal/描述写清 `audit` / `pentest` / `ctf`；生产审计不要套 CTF fail-fast，按面逐项验证。
- **correction_layer**：工具参数/路径被拒时，先 `blackboard_create_tension` 记录代码与运行时差异，
  再用 CDP/日志确认，不要直接改结论。
- **submit_gate**：最终 finding 必须能追溯到 evidence；没有 witness 的 fact 不能作为报告依据。


## 4.1 Skill workflow（可选阶段表）

显式调用的 skill 可以在 frontmatter 声明 `workflow:`：

```yaml
workflow:
  modes: [pentest, audit]
  phases:
    - id: surface
      goal: ...
      tools: [source_extract, blackboard_create_angle]
      evidence: [ASAR listing]
      exit: every surface has an ANGLE
  gates:
    - after: surface
      require: [web_map_summary]
```

用法：

- 每个 phase 对应一个 `blackboard_create_angle`，开始前建 ANGLE，结束用
  `blackboard_hit_angle` / `blackboard_miss_angle` 关闭；
- 当前 phase 未决时不要开下一个；`gates` 里的工具先跑再进入下一阶段；
- FINAL 前所有 phase 必须关闭，confirmed finding 必须绑定 evidence；
- workflow 只是阶段表，不替代 `blackboard_summary` / `blackboard_review`；
- CTF 的 fail-fast 优先于 workflow 阶段表，不要因为阶段没走完而卡死。

## 5. 生产 / CTF 分离

- 本地 `vulnclaw` 是 CTF/aw；生产用 prod worktree 的隔离入口，不要改全局 editable 安装。
- CTF 可以用 `blackboard_record_answer` 进入 answer sheet；生产审计用 `report_finding` + evidence。
- 生产 skill/证据不对外复制；共享参考也不包含真实目标数据。


## 6. 运行 / 安全门（自动机制，但 skill 要配合）

- `exec_gate` + `constraint_policy` + `command_classifier`：shell/python/远程命令会过
  范围与只读/危险命令分类。被拒绝时不要绕过；把约束写进 `blackboard_create_tension`
  或 `constraint_policy` 的允许项，换等价的只读验证。
- `anti_loop` + `loop_controller` + path stall guard：同一路径反复失败会被判 stall。
  先 `blackboard_review`，把失败路径 `blackboard_miss_angle`/`reject_intent`，
  再开新 ANGLE；不要换参数重放同一个 payload。
- `correction_layer`：工具参数/路径/协议被拒时，记录“代码允许 vs 运行时拒绝”，
  用 CDP/日志再确认，不要直接改结论。
- `context_budget` + `context_vault`：大输出不要把全文塞回上下文；先
  `evidence_*` 存档，再用短摘要 + evidence handle 推进。
- `tool_registry` / `tool_schemas` / `tool_result_overrides`：工具面会按任务类型裁剪；
  看不到某个工具时先 `load_skill_reference` 或查 schema，不要假设工具不存在。

## 7. 上下文 / 经验 / 知识

- `kb_context`：知识库检索结果进入上下文；引用时保留来源，不要把 KB 内容当目标事实。
- `experience_context` + `memory_search`：先查跨会话经验和冷记忆，避免重复踩坑；
  经验里的结论仍需当前目标 witness，不能直接当 CONFIRMED。
- `distiller` + `vulnclaw learn`：run 结束后蒸馏经验；`vulnclaw experience
  review/list/show/approve/reject/edit` 人工审核，只有 approved 的 lesson 才能影响后续。
- `vulnclaw feedback`：给已完成 run 附加 operator assessment，用于后续经验质量。
- `vulnclaw kb update/status`：知识库更新与检索后端状态；不要手工改 KB 文件。

## 8. Finding 生命周期

- `finding_parser` / `finding_similarity`：finding 会被解析、去重、相似度合并；
  同一根因不要重复 `report_finding`，先查已有 findings。
- `report_finding`：生产 finding 的唯一入口；需要 evidence handle，不要用
  `blackboard_record_answer` 代替。
- `submit_gate`：报告/提交前做 grounding 校验；没有 witness 的 fact 不能过门。
- `vulnclaw report` / `solve_report`：从 session/target state 生成报告；报告里的
  攻击链按实际步骤生成，不要手写未发生的步骤。
- `vulnclaw retest <finding_id> --verdict reproduced|fixed|inconclusive --note ...`：
  修复后复测；`--list`/`--sweep` 管理复测会话。
- `evidence gc/unbind/reorder`：证据维护；默认只读，不要删除仍被 finding 引用的 blob。

## 9. 状态 / 恢复 / 观测

- `target_state`：`vulnclaw target-state list/preview/diff/rollback/clear`；
  长周期审计用 snapshot 恢复，不要清空别人的目标状态。
- `runtime_state` / `agent_state`：运行状态、evidence、findings 的持久化；
  恢复 run 时先看 `blackboard_summary` 和 evidence，不要从零重放。
- `turn_metrics` 事件 + `scripts/replay_turn_metrics.py`：排查 stall/工具循环/
  token 异常；这不是攻击工具，是复盘工具。
- REPL 空 Enter 会 resume 未完成 run（保留 blackboard/evidence），不是新开 run。

## 10. 多 Agent / 攻击面 wave

- `agent_graph`：durable AgentGraph 是并行 surface 的 source of truth；
  root 只负责 discovery + LOCK，child 按 surface 领 ANGLE。
- `team` + `subagent` + `roles`：team 模式按角色/子任务拆分；每个 child 仍要
  `blackboard_add_fact(evidence_ref=...)`，合并时不要丢 evidence。
- `parallel_agents` / `extract_attack_surfaces`：surface 来自
  `session.recon_data`（network_services/subdomains/paths）和 findings；
  本地 HTTP/路径/子域尽早落到 `recon_data`/WebMap。
- `input_analysis` / `recon_tracker`：从目标输入和 recon 进度提取 surface；
  不要把用户粘贴的 brief 直接当 attack surface（可能把答案/噪声当目标）。

## 11. 范围 / 平台

- `hackerone_scope`：HackerOne 项目先拉 scope；scope 外不发请求。
- `platforms` / `ctf_platform` / `gcs_platform`：CTF/比赛平台适配器；
  生产审计不要走 CTF 提交/计分链路。
- `vulnclaw persistent` / `recon` / `scan` / `exploit`：分阶段 run；
  phase 之间用 target_state/blackboard 交接，不要重复全量扫描。
- `vulnclaw code scan`：本地源码扫描（L1/L2/L3），不替代动态验证；
  L3 结果必须手工降噪，再进 blackboard fact。

## 12. CTF 专用（生产不要用）

- `ctf_mode` + `blackboard_record_answer`：answer sheet / flag 提交；
- `ctf2` / `gcs` / `competition`：比赛平台与策略；
- `benchmark-driving` / `competition-mode` / `ctf-*` skills：CTF 节奏；
- 生产审计只用 `report_finding` + evidence + retest，不用 answer sheet。


## 13. 工具族速查（按能力，不按名字背）

工具面会按任务类型裁剪；先看 schema，再决定用哪个。不要假设某个工具一定在，也不要用 `python_execute` 伪造工具结果。

### 13.1 侦察 / Web

| 工具 | 用途 | 注意 |
| --- | --- | --- |
| `fetch` | 单请求抓取/查看响应 | 走范围门；重定向逐跳校验 |
| `http_probe_batch` | 批量 HTTP 探测 | 不替代手工确认；结果进 evidence |
| `nmap_scan` | 端口/服务扫描 | 只扫授权范围 |
| `brute_force_login` | 登录爆破 | 只对授权账号；注意锁定策略 |
| `space_search` / `subdomain_enum` | 空间测绘/子域 | 被动优先，结果落 recon_data |
| `js_recon` | JS 接口/密钥提取 | 默认会跑未授权探测；接口要进 `unauth_test` |
| `unauth_test` | 未授权访问验证 | 与带凭据请求做差分 |
| `dir_enum` | 目录/文件枚举 | 404 基线 + 状态码过滤 |
| `osint_recon` | OSINT | 不碰非授权个人数据 |

### 13.2 HTTP 流量 / 证据

| 工具 | 用途 | 注意 |
| --- | --- | --- |
| `traffic_list` | 列出已捕获请求 | 先拿 `request_id` |
| `traffic_view` | 查看请求/响应 | 保留原始报文 |
| `traffic_repeat` | 重放请求 | 过 host/path/port 约束；不要改范围 |
| `traffic_bind_evidence` | 把报文绑定到 finding | `report_finding` 后用它补证据 |
| `evidence_list/view/search` | 证据查询 | 报告只引用已绑定 evidence |

### 13.3 上下文 / 经验

| 工具 | 用途 | 注意 |
| --- | --- | --- |
| `vault_archive` / `vault_restore` / `vault_search` / `vault_status` | 长会话归档/恢复/检索 | 先 search 再 restore，不要全量回填 |
| `memory_search` | 冷记忆检索 | 经验结论仍需当前 witness |
| `kb_context` / `experience_context` | 自动注入知识/经验 | 不要当目标事实 |

### 13.4 源码 / 运行时

| 工具 | 用途 | 注意 |
| --- | --- | --- |
| `source_extract` | 源码/ASAR/文件提取 | 只读；保留路径/行号 |
| `runtime_diff_probe` | 运行时差异探测 | 用于 hardening/配置对比 |
| `remediation_advice` | 修复建议 | 不替代验证 |
| `python_execute` / `shell_command` | 本地计算/命令 | 过 exec_gate；不绕范围 |
| `bg_launch` / `bg_result` | 后台爆破/计算 | 只允许白名单命令；结果要真实复验 |

### 13.5 远程 / 多媒体

| 工具 | 用途 | 注意 |
| --- | --- | --- |
| `remote_exec` / `remote_collect` / `remote_fetch` / `remote_hosts` | SSH 目标操作 | 先配 `remote.hosts`；命令仍过分类器 |
| `ocr` | 图片/截图 OCR | 本地 GPU；不读无关图片 |
| `pyc_analyze` | pyc 反编译/常量分析 | CTF/逆向用 |
| `pdf_analyze` | PDF 文本/取证 | 不处理超范围文档 |
| `crypto_decode` | 编码/解码 | 只做本地计算 |

### 13.6 子 agent / 任务控制

| 工具 | 用途 | 注意 |
| --- | --- | --- |
| `agent_run` | 启动 group-leader / researcher / executor / verifier | briefing 必须自包含：目标、scope、已知证据、返回物、停止条件 |
| `agent_job` | list / collect / message / cancel 后台 agent | 终态结果可重复 collect；完成会自动通知 |
| `agent_graph` | durable 多 agent 图 | root 只做 discovery/LOCK，子节点按 surface 领 ANGLE |
| `roles` / `team` | 角色/team 模式 | 子 agent 证据有 namespace；只引用父级 `parent_evidence_ids`，不要引用 leaf-local id |

### 13.7 CTF / 平台专用（生产审计不要用）

| 工具 | 用途 |
| --- | --- |
| `pwn_local_replay` / `pwn_local_stop` / `libc_lookup` | pwn 本地复现/libc |
| `ctf2_submit_flag` / `gcs_submit_flag` / `platform_submit` | 比赛平台提交 |
| `blackboard_record_answer` | CTF answer sheet |
| `competition` / `ctf2` / `gcs` CLI | 比赛入口 |

### 13.8 工具面规则

- `_ALWAYS_KEEP_TOOLS` 里的工具（blackboard、web_map、evidence、report_finding、
  load_skill_reference、remote、lookup/save_playbook、ocr/pyc/pdf 等）通常不会被裁剪；
  其余工具按 task bundle 裁剪。
- 工具没出现时：`tool_schemas` 查当前 face，或 `load_skill_reference` 查 skill 参考；
  不要用 `python_execute` 绕过工具/范围门。
- 每个工具结果先进 evidence，再进 blackboard fact；不要把工具输出直接当 CONFIRMED。

- MCP service tools 要看 `vulnclaw doctor`：`fetch`/`memory` 本地可用；
  `chrome-devtools` 可能 disabled；`burp` 可能只是 placeholder（需 SSE 9876）；
  `ctf2-*` 可能 401。不要把“注册了”当成“可用”。

