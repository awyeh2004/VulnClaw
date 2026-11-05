# VulnClaw CTF 机制（共享参考 · 仅 CTF profile）

本文件只覆盖 CTF/比赛特有机制：flag、answer sheet、比赛平台提交、套娃收尾与节奏。
通用机制（LOCK/ANGLE/EVIDENCE/finding/playbook）在同目录 `operational-mechanisms.md`。

> 生产 profile（`VULNCLAW_PROFILE=prod`）不会加载本文件：loader 会把它从
> `shared_references` 里剔除，`load_skill_reference` 也解析不到。这不是靠文档
> 措辞自律，而是 profile 过滤。

## 1. flag 与证据

- 交付物是平台格式的 flag；`FINAL` 里的 flag 必须能在本次 run 已记录证据中找到，
  否则完成门不收（防猜）。证据通常来自 `evidence_*`、`traffic_*`、工具输出落盘。
- 不要凭题面/记忆“构造” flag；没有 witness 的候选只能写成假设。
- 平台返回 `accepted: true` 才算提交成功；`queued: true` 是已排队，不是失败，也不是成功。

## 2. answer sheet 与平台提交

- `blackboard_record_answer`：CTF 的答案清单，用于 IR 答题制 / 分题提交。
  **生产审计不要用它**——生产用 `report_finding` + evidence。
- `ctf2_submit_flag` / `gcs_submit_flag` / `platform_submit`：比赛平台提交入口。
  - `platform_submit` 需要本次 run 拿到的 challenge `ref`；
  - 没有 ref 时不要枚举平台 collection 去找（实测 10/28 次工具调用、32/79 秒，
    最后 `403 agent_scope_forbidden`）；
  - 提交后必须核对平台返回，`accepted` 才计分。
- `report_finding` 只是本地 finding，**不等于平台提交**。不要把它说成“已上报”；
  工具回执会明确标注“本地 finding，仅写入本次运行”。
- 生产 profile（`VULNCLAW_PROFILE=prod`）下，提交动词在 MCP 与 builtin 两条路由上
  都会被拒绝——不是提示词约束。

## 3. 套娃 / 多层题的收尾

比赛里存在“内层 flag 是诱饵”的题（2026-10-31 ezphp：镜像里烤了
`flag{You_are_so_smart_8080}`，它在证据里，证据门放行，run 提前两层收工）。

因此当 goal 本身说了套娃/多层/下一层/更深一层时，`FINAL` 必须说明为什么这是
最后一层（例如“没有下一层”“不存在后续层级”“已到达最底层”），或者直接给确定性标记：

```text
FINAL_STATUS: deepest_layer_confirmed
```

自然语言词表覆盖常见同义表述，但否定语境不算（“还不能确认没有下一层”会被拒绝）。

反向约束：

- 单层题不受影响；
- “多层编码 / 逐层解码 / 多阶段流程 / layered defense / nested archive”这类
  描述**不是**套娃题，不该被要求最终层声明；
- 该规则是 **CTF 完成策略**（`state.task_mode == "ctf"`），生产 run 不会触发。

## 4. 节奏

- `competition-mode` skill：赛初 batch-download 附件作保险、易题优先、fail-fast。
- fail-fast：约 8 轮无进展就弃题换题；但安全加固类题（加固/安全加固）例外，
  按 30–40 分钟时间盒走加固流程并保持服务存活。
- 提交窗口（`competition.submit_windows`）配置后，提交调用会落盘并到时刻自动发出，
  模型收到 `queued: true` 属正常。

## 5. CTF 专用工具族

| 工具 | 用途 |
| --- | --- |
| `pwn_local_replay` / `pwn_local_stop` / `libc_lookup` | pwn 本地复现 / libc |
| `ctf2_submit_flag` / `gcs_submit_flag` / `platform_submit` | 比赛平台提交 |
| `blackboard_record_answer` | CTF answer sheet |
| `competition` / `ctf2` / `gcs` CLI | 比赛入口 |

生产审计不要使用以上任何一项。
