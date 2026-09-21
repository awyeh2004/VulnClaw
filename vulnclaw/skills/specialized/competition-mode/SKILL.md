---
name: competition-mode
description: 比赛模式策略 — CTF 竞赛(西湖论剑/DASCTF)下抢分策略 + 应急响应实战赛答题制策略。CTF: 赛前探 LLM 延迟决定单/多 agent、易题优先排序、fail-fast 停滞弃题换题、按平台 flag 格式提交。IR赛: 快速分型→按面排查→答案格式化→逐题提交。适用于限时多人竞赛环境，追求单位时间得分最大化。
requires_target: false
routing:
  task_types: [ctf, triage, audit]
  target_types: [ctf, host, web]
---

# 比赛模式 Skill

限时 CTF 竞赛（西湖论剑、DASCTF 等）下，目标是**单位时间得分最大化**，而非把单题做深。判断
自己是否在比赛环境：有题目列表/排名接口、flag 需按平台格式提交、有全局时间限制。此时应切换
到本策略，与开放式的单题深挖（默认 solve 流）不同。

## 核心原则

1. **先易后难**：先拿大量低分题的分，难题留到最后或用剩余时间。
2. **fail-fast**：连续若干 turn 无进展（如 8 turn）就果断弃题换下一题，不恋战。
3. **保险优先**：赛初（或平台可能关闭前）先批量下载所有附件，即使后端关了也能本地分析。
4. **后端省着用**：比赛后端通常共享/易过载，能单 agent 就别并行，能少重试就少重试。

## 赛前：探测 LLM 延迟，决定单/多 agent

- 用 `probe_llm_latency`（或实测一次小请求）量后端延迟。
- **延迟高（如 > 5s）** → 强制**单 agent**、低 max_rounds，并行越多越慢（共享后端互相挤）。
- **延迟低** → 可考虑多 agent/并行抢分。
- 后端不可达/频繁 429/余额类错误时，立即降级为单 agent + 减小重试，别让重试烧时间。

## 赛前：易题优先排序 + 批量下载

0. **知识竞赛/理论题环节最先做** — 它零环境依赖、不受靶机过载影响、答完即
   锁定得分，是单位时间得分率最高的一类题。进场比赛若存在知识竞赛入口，
   先按 knowledge-quiz 策略批量读题作答并提交，再回到攻防题。
1. 拉题目列表（GCS `exercise_list` / CTF2 `challenge` 列表），**按 score 从高到低**（即简单题先做）排序。
   - 平台可达 → 直接取列表的 score/difficulty。
   - 平台不可达 → 退化为本地 `work/attachments` 目录里的文件清单。
2. 赛初 **batch-download 全部附件**到本地工作目录（`VULNCLAW_WORK_DIR`）作保险：
   - 附件 URL 字段名可能变（attachmentUrl/fileUrl/downloadUrl/嵌套 attachment.url），防御式匹配。
   - 平台关闭后，已下载的附件仍可供本地离线分析。

## 赛中：fail-fast 单题求解

- 用 GCS/CTF2 的 `solve`（或 `competition solve <eid>`）逐题求解，**停滞检测**：`stall_turns`
  （默认 8）个无进展 turn 后中止该题，转下一题。
- 每题限制 `max_steps` 控制，避免一道卡死的题吃掉全部时间。
- 环境失效（404 "Target not found"）时：若已构造好 payload/解法，直接换新 host 重放；否则弃题。

## 提交

- flag 必须按**平台要求的格式**提交（`gcs_submit_flag` / 对应平台接口），注意区分
  `flag{}` / `FLAG{}` / 纯 token 等格式差异。
- 拿到 flag 立即提交，再继续下一题——不要攒着一起交。

## 时间分配建议

| 阶段 | 动作 | 目标 |
|------|------|------|
| 前 10% | 探延迟 + 拉列表 + 批量下载附件 | 定单/多 agent、抢简单题 |
| 中段 | 易题优先逐一 fail-fast 求解 | 累积分数 |
| 尾段 | 攻坚难题或核查已交 flag | 查漏补缺 |

## 参考

- `references/competition-strategy.md` — 比赛抢分策略具体操作细节
- `references/ir-competition-strategy.md` — **应急响应赛答题制策略**（IR 赛必读）
- `knowledge-quiz` — 知识竞赛/理论题批量作答策略，开局抢分首选
- `ctf-web` / `ctf-crypto` / `ctf-misc` / `crypto-toolkit` — 具体题型的攻击知识
- `incident-response` — 应急响应完整方法论 + 出题方教材 14 案例知识库
- solve playbook（`lookup_playbook`/`save_playbook` 工具）— 同题新靶机复用已解路径，比赛换实例时尤其省时间
