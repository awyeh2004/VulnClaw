# 比赛抢分策略指南

限时 CTF 竞赛环境下的具体操作细节，配合 `competition-mode` SKILL 使用。

## 一、识别比赛环境

出现以下信号时视为比赛模式：
- 有题目列表接口（`exercise_list` / `challenge` 列表），带 `score`/`difficulty` 字段
- flag 需提交到平台（`gcs_submit_flag`）并按平台格式校验
- 有排名/积分、全局时间限制、多人同场

## 二、赛前准备（前 10% 时间）

### 1. 探测 LLM 延迟 → 决定并发
```
probe_llm_latency()  # 或实测一次小请求
```
- `avg > slow_llm_threshold_s`(默认 5s)→ **单 agent**、低 `max_rounds`、减少并行
- `avg <= threshold` → 可多 agent/并行抢分
- 后端 429/余额错误频繁时 → 降级单 agent + 指数退避（避免重试烧时间）

### 2. 易题优先排序
- 平台可达：`exercise_list()` → 按 `score` 降序（score 高通常=简单/已验证）
- 平台不可达：退化 `VULNCLAW_WORK_DIR/attachments/` 本地清单

### 3. 赛初批量下载附件（保险）
- 遍历列表 → `exercise(eid)` → 防御式匹配下载链接字段
  `attachmentUrl | fileUrl | downloadUrl | attachment.url | file.download_url`
- 存到 `work/attachments/{eid}_{name}.zip`
- 目的：后端关闭/变慢后，已下载附件仍可本地离线分析

## 三、赛中：fail-fast 单题求解

- 逐题 `solve`，设 **停滞检测**：连续 `stall_turns`（默认 8）个无进展 turn 即弃题
- 每题控制 `max_steps`（如 `stall * 4`），别让卡死的题吃掉全部时间
- 环境失效（404 "Target not found"）：
  - 已构造好 payload/解法 → 换新 host 直接重放（参考 solve playbook 的 `{HOST}` 占位复用）
  - 否则放弃该题

## 四、提交与复用

- flag 按平台格式提交（`flag{}` / `FLAG{}` / 纯 token 区分），拿到即交
- 同题换实例：优先 `lookup_playbook` 查旧配方重放，而非重新推导（省时间）

## 五、时间分配

| 阶段 | 动作 |
|------|------|
| 前 10% | 探延迟 + 拉列表 + 批量下载附件 |
| 中段 | 易题优先 fail-fast 逐题求解 |
| 尾段 | 攻坚难题 / 核查已交 flag |
