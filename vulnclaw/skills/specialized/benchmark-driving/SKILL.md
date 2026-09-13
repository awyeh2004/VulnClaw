---
name: benchmark-driving
description: 跑分基准平台驱动 — 用外部 SDK 驱动 VulnClaw 批量解题的完整方法论：以 TSecBench 为参照，覆盖 VPN/凭证预检、容器生命周期(start/submit/close)、持续补位调度、flag 规范化提取、断点续跑、fail-fast 弃题阈值与常见坑(容器槽满/重复提交/网络断连)。适用于任何"批量评测 agent 解题性能"的场景。
requires_target: false
routing:
  task_types: [ctf]
  aliases:
    - 跑分
    - benchmark
    - tsecbench
    - 性能测试
---

# 跑分基准驱动 Skill

把 agent（如 VulnClaw）接入解题跑分平台（参照实现：腾讯 TSecBench
`https://tsecbench.zc.tencent.com`），批量评测解题性能。本 skill 沉淀的是
**驱动架构与实战教训**，参照实现在 `tsec_bench/run_bench.py`。

## 一、接入三要素（缺一即停）

1. **凭证**：平台发放 `BENCHMARK_TOKEN`(UUID) + `BENCHMARK_BASE_URL`。
   写独立凭证文件（如 `tsec.env`，**gitignore**）或环境变量；缺失时打印
   领取指引后退出，不要带着占位符继续。
2. **网络预检**：靶机通常在内网（VPN 之后）。开跑前 GET 预检地址（TSecBench
   为 `http://10.0.100.58`，要求响应 `status=="ok"`）。**VPN 会断**（实测断过
   一次），断连症状 = 多个 solve 同时无产出终止；OpenVPN Connect 会自动重连，
   驱动的断点续跑负责消化善后。
3. **SDK 真实签名**：文档与 SDK 实际接口可能有出入（实例：文档没写
   `container_addr` 是 list）。**先 `inspect.signature` 核对再写代码**。

## 二、平台协议（TSecBench 为例）

```
GET  /openapi/v1/challenges              列题(unique_code/difficulty/is_completed/container_addr)
POST /openapi/v1/challenges/start?unique_code=   开容器 → container_addr
POST /openapi/v1/challenges/submit       body {unique_code, flag}
POST /openapi/v1/challenges/close?unique_code=   释放容器
认证头: BENCHMARK_TOKEN；hint 会扣分，不取
```

- **同时最多 3 题活跃**，超出报 409 `invalid_state`。
- 重复提交返回 `duplicate`（幂等，安全）；超时后返回 `invalid_state`，应停手。

## 三、驱动架构（实战验证的关键设计）

### 调度：持续补位，绝不一次提交全部

只维持 N 个工人线程（= 平台槽位上限），从队列取题、完成即取下一题。
**一次性 submit 全部队列 = 落选线程立刻撞 409 全部假失败**（实测 34 题同时
假 failed 的教训）。遇 409 先 close 该题遗留容器再重试一次（中断恢复场景）。

### 解题：子进程隔离

每题一个 `python -m vulnclaw solve <container_addr> --no-resume --force-fresh`
子进程。进程隔离规避同进程并发的共享状态污染（memory 目录/MCP 会话/黑板）。
库内直调只在串行场景用，且每题重建 AgentCore。

### flag 提取三道闸

1. `extract_flags`（宽松正则）粗提；
2. **规范化**：修剪文本边界毛刺（`nflag{`/`ag{`/`lag{` ←→ `flag{`），否则
   残缺变体会被当真 flag 烧提交次数；
3. `is_placeholder_flag` 过滤模板占位符 + 保序去重。

提交按候选顺序，`correct` 即停；`DuplicateSubmit` 幂等跳过；`InvalidState`
（超时）停手；每题设提交上限（默认 6）。

### 断点续跑

`state.json` 记录每题 status/flags/score/elapsed；重跑跳过平台侧
`is_completed`（双保险）。任何时刻杀驱动都不丢分。

## 四、超时与弃题阈值（实测数据支撑）

deepseek-v4-flash 实测分布（3 并行）：

| 题型 | 中位用时 | 说明 |
|------|---------|------|
| 带指引题 | 30-75 秒 | 题面给了漏洞类型/入口 |
| 常规 medium/hard | 1-5 分钟 | 能解的都很快 |
| 盲测题(一句话题面) | 17-31 分钟 | 侦察占大头 |
| 解不出的 | 烧满超时 | a-18 烧 3600s 无产出 |

阈值建议：总上限 **45 分钟**；**40 分钟无 checkpoint 弃题换下一道**
（fail-fast：解不出/没思路/卡住直接换，不恋战）。弃题判据看 run 目录
`run.json` 的 `updated_at` 距今，**不要**用固定时长猜——`finding_added`
之后的静默是验证推理中，属正常。

## 五、实战教训清单

1. **重启驱动 = 丢弃全部在途 solve**。在途题可能只差十几分钟出分
   （c-03 案例：第 2 次尝试被杀时已找对 CVE 方向，第 3 次 31 分钟解出）。
   切换配置前先评估在途价值。
2. **模型选择决定吞吐**：glm-5.3-flash 深度思考单轮 7-10 分钟，跑分场景
   完全跑不动；deepseek-v4-flash 单轮 2-5 分钟，正确率没掉。切换时注意
   **failover 池 `api_keys` 与 `api_key` 是两个字段**，只改一个会 401。
3. **盲测题成本 ≈ 带指引题 ×2 以上**。排序策略：同难度下题面信息多的先做；
   已知无解的盲测题直接 `--skip`。
4. **重复提交无害但要收敛**：平台幂等，但 writeup/state 会脏；规范化+
   去重后每题收敛到 1-2 次提交。
5. **playbook 复用是隐性加速器**：同类题解出后 `save_playbook`，后续同栈
   题目开局 `lookup_playbook` 直接继承打法（React2Shell RCE playbook 即
   由 c-03 沉淀）。
6. **单题内部时限**（45 分钟）与**停滞检测**（40 分钟无 checkpoint）双闸：
   前者防长尾烧槽，后者防"永远在思考"。

## 六、参照实现

`D:\GitClone\VulnClaw\VulnClaw\tsec_bench\run_bench.py`（本地测试工具，
不提交 git）：

```bash
python tsec_bench/run_bench.py --selftest              # 离线自测
python tsec_bench/run_bench.py --dry-run               # 列题计划
python tsec_bench/run_bench.py --model ds              # 全量(easy优先)
python tsec_bench/run_bench.py --challenge a-05        # 单题
python tsec_bench/run_bench.py --skip c-03,c-06        # 跳过指定题
```

配套文档：`tsec_bench/README.md`（使用说明）、
`tsec_bench/c03_analysis.md`（三次解题对比的深度复盘案例）。
