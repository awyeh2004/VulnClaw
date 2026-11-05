---
name: ai-mcp-security
description: AI与MCP安全评估 — Prompt注入、工具滥用、MCP信任边界、Agent权限逃逸、数据泄露、模型风险、GAARM风险矩阵
routing:
  target_types: [ai_agent, mcp]
  task_types: [pentest, audit]
  technologies: [llm, rag, memory, plugin]
  vulnerability_classes: [prompt_injection, tool_abuse, info_disclosure]
shared_references:
  - vulnclaw-mechanisms.md

workflow:
  modes: [pentest, audit]
  phases:
    - id: inventory
      goal: Inventory LLM/agent/MCP/tools/skills/RAG/memory components and trust boundaries
      tools: [source_extract, fetch, blackboard_create_angle]
      evidence: [component list, tool schemas, config]
      exit: Every component has an ANGLE
    - id: prompt
      goal: Test direct/indirect prompt injection and context/memory poisoning
      tools: [fetch, python_execute, evidence_view]
      evidence: [prompt, response delta, canary]
      exit: Injection confirmed or rejected
    - id: tool-abuse
      goal: Test tool description poisoning, unauthorized tool calls, and MCP trust boundary
      tools: [traffic_list, traffic_view, evidence_view]
      evidence: [JSON-RPC transcript, tool call log]
      exit: Tool abuse confirmed or rejected
    - id: authz
      goal: Test app/server identity, token scope, and cross-app access
      tools: [traffic_list, http_probe_batch, evidence_view]
      evidence: [with/without token, cross-app result]
      exit: Authorization flaw confirmed or rejected
    - id: data
      goal: Test prompt/secret leakage and egress channels
      tools: [evidence_search, traffic_list, evidence_view]
      evidence: [leaked data, outbound request]
      exit: Leak confirmed or rejected
    - id: report
      goal: Bind evidence and report only confirmed findings
      tools: [traffic_bind_evidence, report_finding, blackboard_set_lock]
      evidence: [bound request, reproduction log]
      exit: report_finding accepted and completion gate passed
  gates:
    - after: inventory
      require: [blackboard_summary]
    - after: report
      require: [blackboard_summary]

---

# AI 与 MCP 安全评估 Skill

当目标包含 LLM、Agent、MCP 工具、Skills、RAG、Memory、Plugin 或模型服务组件时使用本 Skill。

**前置条件**：如果 AI 表面只是展示层，真正的阻塞仍是客户端签名或加密协议，先回到 `client-reverse` Skill。

## 场景路由

| 风险类型 | 首选参考 |
|---------|---------|
| Prompt 注入 / 间接注入 / CoT 干扰 | `references/ai-app-security.md` |
| 工具滥用 / MCP 投毒 / Skills 供应链 | `references/04-ai-and-mcp-security-integrated.md` MCP 章节 |
| 权限逃逸 / 角色越界 / 凭据滥用 | `references/ai-identity-security.md` |
| 数据泄露 / Prompt 泄漏 / 模型逆推 | `references/ai-data-security.md` |
| 容器逃逸 / CI-CD / 沙箱失败 | `references/ai-baseline-security.md` |
| 模型风险 / 对抗样本 / 后门 | `references/ai-model-security.md` |
| 影响分类与覆盖评估 | `references/gaarm-risk-matrix.md` |

## 测试流程

### 1. 应用层攻击
- 直接 Prompt 注入
- 间接注入（通过外部数据源）
- CoT 干扰与指令覆盖
- Agent 滥用（未授权操作）
- 代码执行突破
- Memory 投毒

### 2. MCP 与 Agent 风险
- 工具描述投毒
- 指令覆盖
- 隐藏指令注入
- 未授权资源访问
- Skills/Rules 供应链问题

### 3. 身份与授权
- 动作滥用
- 角色逃逸
- 权限漂移
- 云凭据滥用

### 4. 数据与隐私
- Prompt 泄漏
- 敏感数据暴露
- 训练数据问题
- 模型逆推
- API 数据窃取

### 5. 基线与部署
- CI/CD 缺陷
- 容器逃逸
- 向量数据库安全
- 沙箱失效
- 环境隔离缺陷
- 模型服务缺陷

## 参考文档

- `references/04-ai-and-mcp-security-integrated.md` — AI 与 MCP 安全整合参考
- `references/ai-app-security.md` — AI 应用安全
- `references/ai-identity-security.md` — AI 身份安全
- `references/ai-data-security.md` — AI 数据安全
- `references/ai-baseline-security.md` — AI 基线安全
- `references/ai-model-security.md` — AI 模型安全
- `references/gaarm-risk-matrix.md` — GAARM 风险矩阵
