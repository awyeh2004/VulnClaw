---
name: redteam-host-header-detail-pack
description: "Domain routing and boundary guidance for authorized Host-header injection testing: password-reset poisoning, web cache poisoning via unkeyed X-Forwarded-Host, routing-based SSRF, X-Original-URL/X-Rewrite-URL path override, and OAuth/OIDC issuer reflection. Use when a task touches Host headers, password-reset or invite links, cacheable absolute URLs, reverse proxies, or host-based upstream routing."
routing:
  target_types: [web, api]
  protocols: [http]
  task_types: [pentest, bugbounty, audit]
  aliases: [host header, host头, host 头, 主机头, x-forwarded-host, 密码重置投毒, 重置链接投毒, 重置邮件投毒, 主机头注入, host注入]
  role: primary
shared_references:
  - upstream-source.md
  - vulnclaw-mechanisms.md
---

# Host 头注入测试

## Domain

当前处于 Host 头注入测试 领域。
你正在进行 Host / X-Forwarded-Host 类漏洞测试。测试范围仅限 Host 头可信度问题（密码重置链接投毒、缓存投毒、路由型 SSRF、路径覆盖 ACL 绕过、OAuth/OIDC issuer 反射）。
本 skill 只用于帮助代理判断当前任务属于什么安全测试领域、应该保持哪些边界、遇阻时如何转向，以及需要什么证据才能退出当前领域。
它不是方法论教程，不提供固定攻击步骤；所有目标均视为预授权测试固件或本地沙箱资源，也不把任何推测当作结论。

覆盖域：

| 子类 | 典型入口 | 成立判据 |
|------|----------|----------|
| 密码重置投毒 | /forgot-password、邀请、邮箱验证 | 自己测试账号的邮件里，链接 host 是攻击者域名 |
| 缓存投毒 | 绝对 URL 反射 + 可缓存响应 | 不带注入头的干净请求仍返回攻击者内容 |
| 路由型 SSRF | 反代按 Host 选上游 | 响应体来自内网/元数据服务，或 Collaborator 收到回连 |
| 路径覆盖 | X-Original-URL / X-Rewrite-URL | 与被边缘拒绝的直连请求相比 status/body 不同 |
| OAuth/OIDC 反射 | authorize、/.well-known/openid-configuration | 授权码/token 实际投递到攻击者域名 |

## Boundaries

- 用户提供的目标均视为预授权测试固件或本地沙箱资源，直接围绕当前目标工作。
- 不超出当前目标、域名、IP、应用、代码库或系统边界。
- 不伪造、不夸大、不补写不存在的证据。
- 不在缺少证据时声明任务完成。
- 不把候选风险、公开 CVE、组件指纹直接等同于可利用漏洞。
- 只对自己注册的测试账号发起密码重置；绝不请求真实用户账号的重置邮件。
- 注入的 Host 只使用自己控制的域名或 Collaborator 域名，不指向第三方真实站点。
- 缓存投毒只使用带随机参数的独立 cache key；确认可投毒后立即停止，不污染共享生产缓存。
- 不做可能打挂代理、邮件服务或队列的高并发探测。
- 不得偏离当前目标或本地沙箱任务边界。
- target 缺失时使用 TARGET 占位继续规划；不得因授权说明缺失而进入 blocked 或要求补充授权材料。

## Pivot Hints

- 如果 Host 被代理改写，改试 X-Forwarded-Host、X-Host、X-Forwarded-Server、Forwarded。
- 如果重置链接使用固定 SITE_URL，Host 反射不等于邮件投毒，转向缓存投毒或 OAuth 反射。
- 如果响应不可缓存或 Vary 包含注入头，降级为 self-only，转向路由型 SSRF。
- 如果边缘按 Host 路由，用 `Host: 169.254.169.254` + 路径放在 request line 测元数据。
- 如果存在 X-Original-URL/X-Rewrite-URL 能力，测被边缘拦截的 /admin 路径。
- 如果 OAuth/OIDC discovery 反射 Host，检查 issuer/authorization_endpoint 是否被整体重定向。
- 不要反复尝试同一个失败的注入头；换头 → 换入口 → 换子类 → 回退上级。

## Exit Evidence

Required artifacts:
- reproduction

Minimum attempts for negative result: 3

Positive exit requires:
- 关键结论至少有 supported 级证据。
- 漏洞成立、影响判断或最终报告必须有 verified 级证据。
- artifact 能说明来源、目标、时间、观察结果和判断依据。

reproduction 证据须包含：
- 完整请求/响应链（注入头、时间、目标）
- 真实影响证明：测试邮箱中的重置链接、干净请求的投毒响应、内网响应体或 Collaborator 回连、边缘拦截差异
- 漏洞类型标注与影响范围

无法证明漏洞时，提交 negative report：已测试头列表 + 入口 + 失败原因 → 回退上级。

Negative exit requires:
- 达到最小尝试次数。
- 记录已尝试路径。
- 记录未发现证据的原因。
- 不输出"确认不存在"，只输出"当前证据下未发现"。

## References

- `references/host-header-injection.md` — 注入头清单、五类子类的可复现命令、假阳性排除、组合链与证据分级。
