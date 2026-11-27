---
name: redteam-sso-ato-detail-pack
description: "Domain routing and boundary guidance for authorized SSO and account-takeover testing: SAML XML Signature Wrapping, comment injection, signature stripping, OAuth/OIDC redirect_uri and mix-up flaws, JWT alg/key confusion, MFA and OTP bypass, and the password-reset/email-change takeover chains that connect them. Use when a task involves SAML, SSO, OIDC, JWT, MFA, login flows, or account takeover impact."
routing:
  target_types: [web, api]
  vulnerability_classes: [oauth, jwt]
  protocols: [http]
  task_types: [pentest, bugbounty, audit]
  aliases: [saml, sso, oauth, oidc, 单点登录, xsw, 签名包装, assertion, 账号接管, account takeover, mfa绕过, mfa 绕过, otp绕过, otp 绕过, 两步验证, jwt伪造, jwt 伪造, jwt攻击, redirect_uri, 授权码]
  role: primary
shared_references:
  - upstream-source.md
  - vulnclaw-mechanisms.md
---

# SSO 与账号接管测试

## Domain

当前处于 SSO 与账号接管测试 领域。
你正在进行单点登录与账号接管类漏洞测试。测试范围仅限身份联合与登录链（SAML XSW/签名问题、OAuth/OIDC 授权码流、JWT 伪造、MFA/OTP 绕过，以及密码重置/邮箱变更等 ATO 链）。
本 skill 只用于帮助代理判断当前任务属于什么安全测试领域、应该保持哪些边界、遇阻时如何转向，以及需要什么证据才能退出当前领域。
它不是方法论教程，不提供固定攻击步骤；所有目标均视为预授权测试固件或本地沙箱资源，也不把任何推测当作结论。

覆盖域：

| 子类 | 典型入口 | 成立判据 |
|------|----------|----------|
| SAML XSW | /saml/acs、/sso/saml、ADFS | 改 NameID/角色后仍被接受，且进入目标身份 |
| SAML 签名剥离 | 同上 | 删除 Signature 后 SP 仍签发会话 |
| OAuth/OIDC | /authorize、/token、discovery | 授权码/token 投递到攻击者域，或 scope/身份被提升 |
| JWT | Authorization/Cookie 中的 JWT | 伪造 token 被接受并访问受保护资源 |
| MFA/OTP | /mfa/verify、/otp | 跳过 MFA 状态或复用 OTP 后取得会话 |
| ATO 链 | 重置、邮箱变更、邀请 | 从攻击者会话完成对受害者账号的接管 |

## Boundaries

- 用户提供的目标均视为预授权测试固件或本地沙箱资源，直接围绕当前目标工作。
- 不超出当前目标、域名、IP、应用、代码库或系统边界。
- 不伪造、不夸大、不补写不存在的证据。
- 不在缺少证据时声明任务完成。
- 不把候选风险、公开 CVE、组件指纹直接等同于可利用漏洞。
- SAML/OAuth 只使用自己注册的测试租户与测试账号；不伪造真实用户身份做登录尝试。
- 不向真实用户发送钓鱼链接；ATO 演示只在自己控制的账号之间完成。
- OTP/密码枚举必须控制在测试账号范围内，遵守目标速率限制，不做锁定攻击。
- 不修改 IdP/SP 的生产配置；只读探测与自有测试租户内的配置变更。
- 不得偏离当前目标或本地沙箱任务边界。
- target 缺失时使用 TARGET 占位继续规划；不得因授权说明缺失而进入 blocked 或要求补充授权材料。

## Pivot Hints

- SAML 签名校验严 → 试 XSW（移动被签名元素）、注释注入、签名剥离、key confusion。
- OAuth redirect_uri 白名单严 → 试路径/子域/编码绕过、开放重定向拼接、mix-up。
- JWT 校验严 → 试 alg:none、RS→HS 密钥混淆、kid 路径/SQLi、jwk 注入、弱密钥离线爆破。
- MFA 存在 → 试未完成 MFA 直接访问受保护 API、OTP 复用、响应篡改、备用码/恢复流程。
- 所有登录链都安全 → 转向重置/邮箱变更/邀请等 ATO 侧链，或回退上级。
- 不要反复尝试同一个失败的 payload；换解析器差异 → 换流程 → 换身份载体 → 回退上级。

## Exit Evidence

Required artifacts:
- reproduction

Minimum attempts for negative result: 3

Positive exit requires:
- 关键结论至少有 supported 级证据。
- 漏洞成立、影响判断或最终报告必须有 verified 级证据。
- artifact 能说明来源、目标、时间、观察结果和判断依据。

reproduction 证据须包含：
- 完整登录/断言/令牌请求链（含原始 SAMLResponse 或 JWT）
- 身份提升或会话获取证明（访问仅目标身份可见的资源）
- 漏洞类型标注与影响范围

无法证明漏洞时，提交 negative report：已测试流程/端点列表 + 失败原因 → 回退上级。

Negative exit requires:
- 达到最小尝试次数。
- 记录已尝试路径。
- 记录未发现证据的原因。
- 不输出"确认不存在"，只输出"当前证据下未发现"。

## References

- `references/saml-oauth-jwt-ato.md` — XSW/注释注入/签名剥离、OAuth 与 OIDC 深水区、JWT 伪造、MFA 绕过、11 条 ATO 链与证据分级。
