# SSO / JWT / MFA / ATO 参考（授权测试）

适用前提：只使用自己注册的测试租户、测试账号和测试 IdP；不伪造真实用户身份，不向真实
用户发钓鱼链接。

## 1. SAML 攻击面

先找端点与绑定方式：

```bash
grep -iE "saml|sso|idp|sp|assertionconsumer" urls.txt
# 常见：/saml/acs、/sso/saml、/auth/saml/callback、/Shibboleth.sso、ADFS /adfs/ls/
```

SAMLResponse 在 POST binding 下是 base64（无压缩）；Redirect binding 用 raw DEFLATE（不是 gzip）。
解码/重编码：

```bash
echo "$SAMLResponse" | base64 -d | xmllint --format - > saml.xml
base64 -w0 saml.xml
```

### 1.1 XML Signature Wrapping（XSW）

原理：签名覆盖的是某个 `ID` 元素；解析器取“第一个 Assertion”，校验器却验“被签名的那个”。
把合法 Assertion 移到次要位置，注入恶意 Assertion 放前面。

```xml
<!-- 原始：合法 assertion，签名覆盖 ID=legit -->
<saml:Response>
  <saml:Assertion ID="legit">
    <NameID>user@company.example</NameID>
    <ds:Signature><!-- valid, covers ID=legit --></ds:Signature>
  </saml:Assertion>
</saml:Response>

<!-- 攻击：恶意 assertion 在前，签名仍覆盖 legit -->
<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.example</NameID>
  </saml:Assertion>
  <saml:Assertion ID="legit">
    <NameID>user@company.example</NameID>
    <ds:Signature><!-- valid --></ds:Signature>
  </saml:Assertion>
</saml:Response>
```

常见变体（XSW1–XSW8）：把签名元素包进 `<Extensions>`、复制 Assertion 到 `<Advice>`、
利用多 Reference、把签名移到 Object 内等。工具：SAML Raider（Burp BApp）。

### 1.2 NameID 注释注入

```xml
<NameID>admin@company.example<!---->.evil.example</NameID>
```

签名方 C14N 去注释后覆盖的是 `admin@company.example.evil.example`；应用取文本节点时在注释
边界截断，得到 `admin@company.example`。两边身份不一致即漏洞（CVE-2017-11428 类）。

### 1.3 签名剥离

1. 解码 SAMLResponse；
2. 删除整个 `<Signature>`；
3. 改 NameID 为 `admin@target.example`（或目标管理员邮箱）；
4. 重编码提交。

SP 若 `wantAssertionsSigned=false` 且不检查签名存在性 → 直接签发管理员会话。

### 1.4 断言内 XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml:Assertion><NameID>&xxe;</NameID></saml:Assertion>
```

解析器未禁 DOCTYPE 时可用；若 NameID 被渲染/记录，可在响应或审计日志里读文件。

### 1.5 其他检查

- AudienceRestriction 是否校验：IdP-A 签发的断言能否被 SP-B 接受。
- 断言重放：有效窗口内同一断言能否二次使用。
- NameID 操纵：`admin@`、`administrator@`、`support@`、`${7*7}`（若进模板）。
- 属性注入：`AttributeStatement` 中的 role/group 是否可改。

判真：改身份后**实际进入目标账号**（访问仅该身份可见的资源），只改显示名/locale 不算。

## 2. OAuth / OIDC

### 2.1 redirect_uri 绕过

按校验实现试：

- 精确匹配缺失：`https://target/cb.evil.example`、`https://target/cb/../evil`
- 子域/后缀：`https://evil.target.example`（若允许 `*.target.example` 且有可接管子域）
- 路径穿越/双编码：`/%2e%2e/`、`%252e%252e`、`//evil.example`
- 开放重定向拼接：`redirect_uri=https://target/out?next=https://evil.example`
- 参数污染：重复 `redirect_uri`、`redirect_uri[]=`
- 片段/查询注入：`#@evil.example`、`?x=@evil.example`

判真：授权码或 token 实际到达攻击者域（Collaborator 收到），不是 302 到错误页。

### 2.2 OIDC 配置与 mix-up

```bash
curl -s "https://$TARGET/.well-known/openid-configuration" | jq .
```

检查：

- `issuer` 是否与 token 的 `iss` 严格绑定；多租户下能否用 IdP-A 的 token 访问 SP-B。
- `authorization_endpoint` / `jwks_uri` 是否可被 Host 头或参数改写（见 host-header pack）。
- `id_token` 的 `aud`/`azp`/`nonce` 是否校验；`email_verified` 是否被信任。
- PKCE 是否强制；public client 能否省略 code_verifier。
- 授权码是否一次性、短时效、绑定 client 与 redirect_uri。

### 2.3 常见链

- 子域接管 + `*.target.example` 白名单 + 授权码投递 → ATO（Path 9）。
- 开放重定向 + redirect_uri 白名单 → 授权码经跳转泄露。
- 邮箱未验证 + OAuth 账号绑定 → 预注册受害者邮箱后接管。

## 3. JWT

### 3.1 识别

- Cookie/Authorization 中出现 `eyJ...` 三段式；
- 响应体/JS 里有 `access_token`、`id_token`；
- 解码 header 看 `alg`、`kid`、`jku`、`x5u`。

### 3.2 伪造路径

| 路径 | 条件 | 做法 |
|------|------|------|
| alg:none | 服务端接受无签名 | 改 `alg` 为 `none`，删签名段 |
| RS→HS 混淆 | 服务端用公钥当 HMAC 密钥 | 用 JWKS 公钥 PEM 作 HS256 密钥签名 |
| kid 注入 | kid 进文件路径/SQL | `kid=../../dev/null` 配空密钥；或 SQLi 控制密钥 |
| jwk/jku 注入 | 服务端信任 token 内嵌 JWK | 自带公钥并签名 |
| 弱 HMAC 密钥 | 字典可破 | `hashcat -m 16500 jwt.txt wordlist` |
| 算法降级 | 只校验签名不校验 alg | 试 HS256/PS256 混用 |

不要手工 base64 拼 token，用工具（jwt_tool、Burp JWT Editor）避免编码错误。

### 3.3 判真

伪造 token 后访问**需要该身份**的接口，返回数据/操作成功；仅解析通过不算。

## 4. MFA / OTP 绕过

按优先级：

1. **MFA 只在前端**：登录拿到 pre-MFA 会话后，直接访问 `/dashboard`、`/api/me`、
   `/account/profile`；返回用户数据即服务端未强制 MFA。
2. **OTP 不复用**：完成一次 MFA → 退出 → 重登 → 再提交同一 OTP；仍接受即失效缺陷。
3. **响应篡改**：错误 OTP 的响应改为成功（仅当服务端信任客户端状态时成立）。
4. **无速率限制**：对测试账号做小规模枚举；注意锁定策略，不做真实用户攻击。
5. **OTP 前缀泄露**：提交 1–3 位，观察响应差异；若正确前缀响应不同，可逐位收敛
   （6 位码约 ≤60 次）。仅在测试账号上验证。
6. **备用码/恢复流程**：备用码是否可枚举、恢复邮箱是否可改、恢复问题是否 OSINT 可得。
7. **状态跳过**：`mfa_verified=true`、`step=2`、隐藏字段、直接调用下一步接口。

判真：未完成 MFA 却取得完整会话或访问受保护资源。

## 5. ATO 链（按可利用性排序）

1. Host 头重置投毒 → 自己邮箱收到攻击者域链接（见 host-header pack）。
2. 重置 token 经 Referer/开放重定向泄露。
3. 可预测/弱重置 token（顺序、时间戳、短熵）。
4. token 不过期/可复用/跨账号可用。
5. 邮箱变更无需重新认证 → 改邮箱 → 重置。
6. JWT 伪造（见上）。
7. 改密无需当前密码 + 登录时序 oracle。
8. 安全问题/社交恢复可 OSINT。
9. SSO 子域接管 + OAuth redirect_uri 白名单。
10. 预注册/未验证账号接管（先用受害者邮箱注册，受害者后续 OAuth 登录绑定）。
11. 无密码/魔法链接按标识符滥用（改 email 参数即收他人链接）。

严重度门槛：

- Critical：零/低受害者交互（Host 重置投毒、JWT 伪造、lax redirect_uri 授权码窃取、
  IDOR 改邮箱后重置）。
- High：需一次邮件点击或已有会话/Cookie。
- Medium：需钓鱼 + 主动交互。
- Low：需 MitM 或仅影响自己账号。

## 6. 假阳性排除

- SAML：只改非安全属性（displayName、locale）不构成 ATO；必须跨授权边界。
- OAuth：302 到错误页/参数被拒不是漏洞；必须拿到码/token。
- JWT：只验证“能解析”不算；必须被服务端接受并授予访问。
- MFA：只在前端隐藏入口不算；必须服务端放行受保护资源。
- ATO：需要受害者点链接并重新输入密码+过验证码的链，按 Medium 以下处理。

## 7. 证据清单

- 原始 SAMLResponse / 授权请求 / JWT（脱敏后）；
- 篡改前后差异与解析器行为；
- 身份提升证明：目标身份可见资源、管理员操作、跨租户数据；
- 复现步骤与时间线；未成立分支与降级理由。
