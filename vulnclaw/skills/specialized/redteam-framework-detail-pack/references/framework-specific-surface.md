# 框架特定攻击面参考（授权测试）

原则：先指纹、再端点、最后才上 CVE payload。框架指纹本身不是漏洞；必须拿到未授权数据、
命令回显或会话提升。

## 1. Spring Boot

### 1.1 指纹

- 默认错误页 `Whitelabel Error Page`；
- 响应头/静态资源含 `spring`、`X-Application-Context`；
- `/actuator`、`/actuator/health` 返回 JSON；
- 404 页含 `org.springframework` 堆栈（debug 开启时）。

### 1.2 Actuator 端点

```bash
for p in /actuator /actuator/health /actuator/env /actuator/heapdump \
         /actuator/mappings /actuator/beans /actuator/configprops \
         /actuator/loggers /actuator/jolokia /actuator/gateway/routes; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$p")
  echo "$p -> $code"
done
```

高价值：

- `/actuator/env`：配置、数据库口令、云密钥；`/actuator/env/{name}` 可取单值。
- `/actuator/heapdump`：堆转储，含会话、凭据、密钥。只做字符串统计并脱敏，不落地真实凭据。
- `/actuator/mappings`：枚举隐藏接口。
- `/actuator/loggers`：可动态改日志级别（写操作，需授权）。
- `/actuator/jolokia`：JMX 代理，可能到 RCE。
- `/actuator/gateway/routes`：Spring Cloud Gateway 路由与 SpEL 注入面。

### 1.3 Spring Cloud Gateway SpEL（CVE-2022-22947）

条件：Actuator gateway 端点可写。步骤：新增带 SpEL 的 filter → refresh → 触发 → 删除。
只在测试实例验证命令回显，不做持久化。

### 1.4 /env + /refresh gadget

条件：`/env` 可写 + 存在 `spring.cloud.bootstrap` 或日志配置。可通过改
`logging.config`/`eureka.client.serviceUrl.defaultZone` 等触发外连或加载。验证到 Collaborator
回连即可。

### 1.5 Spring4Shell（CVE-2022-22965）

条件：Spring MVC + JDK9+ + 可写 `class.module.classLoader` 绑定（War 部署、非默认
disallowedFields）。用公开 PoC 验证时只写临时文件并删除，禁止写 webshell 到生产目录。

### 1.6 H2 Console

`/h2-console` 可达且允许 JDBC URL → 可到 RCE（`CREATE ALIAS ... Runtime.exec`）。只在测试
环境验证。

### 1.7 判真

- Actuator：未授权返回真实配置/堆信息（不是登录页/403）。
- SpEL/Spring4Shell：命令输出或 Collaborator 回连。
- 仅 200 的 `/actuator` 空壳不算。

## 2. Laravel

### 2.1 指纹

- `X-Powered-By: PHP`、`laravel_session` Cookie、`/vendor/laravel`；
- 错误页 `Whoops!`、Ignition 页面；
- `/.env`、`/storage/logs/laravel.log` 可达性。

### 2.2 Debug 与 Ignition（CVE-2021-3129）

条件：`APP_DEBUG=true` + Ignition 暴露。公开链通过日志文件 + phar 反序列化到 RCE。
只验证命令回显；不要写持久化文件。

### 2.3 Telescope / Horizon

`/telescope`、`/horizon` 未授权可看请求、SQL、邮件、队列任务，常含 token 与用户数据。
判真：返回真实请求记录（非登录页）。

### 2.4 .env / APP_KEY

`/.env` 可达即泄露 DB/邮件/云凭据与 `APP_KEY`。`APP_KEY` 泄露会影响 Cookie 加密与签名 URL：
可伪造 `laravel_session` 或签名链接（视版本与配置）。只用自己的测试账号验证。

### 2.5 签名 URL

`URL::signedRoute` / `temporarySignedRoute` 的签名若基于 APP_KEY，泄露后可伪造。
测试：改路径/参数后签名失效为正常；若仍可用则签名校验缺失。

### 2.6 Mass assignment

Eloquent `$fillable` 缺失时，注册/资料更新可注入 `is_admin=1`、`role=admin`、`balance=...`。
用测试账号验证权限变化。

### 2.7 环境覆盖（CVE-2024-52301）

多环境部署下通过 query 参数覆盖 `APP_ENV` 等，可能切换配置/debug。验证到 debug 页或配置差异。

### 2.8 Cookie 反序列化

`APP_KEY` 泄露 + Cookie 加密/序列化 → 构造恶意 payload。只做无害命令（`id`）验证。

## 3. Next.js

### 3.1 指纹与版本

- `/_next/static/`、`__NEXT_DATA__`、`x-powered-by: Next.js`；
- `/_next/image?url=...` 存在；
- 构建 ID 可从 `__NEXT_DATA__.buildId` 取。

### 3.2 Server Actions

POST 到页面路由，带 `Next-Action` 头与序列化参数。检查：

- Action ID 是否可枚举；
- 是否校验会话/权限（未登录直接调用）；
- 参数是否进 `fetch`/`exec`/`fs`/SQL。

判真：未授权调用产生数据变更或命令/请求副作用。

### 3.3 Middleware 绕过（CVE-2025-29927）

受影响版本可通过 `x-middleware-subrequest` 头跳过 middleware 鉴权。测试：对受保护路径加该头，
对比是否直接返回页面/数据。只在授权测试环境验证。

### 3.4 /_next/image SSRF

```bash
curl -s "https://$TARGET/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75"
curl -s "https://$TARGET/_next/image?url=http://$COLLAB/x&w=64&q=75"
```

判真：返回内部内容或 Collaborator 收到请求；仅 400/报错不算。

### 3.5 /_next/data IDOR

`/_next/data/<buildId>/<page>.json` 常直接返回页面 props（含用户数据）。换 buildId/路径/参数
测试越权。

### 3.6 ISR 缓存投毒

按路径/头缓存页面；若个性化内容进共享缓存，可能跨用户泄露。用两个测试账号验证。

## 4. Node.js / Express

### 4.1 指纹

`X-Powered-By: Express`、错误页堆栈、`/package.json` 可达、静态资源目录。

### 4.2 原型污染

找 JSON 合并/递归赋值入口（`Object.assign`、`merge`、`set`、查询参数解析）。探测：

```json
{"__proto__":{"polluted":"yes"}}
{"constructor":{"prototype":{"polluted":"yes"}}}
```

反射点：后续响应/模板出现 `polluted`。升级到 RCE 常见链：污染 `NODE_OPTIONS`、
`shell`、`env`、模板引擎 options。

### 4.3 trust proxy

`app.set('trust proxy', true)` + 反代 → `X-Forwarded-For` 可伪造，绕过 IP 白名单/速率限制。
判真：伪造 XFF 后访问到仅内网/管理 IP 可用的功能。

### 4.4 模板 SSTI

EJS/Pug/Handlebars 用户输入进模板：

```
<%= 7*7 %>        → 49
#{7*7}            → 49 (Pug)
{{7*7}}           → 49 (Handlebars)
```

升级到 RCE 需引擎 gadget；只验证无害表达式。

### 4.5 /proc/self/environ

文件读/命令执行后读环境变量常含密钥；只做统计与脱敏。

## 5. ASP.NET

### 5.1 指纹

`ASP.NET_SessionId`、`__VIEWSTATE`、`X-AspNet-Version`、`.aspx`/`.ashx`、`trace.axd`。

### 5.2 ViewState

- 未加密仅签名：可解码看结构；有 machineKey 才能伪造。
- 未签名/未加密：可直接改 ViewState 触发反序列化。
- machineKey 泄露（web.config、备份、源码）→ 伪造 ViewState → RCE（ysoserial.net）。

判真：命令回显；仅 base64 解码出结构不算。

### 5.3 调试页

`trace.axd`、`elmah.axd`、`/Error.aspx` 泄露请求头、Cookie、连接串。判真：返回真实请求记录。

### 5.4 Telerik

`Telerik.Web.UI.WebResource.axd`、`RadAsyncUploadHandler` 暴露且版本旧 → 已知反序列化/上传 RCE。
按版本选公开链，只验证命令回显。

### 5.5 SharePoint

匿名端点、`/_layouts/15/`、`/_vti_bin/`、ToolPane、Excel Services 等；与 intranet pack 的
SharePoint 内容配合使用，避免把“可访问页面”当成漏洞。

## 6. 版本链与判真

| 面 | 只读证据 | 升级证据 |
|----|----------|----------|
| Actuator | env/heapdump 真实内容 | SpEL/Spring4Shell 命令回显 |
| Laravel | debug 页、.env、Telescope | Ignition RCE、Cookie 反序列化 |
| Next.js | 版本、Server Action 可达 | 未授权数据变更、SSRF 回连 |
| Node | 原型污染反射 | RCE 链、XFF 绕过 |
| ASP.NET | ViewState 结构、trace.axd | machineKey 伪造、Telerik RCE |

降级规则：只有指纹/端点可达、没有未授权数据或执行证据 → informational；不要报“可能存在”。
