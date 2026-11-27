# SPA 与影子 API 参考（授权测试）

## 1. 先拉壳与 bundle

```bash
curl -sk "https://$TARGET/" -o index.html
grep -oE '<script[^>]+src="[^"]+"' index.html
grep -oE '/(static|assets|_next|dist)/[^"'"'"' ]+\.js' index.html | sort -u
```

常见入口：

```
/static/js/main.<hash>.js
/_next/static/chunks/*.js
/asset-manifest.json
/manifest.json
/build-manifest.json
```

## 2. 从 bundle 取端点

先 grep，再决定是否下载全部：

```bash
# 绝对/相对 API 路径
grep -oE '"/[a-zA-Z0-9_./-]{2,}"' main.js | grep -iE 'api|v[0-9]|graphql|internal|admin|user|order|pay|upload'
grep -oE "https?://[a-zA-Z0-9._-]+" main.js | sort -u

# 调用点
grep -oE '(fetch|axios\.[a-z]+|\.open)\([^)]{0,120}' main.js

# 路由表 / 常量
grep -oE '(path|route|endpoint)\s*:\s*"[^"]+"' main.js
grep -oE '"/api/[^"]+"' main.js | sort -u
```

工具：LinkFinder、JSluice、sourcemapper。只对自有/授权目标使用。

## 3. source map 还原

```bash
# 找 map 引用
grep -oE 'sourceMappingURL=[^ ]+' main.js
curl -sI "https://$TARGET/static/js/main.<hash>.js.map"

# 还原（sourcemapper / unwebpack-sourcemap）
sourcemapper -url "https://$TARGET/static/js/main.<hash>.js.map" -output out/
```

判真：map 返回 200、含 `sourcesContent`，能还原出服务端接口名、内部域名、注释掉的测试端点或硬编码密钥。
只泄露第三方库源码不算；必须暴露目标自身逻辑或凭据。

## 4. 接口文档与旧版本

```bash
for p in /swagger.json /swagger/v1/swagger.json /v3/api-docs /api-docs \
         /openapi.json /docs /redoc /graphql /graphiql /altair; do
  echo "$p -> $(curl -sk -o /dev/null -w '%{http_code}' "https://$TARGET$p")"
done
```

版本面：

```
/api/v1/...   /api/v2/...   /v1/...   /v2/...
/rest/...     /internal/... /beta/... /legacy/... /mobile/...
```

方法矩阵：对每个候选端点分别发 GET/POST/PUT/PATCH/DELETE。很多应用只保护了 UI 使用的方法。

## 5. shadow / zombie API 判定

1. 从当前 bundle 与旧 bundle（缓存、CDN、Wayback 自有快照）各取一份端点列表；
2. 差集里找旧版本路径 `/v1`、`/legacy`、`/internal`、`/mobile`；
3. 对同一对象比较新旧版本响应：字段更多、鉴权更弱、校验更少；
4. 用两个测试账号验证 IDOR/越权。

判真：旧版本返回当前版本不给的数据，或对当前版本受限的操作放行。

## 6. 源码/构建泄露

```bash
curl -sk "https://$TARGET/.git/HEAD"
curl -sk "https://$TARGET/.git/config"
curl -sk "https://$TARGET/.svn/entries"
curl -sk "https://$TARGET/.DS_Store" -o ds.bin   # 需专用解析器列目录

for f in backup.zip www.zip source.zip app.zip dist.zip .env .env.bak \
         docker-compose.yml config.js config.json; do
  echo "$f -> $(curl -sk -o /dev/null -w '%{http_code}' "https://$TARGET/$f")"
done
```

`.git` 可读时先确认能取到 objects，再用 git-dumper 还原；只读、不提交。
`.DS_Store` 用 ds_store 解析出文件名，再按文件名探测。

## 7. 假阳性（必须排除）

- **SPA catch-all**：任何路径都返回 200 + index.html，不代表端点存在。判据：Content-Type、JSON 结构、与已知 404 的 body 差异。
- **401/302 登录页**：只说明路由存在，不说明可未授权访问。
- **source map 返回 index.html**：不是 map；检查 `Content-Type` 与首字符 `{`。
- **Swagger 只有公开端点**：文档泄露本身可能是 Low；必须找到文档中未公开/内部端点才升级。
- **旧版本 404 但返回统一错误页**：不是 zombie API。
- **bundle 里的字符串**：只是候选，必须实际请求成功并取得数据。

## 8. 组合链

| 发现 | 组合到 | 影响 |
|------|--------|------|
| bundle 泄露内部 API | 未授权访问/IDOR | High–Critical |
| source map 含密钥 | 云/第三方接口 | High |
| Swagger 含内部端点 | 未授权数据/管理操作 | High |
| 旧版本 API 无鉴权 | 数据导出/越权 | High–Critical |
| .git 可读 | 源码/密钥/历史凭据 | High |

## 9. 证据清单

- 端点来源：bundle URL、map URL、文档 URL、旧版本路径；
- 完整请求/响应（含状态码与 body 片段）；
- 与对照组（受保护端点/当前版本）的差异；
- 影响范围与数据敏感度；
- 未成立分支与降级理由。
