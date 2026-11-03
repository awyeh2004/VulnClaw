# Electron/PC 客户端审计 Playbook

本文件是 `electron-desktop-audit` 的执行参考。目标是把“攻击面 → 黑板事实 → 证据 → 报告”串起来，而不是只列检查项。

## 1. 机制循环

| 阶段 | 工具 | 用法 |
| --- | --- | --- |
| 锁定边界 | `blackboard_set_lock` | 写清客户端类型、攻击面、目标（读/写/执行/越权） |
| 开攻击面 | `blackboard_create_angle` | 每个面一条 ANGLE，不要只开“审计客户端” |
| 记 Web 面 | `web_map_add` / `web_map_link` | 本地 HTTP/URL/预览/iframe 关系 |
| 记意图 | `blackboard_add_intent` / `blackboard_start_intent` | 每个测试方向一条 intent |
| 记事实 | `evidence_*` → `blackboard_add_fact(evidence_ref=...)` | 有 witness 才 CONFIRMED |
| 交叉验证 | `blackboard_verify_fact` / `blackboard_create_tension` | 代码与运行时冲突时记录 |
| 收面 | `blackboard_hit_angle` / `blackboard_miss_angle` | 有结论/排除都要收 |
| 复盘 | `blackboard_review` / `blackboard_summary` | 每 3–5 步或换面前 |
| 报告 | `report_finding` / `submit_gate` | 证据 witness 通过后才放行 |

## 2. 攻击面拆分模板

对 Electron 客户端，至少拆成：

1. `main/BrowserWindow/webPreferences`
2. `preload/contextBridge/IPC handlers`
3. `renderer XSS/iframe/webview/sandbox`
4. `file read/write/download/share/openPath`
5. `local HTTP/WebSocket routes`
6. `custom protocol/local-file/deep link/openExternal`
7. `MCP Apps/sandbox-proxy/host bridge/market connector`
8. `updater/installer/extension loading`

每开一条 ANGLE，写清“入口 + 权限动作 + 预期影响”，例如：

```text
ANGLE: local MCP Apps proxy can be framed by arbitrary origin; if injected
script can call host/shareFile, impact = workspace file write.
```

## 3. 静态检索起手

```bash
# 解包
npx asar extract resources/app.asar app_asar

# 窗口/沙箱
grep -Rno "new BrowserWindow\|webPreferences\|nodeIntegration\|contextIsolation\|sandbox:\|webviewTag\|webSecurity" main

# IPC/bridge
grep -Rno "ipcMain.handle\|ipcMain.on\|contextBridge\|exposeInMainWorld\|__.*[Ii]nvoke" main renderer

# 文件/路径
grep -Rno "allowedDirs\|validatePath\|savePath\|realpath\|isWithin\|downloadFileToLocal\|shareFile" main

# 本地服务/协议
grep -Rno "createServer\|listen(\|protocol.handle\|registerSchemesAsPrivileged\|local-file\|frame-ancestors\|postMessage" main

# MCP/Agent
grep -Rno "getToken\|shareFile\|downloadFile\|uploadToLibrary\|ui/message\|updateModelContext" main renderer
```

结果不要直接当 finding；先拆到 ANGLE，再用动态证据确认。

## 4. 动态验证模板

### 4.1 IPC/路径

```js
// 默认应拒绝
await __wbInvoke('file:read', '', 'C:/Windows/win.ini')

// 传调用方白名单：若成功，记录 fact + evidence
await __wbInvoke('file:read', '', 'C:/Windows/win.ini', 'utf-8',
                 { allowedDirs: ['C:/Windows'] })
```

### 4.2 本地 HTTP/iframe

- 用不同源页面 frame 本地服务；
- 检查响应头：`frame-ancestors` / `X-Frame-Options` / CORS；
- 监听 `postMessage`：确认是否只校验 `event.source`；
- 注入只读 payload，beacon 回本地 collector；
- 不读用户数据，不写用户目录。

### 4.3 MCP Apps / Agent

- 用真实 MCP App 资源（`resources/read` 返回 `ui://...`）而不是只注入 guest；
- 检查 `ui/message` 是否被 `requestSendPrompt` 消费；
- 测试文本明确“不要调用工具”，避免误执行；
- 截图：payload、日志链路、会话结果。

## 5. Evidence / Finding 模板

- Evidence：请求/响应原文、日志时间线、截图、CDP 输出。
- Fact：`description | evidence_ref`，描述里放可被 witness 的具体字符串。
- Finding：
  - 入口（IPC/HTTP/深链/App）
  - 前置条件
  - 已复现
  - 未复现/链式假设
  - 影响与修复

## 6. 常见 false positive

- `dangerouslySetInnerHTML` 上游已 sanitize。
- `executeJavaScript` 的值是 `JSON.stringify` 结果。
- iframe 无 `allow-same-origin`，不能读父源。
- 扩展桥 `invoke` 透传，但 `daemonRpcInvoke` 缺失会在运行时抛错。
- 权限代码存在，但 iframe 的 Permissions-Policy 没下放，API 仍被拦。
- 分享导出有 sink，但组件因 router/context 缺失根本没渲染。

## 7. 生产/CTF 分离

- 本地 `vulnclaw`：CTF/aw，不要切全局 editable 安装。
- 生产：`E:\work\vulnclaw-prod\run-vulnclaw-prod.cmd`，只在漏洞专用工作区使用。
- 生产 skill/证据不对外复制；不把真实 token、用户路径写进 playbook。
