---
name: electron-desktop-audit
description: Electron/PC 客户端安全审计 — ASAR 解包、BrowserWindow/preload、IPC 权限边界、本地 HTTP/自定义协议、MCP Apps、CDP 无害验证
routing:
  target_types: [client, desktop]
  task_types: [audit, pentest, bugbounty]
  technologies: [javascript, nodejs]
  vulnerability_classes: [sandbox_escape, privilege_escalation, prompt_injection, tool_abuse, info_disclosure, path_traversal, auth_bypass]
  aliases:
    - electron
    - electron客户端
    - desktop client
    - pc客户端
    - asar
    - ipc
    - mcp apps
    - workbuddy
shared_references:
  - vulnclaw-mechanisms.md

---

# Electron / PC 客户端安全审计 Skill

当目标是 Electron/Chromium 桌面客户端（WorkBuddy、CodeBuddy、IM/办公客户端、AI Agent 客户端）时使用。目标是找出**能独立触发、能稳定复现、有明确影响**的问题，而不是堆静态告警。

## 0. 授权与边界

- 只测试已授权版本/安装包；不碰真实用户数据。
- 读文件用无害样本（如 `C:/Windows/win.ini`），写文件只写临时目录并删除。
- 不开启摄像头/麦克风等硬件；权限类问题用 `featurePolicy` / `permissions.query` 证明。
- 本地 HTTP/调试端口只绑 `127.0.0.1`；测试结束停止服务、关闭调试端口、清理测试任务/文件。



## 0.1 与 VulnClaw 机制联动（必须用）

本 Skill 不是独立 checklist。每次 Electron/PC 客户端审计都要把状态写进 VulnClaw 的黑板、攻击面图和证据链，否则会被 stall guard / completion gate 判成“没有进展”。

### 开工：锁定 + 开攻击面

1. `blackboard_set_lock`：
   - 写清审计边界和目标，例如：
     `LOCK: Electron client; main/preload/renderer + local HTTP + MCP Apps; goal = confirmed arbitrary file read/write or agent message injection`
2. `blackboard_create_angle`：为每个攻击面单独开 ANGLE，不要只开一个“审计客户端”：
   - main process / BrowserWindow / webPreferences
   - preload / contextBridge / IPC handlers
   - renderer XSS / iframe / webview / sandbox
   - 文件 API / 路径白名单 / 下载/分享
   - 本地 HTTP / WebSocket 路由
   - 自定义协议 / local-file / 深链 / openExternal
   - MCP Apps / sandbox-proxy / host bridge / 市场 connector
   - 更新器 / 安装器 / 扩展加载
3. `web_map_add` + `web_map_link`：所有本地 HTTP/URL/预览/iframe 关系都记到 WebMap；不要只在对话里贴 URL。
4. `blackboard_add_intent`：每个具体测试方向一条 intent；开始时 `blackboard_start_intent`，失败时 `blackboard_reject_intent`，不要重复同一个 dead end。

### 过程中：事实必须带证据

- `evidence_*` 先保存请求/响应、日志、截图/JSON。
- `blackboard_add_fact(description, evidence_ref=...)` 记录事实；有 evidence 且被 witness 才会 CONFIRMED，否则是 candidate。
- 只有 witness 通过后才 `blackboard_verify_fact`；不要把 candidate 写成 confirmed。
- 代码和运行时冲突时用 `blackboard_create_tension` 记录，不要二选一猜。
- 每完成一个面：`blackboard_hit_angle`（有结论）或 `blackboard_miss_angle`（排除/无入口）。
- 每 3–5 步或换面前 `blackboard_review`；上下文里已有 `blackboard_summary`，先读再决定下一步。

### 收尾：证据门 + 报告

- `report_finding` 写 finding；`submit_gate` 只在证据 witness 通过后放行。
- 报告里的“已复现/未复现”必须和 blackboard fact 状态一致。
- 生产审计不要用 `blackboard_record_answer`（CTF answer sheet）；用 finding/evidence 链路。

### 其他机制

- **攻击面 wave / 并行 agent**：`extract_attack_surfaces` 会从 `session.recon_data`
  （`network_services` / `subdomains` / `paths`）和 findings 提取 surface；本地 HTTP
  路由、子域、路径要尽早落到 `recon_data` 或 `web_map`，不要只留在消息里。
  并行时每个 surface 仍用独立 ANGLE，root 只保留 LOCK 和汇总。
- **playbook**：开始新客户端类型前 `lookup_playbook` 查可复用 recipe；确认后
  `save_playbook` 存“Electron IPC/文件/MCP Apps”方法，但先脱敏（不放 token/用户路径）。
- **reflexion**：同一路径连续失败两次就 `blackboard_miss_angle` + 新 ANGLE；
  不要重复同一个 payload；需要换面时用 reflexion 的 switch-surface 提示。
- **task_mode**：goal/描述写成 `audit`/`pentest`，不要写成 CTF 拿 flag；
  Electron 审计不要套 CTF 的 fail-fast，按面逐项验证。
- **correction_layer**：工具参数/路径被拒时，先 `blackboard_create_tension` 记录
  “代码允许 vs 运行时拒绝”，再用 CDP/日志确认，不要直接改结论。

## 0.2 Electron 常用工具族

详见 `references/vulnclaw-mechanisms.md` 第 13 节。优先用：
`traffic_list/view/repeat/bind_evidence`（HTTP 证据与重放）、
`vault_archive/search`（长日志/上下文）、`source_extract`（ASAR/源码）、
`http_probe_batch`/`fetch`（本地 HTTP）、`evidence_*` + `report_finding`、
`agent_run`/`agent_job`（并行 surface）。工具面被裁剪时先查 schema，不要用
`python_execute` 伪造工具结果。

## 1. 侦察：先把攻击面画出来

1. 定位安装目录与资源：
   - `resources/app.asar`、`resources/app.asar.unpacked`
   - `package.json`、`version`、`main`/`preload` 入口
   - `resources/extensions`、`resources/*preload*.js`、native `.node`/`.dll`
2. 解包 ASAR（保留原目录，不改安装包）：
   - `npx asar extract app.asar app_asar`
   - 记录 `main/`、`renderer/assets/`、`preload/` 的文件清单和构建 hash。
3. 找入口：
   - `BrowserWindow` / `webContents` / `webview` 创建点
   - `contextBridge.exposeInMainWorld` / `ipcRenderer.invoke/on`
   - `ipcMain.handle/on` / `registerHandler` / RPC 注册表
   - `protocol.handle` / `registerSchemesAsPrivileged`
   - 本地 `http.createServer` / `listen(0)` / WebSocket
   - 深链：`setAsDefaultProtocolClient`、`open-url`、`second-instance`
   - 更新：`autoUpdater`、`downloadURL`、`verifyInstaller`
4. 建一张“信任边界表”：
   - 主进程 ↔ renderer
   - 主 renderer ↔ 扩展 iframe / webview / MCP App iframe
   - 本地 HTTP ↔ 任意本地页面/远程页面
   - 应用 ↔ 外部协议/文件系统/网络

## 2. 静态审计清单

优先看“调用方可控 + 高权限动作”的组合。

### 2.1 BrowserWindow / webPreferences

检查：
- `nodeIntegration: true`
- `contextIsolation: false`
- `sandbox: false`
- `webviewTag: true`
- `webSecurity: false`
- `allowRunningInsecureContent: true`
- `preload` 是否暴露过宽 API
- 是否把远程 URL / 用户内容加载进带 preload 的窗口

重点不是配置本身，而是“这个窗口加载谁的内容”。

### 2.2 IPC / preload / bridge

枚举所有 handler，标出：
- 是否有 sender / frame / origin 校验
- 是否按 session、workspace、appId 做授权
- 是否把调用方参数直接传给文件、命令、网络、权限 API
- 是否把 `window.__xxxInvoke` 直接暴露给 iframe/webview/扩展

高危模式：
```js
ipcMain.handle('file:read', (e, path, opts) => read(path, opts))
ipcMain.handle('file:write', (e, path, data, opts) => write(path, data, opts))
```
如果 `opts.allowedDirs` / `savePath` 由调用方传，就是路径白名单绕过/任意写候选。

### 2.3 文件 API

检查：
- `validatePath` / `isWithin` / `realpath` 是否真的限制根目录
- `allowedDirs`、`cwd`、`savePath`、`defaultFileName` 是否调用方可控
- 扩展名黑名单是否覆盖 `.url`、`.lnk`、`.hta`、`.js`、`.vbs`、`.ps1`、`.reg`、`.msi`
- 写文件是否覆盖已有文件；是否写 Startup/配置/插件目录
- `downloadFileToLocal`、`shareFile`、`openPath`、`openExternal` 是否共用同一套校验

### 2.4 本地 HTTP / WebSocket

检查：
- 是否只绑 `127.0.0.1`；端口是否随机
- 路由是否有鉴权（UUID/token/session）
- 是否有 `frame-ancestors` / `X-Frame-Options`
- `postMessage` 是否只校验 `event.source` 而不校验 `event.origin`
- CSP 是否由 URL 参数控制
- 静态文件路由是否有路径穿越
- 是否把本地服务当“可信源”，在其上暴露高权限接口

### 2.5 iframe / webview / sandbox

检查：
- `sandbox` 是否同时有 `allow-scripts` + `allow-same-origin`
- `allow` 是否下放 camera/microphone/clipboard
- `document.write` / `srcdoc` 是否让内层继承父源
- `postMessage` 是否校验 origin/source
- webview 的 `partition`、`preload`、`allowpopups`
- 权限处理器是按 session 安装，还是所有 frame 无条件放行

### 2.6 MCP Apps / Agent 客户端

如果客户端支持 MCP Apps / 工具生态：
- `host/getToken` 是否按 `appId` / server 鉴权
- `host/shareFile` / `downloadFile` / `uploadToLibrary` 的写入路径与文件名
- App 资源里的 `_meta.ui.permissions` 是否被宿主无条件信任
- `ui/message` / `sendMessage` / `updateModelContext` 是否要求用户确认
- MCP App 是否能覆盖项目指导文件（`CODEBUDDY.md` / `AGENTS.md`）
- 市场/创作者提交的 connector 是否能在运行时绕过审核

## 3. 动态验证

### 3.1 CDP

- 以 `--remote-debugging-port=9223` 启动（仅测试机）。
- `http://127.0.0.1:9223/json` 找 page/webview/iframe target。
- 在 renderer 里枚举 bridge：
  ```js
  Object.keys(window).filter(k => /invoke|bridge|wb|electron|ipc/i.test(k))
  ```
- 用 `__wbInvoke(channel, method, ...args)` 这类入口做**无害**探针：先默认拒绝，再传调用方可控参数，证明校验边界。

### 3.2 文件/权限

- 读：`C:/Windows/win.ini`，只读。
- 写：临时目录，写后删除；不要写用户文档/Startup。
- 摄像头/麦克风：只查 `document.featurePolicy.allowsFeature('camera')` 和
  `navigator.permissions.query({name:'camera'})`，不调用 `getUserMedia`。
- 剪贴板：先写测试串，再读；结束清空；不要读用户剪贴板。

### 3.3 证据

每个 finding 至少保留：
- 触发入口（URL / IPC / 深链 / App）
- 请求/响应或 JSON-RPC 原文
- 关键日志（时间、session、调用链）
- 截图：payload、请求链路、结果
- 前置条件、影响、未验证部分

## 4. 常见误报

- minified 代码里的 `dangerouslySetInnerHTML`，如果上游已 DOMPurify/白名单，不是 XSS。
- `executeJavaScript` 拼接的值如果是 `JSON.stringify` 结果，不是注入。
- iframe 有 `allow-scripts` 但没有 `allow-same-origin`，不能读父源。
- 扩展桥 `invoke` 看似透传，但 `daemonRpcInvoke` 未注入时会在运行时抛错。
- 分享导出代码有 sink，但 React Router context 缺失导致组件根本没渲染。
- 权限 handler 代码存在，但 iframe 的 Permissions-Policy 没下放，API 仍被浏览器拦截。

## 5. 报告映射

- 产品类型：PC客户端漏洞
- 常见分类：
  - `权限提升/绕过 → 越权`：IPC 授权缺失、App 驱动 Agent、跨边界读写
  - `信息泄漏`：token、文件、摄像头/麦克风、剪贴板
  - `逻辑漏洞`：分享/安装/更新/深链流程
- 详情按 TSRC 四段写：漏洞描述、复现步骤、危害说明、修复建议。
- 明确写“已复现”和“未复现”的边界，不把链式假设写成 RCE。

## 6. 相关 Skill

- `ai-mcp-security`：MCP / Agent / Prompt 注入 / 工具滥用
- `client-reverse`：桌面客户端签名、Burp 重放、Frida/IDA
- `redteam-auth-detail-pack`、`redteam-file-detail-pack`、`redteam-logic-detail-pack`
- `redteam-code-audit-detail-pack`：ASAR/minified JS 静态审计
- `references/electron-audit-playbook.md`：机制循环、攻击面拆分、静态/动态模板、证据/finding 模板
- `reporting`：报告结构与证据规范
