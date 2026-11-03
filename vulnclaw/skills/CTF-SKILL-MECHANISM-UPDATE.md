# CTF / `aw` 分支的 Skill 机制移植说明

本文说明如何把 prod（`research/vuln-cases`）里的“共享机制 + 工具族”改动移植到 CTF 的 `aw` 分支，同时不把生产专用内容带进 CTF。

## 1. 背景

prod 新增了：

```text
vulnclaw/skills/_shared/references/vulnclaw-mechanisms.md
vulnclaw/skills/specialized/electron-desktop-audit/
```

并把 `vulnclaw-mechanisms.md` 通过 `shared_references` 接到：

```text
electron-desktop-audit
ai-mcp-security
client-reverse
redteam-auth-detail-pack
redteam-file-detail-pack
redteam-logic-detail-pack
redteam-code-audit-detail-pack
web-pentest
```

共享参考覆盖：

- LOCK / ANGLE / INTENT / FACT / TENSION / REVIEW / HIT / MISS
- `web_map_*`
- `evidence_*` + `report_finding` + `submit_gate`
- `lookup_playbook` / `save_playbook`
- `reflexion` / `task_mode` / `correction_layer`
- `retest` / `experience` / `target-state` / `evidence` CLI
- `agent_graph` / `team` / `subagent` / `parallel_agents` / surface wave
- 工具族：`traffic_*`、`vault_*`、`bg_*`、`remote_*`、`source_extract`、`ocr/*`、`pyc/pdf`、`pwn_local`、CTF 平台工具

## 2. 移植到 CTF 的原则

1. **只带共享机制和通用工具族**：
   - 复制 `vulnclaw/skills/_shared/references/vulnclaw-mechanisms.md` 到 `aw` 同一路径。
2. **不要默认带 `electron-desktop-audit`**：
   - 它是 PC/Electron 审计 skill，routing 是 `client/desktop`，不属于 CTF 的常规 skill face；
   - 除非 CTF 题明确是 Electron/客户端逆向，再单独复制。
3. **CTF 专用章节保留**：
   - `blackboard_record_answer`、answer sheet、`ctf2_submit_flag`、`gcs_submit_flag`、
     `pwn_local_*`、`competition` / `ctf2` / `gcs`；
   - 生产审计章节（`report_finding` / `retest` 等）保留在文档里，但 CTF 流程按比赛目标使用。
4. **不改全局 editable 安装**：
   - 本机 `vulnclaw` 继续指向 `aw`；
   - 生产 skill 不复制到 `aw`，避免路由污染。
5. **不把生产证据/目标数据带进 CTF**：共享参考里不放真实 token、用户路径、真实域名。

## 3. 给 CTF skill 接共享参考

对需要机制闭环的 CTF skill，在 frontmatter 增加：

```yaml
shared_references:
  - vulnclaw-mechanisms.md
```

建议优先接：

```text
ctf-web
ctf-pwn
ctf-crypto
ctf-misc
competition-mode
benchmark-driving
security-hardening
```

`security-hardening` 已有自己的 blackboard 说明；仍可加共享参考，保持工具族/复盘一致。

如果 skill 已有 `shared_references`（例如 `client-reverse` 的 Android 参考），追加一行即可，不要覆盖原列表。

## 4. 应用步骤

```bash
# 1. 在 prod worktree 取出共享参考
cp E:/work/vulnclaw-prod/vulnclaw/skills/_shared/references/vulnclaw-mechanisms.md \
   D:/GitClone/VulnClaw/VulnClaw/vulnclaw/skills/_shared/references/

# 2. 给目标 CTF skill 的 frontmatter 加 shared_references
#    建议用编辑器批量处理，保留已有列表

# 3. 跑测试
cd D:/GitClone/VulnClaw/VulnClaw
python -m pytest tests/skills/test_skills.py -q
```

期望：loader 能加载新参考，`shared_references` 解析到文件，skill 测试通过。
prod 当前基线为 **69 passed**；`aw` 的测试数量可能不同，但不应新增失败。

## 5. CTF 使用方式

- CTF/比赛：继续用本机 `vulnclaw`（`aw`），不要用 prod wrapper。
- 生产：只在漏洞专用工作区用 `run-vulnclaw-prod.cmd`。
- CTF 的 answer sheet 用 `blackboard_record_answer`；生产 finding 用 `report_finding`，不要混用。
- 每次 run 结束可用 `vulnclaw learn` / `experience review` 蒸馏经验；只有 approved lesson 才影响后续。

## 6. 不要做的事

- 不要把 `electron-desktop-audit` 默认塞进 CTF skill face。
- 不要把 prod 的 `run-vulnclaw-prod.cmd`（含本机绝对路径）提交到公共/CTF 分支。
- 不要把生产 finding、真实 token、用户路径写进共享 reference 或 playbook。
- 不要修改全局 editable install 指向 prod。
