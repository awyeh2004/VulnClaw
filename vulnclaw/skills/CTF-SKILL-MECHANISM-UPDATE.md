# CTF / `aw` 分支的 Skill 机制移植说明

本文说明如何把 prod（`research/vuln-cases`）里的“共享机制 + 工具族”改动移植到 CTF 的 `aw` 分支，同时不把生产专用内容带进 CTF。

## 1. 背景

prod 新增了共享机制参考，并按用途拆成两份（2026-11-04 拆分）：

```text
vulnclaw/skills/_shared/references/operational-mechanisms.md   # 通用：CTF 与生产都适用
vulnclaw/skills/_shared/references/ctf-mechanisms.md           # CTF 专属：flag/answer sheet/平台提交
vulnclaw/skills/specialized/electron-desktop-audit/            # prod 专用 PC/Electron 审计
```

拆分原因：旧的单文件混装了 `blackboard_record_answer`、`ctf2_submit_flag` 等 CTF 工具，
生产 skill 一旦引用它，生产 run 的提示上下文里就会出现比赛提交链路。**“文档里写生产别用”
不是边界**，所以现在：

- 生产 skill 只声明 `operational-mechanisms.md`；
- CTF-only 文档名登记在 `vulnclaw/skills/loader.py` 的 `_CTF_ONLY_SHARED_REFS`，
  `VULNCLAW_PROFILE=prod` 时 loader 直接把它从 `shared_references` 里剔除，
  `load_skill_reference` 也解析不到。

共享参考覆盖：

- LOCK / ANGLE / INTENT / FACT / TENSION / REVIEW / HIT / MISS
- `web_map_*`
- `evidence_*` + `report_finding` + `submit_gate`
- `lookup_playbook` / `save_playbook`
- `reflexion` / `task_mode` / `correction_layer`
- `retest` / `experience` / `target-state` / `evidence` CLI
- `agent_graph` / `team` / `subagent` / `parallel_agents` / surface wave
- 工具族：`traffic_*`、`vault_*`、`bg_*`、`remote_*`、`source_extract`、`ocr/*`、`pyc/pdf`

CTF 专属（只在 `ctf-mechanisms.md`）：flag 与证据、answer sheet、`ctf2_submit_flag` /
`gcs_submit_flag` / `platform_submit`、套娃收尾、比赛节奏、`pwn_local_*`。

## 2. 移植到 CTF 的原则

1. **两份参考都带，但按 skill 用途分配**：
   - CTF 题类 skill → `operational-mechanisms.md` + `ctf-mechanisms.md`；
   - 通用/防守/跑分 skill → 只带 `operational-mechanisms.md`。
2. **不要默认带 `electron-desktop-audit`**：
   - 它是 PC/Electron 审计 skill，routing 是 `client/desktop`，不属于 CTF 的常规 skill face；
   - 除非 CTF 题明确是 Electron/客户端逆向，再单独复制。
3. **CTF 专用章节只放在 `ctf-mechanisms.md`**：
   - `blackboard_record_answer`、answer sheet、`ctf2_submit_flag`、`gcs_submit_flag`、
     `pwn_local_*`、`competition` / `ctf2` / `gcs`。
4. **不改全局 editable 安装**：
   - 本机 `vulnclaw` 继续指向 `aw`；
   - 生产 skill 不复制到 `aw`，避免路由污染。
5. **不把生产证据/目标数据带进 CTF**：共享参考里不放真实 token、用户路径、真实域名。

## 3. 给 skill 接共享参考

CTF 题类 skill：

```yaml
shared_references:
  - operational-mechanisms.md
  - ctf-mechanisms.md
```

通用/生产 skill：

```yaml
shared_references:
  - operational-mechanisms.md
```

当前接线：

```text
ctf-web / ctf-pwn / ctf-crypto / ctf-misc / competition-mode -> 两份
benchmark-driving / security-hardening                       -> 仅 operational
```

如果 skill 已有 `shared_references`（例如 `client-reverse` 的 Android 参考），追加即可，不要覆盖原列表。

## 4. 应用步骤

```bash
# 1. 在 prod worktree 取出共享参考（两份都要）
cp E:/work/vulnclaw-prod/vulnclaw/skills/_shared/references/operational-mechanisms.md \
   E:/work/vulnclaw-prod/vulnclaw/skills/_shared/references/ctf-mechanisms.md \
   D:/GitClone/VulnClaw/VulnClaw/vulnclaw/skills/_shared/references/

# 2. 给目标 skill 的 frontmatter 加 shared_references
#    建议用编辑器批量处理，保留已有列表

# 3. 跑测试
cd D:/GitClone/VulnClaw/VulnClaw
python -m pytest tests/skills -q
```

期望：loader 能加载新参考，`shared_references` 解析到文件，skill 测试通过。
`VULNCLAW_PROFILE=prod` 下 `ctf-mechanisms.md` 必须解析不到（有测试覆盖）。

## 5. CTF 使用方式

- CTF/比赛：继续用本机 `vulnclaw`（`aw`），不要用 prod wrapper。
- 生产：只在漏洞专用工作区用 `run-vulnclaw-prod.cmd`，且必须设置
  `VULNCLAW_PROFILE=prod`（以及该 profile 专属的 `VULNCLAW_CONFIG_DIR` / `VULNCLAW_WORK_DIR`）。
- CTF 的 answer sheet 用 `blackboard_record_answer`；生产 finding 用 `report_finding`，不要混用。
- 每次 run 结束可用 `vulnclaw learn` / `experience review` 蒸馏经验；只有 approved lesson 才影响后续。

## 6. 不要做的事

- 不要把 `electron-desktop-audit` 默认塞进 CTF skill face。
- 不要把 CTF 专属章节写回 `operational-mechanisms.md`。
- 不要把 prod 的 `run-vulnclaw-prod.cmd`（含本机绝对路径）提交到公共/CTF 分支。
- 不要把生产 finding、真实 token、用户路径写进共享 reference 或 playbook。
- 不要修改全局 editable install 指向 prod。
