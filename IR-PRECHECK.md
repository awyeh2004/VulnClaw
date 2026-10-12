# 赛前清单（按 2026-10-10 实际状态写）

> 比赛：2026-10-11 天津。渗透 9:30–12:00 / 应急 12:20–15:30。
> 本清单只写**现在真实的状态**与**还剩什么**，不重复 runbook 细则。
> 复查命令都在每条下面，可自行复验。

---

## 一、机器状态（实测，2026-10-10 晚）

| 项 | 当前值 | 需要动吗 |
|---|---|---|
| `session.task_mode` | **`ir`**（10-11 应急段切过；备份 `config.yaml.bak-20261011-before-ir`） | 下次打**渗透**段前改回 `pentest` |
| `safety.permission_mode` | `full_access` | 不改（副驾靠 `copilot.cmd` 那层） |
| `safety.denied_hosts` | `['tp.qianxin.com']` | ✅ 对 |
| `competition.allow_flag_submission` | `False` | ✅ 对（提交由人做） |
| `competition.stall_turns` | `6` | ✅ 对 |
| `remote.hosts` | **空** | ✅ 保持空 —— **除了 VPN 直连场景**（拨上 VPN 后要 agent 直连才填） |
| `platforms.ctf2/gcs` | 双关 | ✅ 对 |
| `network.http_proxy` | 空 | ✅ 对（搭隧道时才设） |

```powershell
# 复验（一条命令看全）
cd D:\GitClone\VulnClaw\VulnClaw
vulnclaw config get session.task_mode
vulnclaw config get safety.denied_hosts
```

---

## 二、产物清单（都在，不用再准备）

| 文件 | 用途 | 大小 |
|---|---|---|
| [`IR-CONTRACT.txt`](IR-CONTRACT.txt) | **可直接粘贴的契约**（记事本选段即粘，纯文本 5 段） | 5.4 KB |
| [`copilot.cmd`](copilot.cmd) | 副驾启动器（仓库根，双击/命令行都行） | 2.9 KB |
| [`IR-FIELD-CARD.md`](IR-FIELD-CARD.md) | 现场动作卡（开场清单 / 收束点 / 计时锚点） | 18 KB |
| [`IR-PENTEST-CARD.md`](IR-PENTEST-CARD.md) | 渗透命令卡（≤120 字符） | 15 KB |
| [`PLAYBOOK-SHORTLIST.md`](PLAYBOOK-SHORTLIST.md) | 哪篇历史笔记什么时候贴 | 10 KB |
| [`IR-PROMPTS.md`](IR-PROMPTS.md) | 每条消息怎么写（含两跳模板） | 16 KB |
| `技能卡` | 应急命令卡在 `vulnclaw/skills/.../incident-response/references/paste-cards-{linux,windows}.md` | — |
| **playbook 库** | `~/.vulnclaw/playbooks/`，**315 篇**（新增拓扑判序 / OPNsense 打法） | — |
| **ZCode skill** | `~/.zcode/skills/vulnclaw-competition-copilot/` | — |

---

## 三、今晚（赛前）建议做的

- [ ] **把 `IR-CONTRACT.txt` 复制一份到桌面**（现场从桌面打开最快，不用翻仓库）
- [ ] **试一次启动**，确认横幅与提示符正常：
      ```cmd
      cd /d D:\GitClone\VulnClaw\VulnClaw
      set COPILOT_DENY=<随便一个测试IP>
      .\copilot.cmd
      ```
      看到 `[copilot] DENY=… hard-blocked` 与 `vulnclaw Ready>` 即可 Ctrl+C 退出。
- [ ] **决定 playbook 要不要一键带**：要 → 启动前加 `set COPILOT_PLAYBOOKS=1`（它会从你粘贴的输出自动认类别；认不出就不带）
- [ ] **充电 + 装包**：网线/转接器、充电器、耳机（现场有水晶头，自备更省事）
- [ ] **清 C 盘**（若还要腾空间）：采集物与工具箱默认写 E:/

---

## 四、明天现场流程（照做）

| 时间 | 做什么 |
|---|---|
| 08:30 | 到场签到（**开赛 30 分钟后禁止入场**） |
| 09:00–09:30 | 登录 → 任务中心 →【进入演练】→ 读规则说明 → 看拓扑（**点一下能看到 IP**） |
| **09:30 第一件事** | ⭐ **找 VPN 拨入通道**：拓扑里右键「数字VPN设备」→【VPN信息】拿账号密码 → 本机 VPN 拨入（L2TP/IPSec、共享密钥 `vpn`、服务器=平台登录IP）→ `route print -4` 确认靶网段出现 |
| 09:30–09:40 | **分诊**：记分值 / 解锁关系 / 每题"网页终端还是直连"→ 填网络清单（`#N IP ★`） |
| 09:40 | **过收束点**，然后开打 |
| 11:30 | 停止开新题，核对 flag 都交了 |
| **12:20 前** | **切 `task_mode` 为 `ir`**（`vulnclaw config set session.task_mode ir`） |
| 12:20–12:35 | 应急段分诊 |
| 15:00 | 停开新题，留痕 + 逐题核对提交 |
| 15:30 | 结束 |

**收束点 5 条**（没全绿不许开打）：
① 分诊表在手　② 副驾会话能起且提示符 `vulnclaw Ready>`　③ `COPILOT_DENY` 横幅出现
④ `remote.hosts` 状态明确　⑤ 计时与台账有人

**⭐ VPN 判定（10-11 实付代价换来的，开场必做）**：拨上 VPN 后先确认目标服务与授权，不能仅凭路由可达就认定可自动采集。`remote_collect` 在整体审批后自动探测 OS：Linux 保持 POSIX/tar.gz；Windows 需要**可达 SSH + PowerShell**，走只读 UTF-8 长度帧临时**单文件**回传（base64 传输，不用 zip/tar）。
VPN 不会启用 WinRM/RDP，也不会创建 SSH；缺 SSH/PowerShell 或探测未知/歧义时，退回 `remote_exec` / `remote_fetch`（有 SSH 时）或人工副驾。真实 Windows SSH/PowerShell E2E **未验证**，现场要单独验收。
只有网页终端可用时按 [IR-FIELD-CARD.md](IR-FIELD-CARD.md) §0.1 的信道速查走（短则截图、长则 base64、成批则上传 `.txt` 脚本）。

---

## 五、只剩你能做的（我做不了）

- [ ] **催官方群两个答复**：① **能否搭隧道** ② 是否必须有线（现场已实测水晶头足够，这条可视为解决）
- [ ] **4 人分工的名字落到人**（角色已定稿到动作，只差"谁是谁"）
- [ ] **现场才可能知道**：4 个账号能否各做不同题 / 内存取证给不给镜像 / 网页终端能否粘贴长命令

---

## 六、已知残留（不影响比赛，知情即可）

| 项 | 状态 |
|---|---|
| Docker Desktop | **未运行** → 本地演练靶（ir-drill 等）暂时用不了；**不影响比赛**（靶场在平台侧） |
| 本机有未提交文档 | `HANCLOUD-SITREP.md` / `IR-EXAM-PLAN.md` 未跟踪、`IR-PENTEST-HANCLOUD.md` 已改；需要时说一声推 |
| 全量测试 | 4932 passed / **1 failed** —— 那条是 Windows 保留端口 1455 导致的环境问题，与代码无关（已用 `git stash` 证明） |
| 一键注入的召回 | 可用但**不精**：命中的 2 篇里常有一篇 `autonotes-*`（自动笔记，与干货同分）——按 slug 取舍 |
| 真 Windows 跳板端到端 | **未验证**（本机无真实 Windows SSH/PowerShell 环境）；代码/模拟覆盖自动 OS probe、只读 framed 单文件路径；现场仍需验证 SSH + PowerShell 可达性 |

## 七、10-11 实战复盘（下一场开场前过一遍）

| 教训 | 下一场怎么做 |
|---|---|
| **没先拨 VPN**，两场全程只在网页控制台里敲 ⇒ agent 无法直连，效率被信道掐死 | **开场第一件事找 VPN**（见第四节）；拨上再决定模式 |
| 长命令粘到控制台**必掉字符**（`\f` 翻页、引号丢、残字粘连） | 命令压到 **≤100 字符**；成批走**上传 `.txt` 脚本** |
| 控制台**不能复制文字** ⇒ 靠截图 ⇒ agent 读图反复出错（`SourceFireSux` 读成 `SourceFireSIXTHe`、`id` 读成 `mirror`） | **字符串类答案一律打印字符码/长度**；长输出回传 **base64 一行** |
| 一道题连发多条**口径不明**的计数命令（Q10 试 79/81/82/65 全错） | **先用一条命令打印所有候选口径**，再判交哪个 |
| 凭 pcap 帧号序推"JNDI 第一条命令"（Q4 推 `id`，实测错） | 顺序类题目**按日志/时间戳判**，不能按抓包帧号 |

> 传输手法全表见 [IR-FIELD-CARD.md](IR-FIELD-CARD.md) §0.1；契约文本已含精简版（[`IR-CONTRACT.txt`](IR-CONTRACT.txt) 第 1/2/6 段）。
