# 赛前清单（按 2026-10-10 实际状态写）

> 比赛：2026-10-11 天津。渗透 9:30–12:00 / 应急 12:20–15:30。
> 本清单只写**现在真实的状态**与**还剩什么**，不重复 runbook 细则。
> 复查命令都在每条下面，可自行复验。

---

## 一、机器状态（实测，2026-10-10 晚）

| 项 | 当前值 | 需要动吗 |
|---|---|---|
| `session.task_mode` | **`pentest`** | ⚠️ **12:20 进应急段前改 `ir`** |
| `safety.permission_mode` | `full_access` | 不改（副驾靠 `copilot.cmd` 那层） |
| `safety.denied_hosts` | `['tp.qianxin.com']` | ✅ 对 |
| `competition.allow_flag_submission` | `False` | ✅ 对（提交由人做） |
| `competition.stall_turns` | `6` | ✅ 对 |
| `remote.hosts` | **空** | ✅ 已清；现场要 agent 直连时再填跳板机 |
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
| 本机有 **2 笔未推提交** | 需要时说一声推；不推也不影响现场使用 |
| 全量测试 | 4932 passed / **1 failed** —— 那条是 Windows 保留端口 1455 导致的环境问题，与代码无关（已用 `git stash` 证明） |
| 一键注入的召回 | 可用但**不精**：命中的 2 篇里常有一篇 `autonotes-*`（自动笔记，与干货同分）——按 slug 取舍 |
| 真 Windows 跳板端到端 | 未验（本机 WSL2 跑不了 Windows 容器）；已验到"`remote_collect` 全 POSIX 不可用 / 免批只认 CMD 原生命令" |
