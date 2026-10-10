# 应急响应能力 · 使用与自检速查

> 给未来的自己 / 队友看的操作卡。TL;DR 在最上面。

---

## TL;DR

```powershell
# 1) 自检（确认能力可用）
python .ir-tools\verify-ir.py

# 2) 启用工具箱环境
. .ir-tools\env.ps1

# 3) 启动，强制指定技能
vulnclaw
> /incident-response 目标 10.0.0.5，先查 webshell 和持久化后门
```

---

## 一、怎么调用这个能力

### 启动

```bash
vulnclaw          # 经典 REPL
vulnclaw tui      # TUI 工作台
vulnclaw web      # 本地 Web UI（127.0.0.1:7788）
```

### ⭐ 强制指定技能（推荐）

前缀 `/技能名` 会**无条件选中**，实测 confidence = 1.0：

```
/incident-response 目标 10.0.0.5，先查 webshell 和持久化后门
/incident-response
```

**为什么推荐**：自然语言隐式路由的 confidence 只有 0.11–0.2，且部分表述**根本不命中**。

| 输入 | 结果 | confidence |
|---|---|---|
| `/incident-response 帮我排查这台服务器` | incident-response | **1.0** |
| `这是一个被入侵的 Linux 服务器，帮我找恶意程序` | incident-response | 0.2 |
| `拿到一台机器，怀疑挖矿` | **没命中** | — |

### 自然语言（大多数情况也行）

```
这台机器CPU飙升，怀疑挖矿木马
网站被植入了webshell，帮我查杀
文件后缀被改成.bomber了，还有勒索信
首页被挂黑链了
排查一下有没有克隆账号和隐藏账号
分析一下access.log做攻击溯源
```

已注册的触发词：应急响应 / 入侵排查 / 被入侵 / 失陷主机 / 被植入 / 恶意程序 / 恶意行为痕迹 / webshell查杀 / 查马 / 隐藏后门 / 持久化排查 / 权限维持 / 挖矿木马 / 勒索病毒 / 勒索信 / 网页篡改 / 挂黑链 / 暗链 / 克隆账号 / 隐藏账号 / 日志分析 / 攻击溯源 / 应急取证 / 内存取证 / 痕迹分析 / dfir / forensic

### 参考文档按需加载

技能注入上下文的是**索引不是正文**（73K+ 字符不会一次性灌进去）。正文由模型按需拉：

```python
load_skill_reference(skill_name="incident-response", reference_name="events/webshell.md")
load_skill_reference(skill_name="incident-response", reference_name="40-log-analysis.md")
```

> **嵌套路径**（`events/xxx.md`）需要 `loader.py` 的递归发现改动支持 —— 已改并验证。

---

## 二、怎么测功能正常

### 一键自检

```powershell
python .ir-tools\verify-ir.py
```

五组检查（全部只读，不发网络请求）：

| 组 | 检查什么 |
|---|---|
| **A** | 技能能被发现、SKILL.md 能解析、frontmatter 正确、13 个 reference 全部可读 |
| **B** | 结构完整性（13 篇正文齐全，缺一即 FAIL） |
| **C** | 路由（8 个应命中 + 1 个对照不应命中） |
| **D** | 工具箱（关键文件 + yara 实际编译匹配 + ⭐ **vol 真实分析** banners） |
| **E** | Log Parser（可选） |
| **F** | ⭐ **远程执行模块**（4 个工具 schema + 审批门覆盖 remote + 采集脚本生成 + 归档安全） |

**期望输出**（实测基线，`2026-09-20`）：

```
PASS=76  FAIL=0  WARN=0
结论: 功能可用
```

**WARN=0** —— 13 篇 reference 全部写完，不再有"待补"项。
**FAIL > 0 才需要处理。**

### 单独测某一块

```powershell
python .ir-tools\verify-ir.py --skip-toolkit          # 只测技能与路由
python .ir-tools\verify-ir.py --toolkit D:\ir-tools   # 指定工具箱路径
```

### 项目回归测试

```powershell
python -m pytest tests/skills -q                              # 期望: 137 passed
python -m pytest tests/security/test_command_classifier_ir.py -q   # 期望: 113 passed
```

---

## 三、工具箱

**位置**：`.ir-tools/`（工作区）+ `G:\tool\ir-toolkit`（移动硬盘副本）

```powershell
. .ir-tools\env.ps1        # PowerShell
.ir-tools\env.cmd          # cmd
```

启用后 `PATH` 里会有 `bin/`，`vol` 和（若装在 `E:\LogParser`）`LogParser.exe` 可直接调用。

### ⚠️ 关键认知：CLI 是赛场主力，GUI 是离线分析用

| 类别 | 用在哪 | 例子 |
|---|---|---|
| **CLI / 原生命令** | ⭐ **靶机现场** | `ps aux`、`/proc/<PID>/exe`、`ss -antp`、`find`、`stat`、`rpm -Va`、`last`、`grep` 日志 |
| **GUI / 便携工具** | **本机分析工作台** | D盾、Process Explorer、FullEventLogView、vol |

**靶机上不会有 D盾。** GUI 工具的用途是：分析离线证据（导出的日志/内存镜像/样本），或靶机恰好是 Windows 且你能 RDP 上去。

### 清单

| 工具 | 状态 |
|---|---|
| D盾_Web查杀 | ✅ `bin/D盾_Web查杀/D_Safe_Manage.exe` |
| Sysinternals Suite（164 工具） | ✅ `bin/SysinternalsSuite/` |
| NirSoft 8 件套 | ✅ FullEventLogView / WinPrefetchView / UserAssistView / ShellBagsView / LastActivityView / BrowsingHistoryView / WifiHistoryView / DNSDataView |
| volatility3 2.28.2 | ✅ `vol` 启动器（⭐ 已修 Anaconda 冲突，`banners` 实测通过） |
| ⭐ **tshark / capinfos / editcap / mergecap** | ✅ Wireshark **3.2.1**，`env.ps1` 已加进 PATH |
| yara / oletools / dpkt / pefile / capstone / lief | ✅ `pylib/` |
| pcap 样本生成器 | ✅ `pcap/make_pcap.py`（合成 webshell 流量，可验证文档命令） |
| Log Parser 2.2 | ✅ `E:\LogParser`（COM 已注册 + 已加进 env PATH） |
| 河马 HWS | ❌ 待手动下载（`shellpub.com`） |
| PCHunter / PowerTool | ❌ 待手动下载（`xuetr.com`） |

### ⚠️ 工具的两个"看着能用其实不能用"陷阱

| 陷阱 | 表现 | 真相 |
|---|---|---|
| **vol 的 `--help` 假阳性** | `vol --help` 正常 → 以为能用 | 真实插件会崩在 Anaconda 的 `pyOpenSSL`（`GEN_EMAIL`）。`--help` 不加载 layer 所以不触发 |
| **vol 缺符号表** | 插件报 `Unsatisfied requirement ... symbol_table_name` | 不是坏了：Linux 要自备 ISF（本机没有），Windows 首次要外网下符号 |
| **tshark 不在 PATH** | `tshark` 命令找不到 | `env.ps1` 已修；或显式用 `C:\Program Files\Wireshark\tshark.exe` |
| **tshark 3.2.1 无 `-z export-objects`** | 报 `Invalid -z argument` | 该功能 3.4+ 才有。改用 `-T fields -e http.file_data` |
| **`-Y` 里的裸 `=` / `?`** | `tshark: "=" was unexpected` | Windows 命令行解析问题；用 `==`/`contains`/`>=`，或出字段后 `Select-String` 过滤 |

> ⭐ 自检脚本现在会**真的跑一次 vol 分析**（`banners` over `ntoskrnl.exe`，
> 提取出 `ntkrnlmp.pdb|...` 符号键）而不只是 `--help` —— 就是为了不再漏掉上面第一个陷阱。

---

## 四、技能内容地图

```
vulnclaw/skills/specialized/incident-response/
├─ SKILL.md                    决策树 + 事件分型 + 路由
└─ references/
   ├─ 10-system-basics.md      系统信息 / 启动项 / 计划任务
   ├─ 20-accounts.md           账号（克隆账号 F 值、隐藏账号、UID=0）
   ├─ 25-process-service.md    进程 / 服务 / 驱动 / 模块 / Rootkit
   ├─ 30-file-artifacts.md     文件痕迹 / 时间逻辑判据 / SUID / 完整性校验
   ├─ 40-log-analysis.md       事件ID表 / 登录类型表 / 全组件日志位置表
   ├─ 50-memory-traffic.md     ⭐ 内存取证 / 流量分析（tshark·vol·dpkt，全部实测）
   ├─ 60-tools.md              工具落点（CLI/GUI 场景区分）
   ├─ casebook.md              真实处置案例 + 跨主机溯源范例
   ├─ offline-collection.md    ⭐ 离线取证收集与分诊（远程固化现场 + 证据登记）
   └─ events/
      ├─ webshell.md           11维检测 / 内存马 / 落库型后门 / 流量特征
      ├─ cryptomining.md       分型判据 / 自删除 / base64定时任务 / 清除顺序
      ├─ web-defacement.md     四层篡改 / 3个具体手法 / 数据库侧
      └─ ransomware.md         四项判据 / ⭐错误处置方法 / 查询解密工具
```

**全部 13 篇已写完**，`load_skill_reference` 实测全部可加载，无 `None`。

---

## 四点四、⭐ 远程实操（SSH）：remote_* 工具

**赛题是多题形式：一部分远程实操（给你 SSH），一部分离线取证。**
目标是**另一台机器**时，别用 `shell_command` 拼 `ssh` 命令 —— 用这三个工具。

### 配置：主机清单（必须先做，否则工具完全惰性）

```yaml
# ~/.vulnclaw/config.yaml
remote:
  hosts:
    victim1:
      hostname: 10.0.0.5
      port: 22
      username: root
      key_file: C:/Users/me/.ssh/id_ed25519   # 留空则用 ssh-agent / 默认密钥
      # password: ''                          # 无密钥时的兜底（会出现在审批详情里，慎用）
      host_key_policy: accept_new             # 见下
      note: 应急响应靶机
  connect_timeout_s: 15
  command_timeout_s: 60
```

⭐ **为什么是"清单制"而不是直接传 host 字符串**：比赛规则关心**哪些机器在范围内**。
别名制让"目标是谁"在审批界面和日志里始终可见，也让未声明的机器**根本连不上**。
这也是将来接"越界黑名单"的接缝。

### 工具

| 工具 | 用途 |
|---|---|
| `remote_hosts` | 列出已配置别名（先跑这个，别猜主机名） |
| `remote_collect` | ⭐ **一次性只读采集 33 段**并打包拉回本地、自动解包 |
| `remote_exec` | 在远程跑单条命令 |
| `remote_fetch` | SFTP 取单个大文件（内存镜像、pcap） |

### ⭐ 关键设计：远程命令走**同一个**审批门

`remote_exec` 的 `kind="remote"` 被纳入**同一套只读分类器**，所以：

| 远程命令 | 行为 |
|---|---|
| `ps aux` / `ls -al` / `cat /etc/passwd` / `crontab -l` | ✅ `auto_review` 下**免批准** |
| `rm` / `userdel` / `systemctl stop` / 重定向 `>` / 解释器 | ⚠️ **仍弹窗** |

> 这是刻意的：如果远程命令不走审批门，这个模块就成了**绕过唯一安全控制**的后门。
> 而如果远程命令全部弹窗，人会被训练成无脑点同意 —— 那比不弹更糟。

**批量采集是"一次性整体审批"**：审批界面会列出全部 33 条命令
（`collect_plan()` 与真正执行的脚本由**同一个常量**生成，不可能不一致）。

### ⚠️ 主机密钥策略（现场必读）

| 策略 | 行为 | 什么时候用 |
|---|---|---|
| `known_hosts`（默认） | 未知主机**直接报错** | 有既有 known_hosts 的长期环境 |
| `accept_new` | TOFU：接受并在输出里**报告指纹** | ⭐ **比赛现场**（全新的靶机，没有既有记录） |
| `insecure` | 不校验 | 不建议 |

> 无论哪种模式，**观测到的指纹都会打进工具输出**，留审计痕迹。
> 比赛 VM 一定是首次连接，所以现场要用 `accept_new`；但别把它当默认。

### 采集什么（33 段）

覆盖各篇 reference 的检查点：账号/sudoers/authorized_keys、进程/`/proc/*/exe`/
命令行与环境变量、socket 与网络连接、内核模块与 syscall 表、**cron 全部位置**、
systemd、启动项、`ld.so.preload`、历史命令、Web 根与上传目录、隐藏 dotfile、
SUID/SGID 与 capabilities、世界可写目录、**已删除但仍占用**的可执行、
近 14 天改动、系统与 Web 日志、网络配置与防火墙、软件包、sshd 配置、
容器痕迹、**反取证线索**。

> ⚠️ 采集用的是**目标上已有的** POSIX 工具（实测目标可能没有 python/busybox/curl）。
> 不在目标上装任何东西。

### ⚠️ 采集完记得清理，否则污染证据

演练实测踩到：采集/setup 脚本留在目标 `/tmp` 后，**它出现在"近期改动文件"和
"隐藏文件"清单里**，agent 无法区分"攻击者的"还是"分析员自己的"。
采完删掉自己的脚本，或在报告里标注哪些文件是分析工具产生的。

---

## 四点五、⭐ 非交互式驱动 + 两个环境坑（实测）

### 用 CLI 驱动（可脚本化 / 可让外层 agent 调）

```bash
vulnclaw solve <target> \
  --goal "完成应急响应：找出后门文件、攻击者IP、入侵时间、漏洞行号、持久化机制" \
  --prompt "/incident-response 这台服务器疑似被入侵" \
  --max-steps 60 --run-name ir-target1 [--runs-dir <dir>] [--stream]
```

| 参数 | 说明 |
|---|---|
| `--goal` | ⭐ **必须自定义**——默认是 CTF 向的"找到 flag / 拿到 shell" |
| `--prompt` | 任务描述，**`/skill` 前缀会被正确解析**（实测命中 incident-response） |
| `--max-steps` | 自主轮数上限（默认 240），**防止跑飞烧 token** |
| `--target` | **追加目标**——多靶机可一次纳入同一 run |
| `--resume-run <name>` | 恢复中断的 run |
| `--stream` | 输出 NDJSON 事件流，可实时监控进度 |

### ⚠️ 坑 1：配置目录硬编码，`--runs-dir` 管不了全部

```
~/.vulnclaw/
├─ runs/          ← --runs-dir 能改
├─ targets/       ← ❌ 不受 --runs-dir 控制
├─ sessions/  kb/  python_execute_audit.jsonl
```

`targets/` 写不进去会**直接崩**（`PermissionError ... .vulnclaw\targets\xxx`），
而且**报告也生成失败**（只在末尾打一行红字提示）。整体重定向要用环境变量：

```powershell
$env:VULNCLAW_CONFIG_DIR = 'D:\ir-run\vulnclaw-home'   # 全部状态都去这里
```

> ⭐ **赛前务必确认 `~/.vulnclaw` 可写。** 否则可能"跑完才发现报告没生成"。

### ⭐ 监督长跑：`scripts/run_watchdog.py`（给外层 agent 用）

`vulnclaw solve` 一跑就是几十分钟。这个脚本读 vulnclaw **自己的结构化状态**
（`run.json` / `current.json`），不解析日志文本，所以不受编码与格式变化影响，
输出也压到几行 —— 它是给 agent 当**上下文**用的，不是给人看的。

```bash
# 三选一，别同时开两个（会重复通知）
python scripts/run_watchdog.py --run <name> --status          # 偷看一次，~10 行
python scripts/run_watchdog.py --run <name> --follow          # 变化才打一行
python scripts/run_watchdog.py --run <name> --follow --quiet  # 后台盯梢，只在有事时说话
```

⚠️ **别自己循环调 `--status`**：N 次检查 = N 次工具调用 + N 个状态块。
轮询循环在脚本进程里，所以第三种模式一次后台调用就能覆盖全过程。

⚠️ **`NEEDS_INPUT` 必须处理**：`run.json` 显示 `completed` **不等于任务做完了**。
实测遇到过进程正常退出、但 `agent_state.completed=False` 且 `pending_questions`
非空 —— agent 停在问操作员一个问题。只看 `run.json` 会**关掉一个正等着你回复的
run**。该情形现在单独报成 `NEEDS_INPUT` 并附上待答问题与行动指引。

`python scripts/run_watchdog.py --help` 末尾列了全部结局（`ENDED:COMPLETED` /
`NEEDS_INPUT` / `ENDED:FAILED` / `STUCK` / `NO_RUN_DIR` / `TIMEOUT`）的含义。
**退出码恒为 0**，结局看 stdout 第一行。

### ⚠️ 坑 2：题面提示没有外部注入通道

```
CLI --prompt → add_user_message → system_prompt(if user_input)
             → core._get_active_skill_context(user_input)   # 顺便解析 /skill
```

- `_inject_local_challenge_hint` **只对 `local-NNNNN` 生效**（本地 CTF 附件）
- **HTTP 靶标直接返回原文**——没有"题面文件"或"提示环境变量"机制

**提示只能来自两处**：① 你传的 `--prompt`；② **靶机自己吐出来的内容**。

> ⭐ **不要把题面做成靶机的接口**（如 `/api/hint`）。那样它会被当成
> "目标机的一条证据"照抄——**包括靶机根本验证不了的说法，等于假情报**。
> 真实比赛的提示在**外部平台 / 规则文档**里，不在靶机内。

### ⚠️ 坑 3：平台工具无门禁，agent 会主动去调

实测：一次纯应急响应任务里，agent 第 3 个动作是 `gcs_notice_list {}`
（**主动去查 GCS 比赛平台公告**，与任务无关）。

原因：`builtin_tools.py:2035-2039` **无条件注册** CTF2/GCS 全部工具，无凭据门禁。
而你本机确实存着有效凭据（`~/.vulnclaw/config.yaml` 的 `gcs.access_key` +
从浏览器 localStorage 自动读取的 CTF2 token）。

**赛前处理**：`submit_flag` 类工具切人工确认或禁用；`competition.enabled` 保持 `false`。

---

## 四点六、⭐ 命令审批：哪些免批准、哪些会弹窗

**机制**：`safety.permission_mode` 三档

| 模式 | 行为 |
|---|---|
| `ask`（默认） | **每条** `shell_command` / `python_execute` 都要批准 |
| `auto_review` | 走 `command_classifier` 三态判决：只读命令免批准，其余弹窗 |
| `full_access` | 全放行（不建议现场用） |

**比赛建议 `auto_review`**——否则 `ps aux` / `ls -al` / `grep` 每条都要你点，很费时间。

### 已扩充的免批准白名单

```
# Linux 应急排查
ps  ss  netstat  lsof  last  lastb  lastlog  who  w
systemctl  journalctl  crontab  rpm  dmesg  lsmod  modinfo
lsattr  lsblk  mount  strings  xxd  od  hexdump  getcap
unhide  chkrootkit  service  stat  find  grep  diff
head  tail  cat  wc  file  md5sum/sha*sum  jq  tree  ...

# Windows 应急排查
tasklist  sc  schtasks  reg  wevtutil  net  systeminfo
driverquery  wmic  attrib  dir  findstr  where  fc  comp
ipconfig  arp  route  getmac  nslookup  fsutil  quser  openfiles
```

⭐ **每条都带参数守卫**——同一工具的危险形态仍会弹窗：

| 免批准 | 仍弹窗 |
|---|---|
| `systemctl status nginx` | `systemctl stop / disable / daemon-reload` |
| `crontab -l` | `crontab -e / -r` |
| `rpm -Va` / `rpm -qf x` | `rpm -i / -e / -U` |
| `find / -ctime 0 -name x` | `find / -exec` / `-delete` / `-fprint` |
| `mount`（列举） | `mount /dev/sdb1 /mnt` |
| `net user`（列举） | `net user hacker P@ss /add` |
| `wmic process get ...` | `wmic process call create` / `delete` |
| `sc query/qc` | `sc create / config / stop` |
| `reg query` | `reg add / delete / import` |
| `wevtutil qe` | `wevtutil cl`（清日志） |
| `schtasks /query` | `schtasks /create /delete /run` |
| `dmesg` | `dmesg -C`（清环形缓冲） |
| `service x status` | `service x stop / restart` |
| `fsutil`（只读子命令） | `fsutil deletejournal` |

**仍然一律弹窗**：解释器（`python`/`bash`/`powershell`）、`rm`、`sudo`、`awk`、`xargs`、`nc`、`curl`、
**一切重定向与命令替换**（`>`、`<`、`$()`、反引号）、**前导环境变量赋值**（`PATH=x cmd`）。

> ⭐ **重定向永远弹窗是刻意的**：`>` 能覆盖任意文件。所以
> `ps aux > /tmp/out.txt` 会弹窗，而 `ps aux` 不会。**不影响主要排查流**——
> 需要留证据时把输出交给 `python_execute`，或用 evidence 机制即可。

### 项目专有工具（`nmap` / `sqlmap` / `ffuf`）怎么办

不在白名单里会弹窗。加进配置（`auto_review` 模式生效）：

```yaml
safety:
  permission_mode: auto_review
  trusted_commands:
    - "nmap -sV"
    - "ffuf -u"
```

> ⚠️ 首 token 命中 `BANNED_NAMES` 的条目会被**拒绝加载**（有 warning）——
> 例如 `python xxx` 加不进去，这是设计如此。

### 怎么验证白名单生效

```powershell
python -m pytest tests/security/test_command_classifier_ir.py -q
# 期望: 113 passed（66 条免批准 + 47 条应拦截）
```

> 已纳入项目测试套件，所以以后改动分类器时会自动回归。

---

## 四点七、⭐ 端到端实战验证：Docker 靶机 dry-run 结果

用 `D:\ir-drill`（隔离在仓库外的 Linux Web 服务器靶机）做全流程验证，**两次独立 clean run 都是 6/6 + 3/3**：

| 评分项 | 结果 | 关键证据 |
|---|---|---|
| 1. 三个恶意文件（含**被篡改的** upload.php） | ✅ | 自己跑了基线 `diff`，`37a38,40` 3 行新增 + md5 对比 |
| 2. 攻击者 IP | ✅ | `203.0.113.47`，并正确排除运维 `192.168.1.10` 与 `Googlebot` |
| 3. 首次入侵时间 | ✅ | `2026-03-14 09:22:51`，从 access.log 的 `4×400 → 1×200` 推 |
| 4. 漏洞类型 + 行号 | ✅ | `pathinfo(...PATHINFO_EXTENSION)` 只取最后一段后缀，第 21 行 |
| 5. ⭐ **两处** cron + UID=0 账号 | ✅ | `crontabs/root` 与 `/etc/cron.d/demo-persistence` 都找到 |
| 6. 清除方案顺序正确 | ✅ | 断外联 → **先拆持久化** → 删文件 → 基线覆盖 → 修漏洞 → 加固 |
| 观察 7. 真跑了 `ls -al` | ✅ | 第 2 条命令就是 `ls -al /var/www/html/uploads/`（`ls -l` 看不到 dotfile） |
| 观察 8. 路径真实存在 | ✅ | 全部为 `docker exec` 实测原样，无凭空前缀 |
| 观察 9. `[观测]`/`[推断]`/`[知识]` 分标 | ✅ | 全程标注，且**没把推断写成观测** |

> 报告留档：`D:\ir-drill\RUN-drill-clean-answer.md`、`RUN-drill-clean2-answer.md`

### ⚠️ 靶场搭建的坑：脚手架留在靶机里 = 答案密钥

第一次 clean run **实际被污染**：setup 把 `perm.sh` / `ts.sh` / `check.sh` 拷到容器 `/tmp` 执行后没删，
`docker commit` 把它们**烘进了镜像**。agent 一条 `ls -al /tmp` 就发现并 `cat` 了：

- `/tmp/ts.sh` → `touch -d "2026-03-14 09:22:51" .../a7f3c1.jpg.php`
  → **直接给出"首次入侵时间"这一项的答案，该项就不再是测试**
- `/tmp/check.sh` → 完整自检清单（`ls -al`、两处 cron、UID=0 grep、木马文件名、基线 diff）

**已修**（`D:\ir-drill\setup.ps1`）：`Run-Sh` 用 `finally` 删脚本 → commit 前 scrub `/tmp`
→ commit 后再起一个容器复核 `/tmp` 为空（不通过就 `throw`），实测输出 `image /tmp is clean`。

**通用教训**：暴露面不止宿主机的题面/答案目录 —— **靶机内部任何你自己放进去的脚本都算**。
评估前后都跑一次 `docker exec <target> ls -A /tmp`，并用 `docker inspect --format '{{json .Mounts}}'`
确认没有把宿主机目录挂进去。

### ⚠️ 坑 4：空字符串参数会被 shell 层剥掉（实测踩到）

`docker exec ir-drill grep -rE '' /etc/cron.d/` —— 那个**空引号 `''` 在传到 docker 前就没了**，
grep 退化成"递归搜当前目录所有文件"，10 秒默认超时直接炸：

```
[!] shell_command timed out after 10000ms
```

同一轮里其他 23 条命令都正常，**只有这一条**栽在这。两种自救：

```bash
# ① 给 grep 一个真实模式，别用空模式
docker exec ir-drill grep -r . /etc/cron.d/

# ② 或用工具自己的 timeout_ms（默认 10000，上限 120000）
#    shell_command(command="...", timeout_ms=60000)
```

> ⭐ 实战提示：`shell_command` 的 `timeout_ms` 可以调到 **120 秒**。
> 慢查询（全盘 `find /`、大日志 `grep`）**主动给大超时**，别让它默认 10 秒就断。

### ⚠️ 网络可达性（`2026-09-20` 实测，回答"外网要不要翻墙"）

| 目标 | 用途 | 实测结果 |
|---|---|---|
| `http://msdl.microsoft.com` | ⭐ **Windows 内存符号表** | ✅ **HTTP 200 可达** |
| `ddebs.ubuntu.com` | Linux dbgsym（生成 ISF 用） | ✅ HTTP 200 |
| `debug.mirrors.debian.org` | Debian 调试符号 | ✅ HTTP 200 |
| `pypi.org` | Python 依赖 | ✅ HTTP 200 |
| ⭐ `goproxy.cn` | **dwarf2json 的国内获取路径** | ✅ 有 `v0.8.0` / `v0.9.0` |
| `github.com` / `raw.githubusercontent.com` | 部分工具下载 | ❌ **超时**（不稳定） |
| `proxy.golang.org` | Go 官方代理 | ❌ 超时 |

**结论：外网对内存取证来说指的是"能不能到微软符号服务器和发行版镜像"，
而这两个都是 `http`（非 https）且国内直连可达 —— 不需要翻墙。**

> **现场要问的不是"国内能不能上"**（实测都通），而是赛场网络**给不给公网出口**、
> 以及**国外站点**（`github.com` 一类）会不会被挡。国内镜像/符号服务器已实测可达。

- ⭐ **Windows 内存镜像可以现场分析**（符号能从 msdl 下）
- **Linux 仍然卡在 ISF**：需要目标内核的 DWARF 调试信息（从 `ddebs.ubuntu.com`
  等镜像取，国内可达），但**本机没装 Go**，无法 `go install dwarf2json`；
  且必须知道**目标内核版本**才能预先生成
- ⚠️ **GitHub 不可靠**：`github.com` 与 `raw.githubusercontent.com` 实测超时。
  之前下载 hashcat/john 时反复 `RemoteDisconnected` 就是这个原因。
  **别把"从 GitHub 下工具"写进现场流程**；优先用国内代理（如 `goproxy.cn`）
  或镜像站

> ⚠️ 更正：本文早前版本写过"实测能连 `raw.githubusercontent.com`"。
> 复测为**超时**，该说法不成立，已删除。判断网络一律以现场复测为准。

---

## 四点八、⭐ volatility3 的隐藏故障（已修）与其通用教训

**现象**：`vol --help` 一切正常，但**任何真实插件都崩**：

```
AttributeError: module 'lib' has no attribute 'GEN_EMAIL'
```

**根因**：本机 `python` 是 **Anaconda**（`D:\anacond_1`），其 win32com `lib`
与已装的 `cryptography 50.0.0` 不兼容 → 导入 `pyOpenSSL` 必炸。
volatility3 **自己不 import requests**，但全量解释器下任何传递依赖都可能走到
`urllib3 → pyopenssl`。

**为什么自检漏了**：`vol --help` 在构建 layer **之前**就退出，所以不触发这条路径。
原来的自检只测 `--help` → 一直"通过"。

**修法**（`.ir-tools/bin/_vol_entry.py`）：脚本自动 `re-exec` 到 `python -S`
（禁用 site-packages），只让工具箱自带 `pylib/` 可导入。

⚠️ 写这个守卫时踩到一个会让 vol **无限自我 exec** 的坑：
**`import site` 在 `-S` 下仍然成功**（只是不自动调用 `site.main()`），
所以不能用"import site 失败"当隔离判据。正确判据是 **`sys.flags.no_site`**。

**通用教训**：**"能启动"≠"能干活"**。自检必须跑一次**真实任务**并检查实质输出。
现在 D 组会真的用 `banners` 分析 `ntoskrnl.exe` 并校验提取到的 PDB 符号键。

> 附带发现：判定输出时**别用宽泛关键词**。第一版检查在 stderr 的进度行
> `Progress: 100.00  PDB scanning finished` 上误匹配了 `pdb`，
> 报了假失败。改成要求"含 `|` 且含 `.pdb` 且不以 progress 开头"。

---

## 四点九、⭐ CTF2 平台实战验证（攻击能力实测）

`2026-09-20` 用 CTF2 练习场做了一次真实端到端验证，结论：**Web 攻击链路可用，
且验证了两个必须处理的工具层缺陷。**

### 战果：N1BOOK「SSTI」题，1 轮内解出

| 阶段 | 观测到的证据 |
|---|---|
| 指纹 | `{{7*7}}` → `49`，`{{7*'7'}}` → `7777777` → **Jinja2** |
| 注入点 | 根路径 GET 参数 `password`（首页回显 `password is wrong: <输入>`） |
| RCE | `{{lipsum.__globals__["os"].popen("printenv FLAG").read()}}` |
| flag | `CTF2{36cec5fa-1bba-4efb-bbfc-0271533523ce}`（容器环境变量 `FLAG`） |
| 独立复核 | ✅ 绕过 agent 直接打靶机，返回**同一个 flag** |

用了 16 条证据、3 轮结束 —— 前 8 条里就锁定了漏洞类型并拿到 flag，
之后的轮次是**自我验证**（换 `cat /app/flag*`、`printenv FLAG` 两条路交叉确认）。

### ⚠️ 缺陷 1：`ctf2_*` 工具在只有浏览器登录态时全废（已修）

`ctf2_list_practice` / `read_challenge` / `start_environment` 走 Open API
（`/api/open/v1/user/...` + `X-CTF2-API-Key`），只有 session JWT 时全部 401
`AUTH_REQUIRED`；而等价的前端路径 `/api/v1/practice/` 是 200。
**报错信息还指向"没授权"，会把人带偏。**

现已加 session API 回退。另注两条实测事实：

- 起靶机的 session 路由是 **`POST .../target/`**（202 + task_id），
  **不是** `/environment/start/`（那个在前端 API 返回 404）；随后
  `GET .../target/` 轮询，`status` 从 `starting` → `running`。
- `/daily/`、`/submissions/`、`/stages/...` **没有** session 对应路由 ——
  映射表对这些返回 None 并给出"需要 personal token"的明确报错，
  而不是瞎猜路径。**别给它们编一个路由。**

### ⚠️ 缺陷 2：agent 会去调**错平台**的提交工具（未修，需你决定）

实测那次运行里，agent 拿到 flag 后的**第一个提交动作是 `gcs_submit_flag`**
（带 `exercise_id: 86`），返回 `GCS API 40403: 无权操作`。
它**没有**先判断"这题属于哪个平台"，只是因为工具名里有 `submit_flag` 就用了。

危害目前有限（跨平台 ID 不存在，被服务端拒了），但这条路径本身是**无门禁**的：
`competition.enabled: false` **不生效**，`gcs_tool_schemas()` 是硬编码返回、
注册处无任何判断。也就是说 —— **agent 随时可能往平台发东西。**

### ✅ 已加的门禁：flag 提交必须显式开启

```
competition.allow_flag_submission: true        # 或
VULNCLAW_COMPETITION__ALLOW_FLAG_SUBMISSION=true
```

默认 **false**。理由：提交 flag 是平台上**不可逆**的动作，而手册把"非有效操作"
（含猜错）当取消资格依据。门禁只覆盖提交这一个动作 ——
列题、读题、起靶机、停靶机全部照常。

**实测拦截效果**：agent 拿到 flag 后调 `ctf2_submit_flag`，被拦下并返回
`[ctf2_flag_submission_disabled]`；agent 如实报告"提交被环境配置阻止，
不是调查没做完"，并给出 `practice_id` / `challenge_id` 让人工提交。
**这正是想要的行为** —— 不该自动发的东西没发出去，而且没有假装成功。

### 怎么重复这套验证

```powershell
# 1) 列练习场（session token 会自动从浏览器读）
vulnclaw   # REPL 里: ctf2_list_practice
# 2) 读题目
#    ctf2_read_challenge practice_id=<PID> challenge_id=<CID>
# 3) 起靶机（session 路由）
#    ctf2_start_environment practice_id=<PID> challenge_id=<CID>
#    或 ctf2_get_target 轮询直到 status=running
# 4) 用 solve 打靶机 URL（不要用 ctf2 命令，避免重复起容器）
$u = '<access_url>'
$goal = Get-Content goal.txt -Raw -Encoding UTF8     # ⚠️ 见下面这个坑
vulnclaw solve $u --goal $goal --prompt $prompt --max-steps 40 --run-name myrun
# 5) 打完释放
#    ctf2_stop_environment practice_id=<PID> challenge_id=<CID>
```

⚠️ **坑：goal/prompt 别写在 PowerShell 单引号字符串里。** 我写的那版含中文引号
`"`，CLI 直接把参数切断了（`Got unexpected extra argument(s)`）。
**写进 UTF-8 文件再 `Get-Content -Raw` 传入。**

⚠️ **靶机 TTL 1 小时**（`expires_at`），且**打完要 `stop_target` 释放** ——
否则白占一个容器槽位。

---

## 五、⚠️ 赛前必须处理的合规风险

通知七(三)：**严禁攻击竞赛平台、赛事系统及第三方服务**；七(六)：**非有效登录/非有效操作视为弃赛**。

### ✅ 已确认合规：AI 辅助 —— 有群内书面依据（10/9）

**原始群记录**（用户提供；现场抽查日志时可直接引用这句）：

| 时间 | 发言人 | 原话 |
|---|---|---|
| 09-18 14:35:00 | ⚜（选手提问） | 线下赛对ai的包容度怎样，录屏中能出现询问ai辅助的情况吗? |
| 09-18 14:35:23 | **hongge**（李洪，官方联系人） | **不做限制** |
| 09-18 14:35:45 | **hongge** | **不断网** |

**两条结论**（本节的合规基调以这两句为准）：

1. **AI 辅助官方明确不做限制** —— 含"录屏中出现询问 AI"的情形；本机用 vulnclaw 出命令 / 解码 / 写报告都可以。
   此前本文档早期版本与 §五点五 P0-1 写的"**没人问过 / 群里问一句**"是 **10/08 的状态，已作废**。
2. **现场不断网** —— 保留互联网出口，云端 LLM 路径可用；"断网退人工 + 本地工具"的退路**不需要**。
   反过来**现场网络可用性**才是硬要件（见 §五点五 P0-3）。

**这两句答复管不到、仍按保守执行的两条**：

- **agent 经 SSH 驱动跳板机**（`remote_exec`/`remote_collect`/`remote_fetch`）**是否算红线里的"远程操作"**——
  "不做限制"答的是"AI 辅助提问"，不是授权"远程操控"。**主路径仍为副驾模式**（人打字、agent 出命令），
  直到群里给出明确答复；见本节末「自动化边界」。
- **跳板机 ↔ 笔记本能否搭隧道** —— 朱禹明确"**未做过相关技术测试**"、群里待答复（待确认表 #1）。

### ✅ 赛前培训（10/9，朱禹）确认的赛事事实 —— 以这份为准

| 项 | 事实 | 对我们的影响 |
|---|---|---|
| 日程 | 10/11 **8:30–9:00 签到**（身份证+学生证人证核验）→ 9:00–9:30 开场 → **9:30–12:00 渗透** → 12:00–12:20 午休 → **12:20–15:30 应急响应** → 15:30–16:30 统计/颁奖 | **开赛 30 分钟后禁止入场、颁奖结束前不得离场**——按 8:30 到场，别按指南里那个 8:00/8:30 混着的版本赌 |
| 计分 | 系统自动评分，分值按题难度；**设"一血/二血/三血"速度权重**；**不同 flag 的分值存在差异** | **速度就是分**：先做能快速拿下的题；分诊时把每题**分值记进状态表**，按"分值 ÷ 预计耗时"排序，别在低价值目标上烧时间 |
| 工位与环境 | **工位随机分配**；**各队伍独立环境**；**严禁跨组交流解题思路** | 别指望邻座、别串门；独立环境也意味着队友的账号/环境不通用（与"一人一个账号"一致） |
| 场景开放 | 登录 → **点【进入演练】**；**上午只开放渗透场景，应急响应场景暂不开放**（分时段解锁）；演练界面内的介绍与规则说明文档**需自行查阅**（官方后续会另发详细演练说明） | 开场先读那份文档再动手；IR 段开始前不要去找 IR 题 |
| 渗透场景 | 独立靶场，**外部打点 + 内网渗透**，多个 flag | 侦察→外网打点→横向，链式题多 |
| 应急场景 | **提供被入侵服务器 + 跳板机**，经跳板机登录服务器找隐藏 flag；场景背景=**高校网站故障**（运维视角）；**下载任务附件**拿网络拓扑与登录方式 | 见下面的副驾模式与 `flag-landing-spots.md` |
| 应急环境细节 | **初始只开放部分节点的控制台权限**（其余要自己判断/先拿下）；**存在非线性解锁** —— 留意题目**高亮/灰度**状态，别默认"必须按顺序"；**题目过难时官方会适时发放提示** | 分诊时先看拓扑里哪些节点可点；非线性题可与主链并行（见 §九），卡死一道不等于锁死全局 |
| 平台路径 | 登录平台 → **直接进"任务中心"**（忽略自学课程/竞赛训练）→ **点【进入演练】** → 演练环境给拓扑（攻击机/数据库等）→ **右键攻击机 → 控制台** → **用内置账号密码登录**后打内网；界面**右上角有倒计时与队伍基础信息** | 平台只是入口，不是攻击目标；倒计时是现场唯一可信时钟，§九的锚点按它报 |
| 解锁机制 | 部分题**按顺序解锁**（没交任务一 flag 解锁不了横向移动） | 一题一 flag，交完再下一题 |
| 工具 | 平台**内置免费工具供选手下载使用** | 到场先下载；本机工具箱（`.ir-tools`）继续做离线分析 |
| 网络 | **现场提供网线**，选手自带笔记本（无网口要自带转接器），网线可连**比赛环境及互联网** | 公网出口问题基本落地（能连互联网） |
| 部分题 | **需通过 VPN 登录**，平台提供教程；~~需在截止前提交演练报告（WP）~~ **已作废：赛方 2026-10-10 明确 WP 不用交** | 无 WP 交付物；收工段只做"留痕 + 逐题提交核对"（见 §九） |
| 违规 | ①严禁跨组交流 ②**禁止攻击竞赛平台** ③**严禁用 C2 管理工具等进行非有效登录或远程操作**，**抽查系统日志** ④~~全程电脑录屏~~ **已澄清（10/9）：不用录屏、不用交** | ⭐ 见下面"自动化边界" |
| 报障 | 平台内提交故障/举报，无响应举手找现场老师 | — |

**答疑里最有用的三句**（朱禹原话）：

- "**部分题目必须通过跳板机访问，但也有题目需要选手先攻击跳板机获取权限**，具体需根据比赛场景判断，但**跳板机一定会存在**。"
- "（跳板机系统）**不确定**，不能绝对说是 Windows，也有可能攻击的是 Linux 主机并将其作为跳板机使用。"
- "（能否在跳板机和选手笔记本之间搭隧道）**未做过相关技术测试**，记录后稍后在群内解答。"

### ⚠️ 10/9 培训纪要（腾讯会议"元宝纪要"）带来的三点待澄清

> 这份纪要是**腾讯会议"元宝纪要"的 AI 提炼**（带"这相当于…""可见…"这类评述），**不是赛方逐字稿**。
> 下面三条一律按"**待群内确认**"处理，别当成已定事实写进打法。

1. **"本地大模型对跳板机的调用能力至关重要"** —— 纪要称赛方强调大模型是核心辅助工具、能否调用跳板机直接决定操作效率。
   ✅ **合规已明确**：群内书面依据（用户提供原始记录）——
   `⚜ 09-18 14:35:00`「线下赛对ai的包容度怎样，录屏中能出现询问ai辅助的情况吗?」
   → `hongge 09-18 14:35:23`：「**不做限制**」；`hongge 09-18 14:35:45`：「**不断网**」。
   即 **AI 辅助（含录屏中出现询问 AI）官方不做限制，且现场保留互联网**。
   > 仍未覆盖的一层：**agent 经 SSH（`remote_exec`/`remote_collect`/`remote_fetch`）驱动跳板机，是否算红线里的"远程操作"**。
   > "不做限制"回答的是"AI 辅助"，不等于授权"远程操控"——所以在拿到明确答复前，主路径仍是**副驾模式**
   > （人打字、agent 出命令），与下面「自动化边界」一致。
2. **"攻击机就是官方指定的跳板机"** —— 纪要演示**渗透**拓扑时把攻击机称为跳板机。我们此前把"攻击机（渗透入口）"与"跳板机（IR 入口）"当两件事。现场先确认：**是同一台，还是渗透用攻击机 / IR 用跳板机两台**——这直接决定模式 B 变体（`remote_exec`）连的是哪台。
3. **"部分任务非线性解锁"** —— 纪要明确要留意题目**高亮/灰度**状态。§九"顺序解锁 ⇒ 到点必跳"的推论收敛为：**线性链上到点必跳；非线性节点可与主链并行**（跳 ≠ 放弃，先记 3 行状态再回来）。

### ⚠️ 自动化边界（日志抽查 + 禁 C2 非有效操作）

朱禹明确"严禁使用 C2 管理工具等进行**非有效登录或远程操作**"，加上**赛后抽查系统日志**（10/9 澄清：**录屏不再要求，抽查仍在**），我们把边界定成：

| 场景 | 做法 |
|---|---|
| 平台页面 / 跳板机控制台 | **人操作**，agent 只出命令与解读（副驾模式）——不要用浏览器自动化去点平台终端 |
| 本机（笔记本）分析、解码、写 payload、留证据 | agent 正常用（`shell_command` / `python_execute` / `crypto_decode` / `evidence_*`），屏幕上看得见；留证据是为了**赛后复核**（WP 已不用交，但赛后可能抽查答题思路） |
| VPN 题目（本机直连靶机网络） | 与"自己跑工具"同级：agent 可以驱动，但仍逐题限定 `--only-host`，别越界扫网段 |

> 一句话：**agent 不碰平台与跳板机的登录/远程操作**；靶场内的动作尽量留痕（命令回显/采集文件），这是**赛后复核**的料。

### ⚠️ 两个"能不能让 agent 上"的问题（2026-10-08 晚讨论）

**Q1：跳板机只能一人连；如果笔记本能搭隧道，是不是就能用 agent 了？**

技术上要看清两件事，**目前不是开箱即用**：

1. **账号是按人下发的**（平台登录账号，现场发放；"一人一个账号"）→ 队友各自开自己的控制台
   **互不影响**，不存在"全队只有一个人能连"。真正要注意的是**你自己那个账号**：
   如果同一账号同时只允许一个会话，那么**隧道一旦占住，你自己就进不了控制台**——
   那时你要么全程走隧道，要么借队友的控制台看。**到场花 5 分钟验证：先开控制台，
   再从笔记本试隧道，看两者能否并存**（能并存就皆大欢喜）。
2. **内建 HTTP 工具对私网/回环目标刻意绕过代理**（[http_client.py](vulnclaw/utils/http_client.py)：
   `loopback / private / link-local -> trust_env=False`）。于是：
   - `ssh -D 1080`（SOCKS）→ `fetch` / `http_probe_batch` **不会自动走 SOCKS**
     → **2026-10-10 已补**：见下面「✅ 已落地：显式出口代理」。
   - `ssh -L 8080:target:80`（端口转发）→ agent 只能请求 `http://127.0.0.1:8080`，
     而**作用域闸看到的 host 是 `127.0.0.1`**：`--only-host <网段>` 与 `tp.qianxin.com`
     黑名单**全部失效**（闸门看不出真实目标是谁）。
   - 想走隧道就得二选一：**(a)** 给 HTTP 工具加显式代理配置（SOCKS/HTTP，需改代码）
     —— **2026-10-10 已实现**；
     **(b)** 绕开内建 HTTP 工具，用 `shell_command` + `curl --socks5` / `proxychains`。
3. **合规未知**：培训明确"严禁 C2 类非有效登录或远程操作"+ 抽查日志，而**"能否搭隧道"赛方
   尚未答复**（已列入群内待办）。在得到肯定答复前，别把它当主路径。

> ⚠️ **凭据纪律**：平台账号密码**绝不写进 agent 配置或提示**（`remote.hosts` 只放靶场侧主机）。
> 平台地址已在 `safety.denied_hosts` 里，agent 本来也碰不到——别自己把口子打开。

> 结论：隧道 + agent 的**技术可行性 = 中**（要我加代理支持），**合规可行性 = 未知（等赛方）**。
> 保守做法仍是"人打字 + agent 出命令"。

**Q2：网页终端能粘贴长命令，是不是能用 `chrome-devtools` MCP 去驱动？**

- **技术上可以试**：MCP 在配置里是**已启用**的（navigate/click/fill/type/press/evaluate/screenshot）。
  xterm.js 类终端通常有个隐藏 `textarea`，`fill` / `Input.insertText` 能灌长命令；
  纯 canvas 终端只能靠键盘事件，成功率低。**先用非比赛平台干跑一次再谈**（CTF2 练习场）。
- **风险（默认不做）**：①自动操作**平台自身 UI** 最容易被判"非有效操作"；②MCP 起的是
  **另一个 Chrome 实例**，得在里面重新登录平台；③**一人一连**——自动化占住控制台时你手动也进不去；
  ④误点（提交 / 停止 / 删除）不可逆；⑤赛后**抽查系统日志**，自动化点平台会留下指向自己的记录。
- **中间路线（推荐）**：人负责粘贴，agent 只负责**生成**命令；长 payload 用两步法
  （`echo <base64> | base64 -d > x`）绕开长粘贴限制。

### ✅ 已落地：显式出口代理（2026-10-10）—— 让靶场流量走自建隧道

补齐上面 Q1 第 2 条那个"当前没有"的缺口（commit `d5df744`）。

```yaml
# ~/.vulnclaw/config.yaml
network:
  http_proxy: "socks5://127.0.0.1:1080"   # 或 VULNCLAW_HTTP_PROXY=socks5://127.0.0.1:1080
```

```bash
ssh -D 1080 <跳板机>            # SOCKS，**不是** -L（理由见下）
pip install 'vulnclaw[socks]'   # SOCKS 需要 socksio
```

- **生效范围**：`fetch`、`http_probe_batch`、`brute_force_login`、`traffic_repeat`
  （target-facing 工具）。**LLM 网关 / 情报 API / 远端 MCP 不走**这个代理 ——
  免得把评测与情报流量误送进靶场隧道。
- **语义**：显式代理对**私网目标照样生效**；**回环目标仍直连**（隧道对端会把
  `127.0.0.1` 读成它自己）；强制 `trust_env=False`，实测可盖过
  `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY=*`。
- **为什么必须 `-D` 而不是 `-L`**：实测 httpx 交给 SOCKS 代理的是**主机名**
  （SOCKS5 `ATYP=3`），DNS 在跳板机侧解析 → URL 里保留真实 host，
  `--only-host <网段>` 与 `tp.qianxin.com` 黑名单**继续有判别力**。
  `-L` 下 agent 只能请求 `http://127.0.0.1:8080`，闸门看到的 host 就是
  `127.0.0.1`，**作用域闸失效** —— 这是隧道形态的唯一可信选法。
- **坑（实测）**：`socks5h://` 在 httpcore <1.0.9 是裸 `KeyError: b'socks5h'`
  （本机 1.0.2 复现、临时 venv 1.0.9 通过）→ 已统一改写成 `socks5://`。
- **现场用同一份操作卡**：[`IR-FIELD-CARD.md`](IR-FIELD-CARD.md)。

> ### ⏸ 合规未答 = 唯一待办；**答复为"可以"则按下面直接执行，不需要再出方案**
>
> 赛方"能否搭隧道"**尚未答复**（朱禹：未做过技术测试，群里待答）。**在那之前的默认路径仍是
> "人打字 + agent 出命令"**（副驾模式，`VULNCLAW_REPL_NO_AUTO=1` 可把 REPL 锁成单轮，防止粘贴输出误触发自主循环）。
>
> **一旦群里答复"可以"，照抄执行，无新增设计**：
>
> ```bash
> # 0) 前置（只做一次，若未装）
> pip install 'vulnclaw[socks]'          # SOCKS 需要 socksio（httpcore>=1.0.9）
>
> # 1) 建隧道：必须 -D（SOCKS），不要 -L（理由见上：-L 会让作用域闸失效）
> ssh -D 1080 <跳板机>                    # 保持这个会话开着
>
> # 2) 让 agent 的靶场流量走隧道（二选一）
> setx VULNCLAW_HTTP_PROXY "socks5://127.0.0.1:1080"     # 或写进 config.yaml 的 network.http_proxy
> #    → 生效范围：fetch / http_probe_batch / brute_force_login / traffic_repeat
> #    → LLM 网关、情报 API、远端 MCP 不走此代理（好事，别改）
>
> # 3) 起 agent，目标写**真实内网 host**（不是 127.0.0.1）
> vulnclaw solve http://<内网靶机>/ --only-host <靶场网段>
> ```
>
> **执行后立即自查三条**（缺一条就退回副驾模式）：
>
> | 检查 | 判据 | 不合格怎么办 |
> |---|---|---|
> | 隧道真的通 | `curl.exe --socks5 127.0.0.1:1080 -m 5 -i http://<内网靶机>/` 有响应 | 检查跳板机是否放行 SOCKS、账号是否被"一人一连"限制 |
> | agent 走了隧道 | 让 agent 跑一次 `fetch`，看它能否读到内网页面（而不是超时） | 确认 env/config 生效、URL 用的是真实 host 不是 `127.0.0.1` |
> | 作用域闸仍有效 | `--only-host` 写窄网段，agent 打网段外主机会被拒 | **若打网段外没被拒 = 隧道形态选错了**（多半用了 `-L`），立即停 |
>
> **隧道获批也仍不覆盖的两类动作**（隧道只带 HTTP 工具，不改变这两者）：
> ① **nmap / 端口扫描**——nmap 原生不支持 SOCKS，`execute_nmap` 未接代理；需 `shell_command` +
> `proxychains`，或回跳板机手打；② **agent 经 SSH 驱动跳板机**是否算红线"远程操作"——那是另一个问题
> （"不做限制"答的是 AI 辅助），仍走副驾。

### ⭐⭐ 跳板链式真机验证（2026-10-10 上午，本地两跳 Docker 拓扑）—— 记忆里标"最高缺口"的那条已闭合

**拓扑（一次性搭建，验完即拆）**：`笔记本 → jump-drill(宿主 2222→22) → internal-drill(:8080, 仅在 internal 网络)`。
前提先钉住：笔记本直连内网靶机 = `curl 000`（不可达）、跳板机到靶机 = 拿到 `flag{INTERNAL_TARGET_REACHED}`。
`remote.hosts` 临时加 `jump` alias；验完已还原（`config.yaml` 与 `known_hosts` 都恢复原状，容器/网络/镜像已删）。

| # | 验的是什么 | 结果 | 证据 |
|---|---|---|---|
| 1 | **`remote_exec` 链式抽内网** | ✅ **通** | 在跳板机上执行 `curl http://172.19.0.2:8080/flag.txt` → `flag{INTERNAL_TARGET_REACHED}`——**这是此前从未验过的一跳** |
| 1b | 打跳板机本身（拿立足点） | ✅ 通 | `id` → `uid=0(root)`；`cat /root/flag-local.txt` → 本地 flag |
| 1c | **硬黑名单在 SSH 链上生效** | ✅ 生效 | `denied_hosts=['127.0.0.1']` → `[constraint_violation] Host 127.0.0.1 is blocked … remote_exec/remote_collect/remote_fetch will not connect` |
| 1d | **只读分类在 SSH 链上生效** | ✅ 生效 | `auto_review` 下：`id`/`cat /etc/passwd` **免批通过**；`touch`/`rm` **被拒**（`no_channel`，脚本环境无审批通道 → fail-closed） |
| 2 | **`ssh -D` SOCKS 隧道 + `VULNCLAW_HTTP_PROXY`** | ✅ **通** | `resolve_egress_proxy()` 读到 `socks5://127.0.0.1:1080`；vulnclaw 自己的 `http_client(targets=…, proxy=…)` 穿隧道取回 `flag{…}`（HTTP 200） |
| 2b | 决策表方向正确 | ✅ | 私网 `172.19.0.2`/`10.20.0.30` → `(隧道, False)`；回环 `127.0.0.1` → `(None, 直连)` |
| 3 | **`-D` 下 `--only-host` 判别力** | ✅ 保持 | 作用域 `10.20.0.0/16`：`172.19.0.2` → **被拒**、`10.20.0.30` → 放行 |
| 4 | **`-L` 反例（为什么不能用）** | ❌ 实测坐实 | `-L 18080:172.19.0.2:8080` 隧道本身**能通**，但 agent 只能写 `http://127.0.0.1:18080` ⇒ ① 作用域闸看到的 host 是 `127.0.0.1`（**判别力归零**）；② `is_local_target()` 判它为**本地** ⇒ 客户端**直连、根本不走隧道**。**两个独立原因都指向同一结论：`-L` 不可用。** |

**Windows 跳板机（原"Win跳板未验"）—— 验了能验的部分，结论是"命令面要整个换"**：

- **`remote_collect` 在 Windows 上整条不可用**（已核代码）：33 段采集命令**全是 POSIX sh + `/proc` + `/etc/*`**
  （`cat /etc/passwd`、`ps auxww`、`for d in /proc/[0-9]*`…）。跳板机是 Windows ⇒ 别指望 `remote_collect`，
  改用手打 Windows 取证卡（`paste-cards-windows.md`）。
- **只读分类器只认 CMD 原生，PowerShell 全需批**（实测）：`whoami`/`ipconfig /all`/`systeminfo`/`tasklist`/
  `net user`/`netstat -ano`/`dir`/`type`/`reg query`/`wmic`/`findstr` → **免批**；
  但 `Get-Process`/`Get-ChildItem`/`powershell -c "…"` → **一律需批**（不在信任表 / 解释器一律询问）。
  ⇒ Windows 跳板上想免批跑取证，**优先用 `cmd` 原生命令**，不要习惯性打 `Get-*`。
- **未验的（诚实说明）**：真正的 Windows 主机 SSH 到 Windows 的端到端——本机 WSL2 后端**跑不了 Windows 容器**，
  没有真环境。上面两条是从**代码与分类器实测**得出，不是端到端跑通。
- 另记一个**运维坑（实测踩到）**：本机 `~/.vulnclaw/known_hosts` 里有 10-04 留下的 `[127.0.0.1]:2222` 记录，
  新跳板机复用同一 host:port ⇒ `BadHostKeyException` **直接连不上**。**现场若跳板机地址与演练环境撞端口，
  先查 `~/.vulnclaw/known_hosts`**（`host_key_policy: accept_new` 只在"该 host:port 没记录"时才自动接受）。

### ✅ 赛前培训提到的两件事（其一已作废）

1. ~~**演练报告（WP）**：部分题目要求截止前提交~~ **作废（2026-10-10：赛方明确不用交）**。
   本机的 `vulnclaw report` / 自动 writeup 仍在，但**收工段不再产出交付物**，只用来
   **留痕**（赛后可能抽查 System 日志与答题思路，留证据照样有意义）。
   `IR-WP-TEMPLATE.md` 保留在仓库，但**现场不填**。
2. **一血权重**：策略上把"能 10 分钟内拿下的题"排在最前（与 `competition-mode` skill 的
   fail-fast/先易后难一致），别为一道难题错过一血。

### ✅ 已落地：计分平台硬黑名单（2026-10-08）

《决赛安排指南（学生版）》给出了计分平台：**`https://tp.qianxin.com`**
（"应急响应与渗透测试实战场景赛"，账号密码现场下发）。它现在**任何运行都碰不到**：

```yaml
# ~/.vulnclaw/config.yaml
safety:
  denied_hosts:
  - tp.qianxin.com
```

- **机制**：`safety.denied_hosts` 在**每次安装运行约束**时并入本次运行的
  `blocked_hosts`（`AgentCore._reset_runtime_state` 与
  `AgentCore.apply_task_constraints` —— CLI / REPL / Web 任务 API / TUI / 平台交接
  都从这里进）；`enforce_host_path_constraints` **先查 allowed 再查 blocked**，
  所以任务作用域把平台写进 allowed 也**翻不了案**。
- **粒度**：域名作用域 —— `tp.qianxin.com` 覆盖它自己和子域。**刻意不写 `qianxin.com`**：
  靶场/靶机很可能就在奇安信基础设施上，一刀切会把靶机自己挡了。
- **覆盖**：`fetch` / `http_probe_batch` / `shell_command` 里的 URL / `nmap` 目标 /
  MCP 浏览器与 fetch（约束对象会推给 MCP 管理器）/ 插件运行时。
- **环境变量写法**（不想改文件时）：`VULNCLAW_SAFETY_DENIED_HOSTS=tp.qianxin.com`。
- **验证**：

```powershell
vulnclaw
> fetch https://tp.qianxin.com     # 期望 [constraint_violation] ... is blocked / outside allowed scope
```

回归测试：`tests/security/test_hard_denied_hosts.py`（含"allowed 不能翻案"与
"后缀相似域不误伤"两组断言）。

### ✅ 已落地：flag 自动提交关闭（2026-10-08）

`competition.allow_flag_submission: false`。计分平台（`tp.qianxin.com`）**没有适配器**，
自动提交本来也发不出去；关掉它是为了杜绝 agent 往**第三方平台**（CTF2 / GCS）发东西。
练习场要恢复自动提交时改回 `true`，或临时
`VULNCLAW_COMPETITION__ALLOW_FLAG_SUBMISSION=true`。

### ✅ 已确认：接入形态 = 官方网线 → **跳板机** → 靶场（2026-10-08）

联网走**比赛官方网线**；靶场在跳板机后面，**通过跳板机访问**（不是 VPN，也不是本机直连靶段）。
三条推论：

1. **本机工具链只作用于本机**：D盾/Sysinternals/vol/yara 用来分析**拿回来的证据**；对靶机的
   实时操作要走 **`remote_*`（SSH）**，并把靶机产物拉回本机（`remote_exec` / `remote_collect` /
   `remote_fetch`）——这正是设计里的分工。
2. **本机的作用域闸只管到跳板机为止**：`shell_command` 的出站检查只覆盖本机发出的连接；
   进了跳板机之后，从跳板机再往靶机发的命令**不受本机约束**。现场纪律要写死：
   **只碰平台下发的靶机 IP，不在跳板机上扫网段。**
3. **公网出口只能现场验证**（家宽实测国内可达 ≠ 赛场网线给 NAT）。**工具与符号到场前备好**，
   别把"现场下载"写进流程。

**跳板机上的两条路径**（现在就能用，无需改代码）：

```powershell
# A) 把跳板机注册成 remote host（别名 hostname/port/username/password），在它上面执行命令：
#    remote.hosts.jump: {hostname: 10.20.0.1, port: 22, username: <给的>, password: <给的>}
#    remote_exec(host="jump", command="ssh root@10.20.0.50 'ps aux'")

# B) 本机用系统 ssh 的 ProxyJump（走 shell_command，agent 间接驱动）：
ssh -J <user>@10.20.0.1 <user>@10.20.0.50 "ps aux"
```

> ⚠️ **`remote_*` 不支持 ProxyJump / ProxyCommand**（`_connect` 是直连 hostname:port），
> 且**从未对真实 SSH 服务端做过端到端验证**（本机 sshd 起不来、Docker 未启动）。
> 若赛方给的是"只能从跳板机再跳"的形态，A 的嵌套 ssh 可用但笨；要不要给 `remote.hosts`
> 加 `jump` 字段（paramiko `direct-tcpip` 通道）另定。

**插上网线后的 30 秒动作**：

```powershell
ipconfig /all ; route print                        # 本机网段/网关 + 跳板机地址
ssh <user>@<跳板机> "hostname; ip -4 a"             # 确认能进跳板机、拿到它那侧网段
vulnclaw run <靶机IP> --only-host 10.20.0.0/16     # ⚠️ 不是 solve —— 见下面的实测更正
```

> ⚠️ **实测更正（2026-10-09 夜）**：`--only-host` **不在 `solve` 上** —— 跑
> `vulnclaw solve <target> --only-host 10.20.0.0/16` 会直接报 **`No such option: --only-host`**。
> 带这个开关的命令只有 **`run` / `recon` / `scan` / `network-scan` / `exploit` / `persistent` / `tui`**
> （`solve --help` 与 `run --help` 实测对照）。要在"模型主导求解"里带硬作用域，两条路：
> ① `vulnclaw run <target> --only-host <CIDR>`；② 用 **TUI**（`/scope`，会存进
> `session.tui_scope_only_host`）或 **Web 任务台**（有 `only_host` 字段）起 solve。
> ⚠️ 也别指望把网段写进题面绕过去：核心从任务文本里解析 `Only test host X` 用的是 `[a-z0-9.-]+`
> （`agent/input_analysis.py:408-414`），**`10.20.0.0/16` 会被截断成 `10.20.0.0`**（退化成单主机精确匹配）。

> TUI 里也能用 `/scope` 把 `only_host` 存进配置（`session.tui_scope_only_host`），
> 之后每条命令都带着这个段，不必每次敲。

### ✅ 已确认：应急响应题 = 经跳板机登录被入侵服务器，实时排查 + 找隐藏 flag（2026-10-08）

赛方材料原文：**"选手需通过跳板机访问被入侵服务器，利用工具与思路寻找隐藏的 flag"**。
这条把两件事一起定了：

- **作答形式 = 远程实时排查**（**经平台网页终端**，见下节）→ 现场实际是**人打字 + agent 出命令**
  的副驾模式；离线取证（vol/yara/D盾）继续承担"把产物拉回本机再分析"的角色。
- **交付物是 flag**，不是分析报告 → solve 的完成闸门（flag 必须有证据支撑）正好对上；
  IR skill 的排查面（webshell / 挖矿 / 勒索 / 账号 / 日志 / 持久化）要落到**具体的隐藏落点**上。
- ⭐ **已补一份"找 flag 落点清单"进技能**：
  `vulnclaw/skills/specialized/incident-response/references/flag-landing-spots.md`
  （五步作业顺序：内容搜 → 时间圈定 → 进程/环境 → 服务侧 → 变形解码；
  含 Linux/Windows 落点表、已删除文件/磁盘块/数据库/ADS、以及搜不到时的收尾）。
  agent 在 IR 场景会看到它的索引，也可显式 `load_skill_reference` 加载。

> ⚠️ **优先级更正（2026-10-08 晚）**：确认入口是**平台网页终端**后，`remote_*`（SSH）
> 从"比赛主路径"**降级为备选** —— 只有当某台攻击机/靶机确实能 SSH 时才用得上。
> 它仍然**从未对真实 SSH 服务端端到端验证过**；要投的话（启动 Docker 或用赛方机器）
> 仍值得走一遍 `remote_hosts → remote_exec → remote_collect → remote_fetch`，
> 但不再是赛前必做项。

### ✅ 已确认：平台提供内置工具库（2026-10-08）

赛方说明：**平台有内置工具，在平台工具库里**（对应决赛通知那句"使用环境中提供的各类渗透
测试工具"）。三条影响：

1. **现场主力是工具库里的工具**，不是你自己装的那套。本机 `.ir-tools`（D盾/Sysinternals/
   vol/yara）重新定位为**离线分析 + 兜底**：拿到产物（日志/镜像/样本）时在本机跑。
2. **工具库若在跳板机上**，agent 的用法是 `remote_exec(host="jump", command="<工具名> ...")`
   —— 前提是知道**工具名与调用方式**。把清单放进别名备注，agent 调 `remote_hosts` 时
   就能直接看到（`list_hosts` 会把 `note` 渲染出来）：

   ```yaml
   remote:
     hosts:
       jump:
         hostname: 10.20.0.1
         port: 22
         username: <给的用户>
         password: <给的密码>
         note: "平台工具库: nmap/volatility3/yara/tshark/D盾(win)…路径 /opt/tools"
   ```

3. **别假定工具库里有什么**：现场先 `ls /opt/tools`（或平台工具库页面）**照抄一份清单**
   进这个 `note`，再决定用工具库还是本机工具。

**任务 prompt 模板**（把工具库与访问路径一次交代清楚，省掉模型的试探轮）：

```powershell
# prompt 写进 UTF-8 文件再读：内联中文引号会被 PowerShell 切断（见"四点九"那个坑）
$p = Get-Content prompt.txt -Raw -Encoding UTF8
vulnclaw solve <靶机IP> --goal $goal --prompt $p --max-steps 40   # ⚠️ solve 没有 --only-host（见前文实测更正；要硬作用域用 run）
# prompt.txt 内容：
#   远程目标经跳板机访问：remote_hosts 里的 jump 别名。
#   平台工具库在跳板机 /opt/tools（<照抄清单>），优先用它；本机工具只用于离线分析。
#   flag 格式：flag{...}。先 remote_collect 固化现场，再按 flag-landing-spots.md 五步找。
```

### ✅ 已确认：题目**链式解锁** —— flag 必须提交，但**提交由人做**（2026-10-08）

赛方强调：**必须提交正确 flag 才能解锁后续题目**。这条与"提交是不可逆动作、
猜错算非有效操作"直接冲突，处理方式：

- **agent 只交付 flag，绝不提交**：平台（`tp.qianxin.com`）是硬黑名单，
  `competition.allow_flag_submission` 保持 **false**——**不要为了让 agent 提交而打开它**。
- **人工节奏**：agent 报告 flag → 人在平台页面提交 → 解锁下一题 → 把新题面丢回给 agent。
  一次做一题、交付一个 flag，别让它一口气扫全链。
- **goal / prompt 要写死这条**（否则模型会去试 `platform_submit` 或纠结"要不要提交"）：

  ```
  找到 flag 后立即在 FINAL 里原文报告（格式 flag{...}），不要尝试提交；
  提交由选手手工在平台完成。
  ```

- **提交前自查**（人做的最后一道闸）：格式与题目要求一致；flag 在真实工具输出里
  **逐字符**出现过（solve 的证据闸门本来就这么判）。猜错就是白送一次"非有效操作"。
- ⭐ **括号必须配对**：候选里出现 `{`，就必须在真实输出里找到配对的 `}`；**缺尾段时绝不自己补 `}`**。
  2026-10-09 就因此交错过一次：六段碎片只拼了五段，模型自己把 `}` 补上、闸门放行 —— 因为那个串
  已被写进黑板，而黑板的 tool result 本身算"证据"，**等于自己给自己担保**。
  agent 侧已加 `ctf_mode.flag_completeness_issues()`：答案里只出现开括号而找不到闭括号、或 UUID 形
  body 的末段不足 12 位时，完成闸会拒绝并明说"尾段从未被观测到，别自己补括号"。**拼装是允许的**
  （正解就是拼出来的），所以判据不能写成"整串必须在输出里逐字符出现过"。

### ✅ 已确认：操作入口 = 平台上的**攻击机控制台**（右键 → 控制台）（2026-10-08）

赛方演示的拓扑：选手**先登录攻击机**，再**右键选"控制台"**开展后续操作；
**有些攻击机（跳板机）要自己先拿到登录权限**。渗透题目标也明确了：**拿 OA 系统漏洞 + 植入 webshell**。

对 agent 的影响是**关键分叉** —— 现已确认走的是**下面这一行**：

| 攻击机怎么访问 | agent 能否驱动 | 做法 |
|---|---|---|
| 能 SSH 到（本机直连，或从另一台机器） | ✅ 能 | 注册进 `remote.hosts`，用 `remote_exec` / `remote_collect` 全链路驱动 |
| ⭐ **平台网页端右键 → 打开终端**（2026-10-08 确认） | ❌ **不能直接驱动** | **人操作、agent 出命令与解读**（副驾模式，见下）。浏览器自动化能点（`chrome-devtools` MCP），但**平台把"非有效操作"当弃赛情形，默认不做** |

### ⭐ 主路径 = 副驾模式（人打字、agent 出命令）

既然靶机只能从平台网页终端进，agent 的 `shell_command` 就**不在那台机器上执行**；
比赛现场实际发生的是：

```
选手：把上一条命令的输出原文粘回会话
agent：读输出 → 给出下一条命令（+ 为什么）→ 需要时本地解码/写 payload
选手：在网页终端里执行
（循环）→ 拿到 flag → 人提交 → 解锁下一题
```

> **例外（培训确认）**：**部分题目需通过 VPN 登录**，平台给教程 —— 那些题是**本机直连靶机网络**，
> agent 可以直接驱动（`shell_command` / `http_probe_batch`），逐题用 `--only-host <网段>` 收口。
> 所以现场是**逐题判断**：控制台类 → 副驾模式；VPN 类 → agent 可驱动。

四条纪律：

1. **输出必须原文粘回**：agent 看不到终端，任何"我推测输出是…"都是幻觉。
   agent 侧同样受证据闸门约束——**没见过的输出不许当结论**。
2. **本机工具仍然有用**：`crypto_decode` / `python_execute` / `evidence_*` 用来解码、
   写脚本、留证据；本机只是**工作台**，不是执行点。
3. **作用域闸在这个模式下失效**：命令是人打的，`--only-host` / 黑名单拦不到网页终端里的操作。
   **纪律完全在人**：只碰平台下发的靶机，绝不碰平台/赛事系统/第三方服务。
4. **长命令要短**：网页终端可能不支持粘贴/回车即执行，payload 尽量短或用
   `echo <base64> | base64 -d > x` 这类两步法；**先把"能不能粘贴"当成要现场验证的事**。

**现场 prompt 模板（副驾模式 · 2026-10-09 修订：先抹目标、后打 `chat`）**：

```text
以下是被入侵服务器（经平台网页终端）上的命令输出（目标地址已抹成 <target>），原文如下：
<粘贴：把 IP / URL / 域名一律替换成 <target>，只留命令与结果>
目标系统：Linux（或 Windows，按探测）
执行环境：我在 Windows cmd 里执行 —— 请只给【单行】命令（不要多行、不要 \ 续行、不要行尾 # 注释；要引号用双引号）。
请只输出【下一条命令 + 判据】，不要调用任何工具、不要自己去连目标、不要重复我已跑过的命令。
找到 flag 后直接告诉我原文，不要建议提交。
```

> **两个动作固定下来**（实测缺了会翻车，见下节彩排结果）：
> ① **粘之前**：输出里的 IP / URL / 域名一律抹成 `<target>` —— 判读命令不需要真地址，而留着它 REPL 会把地址抓成 target；
> ② **粘之后**：立刻打一个 `chat`（退出 AUTO 自主模式；也认 `单轮` / `手动` / `exit auto`）。
> ③ **模板里要写执行环境**（10/9 彩排实测）：不写它默认按 bash 给多行命令，而 cmd 只吃单行 ——
> 多行 + `\` 续行会被逐行执行、`#` 变成参数、单引号不被剥掉。

### ⚠️⚠️ 副驾模式彩排结果（2026-10-09 夜，实测）：**默认 REPL 会自己动手**

一次真人彩排（裸启动 `vulnclaw`，粘一段**假**的"网页终端输出"，其中含一台测试用 IP）。它照做了——
**但也做了四件在赛场上算事故的事**：

| 观察到什么 | 证据 | 现场后果 |
|---|---|---|
| ⭐ **从粘贴内容里抓出 URL 当 target，并切进 AUTO（自主）模式** | 提示符从 `vulnclaw Ready>` 变成 `vulnclaw http://203.0.113.7 \| Ready \| AUTO>`，日志出现 `[*] Entering autonomous pentest mode` | **贴原文 = 把目标 IP 交给它自己去打**（随后它真的发了三条 HTTP 探测，18.7 s 超时） |
| **主动去连 `remote.hosts` 里配置的主机** | 对 victim / victim-crypto / victim-ransom（127.0.0.1:2222-2224）逐个 `remote_exec` | 若赛前把跳板机填进 `remote.hosts`，它会直接 SSH 上去——**这正是红线"远程操控"的灰区** |
| **乱调平台工具** | `platform_list {}` 列出 7 个 CTF2 练习场；`platform_list {"ref":"ctf2:daily"}` → `403 agent_scope_forbidden` | 浪费轮次；比赛环境里等于去碰平台 |
| **在笔记本上全盘搜索** | `shell_command` 执行 `Get-ChildItem C:\ -Recurse …` → **60 s 超时** | 白烧一分钟 + 一次工具降级标记 |

另外：它确实给出了**命令 + 判据**（`cat -A` 看马、`ls -laR /tmp/.x` 看落地件、`grep -rIn 'flag{'` 全盘定位），
这部分是对的；但它同时把自己加载的**技能文档内容**当成"未解决的 pinned fact"，跟自己的 ASK/证据闸门来回较劲两轮，
最后以 `Not achieved — steps=2` / `waiting for user input` 收场。

**⇒ 副驾模式必须先做这四件事（缺一不可）**：

1. **贴之前把目标抹掉**：输出里的 IP / URL / 域名一律替换成 `<target>`（判读命令不需要真 IP）。零成本、立刻生效。
2. **粘完立刻打 `chat`**（REPL 自己的提示："Type chat to switch to single-turn mode"；也认 `单轮` / `手动` / `exit auto`）→ 退出 AUTO，不再自跑。
3. **关掉平台工具面**：`vulnclaw config set platforms.ctf2.enabled false`（必要时加 `platforms.gcs.enabled false`）→ `platform_list` / `ctf2_*` / `gcs_*` 不再出现。（代价：练习场那条链也一起关，赛前要练时再打开。）
   > 这条路径**第四轮时是坏的**（`config set platforms.*` 直接抛 traceback，只能手改 YAML）；**第五轮已修**：遍历支持 Pydantic `extra="allow"` 段 + 新建段落布尔（原先 `"false"` 会以字符串落盘，读端 `bool("false")==True` 反而把开关**打开**）。现在可读可写，`vulnclaw config get platforms.ctf2.enabled` 也已可用。
4. **副驾会话单独用更严的审批**（不动全局配置）：`$env:VULNCLAW_SAFETY_PERMISSION_MODE='auto_review'` —— 它想跑 `python_execute` / `shell_command` 时会弹窗，直接拒。全局 `full_access` 只留给"agent 驱动打跳板机"那个场景。

> **比赛当天还要清理 `remote.hosts`**：目前里面是三台本地演练容器（127.0.0.1:2222-2224）。要么清空，要么只留跳板机 alias 并写好 `note`——否则它会去连一堆没用（且可能违规）的机器。

### ✅ 第二轮彩排（同日）：A/B/C 生效了一半，暴露出**代码级**根因

按上面的四条纪律再跑一次（**同样一段假输出，IP/URL 已抹成 `<target>`**，模板里加了"不要调用任何工具、不要自己去连目标"）：

| 观察点 | 结果 |
|---|---|
| **工具调用** | ✅ **0 次**（第一轮 16 次）—— 没有再出现 `python_execute` / `Test-NetConnection` / `remote_exec` |
| **平台工具** | ✅ **没有再出现** `platform_list` / `ctf2_*` / `gcs_*`（C 生效） |
| **不脑补 flag** | ✅ 五轮里每轮都明确写"当前没有任何 flag 字面量，无法凭空给原文" |
| **命令质量** | ✅ 第 3 轮那条是最优解：`cp /proc/9137/exe` + `/proc/9137/{cmdline,environ,fd}` + `strings \| grep -iE 'flag\|http\|secret'` —— **对"已删除的存活进程"就该这么取样本** |
| **`chat` 退出 AUTO** | ❌ **没生效** —— 它和粘贴内容黏在同一次输入里，而识别要求 `user_input.strip()` **恰好等于** `chat`/`manual`/`exit auto`/`单轮`/`手动`，且**必须在 AUTO 已经激活之后**单独发一次（`cli/main.py:977-983`） |

**根因（这才是关键，别再当成用法问题）**：让它进 AUTO 的**不是 IP，是路径**。`_should_auto_pentest` 的最后一段是
——只要输入里能抽出**本地路径型 target** 就直接返回 True（`cli/main.py:4651-4655`，`_extract_target_from_input` + `_is_local_path_target`）。
IR 的输出里全是 `/usr/sbin/cron`、`/var/www/html/uploads`、`/tmp/.x/.kworker` 这种路径 ⇒ **每一次粘贴都会重新进 AUTO**，
所以"抹掉 IP + 事后打 `chat`"只能压住它动手（靠模板那句"不要调用任何工具"），**压不住它自跑**。
顺带：这一轮它把 target 认成了 **`/usr/sbin/cron`**（提示符 `vulnclaw /usr/sbin/cron | Ready>`），一度还有 `access.log` 进了 allowed_hosts —— 说明**"抹 IP/URL"不足以消除目标误认，路径也会被认成目标**。

**⇒ 出路 ①（已实现，推荐）**：新增 env 门 —— 置 `VULNCLAW_REPL_NO_AUTO=1` 后，**同一个目标有三个来源，全部关掉**：

| 关掉什么 | 实现 | 效果 |
|---|---|---|
| 自主循环 | `_should_auto_pentest` 最前面 `if _repl_no_auto(): return False` | 每次粘贴都落**单轮 chat**，不再有 AUTO |
| **REPL 自己挖 target** | `_mined_target_for_session()`（`new_target = _mined_target_for_session(user_input)`） | 粘贴里的 `/usr/sbin/cron`、`/3` 不再变成会话目标 |
| ⭐ **agent 回合回报的 target** | `_target_after_agent_result(current, reported)`（单轮 chat 的 `after_result` 里） | agent 从粘贴里"报"回来的 `access.log` / `/usr/sbin/cron` 不再被采纳 —— 第四轮彩排就是栽在这条上（前两道门都开了，提示符仍是 `vulnclaw access.log \| Recon>`） |
| ⭐ **chat 内部的认领**（第五轮审计补） | `AgentCore.chat` 里的 `_copilot_pins_target()`（`agent/core.py`） | 上面三道只治 REPL 的显示变量；`chat` 另有一条独立路径 `_detect_target(粘贴)` 会写进会话状态、注入提示词（`当前渗透测试目标: access.log`）并重写 `targets/<key>/state.json` —— 这道门把它一并钉住 |

四条一起 ⇒ 提示符保持 `vulnclaw Ready>`，且**会话状态与落盘的 target 也不再被粘贴污染**。

**副驾会话统一用启动器起**（仓库根目录 [`copilot.cmd`](copilot.cmd)，一行钉死三层）：

```cmd
.\copilot.cmd
```

| 层 | 变量 | 作用 |
|---|---|---|
| 1 | `VULNCLAW_REPL_NO_AUTO=1` | 单轮 chat + 不认领 target（上表两件事） |
| 2 | `VULNCLAW_SAFETY_PERMISSION_MODE=auto_review` | 只读命令免批；`python_execute`/`shell_command` 等弹窗——**副驾模式下直接拒**（提示词失效时的兜底） |
| 3 | 屏幕提示 | 三条规则（抹地址 / 必带"不要调用任何工具" / 提示符应为 `vulnclaw Ready>`） |

> 手敲等价物：`$env:VULNCLAW_REPL_NO_AUTO='1'; $env:VULNCLAW_SAFETY_PERMISSION_MODE='auto_review'; vulnclaw`
> 实测：该 env 覆盖有效（未设 → `permission_mode=full_access`，设了 → `auto_review`）；启动器参数透传正常（`copilot.cmd --version` → `0.3.9`，退出码 0）。

> 需要真的指定目标时**显式**用 `target` 命令（`cli/main.py:890` 那条路径不受影响）——副驾本来就是"你打目标、它出命令"。

⇒ env 未设时行为逐字节不变（回归：`tests/cli/test_user_intent.py::TestReplNoAutoOptOut` **9 例**，含一条"先钉住前提"的用例；
另加第五轮审计的 `TestCopilotPinsChatTarget` **4 例**盖住 `chat` 内部那道门）。**第三轮彩排实测**：同一段粘贴 → 日志**没有** `[*] Entering autonomous pentest mode`、
**只答一轮**、`Tools: none`，且不再认领 target。

**⇒ 出路 ②（不改代码的兜底，万一忘了设 env）**：粘贴 → 它自跑一轮给出命令 → **立刻 Ctrl+C** → 提示符回到
`Press Enter to resume auto pentest, or type a new command.` → **单独发一个 `chat`** → 再粘下一条。
功能上够用（第二轮 0 工具调用就是证据），代价是每次粘贴多烧 1+ 轮 LLM 调用，而且**依赖模板里那句"不要调用任何工具"不失效**。

> ⚠️ 无论哪条，**A（抹 IP/URL）仍要做** —— 它是给**你**和**模板**兜底的一层，也防止把真实目标地址写进会话记录。

### ✅ 已确认：攻击机/跳板机**系统未知**（2026-10-08）→ 现场先定性，别假设 Linux

这条不是"要问赛方"的问题，而是**动手前 10 秒要做的探测**，因为它决定命令语法与工具能不能用：

| 探测 | Linux 回答 | Windows 回答 |
|---|---|---|
| `uname -a` | 有输出（内核版本） | `'uname' 不是内部或外部命令` |
| `ver` | 报 command not found | `Microsoft Windows [版本 10.0.x]` |
| SSH banner | `SSH-2.0-OpenSSH_8.x` | `SSH-2.0-OpenSSH_for_Windows_8.x` |
| `whoami /all` | 语法错误 | 完整令牌信息 |

**代码侧的硬事实**（决定用哪个工具）：

- `remote_collect` 发的是 **POSIX `sh` 脚本**（`#!/bin/sh` + `tar`）→ **Windows 上整条不可用**；
  失败时现在的报错会直接点名"目标像 Windows cmd，请改用 `remote_exec` + `remote_fetch`"
  （`_windows_target_hint`，2026-10-08 加），但**别等它失败**，先探测。
- `remote_exec` 是把命令**原样**交给远端 shell（`exec_command`，不开 pty）：
  Linux 走 sh/bash，**Windows 走 cmd.exe** → 命令必须换成 `dir /a`、`tasklist`、`whoami /all`、
  `powershell -c "..."` 这类写法，Linux 的 `ls -al` / `ps aux` 一律不认。
- `remote_fetch` 走 SFTP，两端都可用（Windows 路径写 `C:/Users/...`）。

**探测结果写进别名备注**，agent 调 `remote_hosts` 就能直接看到该用哪套语法：

```yaml
remote:
  hosts:
    jump:
      hostname: 10.20.0.1
      username: <给的用户>
      password: <给的密码>
      note: "Windows 10 (OpenSSH_for_Windows) — 用 cmd/PowerShell 语法；remote_collect 不可用"
```

> ⭐ 渗透那条线（OA + webshell）也补了一张卡：
> `vulnclaw/skills/specialized/web-security-advanced/references/web-oa-webshell.md`
> —— 产品指纹表（泛微/致远/通达/蓝凌，要求两条互相印证）→ 能出 shell 的漏洞族 →
> 上传后缀与解析差异 → 上传目录可访问性 → 无回显三法 → 落马后取证与找 flag 顺序。
> 路由：`web-pentest` 与 `web-security-advanced` 的 SKILL.md 都已挂指针。

### ❌ 仍然待现场 / 赛方确认（10/9 培训后只剩这些）

| # | 待确认 | 现状（10/9 培训） | 影响 |
|---|---|---|---|
| 1 | **跳板机 ↔ 笔记本能不能搭隧道** | ❓ **朱禹：未做过技术测试，群里待答复** | 能搭隧道 → 本机工具可直接打内网；不能 → 只能在控制台里手打 |
| 2 | ~~是否必须有线~~ **✅ 已解决（2026-10-10 用户实地）** | **现场水晶头数量足够** —— 有线不用担心。网线/转接器照旧带上（自备省事） | ✅ **关闭** |
| 3 | **网页终端能力**：粘贴长命令？复制输出？上传/下载文件？ | ⚠️ 朱禹："需大家根据具体场景去看" | 不能粘贴 → payload 走短命令/两步法；不能复制 → 手抄输出风险 |
| 4 | **跳板机能否多人同时连** | ✅ 按"一人一个账号"理解：队友各用自己账号互不影响；**待到场验证同一账号能否"隧道 + 控制台"并存** | 决定你能不能一边挂隧道一边看控制台 |
| 5 | **哪些跳板机要自己打** | ✅ 已答：部分题必须先攻击跳板机拿权限；**跳板机一定会存在** | 第一层可能就是入口，别以为一定给凭据 |
| 6 | **平台工具库怎么访问** | ✅ 已答：**平台内置免费工具供下载使用** | 到场先下载；清单现场照抄进 `remote.hosts.<alias>.note` |
| 7 | **内存取证题给不给镜像 / PCAP** | ❓ 未提及 | 给 Windows 镜像现场可做；Linux 要 ISF（不装 Go 就别指望） |
| 8 | **账号题集**：**4 个账号**能不能各做**不同**的题；团队能否共用**一个**账号（即 4 个账号能否都变成战力） | ❓ 没直接问过；**10/9 纪要信号：决赛各队伍处于独立环境**（防互相干扰/抄袭） | 环境按队隔离 ⇒ 队内更像"一套环境 + 多账号"；**"4 个账号能否各做不同题"仍待现场验证**（成立才可以考虑让门外汉当手/各开线，见 §9.3） |

> 朱禹留下的三条待办（会在官方群答复）：~~①是否必须有线~~（**已实测解决**）②能否搭隧道 ③其他未定问题的统一答复。**待答复实际只剩「能否搭隧道」一条。**
> **10/10 晚刷一次群**，有新答案就更新这一节。

**只允许靶场段**（`--only-host` 接受 **CIDR**，2026-10-08 起）：照上面那条命令即可；
要把网段固化成默认值，用 TUI 的 `/scope host=10.20.0.0/16`
（参数名是 `host=`，存进 `session.tui_scope_only_host`）。

> 顺带修掉一个**看起来在拦、其实没拦**的缺陷：私网地址本来写成 `"10."` /
> `"192.168."` / `"172.16."`，而 `host_in_scope` 对裸 IP 是**精确匹配**、没有前缀形式，
> 所以那几条**永远匹配不上**（本地文件型任务因此并没有真正被挡住访问自己的局域网）。
> 已改为 CIDR（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`127.0.0.0/8`），
> 并给 `host_in_scope` 加了 CIDR 支持；回归见 `tests/config/test_host_scope.py`、
> `tests/agent/test_task_path_scope.py` 与 `tests/cli/test_local_path_egress_scope.py`。

> **不用再问**：靶机是 Linux 还是 Windows（现场看即可，两套手册都在）；
> 赛方是不是用 CTF2 练习场（**不是** —— 计分平台是 `tp.qianxin.com`，自带靶场）。

> 操作记录已经在跑：`log.txt` + Solve Report —— 赛后可能抽查 System 日志与答题思路，
> 这两样正好能自证。

---

## 五点五、赛前缺口清单（10/10 复核用）

> 2026-10-08 实测出来的、**还没补上的**洞。每条都带证据，别当提醒清单扫一眼就过。

### P0 — 不做有资格风险或现场翻车风险

| # | 缺口 | 证据 | 谁做 |
|---|---|---|---|
| 1 | ~~**AI 辅助的合规性没人问过**~~ **✅ 已确认合规（10/9，有群内书面依据）** | **原始群记录**（用户提供）：`⚜ 09-18 14:35:00`「线下赛对ai的包容度怎样，录屏中能出现询问ai辅助的情况吗?」→ `hongge 09-18 14:35:23`：「**不做限制**」；同人 `09-18 14:35:45`：「**不断网**」。**本行 10/08 写的"没人问过 / 群里问一句"已作废** | ✅ **解除**——把那两句抄到设备上备用（抽查日志时可直接引用） |
| 2 | ~~录屏没有落地安排~~ **已关闭（10/9）** | 用户拍板：**不用录屏、也不用交** → 原先"先试录 10 分钟、落 E:/G:"的安排作废 | ✅ 无需动作 |
| 3 | **LLM 凭据（多 key 自动轮换）** | `llm.api_keys` 已配 **2 把**（`~/.vulnclaw/config.yaml`，备份 `config.yaml.bak-20261008b`）→ 429/配额类错误会**自动轮换**；跨 provider 是**手动切换**（moonshot/qwen/siliconflow/openrouter…） | 网络轴备**手机热点**；断网时 `.ir-tools`（vol/yara/D盾）仍可本地跑。⑥**token 预算旋钮（用历史数据校准过，别凭感觉砍）**：13 条有记账的 run 里 total token p50=2.81M / p90=4.16M / max=**5.21M**；**成功**的 7 条 p50=1.08M 但 **max 也是 5.21M**，**失败**的 6 条 1.67M–3.30M（中位 2.86M）。现值 `session.solve_max_model_tokens = 6,000,000` 在 13 条里**一次都没触发** → **保持不动**（砍到 2.5M 会直接掐死那条 5.21M 的成功题）；真正省 token 的杠杆是**早停**：`competition.stall_turns` 8 → **5–6**、单题 `--max-steps` 用 **40–60**。无用消耗实测（最贵那条成功题，5.21M / 117 请求 / 135 次工具调用）：**11 次重复调用**（其中 4 次完全相同的 `python_execute`）+ **15 次失败调用**（python 12）+ 1 次空转 + **2 次被证据闸门拒掉的 FINAL（模型先猜 flag）**≈ 24 请求 ≈ **20% ≈ 1.0M token**；算上黑板为空时干跑的 8 轮则 **≈27% ≈ 1.4M**。注意 `_REPEAT_TOOL_LIMITS` 里 `python_execute`/`shell_command` 的同结果重复预算**已从 30 收紧到 10**（2026-10-08，代码默认与本机配置同步改；`competition.stall_turns` 也已 8 → 6）——但它**管不到**上面那 11 次冗余：实测那些重复是 **2–4 次一簇**，远低于任何阈值；真正有效的是 `stall_turns` / `--max-steps` 与人盯着"同一段代码别发第二遍"。 |

### P1 — 直接影响得分效率

| # | 缺口 | 证据 | 谁做 |
|---|---|---|---|
| 4 | ~~没有"可直接粘贴的短命令卡"~~ **两边都齐了**：应急段 `vulnclaw/skills/specialized/incident-response/references/paste-cards-linux.md`（100 行 / 45 条命令）+ `paste-cards-windows.md`（107 行 / 40 条）；渗透段 `IR-PENTEST-CARD.md` | ⚠️ **原判据是错的**：这条当时写"IR references 里全是分面长文档、没有任何'粘贴即用'的短清单"，但两张 IR 卡**早就在技能 references 里**（卡自己的开头就写着"为什么有这张卡：…网页终端可能不支持长粘贴"）—— 写缺口前没搜 references。教训留在这条里 | ✅ 已闭合：三张卡**全部 ≤120 字符**（Windows 卡原本那条 140 字符的整盘 PS 命令，已改写成 `%TEMP%` / `C:\inetpub` 两条窄范围版，顺带避开卡里自己实测的"递归扫全盘 271 秒"陷阱） |
| 5 | **"用 MCP 驱动网页终端"目前连本地都不可用** | `vulnclaw doctor`：`chrome-devtools: placeholder schema-only, attach_failed: stdio probe skipped for package-manager command`；`_npx` 缓存为空（**从未下载过**该包） | 要么现在跑一次 attach 测试，要么**别把它算进方案** |
| 6 | **WP（演练报告）交付格式未定，PDF 导不出** | `vulnclaw report --pdf` 需要未安装的 `weasyprint`；`python-docx` 可用，且有 `office-docx` skill + 自带 LibreOffice | 我（把 Markdown → docx/pdf 的路径打通并实跑一次） |
| 7 | **没有一次端到端彩排** | 单题能力有 304 份历史报告为证，但"按现场流程走一遍"从未做过：控制台/隧道 → 读题 → 打点 → 落马 → 找 flag → **人工提交** → 生成 WP | 我 + 你（今晚用练习场或本地容器跑一次） |
| 8 | **时间盒与角色分工未定** | 渗透 2.5h、IR 3h10m、**一血/二血权重**，但没定"每题最多几分钟"与谁盯时间/谁提交 | 我出一版建议，你拍板 |

### P2 — 已知技术债（不一定现场用得上，但要知道）

| # | 缺口 | 证据 | 影响 |
|---|---|---|---|
| 9 | `remote_*` 从未真机验证，且 **paramiko 只有 2.8.1** | `paramiko 2.8.1`（2021 年）；rsa-sha2 支持是 2.9+ 才有，现代 OpenSSH 只给 RSA 主机键时会握手失败 | 走 SSH/隧道前先 `pip install -U paramiko` 并用真实服务端验一次 |
| 10 | 裸 IP 的 `shell_command` 不受作用域检查 | `_validate_command_url_scope` 只扫 URL | 隧道/VPN 场景下边界靠人 |
| 11 | `permission_mode: full_access` | 本机 config | 所有命令免批准（你说过不管，但现场无人值守时风险自担） |
| 12 | `uvx` 未安装 | `vulnclaw doctor`：`uvx: missing` | 依赖 uvx 的 MCP 会静默降级（`fetch` 已由本地实现兜住，影响小） |
| 13 | burp / ctf2 MCP 是 placeholder | `burp: sse server unreachable`、`ctf2: unreachable` | 工具面板有"看着能用其实不能用"的项；本赛用不上 |

---

## 六、常见问题

**Q: 技能明明加载了，为什么模型行为没变化？**
A: 注入的是 skill **索引**，正文靠模型主动 `load_skill_reference`。可以显式要求它读某篇：
   "先读 webshell.md 的排查清单，再动手"。

**Q: 为什么 `/incident-response` 比自然语言可靠？**
A: 前者走 resolver 的显式分支（confidence 1.0），后者靠关键词打分（0.1~0.2）。

**Q: `load_skill_reference` 返回 None？**
A: 路径写错，或该文档待补。用 `events/webshell.md` 这种 POSIX 相对路径，别用反斜杠。

**Q: 工具箱里的工具在靶机上能用吗？**
A: 不能。工具装在你本机。靶机上只能用原生命令（或靶机自带的）。

**Q: `vol` 报 "cannot find the drive"？**
A: cmd 跨盘调用问题。先切盘符：`G: && cd G:\tool\ir-toolkit && vol --help`

---

## 七、维护

```powershell
# 重新生成工具箱清单（加了新工具后）—— 完整脚本见 .ir-tools/README.md 末节
# 简要版：遍历 .ir-tools 下所有文件算 MD5，写 _manifest.tsv（md5 \t bytes \t 相对路径）

# 同步到移动硬盘
robocopy "D:\GitClone\VulnClaw\VulnClaw\.ir-tools" "G:\tool\ir-toolkit" /MIR /XD _piptmp _wheels

# 校验自检仍然全绿
python .ir-tools\verify-ir.py
```

### 改动过的项目文件（记得纳入版本管理）

| 文件 | 改动 |
|---|---|
| `vulnclaw/skills/loader.py` | ⭐ 递归发现 references（原来 `iterdir()` 只取顶层，`references/` 下的子目录完全被发现不了） |
| `vulnclaw/skills/dispatcher.py` | 加 8 组 incident-response 路由关键词 |
| `vulnclaw/agent/tool_schemas.py` | 更新 `load_skill_reference` 描述，加嵌套路径示例 |
| `vulnclaw/agent/command_classifier.py` | 加约 70 条应急排查只读命令 + 参数守卫（子命令白名单，不是黑名单） |
| `tests/security/test_command_classifier_ir.py` | 新增 113 条（66 免批准 + 47 应拦截），防止以后改分类器时白名单退化 |
| `vulnclaw/skills/specialized/incident-response/` | 整个技能目录（SKILL.md + **12 篇 reference**，已全部写完） |

**工具箱改动**（`.ir-tools/`，gitignored，但移动硬盘要同步）：

| 文件 | 改动 |
|---|---|
| `bin/_vol_entry.py` | ⭐ 加 `python -S` 重执行隔离，修 Anaconda pyOpenSSL 崩溃（判据用 `sys.flags.no_site`） |
| `env.ps1` / `env.cmd` | 加 Wireshark 目录进 PATH（session 级，缺失不报错） |
| `pcap/make_pcap.py` | 新增：合成 webshell PCAP 生成器，用于验证流量分析文档的命令 |
| `pcap/sample-webshell.pcap` | 新增：生成好的样本（18 包，含 HTTP + DNS beacon） |
| `verify-ir.py` | ⭐ 加 vol 真分析检查；`PENDING` 列表并入 `EXPECTED`（不再有"待补"概念） |

**回归验证**：`python -m pytest tests/skills -q` → 137 passed；
`python -m pytest tests/security/test_command_classifier_ir.py -q` → 113 passed；
`python .ir-tools/verify-ir.py` → `PASS=66 FAIL=0 WARN=0`。

---

## 八、10/9 复核：缺口清单的当前状态（实测更新）

> 对"五点五"那 13 条**逐条核当前机器状态**，不是复述。本节只记**变化与证据**；
> 五点五那些行原样不动（那份是 10/08 的快照，本节的日期更近）。

| # | 项 | 10/9 实测 | 状态 |
|---|---|---|---|
| P0-1 | AI 辅助合规性 | ✅ **已确认合规**（用户 2026-10-09 确认）。若群里/通知里有书面依据，把那句话抄到设备上备用 | **解除** |
| P0-2 | ~~录屏落地~~ **已关闭（10/9）** | 用户拍板：**不用录屏、不用交** → 不再占分析机与磁盘；C: 14.6 GB 仍紧，工具箱/采集文件写 E:/G: | ✅ 无需动作 |
| P0-3 | LLM 凭据/token 预算 | ✅ `llm.api_keys` 实测 **2 条**（429/配额类错误自动轮换）；✅ `competition.stall_turns` 已是 **6**；`solve_max_model_tokens` 保持不动。**2026-10-09 实测用量**：当天 5 个 run 共 **7.33M token**（本地 IR 彩排 0.43M / BUU LFI 0.09M / **CTF2 WEB2 3.38M（未解出、中途叫停）** / **CTF2 鸡公煲 3.41M（解出）**）—— **两道 CTF2 占 93%**，是 token 消耗的主体，也是"早停比调预算更有效"的实测依据 | ✅ 配置面已就绪（旋钮保持不动，靠 `stall_turns`/`--max-steps` 早停） |
| P1-4 | 短命令卡 | ✅ **已补**：`references/paste-cards-linux.md` + `paste-cards-windows.md`（逐行可粘贴；Windows 那份在本机 Win11 23H2 逐条实跑） | **关闭** |
| P1-5 | chrome-devtools 驱动终端 | ❌ `_npx` 缓存目录**不存在**（从未下载过） | 建议**不做** |
| P1-6 | ~~WP / PDF 交付~~ **整条作废（2026-10-10）** | 赛方明确 **WP 不用交** ⇒ 不再是交付物。PDF 链路本身仍可用（`reportlab` 已装、`vulnclaw report <session.json> --pdf` rc=0），但现在只作**赛后复盘**用途 | **不再占用现场时间**（`IR-WP-TEMPLATE.md` 保留在仓库，现场不填） |
| P1-7 | 端到端彩排 | ✅ **三半 + 跳板链式（2026-10-10）** —— 跳板链式/隧道/`-D`判别力/Windows跳板命令面已实测（见 §五「跳板链式真机验证」）。**三半都已完成（2026-10-09）**：① **IR 半** —— 本地容器，105 秒 / 5 分，并**暴露出 IR 交付链是断的**（见下）；② **渗透半** —— CTF2 真靶机 BUU LFI COURSE 1，1 轮拿到 flag（注：那次复用了 3 天前的 playbook，**不算冷解**）；③ **B 半（副驾交接）** —— 同一台 `ir-drill`，6 轮 / 5 分 05 秒 / 4.5–5 分，**抓到副驾闸门漏在 `result.target` 上**（见下） | ✅ **完成** |
| P1-8 | 时间盒/分工 | ✅ **已定稿（V4，2026-10-10）**：**4 名选手 = 你 + 1 位稍熟练 + 2 位门外汉**（用户更正，见 §9.3）→ 2 名能打的各开一条线，2 名门外汉只做**计时 / 台账 / 素材**（不碰靶机、不做判断）；4 个账号，2 个暂时闲置 | ✅ 角色与职责均已落到动作；名字现场 1 分钟填 |
| P2-9 | paramiko / `remote_*` 真机验证 | ✅ **已升级 + 已验证**。2.8.1 → **5.0.0**（+invoke 3.0.3）。证据见下 | **关闭** |
| P2-11 | `permission_mode: full_access` | 确认仍在（无人值守时风险自担） | 不变 |
| P2-12/13 | `uvx`/`uv` 缺失、burp/ctf2 placeholder | 确认缺失/placeholder；本赛用不上 | 不变 |

### P2-9 的证据（为什么这条必须升）

* **升级前**客户端主机键算法表：`('ssh-ed25519','ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521','ssh-rsa','ssh-dss')` —— **没有 `rsa-sha2-*`**。
* **升级后**：`('ssh-ed25519','ecdsa-*×3','rsa-sha2-512','rsa-sha2-256')`。
* 现代 OpenSSH（8.8+）默认**不再提供 `ssh-rsa`（SHA-1）**，只给 `rsa-sha2-*`。用本机
  真 **OpenSSH 9.5** 起了一个**只挂 RSA 主机键**的 sshd：服务端日志
  `debug1: list_hostkey_types: rsa-sha2-512,rsa-sha2-256` → 协商
  `debug1: kex: host key algorithm: rsa-sha2-512` ✅ 连接成功。
  旧版在这种服务器上**无从协商** → 现场"只挂 RSA 主机键"的跳板机/靶机会直接握手失败。
* **repo 自己的代码也验了**：用 `vulnclaw.agent.remote` 打这个真 sshd ——
  `list_hosts()` 正常；`run_command("echo ...; hostname; whoami")` → **exit 0** + 真实
  stdout + 主机键指纹；`run_command("exit 42")` → **exit_code 42**。
  所以"`remote_*` 从未真机验证"这条同时关闭。
* 顺带实测：Windows 目标的默认 shell 是 **cmd.exe** —— `;` 不是分隔符、`1>&2` 无效
  （`echo x 1>&2; exit 7` 在远端被 cmd 解析成别的东西 → 返回 exit 0）。给 Windows 目标
  下命令要按 cmd 语法写（见 `paste-cards-windows.md`）。
* 仍然是**未验证**的：真实跳板机上的密码/密钥认证与网络路径 —— 那条只有到现场才能验。

### 已明确与仍未答（10/9 末）

1. ✅ **AI 辅助合规 = 已明确**（群内书面依据，用户提供原始记录）：`hongge 09-18 14:35:23`「**不做限制**」+
   `hongge 09-18 14:35:45`「**不断网**」。**"不断网"这条同等重要**：现场保留互联网 → vulnclaw 的云端 LLM 路径可用，
   "断网就退人工+本地工具"的退路不需要，但反过来**现场网络可用性成为硬要件**（见 P0-3）。
2. ⏸ **"能否搭隧道"**仍是待答复（五点五待确认表 #1）—— **这是唯一还挡着 agent 全速运行的合规项**。
   **技术侧已就绪、执行清单已写死**（见 Q1 末尾「⏸ 合规未答」块：`ssh -D` + `VULNCLAW_HTTP_PROXY` +
   三条自查）。**群里一旦答"可以"，直接照抄执行，不需要再出方案**；未答期间守副驾模式。
   （"是否必须有线"已实测解决——现场水晶头足够；且它本来也不影响 agent 路径。）
3. ⚠️ **agent 经 SSH 驱动跳板机是否算红线"远程操作"** —— 未被"不做限制"覆盖（那句答的是 AI 辅助提问），
   仍按**副驾模式**保守执行。
4. ~~录屏是否需上交 + 用什么软件~~ —— **已定（10/9）：不用录屏、不用交**。

### ✅ 10/9：`.ir-tools` 的 vol 自检 FAIL=2 —— **已修**（根因两层，都不是 vol 的问题）

原本报 `PASS=97 FAIL=2`（两条都在 volatility3），现在 **`PASS=99 FAIL=0 WARN=0`，
结论"功能可用"**，`vol 真分析可用（banners 提取到符号键 ntkrnlmp.pdb…）`。两层根因：

1. **`os.execve` 在这台机器的 Anaconda 3.12.7 上直接崩（访问违例 rc=139）**。最小对照即可复现：
   `python -c "import os,sys;os.execve(sys.executable,[sys.executable,'-c','print(42)'],dict(os.environ))"`
   → rc=139；`-X faulthandler` 指到 `_vol_entry.py` 的 execve 行。而 `vol.cmd` 用裸 `python`，
   本机 PATH 第一位就是 `D:\anacond_1` → **每次都在这里死，`vol --help` 一个字都不输出**。
   → 改成 `subprocess.call(...)` + 回传子进程退出码。
2. **App 注入的 `PYTHONPATH=…\resources\backend\_internal` 污染**（里头是 **Py3.11 的 .pyd**）：
   `import socket` 报 `ImportError: Module use of python311.dll conflicts with this version of Python`。
   文档原写"-S 会清掉 PYTHONPATH"是**错的**（实测 -S 照样认 PYTHONPATH），入口还把污染原样
   传给了子进程 → 改成：剔除 `_internal`/`routercode` 的 sys.path 与环境项，子进程只给 pylib。
   另外 `vol.cmd` 现在自带 `-S`，常态路径根本不会再 re-exec。

**验收**：带污染时 `bin/vol.cmd --help` 也 rc=0（182 个插件行）。
`.ir-tools/verify-ir.py` → `PASS=99 FAIL=0 WARN=0`。

⚠️ **两件必须记住的事**：
* **`.ir-tools/` 是 gitignore 的**（`.gitignore:130`）→ 这个修复**只在本机磁盘**，没进任何提交。
  **换机/重装工具箱要把它带过去**（就改了 `bin/_vol_entry.py` 和 `bin/vol.cmd` 两个文件）。
* `verify-ir.py` **要在干净的 PYTHONPATH 下跑**（`env -u PYTHONPATH -u PYTHONHOME …`）。
  直接在 App 终端里跑会被那层污染带偏成 `PASS=43 FAIL=3` —— 那是测量工具被污染，不是工具箱坏。

---

### 🎯 P1-7 彩排 · **A 半**（agent 驱动，本地容器）—— 已完成 2026-10-09

> 靶机：本机 Docker `ir-drill`（`docker start ir-drill`；镜像 `ir-drill:1.0`）。跑前 `docker exec ir-drill ls -A /tmp` **为空** ⇒ 脚手架没泄漏进镜像（setup 的 scrub 有效）。
> 跑法：`vulnclaw solve ir-drill --goal "完成应急响应排查：…" --prompt "$(cat 题面)" --max-steps 12 --run-name drill-rehearsal-1`
> ⚠️ BRIEF 里写的 `docker-container://ir-drill` **不是真 scheme**（全仓 0 命中），目标串只是描述性的，真正驱动 agent 的是 `--prompt`。
> 结果：`status=completed` / `agent_state.completed=true` / **105 秒** / 3 轮 / 38 次工具调用 / prompt 415,468 + completion 18,072 tokens（≈0.43M）。
> 会话档（权威）：`~/.vulnclaw/sessions/20261009_162535_ir-drill.json`；run 目录：`~/.vulnclaw/runs/drill-rehearsal-1/`。

**用时分解（对照 §9 时间盒）**

| 阶段 | 时刻 | 说明 |
|---|---|---|
| 启动 → 首次调用 | 16:24:52 → 16:24:57 | 5 秒 |
| 侦察爆发 | 16:24:57 → 16:25:08 | 11 条 `shell_command`（11 秒） |
| 深挖 | 16:25:18 → 16:25:39 | 基线 `diff` / `find` / `grep`（21 秒） |
| 写答案 | 16:25:39 → 16:26:05 | 26 秒（整段生成 6 答） |
| 完成闸 + 收尾 | 16:26:05 → 16:26:37 | 记 6 答 → 扫描面 → LOCK/facts/angles |

**⇒ 这类"笔记本可达、agent 直连"的题 105 秒就闭合，§9 的 15/25/30 分钟硬盒对它过于宽松。** 硬盒真正的约束对象是"只能经跳板机手打的题"（= B 半要验的）。

**评分（ANSWER-KEY 6 项）：5 / 6**

| 项 | 分 | 依据 |
|---|---|---|
| 1 三个恶意文件（含**被篡改的** upload.php） | ✅ | 3/3 命中，且用基线 `diff` 找出注入。**但多报 3 条**（两处 cron + `/etc/passwd`）：前两条实为"持久化"，第三条是系统文件 ⇒ 分类混淆 |
| 2 攻击者 IP | ✅ | `203.0.113.47`，并显式排除 `198.51.100.9`（伪 Googlebot）与 `192.168.1.10`（运维 webadmin） |
| 3 首次入侵时间 | ❌ | 答 **09:22:31**（探测起点），应为 **09:22:51**（`upload.php` 返回 200 = 上传成功那一刻）。数据它都拿到了，只是选错了那一个 |
| 4 漏洞类型 + 行号 | ✅ | 上传扩展名校验缺陷 / 第 21 行 `pathinfo(...,PATHINFO_EXTENSION)` / 注入行 38–39 |
| 5 两处 cron + UID=0 账号 | ✅ | `crontabs/root` + `/etc/cron.d/demo-persistence` + `sysupdate` |
| 6 清除方案顺序 | ✅ | 明确"只删文件不够"：阻断 → **先拆持久化** → 删文件 → 基线覆盖 → 修漏洞 → 加固 |

观察项：⑦ 真跑了 `ls -la`（e003/e006/e019）✅；⑧ 报告里 5 条路径逐条 `docker exec` 复核 **全部真实存在** ✅；⑨ 全程 `[观测]` 标注 ✅。
完成闸有实效：过程中被拒 1 次（"先 LOCK + 确认关键事实 + 关掉 ANGLES 再宣布完成"），随后补齐才结束。

**⭐⭐ 彩排真正抓到的两个问题**

1. **WP 交付链不对接**（我先前"空报告是 bug"的定性**需更正**）—— 6 个答案经 `blackboard_record_answer` 落库后是
   `vuln_type="ir-answer"` 的 Info/always-pending 卡片，而**报告 / SARIF / verify-pending / `--fail-on` 消费者按设计就必须跳过答案卡**
   （`domain_models.ANSWER_CARD_VULN_TYPE`，round-10 finding #1：不跳的话"漏洞名称"这种提问会被当成已验证漏洞印进报告）。
   ⇒ `vulnclaw report` 对 IR 出 0 findings **是设计，不是 bug**。
   **但操作后果照样成立**：WP 只能走 `IR-WP-TEMPLATE.md` 人肉填，而**没有任何工具把答案卡渲染进那个骨架**
   ⇒ 15:00–15:20 那 20 分钟得有人从会话/黑板抄 6 条结论 + 证据 —— 这是**分工里没落到的活**。
2. **`vulnclaw report <session.json>`（CLI 路）拿不到本 run 的取证仓库，而且是"假告警"**（**受控实验**，非推断）：
   `generate_report_from_file()` → `generate_report(session)` **不传 `run_dir`** ⇒ 取证仓库回退到 `output.parent`
   （= `~/.vulnclaw/sessions`）→ 空。同一个 run 各渲一次的实测对照：

   | 路径 | 正文内联 | 报告里的措辞 | `evidence_bundles` |
   |---|---|---|---|
   | A `report(session)`（= CLI `vulnclaw report`） | ❌ | **⚠ 已绑定但正文不可读取（快照已不在索引中）** ×2 | ❌ |
   | B `report(session, run_dir=…)`（= agent/orchestrator） | ✅ 原文进报告 | 正常渲染 `GET … → 500` + 响应体 | ✅ **实测已生成** |

   ⇒ 不光丢证据，还**把"证据就在那儿"误报成"证据没了"**。§9.2 让用 `vulnclaw report <session.json> --pdf` 交 WP，
   那交出去的就是一份**自己声称证据不可读**的报告 —— **渗透题同样中招**，不只是 IR。
   ⚠️ 顺带确认：新接的第 6 条那条 `evidence_bundles` 线在**传了 `run_dir` 时确实生效**（B 路径实测产出），
   所以它不是"在 IR 不生成"，而是**只有 CLI 那条路生成不了**。

**小摩擦（不扣分，但现场会重复出现）**：`load_skill_reference("incident-response/ir-competition-strategy")` 文档不存在 ⇒ 1 次 degraded；两条命令被 Windows shell 包装吃掉（`find -exec` → `CommandNotFoundException`、`Out-File` → `DirectoryNotFound`）；一条 `awk` 语法错。框架口径 0 次失败调用，但真实命令里有 3 处语法级失败。

**✅ 同日已修（2026-10-09）**

| 问题 | 修法 | 验证 |
|---|---|---|
| ② CLI 报告拿不到 run 证据 | `generate_report_from_file()` 先按 `session.run_id` 反查 run 目录；`vulnclaw report` 加 `--run-dir`（显式优先）。**根因比表面更深**：`vulnclaw solve` 从前根本没把 run 写进会话（`session.run_id` 为空，只有 subagent 那条路会生成）→ 一并修在 `orchestrator` 注入 `agent.run_dir` 的地方 | `tests/traffic/test_evidence_report.py` 新增 4 例（正文内联 / 显式优先 / 反查 best-effort / 无 run 不崩）；**真实 run 复核**：新会话 `session.run_id` == `run.json.run_id`，`find_run_dir_by_run_id` 反查命中 run 目录 |
| ① WP 要人肉抄答案卡 | **关闭 —— 不做这个工具（同日撤回 `wp` 方案）**：把答案卡渲成交付物的 `vulnclaw wp` 已删除（命令 / `vulnclaw/report/ir_wp.py` / 其测试一并移除；`test_the_report_itself_still_omits_answer_cards` 已迁到 `tests/report/test_report.py`）。报告跳过答案卡的设计**不变**（round-10 finding #1）；WP 走 `IR-WP-TEMPLATE.md` 人肉填 | — |

⇒ 15:00–15:20 那段仍是**人肉抄 6 条结论 + 证据**（落到分工里的人头上），WP 走 `IR-WP-TEMPLATE.md`。

---

### 🎯 P1-7 彩排 · **渗透半**（agent 驱动，CTF2 练习场真靶机）—— 已完成 2026-10-09

> ⚠️ **前置坑：CTF2 的浏览器 session 会过期**（实测 `TOKEN_EXPIRED` / `errors.auth.token_expired_login`）→ 会话态列表写题（**session-only** 路由）全废。**但 Open API 的 API key 仍有效**，所以 `read_challenge` / `start_environment` / `get_environment` / `stop_target` 都能用，**只有 `get_target` 是 session-only**。
> **绕法（不用登录）**：① 题目 id 从 `~/.vulnclaw/playbooks/` 里 `ctf2:practice:<pid>:<cid>` 的引用捞；② `start_environment()` 起靶机；③ `get_environment()` 拿 `access_url`（`get_target` 拿不到）。
> **释放**：跑完 `stop_target()`（实测返回 `removed: true`）——别白占容器槽位。

- 题目：**BUU LFI COURSE 1**（practice `4cdd8933-…` / challenge `31ceabbf-…`，Easy，`has_container: true`）
- 靶机：`http://9c8d2d0ea9fd2fedaf9c4b2c.http-ctf2.dasctf.com:80`（TTL 3580 秒）
- 结果：`completed` / **1 轮 / 7 次工具调用** / prompt 85,850 + completion 1,781（≈0.09M）
- 利用链：`?file=php://filter/convert.base64-encode/resource=index.php` 读源码 → `?file=/flag` → **`CTF2{13506443-96d5-4fdf-9faa-402a44c1b373}`**
- ⚠️ **这次 1 轮命中不算冷解**：playbook `buu-lfi-course-1.md` 的 mtime 是 **10-06**（3 天前解过）⇒ 本次是**复用 playbook** 一发命中。playbook 复用是设计内的好事，**但别拿它当现场速度**；冷解基线仍是 §四点九 的「SSTI 16 条证据 / 3 轮」。

**⭐ 交付链实测（跑这半的真正目的）**

| | `vulnclaw report` |
|---|---|
| Verified Findings | **0**（"No valid vulnerabilities were found"） |
| flag 在里面？ | ✅ 但只在 **§4 攻击路径摘要**里（LLM 摘要救的场） |
| 利用链 / 证据 | 摘要里带 `GET /?file=/flag` |
| 体量 | 77 行 / 2,478 B |

> 同日曾用 **已删除**的 `vulnclaw wp` 渲过一版（**148 行 / 5,117 B**，flag 落在结构化答案卡里）—— 数字留作复盘记录，命令与代码已移除。
>
> ⇒ **flag 型渗透题**：`report` 只在该 run 真有 verified findings + 绑定证据时才是正确交付物（评估型 run）；答案卡型交付物回到 `IR-WP-TEMPLATE.md` 人肉填。

⚠️ **`evidence_bundles` 本次没生成，而且不是 bug**：agent 全程**没调 `traffic_bind_evidence`**（工具序列 = `fetch`×3 / `dir_enum` / `http_probe_batch` / `blackboard_record_answer` / `save_playbook`）⇒ run 里既无 `snapshots.jsonl` 也无 http_capture 引用，所以第 6 条那条线不启用。**只有 agent 真去固化证据才会有包** —— 这是纪律/prompt 问题，不是代码问题。

**另记一道未解出（留卡点，避免盲目重跑）** —— CTF2 **WEB2**（Medium，带 `www_4.zip` 源码包）：**11 轮 / 117 次工具调用 / 3.38M token，中途叫停，未解出**（也**没有** playbook）。卡在**部署脏**上：① `config.inc.php` 的 DB 凭据是发布时的占位符 ⇒ `/search/` 直接 500，**DB 整条链是死的**；② `/.git` 是基础镜像 `hello-world-lamp` 的残留，**不是 CMS 的仓库**（顺着走是死胡同）；③ 但**目录列举开着**（`/controller/` 能列到 `Action.class.php`），agent 当时已转向源码审计，找**不依赖 DB** 的路径（上传 RCE / 源码泄露 / 模板注入），没走完就被停。**下次重跑**：把"DB 死 ⇒ 立刻换非 DB 链"写进 prompt，并先花 1 分钟确认目录列举到底能列出哪些控制器。

---

### 🎯 P1-7 彩排 · **B 半**（副驾交接：人打字、vulnclaw 出命令）—— 已完成 2026-10-09

> 这是现场主路径（平台网页终端只能手打），也是彩排里最后没验的一半。
> 靶机：**同一个 `ir-drill` 容器，故意与 A 半完全一致** —— 变量只剩"交接循环"这一个，A/B 才可对照。
> 角色：**vulnclaw = 脑子**（真盲，不知道 `ANSWER-KEY.md`）；**DSH = 手**（替主攻手在容器里执行、把输出原文喂回）。
> 开关：`VULNCLAW_REPL_NO_AUTO=1`（副驾模式）+ 常驻 broker 把 `vulnclaw repl` 挂住跨轮保上下文。
> ⚠️ 驱动它的 PATH 里**摘掉了 `docker`** —— 现场 vulnclaw 本来就没有到靶机的路，这是等价条件。实测它全程没试图自己去连。

**结果：6 轮闭环 / 5 分 05 秒 / 4.5–5 分**（A 半：105 秒 / 5 分）

| 阶段 | 时刻 | 说明 |
|---|---|---|
| 首次输入 → 回复 | 22:50:30 → 22:50:40 | 10 秒，**但一条命令都没给**（见问题 2） |
| 顶一句 → 第 1 批命令 | 22:51:06 → 22:51:22 | 16 秒，给出 6 组命令 + 判据 |
| 第 2 批（web 目录 / 日志 / 持久化 / 时间线） | 22:52:55 → 22:53:19 | 23 秒 |
| 第 3 批（cron 正文 / stat / 源码 / 全量时间线 / 账号） | 22:54:20 → 22:54:47 | 27 秒 |
| 第 4 批（access/secure 日志 / 木马与脚本正文 / md5） | 22:55:07 → 22:55:35 | 28 秒，**6 问闭环** |

⇒ **交接循环本身不是瓶颈**：6 轮里 vulnclaw 的推理只占约 2 分钟，其余是执行与中转。
⚠️ **5 分 05 秒是下界，不是现场速度**：这一轮的"手"是程序化 `docker exec`（瞬时执行、无打字、无复制限制），
现场是真的手打 + 网页终端可能不支持长粘贴。**能拿走的结论是"循环能在硬盒内收敛"，不是"现场 5 分钟能做完"。**

**评分（同一份 ANSWER-KEY，6 项）**

| 项 | 分 | 依据 |
|---|---|---|
| 1 三个恶意文件 | ✅ 方法弱 | `a7f3c1.jpg.php` + `.cache_update.sh` + 被篡改的 `upload.php`，**3/3 命中**。**但没做基线 diff** —— 它靠文件里那行 `// <<< INJECTED` 注释认出篡改，没去 `/root/baseline/` 比对（A 半是 diff 出来的）。同样多报 2 条 cron 为"恶意文件" |
| 2 攻击者 IP | ✅ | `203.0.113.47`，并显式排除 `198.51.100.9`（伪 Googlebot）与 `192.168.1.10`（运维 webadmin） |
| 3 首次入侵时间 | ❌ | 答 **09:22:29**（`secure.log` 首条 SSH 失败），应为 **09:22:51**。**A 半答 09:22:31，也是错的** ⇒ 两半栽在同一项 |
| 4 漏洞类型 + 行号 | 半对 | 位置给了"第 20–27 行扩展名校验 + 第 41 行 `move_uploaded_file`"（⊃ 正确的第 21 行），但**机制说反了**：它认为校验"本该拦住却被绕过"，而真正的缺陷正是第 21 行 `pathinfo(..., PATHINFO_EXTENSION)` **只取最后一个点之后的后缀**。它自己发现了矛盾（"`a7f3c1.jpg.php` 末段是 php，按代码该 400，可日志是 200"）却没收敛 |
| 5 两处 cron + UID=0 | ✅ | `crontabs/root` + `/etc/cron.d/demo-persistence` + `sysupdate`，**两处都拿到** |
| 6 清除方案 | ✅ 缺一项 | 明确"只删文件一定不够"、且先把持久化拆掉；但**没把"先阻断外部连接"放在第①步**，也**没想到用 `/root/baseline/` 覆盖**（它主张手工删第 38–39 行 —— 正是 KEY 里点名不要的做法） |

**⭐⭐ B 半抓到的五个问题（按严重度）**

1. **[高] 副驾闸门漏在 `result.target` 上 —— 粘一段 dump 照样把"文件名字符串"变成会话 target。**
   `_mined_target_for_session()` 在 `VULNCLAW_REPL_NO_AUTO=1` 时返回 `None`（`main.py:4578`），
   所以**REPL 自己不再挖 target**；但单轮 chat 分支的 `after_result` **照样采纳 agent 返回的 target**
   （`main.py:1163-1164`）。
   **两次独立复现（观测）**：
   ① 本次 B 半 —— 粘回第 1 批输出后提示符从 `vulnclaw Vulnerability Discovery>` 变成
      **`vulnclaw upload.php | Exploitation>`**；会话文件 `~/.vulnclaw/sessions/20261009_225034_unknown.json`
      落盘 `target: upload.php` / `phase: post_exploitation`；
   ② 同期**另一个** vulnclaw 进程（不是本次 broker）落了 `20261009_225456_access.log.json`，
      `target: access.log` —— 同一形态，同样在副驾条件下。
   ⇒ 夜彩排"贴原文 = 把 target 交给它"那条根因**并未在副驾模式下消除**，只是从 REPL 挪到了 agent 返回值上。
   而 `copilot.cmd` 第 24 行那条检查（"prompt must stay `vulnclaw Ready>`，出现 target / AUTO = 副驾没开"）
   **会正常报警，但归因是错的** —— 模式确实是开的，漏点在 `result.target`。
   修法（1 行）：`after_result` 采纳 `result.target` 前也过一遍 `_repl_no_auto()`（与 `_mined_target_for_session` 同一道闸）。

2. **[高·更正] 本该兜底的那道封锁是死代码 —— 我彩排当时"会把内网封掉"的判断不成立，撤回。**
   最初我据 `main.py:1034` 推断：`_is_local_path_target("upload.php")` 命中 `\.php$`（`main.py:4735`），
   于是 `_apply_local_path_constraints()`（`main.py:4740`）会把 `10/172.16/192.168/127.0.0.0-8` 加进
   `blocked_hosts`，**静默切断 VPN 类题目的靶机路由**。
   **查证后撤回**（`agent.session_state` 就是 `agent.context.state`，`core.py:162`，故会话文件是权威的）：
   本次会话文件里 `strict_mode: False` / `allowed_paths: []` / `blocked_hosts: ['tp.qianxin.com']`
   —— 那道封锁**一次都没落地**（我另行单独复现函数体，无异常、顺序执行完全正常）。
   原因在调用链：`_apply_local_path_constraints` 改的是 `context.state.task_constraints`，
   而每次 run 开头的 `_reset_runtime_state` 会用 `extract_task_constraints(操作手那句话)` 重新解析，
   并在 `core.py:286` **把 `context.state.task_constraints` 整个重新赋值** ——
   粘回去的 dump 里必然含 IP / 路径 ⇒ 解析结果非空 ⇒ **上一轮刚加上的封锁被原地丢掉**。
   ⇒ 两面都要记：**好的一面**是"封掉内网"不会发生（虚惊一场）；
     **坏的一面**是这道安全兜底**在实践中完全失效** —— 它本该保证"本地文件类 target 不会变成全盘遍历 / 扫自己内网"
     （`main.py:4721-4725` 的原意），现在等于没有。**这是一条独立的、比 target 泄漏更该修的缺陷。**

3. **[中] 开题第一轮可以整轮不产出命令。** 冷启动的首次输入（题面 + 操作约束），它花掉整轮去
   `load_skill_reference`（`10-system-basics.md` + `30-file-artifacts.md`），**一条命令都没给就回到提示符**
   （10 秒 / 7.9k 字符全是技能文档预览）。操作手顶一句"我没收到命令"才纠回来。
   这正是夜彩排那次 `Not achieved — steps=2 / waiting for user input` 收场的同一形态 —— **换了开关，形态还在**。
   现场代价：一次往返，且操作手必须**预先知道"它会空转一轮"**，否则会以为工具坏了。

4. **[中] 内部独白与技能正文淹没控制台。** 每轮把 `<thinking>` 全文打进操作手终端；技能文档以
   `[active-context high-signal preview]` 形式回灌 **6.5k + 6.9k 字符**。手打时操作手要在一屏独白+文档里找那段命令。
   ⇒ 副驾会话里 `show_thinking` 应默认关；技能回灌只留 `[signal lines]`。

5. **[轻] 换行/编码坑（现场同类会复现）。**
   ① 批量脚本用 CRLF 写，`sh` 把尾部 `\r` 当参数（实测 `/proc/1/cwd'$'\r': No such file or directory`）
   —— **网页终端若按 CRLF 粘贴，同理会崩**；
   ② 控制台按 GBK 解码 UTF-8 文件内容，两处中文注释成乱码（命令行本身纯 ASCII、没受影响）；
   ③ 驱动管道不是 TTY，`console.input()` **一次只吃一行**，多行输出只能用 `⏎` 占位中转，而现场
   prompt_toolkit 的括号粘贴能整块收 ⇒ **这轮在"结构"上比现场更严、在"手速"上比现场更松**。

**✅ B 半同时验证了这几件事是好的**

- **换不到工具会自动改道**：`ss` / `netstat` / `crontab` 三个命令都不存在时它没卡住，自己提出用
  `/proc/net/tcp` 代替 `ss`、用"查 `/etc/cron.d/` 与 `/var/spool/cron/crontabs/` 文件"代替 `crontab -l`。
- **没证据就不编**：轮到攻击者 IP 时它明说"日志没读到，不能编"，并要求读 `/var/www/logs/` ——
  证据闸门在副驾模式下照样生效。
- **它自己发现日志在非标准路径 `/var/www/logs/`**（`/var/log` 里没有 web 日志），这一跳是它靠时间线命令捞出来的。
- **时区陷阱它自己抓到了**：系统 `Etc/UTC` 而 `access.log` 是 `+0800`，它主动标注了 8 小时偏移
  （但最终仍选了 SSH 首败那条当"首次入侵时间"）。

**⇒ 两条与代码无关、可以立刻改的**

1. **"首次入侵时间"的判据要写死**：**首次恶意"成功"动作（返回 200 / 文件落地），不是探测起点。**
   A、B 两半在同一项上各错一次（09:22:31 / 09:22:29）⇒ 这不是交接问题、是**判据问题**，
   该写进 `incident-response` 技能与现场 prompt。
2. **完整性校验要进流程**：B 半全程没人想到 `/root/baseline/`。
   ⇒ 在 prompt / paste-card 里补一条"找靶方自带的基线副本并 `diff`"
   （`30-file-artifacts.md` 有 `rpm -Va`，但没提"基线备份"这种形态）。

---

## 九、时间盒与角色分工（**V4 · 4 人队 = 2 能打的 + 2 门外汉**，2026-10-10 定稿）

> 依据（培训确认的硬事实）：**9:30–12:00 渗透（150 分）/ 12:00–12:20 午休 / 12:20–15:30
> 应急（190 分）**；分值按难度 + **一血/二血/三血速度权重**；部分题**按顺序解锁**（不交前一题
> 就解锁不了下一题）；**一人一个账号**（队制）；**不同 flag 分值不同**；
> 纪要另补：**部分任务非线性解锁**（高亮/灰度区分状态）。
> **WP 不用交**（赛方 2026-10-10 明确，培训时那句"需在截止前提交演练报告"已作废）。
> 两个推论直接决定打法：**① 速度就是分（一血权重）→ 拿到 flag 立刻交，别攒着整理。
> ② 线性链上顺序解锁 → 卡住的一道题会卡死后面的题，所以"到点必跳"必须比"做完"优先；
> 非线性节点（高亮/灰度可辨）可与主链并行 —— 跳 ≠ 放弃，先记 3 行状态再回来。**

### 9.1 渗透段（9:30–12:00，150 分钟）

| 时间 | 干什么 | 硬规则 |
|---|---|---|
| 9:30–9:40 | **分诊**：进任务中心，数题 / 记分值 / 看解锁顺序；对靶机做一次 30 秒**可达性测试**（`Test-NetConnection <ip> -Port <p>`）判定这道题是 **agent 打**（可达）还是 **你手打**（只能走控制台） | 这 10 分钟不许开打 |
| 9:40–11:30 | **主攻**：先挑 2–3 道**最有把握的速通题**抢一血（速度权重最高的一段就在开头）；之后按分值降序做 | 每题**硬时间盒**：速通题 **15 分** / 常规题 **25 分** / 卡住 **30 分封顶** |
| 11:30–11:50 | **停止开新题**，回收：逐题核对 flag **是否已提交**（顺序解锁题交一解一），每题写 3 行状态 | "已拿到但没交"是本赛最亏的失分 |
| 11:50–12:00 | 缓冲：切到 IR 段（下载平台工具、验隧道/控制台、确认 python 与工具箱可用） | 别在 12:00 还坐在渗透桌上 |

### 9.2 应急响应段（12:20–15:30，190 分钟）

| 时间 | 干什么 | 硬规则 |
|---|---|---|
| 12:20–12:35 | **分诊**：数题 / 分值 / 解锁顺序；判每题是"网页终端手打"还是"agent 打" | 同样 15 分钟不许开打 |
| 12:35–15:00 | **主攻**：按 `flag-landing-spots.md` 的**五步**走（内容搜 → 时间圈定 → 进程/环境 → 服务侧 → 变形解码）；优先 `remote_collect` 一键固化现场 | 每题 **30 分钟硬盒**；到点写 3 行状态跳走。**不要一进题就全盘搜索**（实测 271 秒起） |
| 15:00–15:20 | **回收**：逐题写 3 行状态（结论 / 证据出处 / 是否已交），把会话里的关键命令与输出**归档留痕**（赛后可能抽查答题思路）。WP 不用交（赛方明确），所以这里只做"留痕 + 核对"，不拼报告 | **先把 flag 交了再整理**；结论比过程重要 |
| 15:20–15:30 | 最终提交核对（**链式：逐题确认都交了**）+ 把留痕文件落到 E:/G:（**无交付物要交**） | 漏交一个可能少解锁一整题 | 

### 9.3 角色分工（**V4 · 4 人队 = 2 能打的 + 2 门外汉 · 2026-10-10 更正**）

> **实际人力（用户 2026-10-10 更正，我上一版理解反了）**：**4 名选手（4 人队，一人一个账号 = 4 个账号）**，
> 构成为 ① **你** ② **一位稍微有点经验的选手** ③④ **两位门外汉**（不会 vulnclaw、不会 CTF，彻底的外门）。
> 另：**WP 不用交**（赛方明确）。
>
> ⇒ 上一版写成"2 选手 + 2 协助"是错的；但**能力分层这个结论不变**：
> 4 人里真正能判断漏洞/读输出的只有 **2 人**，另 2 人只能做**不需要判断的活**。
> 外门能做的三类事：**字面工作**（照抄、登记、计数、报时）、**机械记录**（复制粘贴、截图、存文件）、
> **喊人**（到点提醒、举手找老师）。**任何需要"这是不是漏洞 / 这个 flag 对不对"的活，不许派给他们。**

**定稿：2 人主攻（各开一条线）＋ 2 人辅助（计时/台账/素材），辅助不碰靶机、不做判断。**

| 角色 | 谁 | 职责（都写成可照做的动作） | 明确不做 |
|---|---|---|---|
| **主攻手 1** | 你 | 选题、出命令、判读结果、决定跳/留；对 agent 说人话（用 `IR-PROMPTS.md` 模板） | 不记账、不盯钟 |
| **主攻手 2** | 稍熟练的那位选手 | 独立开**第二条线**；与主攻 1 只在"分诊"和"停开新题"两个锚点对齐；会 vulnclaw 就自己开一个副驾会话 | 不替主攻 1 记录 |
| **辅助 1（管时间与台账）** | 门外汉 | ① **计时**：手机定 9:30/9:40/11:30/11:50/12:20/12:35/15:00 七个闹钟，**每个时间盒走到 80% 喊"还剩 5 分钟"**；② **台账**（一页纸：题号 / flag 原文 / 谁交的 / 几点）**只登记，不代交**；③ 到锚点逐题念"这题交了吗" | 不碰靶机、不判 flag 对不对 |
| **辅助 2（管素材与抄写）** | 门外汉 | ① **截图/存档**：主攻手说"截这张图/存这段输出"就照做（文件名带题号）；② **抄写**：把网页终端/REPL 里的命令**原文照抄**进台账（**只复制，不改写、不总结**）；③ 举手找现场老师（报障） | 不碰靶机、不做判断 |

**给门外汉的三条硬规矩（贴他们屏幕上）**：

1. **只做我让你做的动作**，不要"顺手试试"——尤其**别自己去点网页终端/平台页面**（那是选手操作，
   且规则里"网页终端里的操作始终是本人"，乱点还可能误改环境）。
2. **看到不确定的东西，原样贴出来 / 喊人**，不要自己下判断（"这个应该是漏洞吧"）。
3. **不代提交**：flag 只由**发现者本人**在自己账号提交（见下）。

**⚠️ 4 个账号怎么用**：主攻 1、主攻 2 **各用一个**；剩下两个账号**先不用**（门外汉不操作平台）。
   **两个未分配账号是本次唯一还没用上的资源**——能不能用，取决于现场要确认的**第 8 条**
   （4 个账号能否各做不同的题 / 能否共用一套环境）：
   - 若**各账号能看到同一套题**（大概率）→ 可以试"**门外汉当手**"：主攻手**逐字口述**、门外汉在自己账号的
     控制台里照打（人打字，不是自动化）。**先用在应急段**（命令天生只读、短、可粘贴），
     **渗透段慎用**（打错 IP/打错参数代价高）。
   - 若**四个账号各是一套独立的题** → 那就不是"当手"，而是门外汉各自开最简单的题，
     但**他们做不了判断**，所以实际只能抄题面给你、或在你的逐字指导下操作 —— 收益低，宁可闲置。

**⚠️ flag 谁提交**：**由发现者本人在自己账号上提交**（先交先解链；交完立刻回喊一声）。
   **辅助 1 只做"提交核对"**：台账登记 + 在每个"停开新题"锚点逐题点名"这题交了吗"
   —— 这是防"漏交"的机制，不是替他交。

**分诊并行**：9:30 / 12:20 那 10 分钟，**两位门外汉只做一件事——把题号和分值照抄成表**（不解读）；
**两位主攻**拿着这张表决定先后与分工。**仍然 10 分钟内不许开打。**

**他们真正的价值**：选手最贵的是"脑子"。把**计时、复述、登记、截图、抄命令**全交出去，
主攻手只留"看输出 → 判断 → 下一条命令"。
**别指望他们出主意，也别在他们没准备好时给他们讲背景** —— 他们只需要知道"照着表问、照着我的话做"。

**不管几人的铁律**：**网页终端里的操作始终是人打的**（不做平台 UI 自动化）；
**提交 flag 始终由发现者本人做**；agent 只出命令 / 判读 / 写报告（WP 已不用交，报告仅作赛后复盘）。


### 9.4 计时锚点（抄到手机备忘录上）

```
9:30 开赛   9:40 分诊完   11:30 停开新题   11:50 缓冲
12:20 IR    12:35 分诊完                         15:00 停开新题
15:20 回收完/核对完                            15:30 结束
```

**每题开始前的 60 秒三问**：① 这题几个 flag？② 是不是顺序解锁的（不解锁后面做不了）？③
它比我手上这道更值钱吗？—— 三个答案里只要有一个是"否"，就别换题。
