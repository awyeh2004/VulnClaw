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

## 五、⚠️ 赛前必须处理的合规风险

通知七(三)：**严禁攻击竞赛平台、赛事系统及第三方服务**；七(六)：**非有效登录/非有效操作视为弃赛**。

**现状**：项目只有 `_validate_command_url_scope`（只校验命令字符串里的 URL），
**拦不住裸 IP、SSH、nmap**，也没有域名/IP 黑名单。

**在明确赛场网络配置之前无法完成实现**，但赛前必须做的是：

1. **确认靶场网段**（问赛方 / 看现场说明）→ 写进 scope 白名单
2. **确认计分平台地址** → 硬性加入黑名单，**绝不让 agent 碰**
3. **`submit_flag` 类工具切人工确认**（或直接不启用），避免"非有效操作"
4. **保留完整操作记录**（赛后可能抽查答题思路）：已有的 `log.txt` + Solve Report 够用

> 这四条是**资格问题，不是分数问题**。

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
