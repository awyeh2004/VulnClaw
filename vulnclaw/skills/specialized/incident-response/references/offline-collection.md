# 离线取证收集与分诊

> 赛题可能是**多题形式**：一部分是远程实操（给你 SSH，上去排查），
> 一部分是**离线取证**（给你一堆文件/镜像/pcap，让你本地分析）。
> 这篇讲第二种，以及"拿到一个不知道是什么的文件"时该怎么起步。
>
> 内存镜像与流量分析的具体命令在 `50-memory-traffic.md`；这里不重复，只讲
> **收集**和**分诊**。
>
> 标 `[实测]` 的在 2026-09-20 本机验证过。

---

## 〇、拿到证据后第一件事：别急着分析，先固定与登记

⚠️ **离线取证最容易犯的错不是"分析错"，而是"把证据弄坏了或搞混了"。**

```powershell
# 1) 先算哈希并登记 —— 分析前做，不是分析后做
$dir = 'D:\case\evidence'
Get-ChildItem $dir -Recurse -File | ForEach-Object {
  $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
  "{0}`t{1}`t{2}" -f $h, $_.Length, $_.FullName.Replace($dir,'')
} | Out-File "$dir\_MANIFEST-sha256.tsv" -Encoding utf8

# 2) 识别每个文件到底是什么（别信扩展名）
foreach ($f in Get-ChildItem $dir -Recurse -File) {
  "=== $($f.Name) ==="
  & 'D:\GitClone\VulnClaw\VulnClaw\.ir-tools\bin\SysinternalsSuite\sigcheck.exe' -nobanner $f.FullName 2>$null | Select-Object -First 3
}
```

⭐ **为什么先算哈希**：报告里写"我分析了这个文件"必须能证明是**同一个**文件。
赛后抽查时，`_MANIFEST-sha256.tsv` 就是你的证据链起点。

`[实测]` 判类型用系统自带即可（不必装 file）：

```powershell
# 二进制文件的前 16 字节就是最有价值的信息
$b = [System.IO.File]::ReadAllBytes($f.FullName)[0..15]
($b | ForEach-Object { $_.ToString('x2') }) -join ' '
```

常见魔术字节对照：

| 开头 | 是什么 |
|---|---|
| `4d 5a` (MZ) | Windows PE（exe/dll/sys） |
| `7f 45 4c 46` (ELF) | Linux 可执行 |
| `50 4b 03 04` (PK) | zip/jar/docx/apk |
| `1f 8b` | gzip |
| `d4 c3 b2 a1` / `a1 b2 c3 d4` | **pcap**（两种字节序） |
| `0a 0d 0d 0a` | **pcapng**（新版抓包格式） |
| `45 4c 46` 前的 `50 41 43 4b` | 内存镜像常见（LiME/AVML 之类） |

---

## 一、⭐ 分诊决策树：先判断题型，再选工具

```
拿到证据文件
   │
   ├─ 是 pcap/pcapng？ ──────> 50-memory-traffic.md 第三节
   │                            （tshark 5 条命令先跑一遍，成本极低）
   │
   ├─ 是内存镜像（几 GB、无文件系统结构）？
   │      │
   │      ├─ Windows 镜像 ──> vol + 符号（msdl 国内直连可达 [实测]）
   │      │                    先 `vol -f <img> banners` 拿到 PDB 键
   │      └─ Linux 镜像 ────> ⚠️ 需要该内核的 ISF，本机没有
   │                            能拿到目标内核就先生成，否则承认做不了
   │
   ├─ 是磁盘镜像/目录快照？ ──> 当"一台机器的文件系统"排查
   │                            用 10/20/25/30/40 那几篇的检查点逐个过
   │
   ├─ 是单个可疑文件？ ─────> YARA + strings + 哈希情报
   │
   └─ 是日志文件？ ────────> 40-log-analysis.md
                              + LogParser（Windows 日志）或用 Python 解析
```

---

## 二、⭐ 从目标机器批量采集（远程实操的收尾动作）

**如果题目同时给了远程访问，最省事的路线是：先在目标上跑一次批量采集，
把现场固化成本地文件，再慢慢分析。** 理由：
- 目标可能随时被重启/回收，现场只存在一次
- 本地分析不受目标算力限制
- 采到的原始文件可以反复复核（赛后抽查要的就是这个）

### 2.1 用工具一键采集（推荐）

agent 有 `remote_collect` 工具，对已配置的主机跑 33 段只读采集并打包回来：

```
remote_hosts                     # 先看有哪些主机别名
remote_collect host=victim1      # 采集 + 拉回本地 + 自动解包
```

采集内容（33 段，覆盖 `references/` 各篇的检查点）：
账号/sudoers/authorized_keys、进程/`/proc/*/exe`/命令行/环境变量、
socket 与网络连接、内核模块与 syscall 表、**cron 全部位置**、
systemd、启动项、`ld.so.preload`、历史命令、Web 根目录与上传目录、
隐藏 dotfile、SUID/SGID 与 capabilities、世界可写目录、
**已删除但仍被占用的可执行**、近 14 天改动文件、系统与 Web 日志、
网络配置与防火墙、软件包、sshd 配置、容器痕迹、**反取证线索**。

> ⭐ 采集全部命令是**一次性整体审批**的，审批界面会列出每条命令 ——
> 这是刻意的：逐条批准 33 次会把人训练成无脑点同意。

### 2.2 手工采集（没有工具时）

`remote_collect` 的采集脚本本身就是一份可读的清单。核心几条手工版：

```bash
# 现场固化：把关键目录打包（⚠️ 不要打包整个 /）
tar czf /tmp/ir-$(date +%s).tar.gz \
  /var/log /var/www /etc/passwd /etc/shadow /etc/group /etc/crontab \
  /etc/cron.d /var/spool/cron /etc/systemd/system /etc/ld.so.preload \
  /root/.bash_history /tmp 2>/dev/null
# 然后本地用 remote_fetch 拉回来
```

⚠️ **三个坑**：
1. **别打包 `/tmp` 到 `/tmp` 里**（自我递归，包会越打越大）
2. **先删掉你自己的采集脚本**，否则会被当成"攻击者留下的"（演练时真踩过）
3. **镜像文件用 `remote_fetch`（SFTP）而不是 base64** —— 几 GB 走 stdout 不现实

### 2.3 ⚠️ `[实测]` 采集脚本留在靶机上 = 污染证据

演练时踩到的真实教训：采集/setup 脚本拷进目标 `/tmp` 后忘记删除，
之后**它出现在"近期改动文件"和"隐藏文件"清单里**，
agent 无法区分"这是攻击者的"还是"这是分析员自己的"。

**采完立刻清掉自己的脚本**，或者在报告里明确标注哪些文件是分析工具产生的。

---

## 三、单文件分诊：YARA + strings

### 3.1 YARA（工具箱已带，`[实测]` 可用）

```powershell
. .ir-tools\env.ps1
cd .ir-tools\pylib
python -c @"
import yara
rules = yara.compile(source='rule r { strings: \$a = \"eval\" condition: \$a }')
print(rules.match(r'D:\case\evidence\suspicious.php'))
"@
```

> ⭐ 实战更有用的是**自写规则扫一批文件**：把 IOC（域名、路径、函数名）
> 写成规则，一次扫完整个证据目录。比逐个 `grep` 快且不漏二进制。

### 3.2 strings（Sysinternals，比 `strings.exe` GNU 版更顺手）

```powershell
# 提取可打印字符串
& .ir-tools\bin\SysinternalsSuite\strings.exe -n 8 -accepteula suspicious.bin | Select-Object -First 60

# ⭐ -n 8 起：短于 8 字符的基本是噪音
```

`[实测]` **从可疑文件里找 IOC 的优先顺序**：

| 顺序 | 找什么 | 为什么 |
|---|---|---|
| 1 | **URL / IP** | 直接给出 C2 |
| 2 | **文件路径**（`/etc/`、`C:\`） | 暴露持久化手法 |
| 3 | **命令/解释器**（`sh -c`、`cmd /c`、`base64`） | 暴露执行链 |
| 4 | **API 名串**（`VirtualAllocEx`、`CreateRemoteThread`） | 暴露技术手法 |
| 5 | **base64 长串** | 载荷编码 |
| 6 | **编译器/工具链痕迹**（Go、PyInstaller、UPX） | 判断生成方式 |

---

## 四、Windows 日志离线分析：LogParser

`[实测]` **LogParser 2.2 已装在 `E:\LogParser`**，`env.ps1` 会加进 PATH。
它的价值是**用 SQL 语法查 EVTX/CSV/IIS 日志**，比 PowerShell `Get-WinEvent` 写起来快：

```powershell
# 安全日志里的事件 ID 统计（找爆破、账号变更）
LogParser.exe -i:EVT -o:CSV "SELECT EventID, COUNT(*) AS n FROM Security GROUP BY EventID ORDER BY n DESC" -o:D:\case\out.csv

# ⭐ 登录失败来源 IP Top（4625）
LogParser.exe -i:EVT "SELECT TOP 20 EXTRACT_TOKEN(Strings,19,'|') AS User, EXTRACT_TOKEN(Strings,20,'|') AS SrcIP, COUNT(*) AS n FROM Security WHERE EventID=4625 GROUP BY User,SrcIP ORDER BY n DESC"
```

> 事件 ID 语义见 `40-log-analysis.md`（4624 登录成功 / 4625 登录失败 /
> 4720 建号 / 4728 加入特权组 / 1102 日志被清 …）。

⚠️ **`-i:EVT` 只支持老式 `.evt`**；`.evtx` 需要先用
`wevtutil epl` 或 NirSoft 的 `FullEventLogView`（工具箱里有）导出。

---

## 五、报告写法：离线证据的表述纪律

离线证据**可复现性强**（同一文件反复算哈希都一样），所以表述要更硬：

| 该说 | 不该说 |
|---|---|
| "文件 X（sha256 前 16 位 `abc…`）第 38-39 行包含…" | "我怀疑这个文件有后门" |
| "`access.log` 09:22:51 有一条 200" | "攻击者在这个时间成功了"（若没交叉验证） |
| "[观测] `ls -la` 输出含 `.cache_update.sh`" | "[观测] 这是隐藏的下载器"（恶意性属推断） |
| "[推断] 该脚本经 base64 解码后执行 `sh`" | "[观测] 它执行了远端载荷"（没跑过就不是观测） |

⚠️ **离线证据最容易越界的地方**：把一个**没执行过**的样本描述成
"它下载并执行了 X"。没跑就是没观测到 —— 只能说"代码显示它具备这种能力"。

`SKILL.md` 的两条铁律在这里同样适用：
**路径证据纪律**（观测到什么就写什么，不补全前缀）、
**证据类型标注**（`[观测]`/`[推断]`/`[知识]`）。

---

## 六、速查

```powershell
# 证据登记（分析前）
Get-ChildItem $dir -Recurse -File | % { (Get-FileHash $_ -Algorithm SHA256).Hash + "`t" + $_.Name }

# 编排顺序（用 agent 时）
remote_hosts                  # 看有哪些主机
remote_collect host=victim1   # 现场固化 + 拉回本地
# 然后本地: evidence_list / yara / tshark / vol / LogParser

# pcap -> 50-memory-traffic.md 第三节
# 内存 -> 50-memory-traffic.md 第二节
# 日志 -> 40-log-analysis.md
# 文件痕迹 -> 30-file-artifacts.md
```
