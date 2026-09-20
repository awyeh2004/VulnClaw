# 文件痕迹排查

大部分恶意软件、木马、后门都会在**文件维度**留下痕迹。三条排查路径：

1. **敏感目录**——恶意软件常驻路径
2. **时间点**——确定事件时间后，排查该时间点前后的文件变动
3. **特征**——代码关键字/关键函数、文件权限特征

> ⭐ 这一篇是"找被植入了什么"的正面回答，也是**应对免杀马**的关键。

---

## 一、敏感目录

### Windows

| 位置 | 说明 |
|---|---|
| **各盘 `temp` / `tmp`** | ⭐ 恶意程序释放**子体**（运行时投放的文件）默认落点——程序里写死的路径通常是临时目录 |
| **浏览器历史 / 下载文件 / Cookie** | 人工入侵事件：攻击者会下载后续攻击工具 |
| **`Recent`** | 最近运行文件的快捷方式 |
| **`Prefetch`** | ⭐ 预读取信息（执行历史） |
| **`Amcache.hve`** | ⭐ 应用程序执行路径 + 上次执行时间 + **SHA1** |

```cmd
:: Recent（最近运行文件）
%UserProfile%\Recent
:: 旧系统: C:\Documents and Settings\<用户名>\Recent

:: Prefetch
%SystemRoot%\Prefetch\
explorer %SystemRoot%\Prefetch\

:: Amcache（在 regedit 里加载为 hive 文件，或用 EZ Tools 解析）
%SystemRoot%\appcompat\Programs\Amcache.hve

:: 系统临时目录
C:\Windows\Temp
C:\Users\<用户>\AppData\Local\Temp
```

**Prefetch 容量**（考点）：Win7 记录最近 **128** 个可执行文件，Win8–Win10 记录最近 **1024** 个。

**判据**：

- **非 `System32` / `Syswow64` 目录下的 `svchost.exe` 基本为恶意文件**
- 命名特殊的文件重点排查（真实案例：`m.ps1`、`mkatz.ini`、`schost.exe` 仿冒 `svchost.exe`）

### Linux

| 位置 | 说明 |
|---|---|
| **`/tmp`、`/var/tmp`、`/dev/shm`** | ⭐ 恶意软件下载与释放的主要目录 |
| **`/usr/bin`、`/usr/sbin`** | ⭐ **系统命令被替换**的目录 |
| **`~/.ssh`、`/etc/ssh`** | 后门配置路径（`authorized_keys`） |
| `/etc/rc.d`、`/etc/cron*` | 自启动与定时任务（见 `10-system-basics.md`） |

```bash
ls -alh /tmp                    # 注意隐藏文件（. 开头）
ls -al /root/.ssh/              # 查看是否有非已知 ssh 公钥
```

真实案例：`/tmp` 下发现 `.beacon` 恶意文件；`/root/.ssh/` 里发现攻击者在 kali 主机上生成的公钥。

---

## 二、时间点排查

**先确定事件时间点（恶意文件的创建时间）→ 圈出该时间点前后的文件变动 → 大幅缩小范围。**

### Windows

```cmd
:: 查找指定日期之后创建的 exe
forfiles /m *.exe /d +2020/2/12 /s /p c:\ /c "cmd /c echo @path @fdate @ftime" 2>nul

:: 按修改日期排序找可疑文件
dir /od /s /a

:: 资源管理器按「修改日期」排序
```

**⚠️ 判据：时间逻辑错误 = 恶意文件**

> 攻击者会用"菜刀类"工具**改变文件修改时间**以规避排查。
> **文件的修改时间为 2015 年、创建时间为 2017 年** —— 存在明显逻辑问题，极可能为恶意文件。

这是**答案型判据**：题目问"哪个文件是恶意的，依据是什么"时，直接答"修改时间早于创建时间"。

### Linux

```bash
# find 常用参数
-type b/d/c/p/l/f     # 块设备/目录/字符设备/管道/符号链接/普通文件
-mtime -n +n          # 修改时间：-n = n 天以内，+n = n 天前
-atime -n +n          # 访问时间
-ctime -n +n          # 创建/状态变更时间

# 一天内新增的 sh 文件
find / -ctime 0 -name "*.sh"

# 一天前访问过的文件
find /opt -iname "*" -atime 1 -type f

# 按时间排序看最近变动的文件
ls -alt | head -n 10
ls -alt /bin

# 详细时间（三个时间）
stat commandi.php
stat /etc/passwd
```

**`stat` 的三个时间**（考点）：

| 字段 | 含义 |
|---|---|
| `Access` | 访问时间 |
| `Modify` | **内容**修改时间 |
| `Change` | **属性**（元数据/inode）变更时间 |

> **重点看 Modify 和 Change**：两者可判断是否存在系统文件被修改或系统命令被替换。

---

## 三、特殊权限与特殊文件

### Linux

```bash
# ⭐ SUID 程序排查（攻击者用它留后门提权）
find / -type f -perm -04000 -ls -uid 0 2>/dev/null

# 其他 SUID/SGID 写法
find . -perm /4000        # SUID
find . -perm /2000        # SGID
find /tmp -perm 777       # 777 权限文件

# ⭐ 不可变文件（chattr +i）——root 都删不掉
lsattr <filename>
chattr -i <filename>      # 取消 i 属性后才能删
chattr +i evil.php        # 攻击者加锁
```

**攻击者 SUID 后门手法**（对照判读）：

```bash
cp /bin/bash /tmp/shell
chmod u+s /tmp/shell
# 之后用普通用户执行 /tmp/shell -p 即得 root shell
```

### Windows

```cmd
:: 文件属性
attrib <file>
:: 查看 ADS（备用数据流，隐藏内容）
dir /r
```

---

## 四、系统命令是否被替换（Rootkit / 后门）

**`ls`、`ps`、`netstat` 等命令很可能被攻击者替换**以隐藏行踪。

```bash
# ① 看修改时间
ls -alt /bin
ls -alt /usr/bin

# ② 看文件大小（明显偏大 = 很可能被替换）
ls -alh /bin
ls -alh /usr/sbin

# ③ ⭐ 包完整性校验（最可靠）
rpm -Va > rpm.log
```

**`rpm -Va` 输出格式**（8 位标志，`. ` = 通过）：

| 标志 | 含义 |
|---|---|
| `S` | 文件**大小**是否改变 |
| `M` | 文件**类型或权限**（rwx）是否改变 |
| `5` | 文件 **MD5** 校验是否改变（= 内容改变） |
| `D` | 设备中从代码是否改变 |
| `L` | 文件**路径**是否改变 |
| `U` | 文件**属主**是否改变 |
| `G` | 文件**属组**是否改变 |
| `T` | 文件**修改时间**是否改变 |

**一切正常则不产生任何输出。**

**若命令被替换，从 RPM 包还原**：

```bash
rpm -qf /bin/ls                              # 查 ls 属于哪个包
mv /bin/ls /tmp                              # 移走被替换的（造成丢失假象）
rpm2cpio /mnt/cdrom/Packages/coreutils-8.4-19.el6.i686.rpm | cpio -idv ./bin/ls
cp /root/bin/ls /bin/                        # 还原
```

**Rootkit 专用工具**：

```bash
chkrootkit                  # 出现 INFECTED 即检测出后门
chkrootkit -q | grep INFECTED
rkhunter -c                 # 系统命令 MD5 校验、rootkit 检测、敏感目录、配置、服务套件、第三方版本
```

> ⚠️ 用前**更新到最新版本**，否则漏报。

**隐藏进程/模块的主机侧检查**：

```bash
# 隐藏内核模块：/proc/modules 与 lsmod 交叉对比
cat /proc/modules | wc -l ; lsmod | wc -l

# ⭐ LD_PRELOAD 劫持（ps/top 都看不到进程）
cat /etc/ld.so.preload
# 攻击者手法：
#   cp libprocesshider.so /usr/local/lib/
#   echo /usr/local/lib/libprocesshider.so >> /etc/ld.so.preload
# 此时 CPU 满但 top/ps 找不到占用者 —— 用 unhide 查
unhide proc
```

---

## 五、⭐ 文件完整性校验（应对免杀 Webshell 的正解）

**核心矛盾**：一个**免杀的** Webshell 藏在数以万行的代码中，特征库扫不出来，手工也看不完。即使 99.9% 检出率的引擎也会漏。

**正解：与纯净源码做 hash 比对**，输出**新增 / 修改 / 删除**的文件列表。

**前提**：团队有代码版本管理，或你备份过原始代码。

### 方法一：MD5 校验

```python
def md5sum(file):
    m = hashlib.md5()
    if os.path.isfile(file):
        f = open(file, 'rb')
        for line in f:
            m.update(line)
        f.close
    else:
        m.update(file)
    return (m.hexdigest())
```

**流程**：纯净源码算一次 hash 存库 → 应急时对部署目录再算一次 → 比对。

真实案例输出：

```
可能被删除的文件有:
新增的文件有:    hackable/uploads/evil.php
可能被篡改的文件有: vulnerabilities/source/low.php
```

→ 再对 `low.php` 做 diff，发现被插入了一句话 `@eval($_POST['g']);`

### 方法二：`diff` 命令（一条命令搞定）

```bash
diff -c -a -r cms1 cms2
# -c 上下文格式  -a 按文本比较  -r 递归目录
# 只看是否不同、不看差异内容：加 -q
```

输出直接指出 `low.php` 被篡改，篡改内容是 `@eval($_POST['g']);`

### 方法三：版本控制

```bash
git add -A && git commit -m "post-incident" && git push
# 在 commits 历史里看文件改动
git diff <干净版本> <当前版本>
```

### 方法四：图形对比工具

**Beyond Compare** / **WinMerge** —— 文件夹比较，紫色 = 新增，红色 = 被篡改。

### 方法五：Webshell 关键字初筛（缩小范围用）

```bash
find /var/www/ -name "*.php" | xargs egrep -l 'eval|assert|base64_decode|system|exec|shell_exec|passthru|preg_replace.*\/e'
```

**常见关键字**：`eval`、`assert`、`base64_decode`、`system`、`exec`、`shell_exec`、`passthru`、`call_user_func`、`$_POST`、`$_REQUEST`、`preg_replace`(`/e`)

> ⚠️ 关键字初筛**误报率高**（正常框架也大量用这些函数）。它的作用是**缩小范围**，最终判定要靠源码 diff 或人工审读。

**工具**：D盾、HwsKill（河马）、WebShellKill、findWebshell、Scan_Webshell.py

---

## 六、网页篡改与暗链的特殊位置

| 手法 | 位置 |
|---|---|
| 首页被篡改 | 首页文件、图片（真实案例：PS 替换图片后上传） |
| 挂黑页（隐藏文件夹） | Windows 隐藏属性 + **IIS 临时压缩缓存**残留 |
| 隐藏目录型包含 | `index.php` 里 `include` 指向**非脚本后缀**的隐藏文件 |
| Nginx 反代劫持 | **`nginx.conf` / `VirtualHost.conf`** 里的 `proxy_pass` 规则 |
| 移动端/搜索引擎劫持 | 页面里的第三方 JS（按 UA / Referer 判断跳转） |

```cmd
:: 批量挂黑页的残留（真实案例路径）
C:\inetpub\temp\IIS Temporary Compressed Files\WEBUI\$^_gzip_D^\WEB\WEBUI\UPLOAD
:: 文件删了链接还能访问 → 就是这个缓存在兜底
```

```php
// 隐藏目录 + 非脚本后缀（真实案例）
include('/tmp/.ICE-unix/../c.jpg');   // c.jpg 实际是攻击者的劫持程序
```

**判据**：`include`/`require` 的目标**后缀不是 .php**、或路径含 `/tmp/`、`/.xxx/` ⇒ 高度可疑。

---

## 七、常见问法与答法

| 问 | 答什么 |
|---|---|
| 恶意文件路径/文件名 | 命令输出中的完整路径 |
| 什么时候被植入的 | 文件创建时间（注意与日志时区对齐） |
| 依据是什么 | 创建时间 / 时间逻辑错误（改早于建）/ hash 与纯净源码不一致 / 关键字命中 |
| 被篡改了哪些文件 | 完整性校验输出的新增+修改列表 |
| 有没有被替换的系统命令 | `rpm -Va` 输出 / `ls -alh /bin` 大小异常 |
| 有没有隐藏文件 | `ls -al` / `find -name ".*"` / Windows 隐藏属性 |

---

## 相关文档

- `10-system-basics.md` — 自启动与定时任务中的文件
- `25-process-service.md` — 从进程反查文件
- `40-log-analysis.md` — 用文件时间锚定日志时间窗
- `events/webshell.md` — Webshell 专项排查
- `events/ransomware.md` — 勒索病毒的文件特征
