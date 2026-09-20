# 账号排查

攻击者建立账号通常用三种手法：**直接新建**（有时仿冒系统常用名）、**激活不常使用的系统默认账户**、**建立隐藏账户**。无论哪种，后续都会提权到管理员再用它控制主机。

**账号类问题是应急响应最高频的答题点**：要用户名、要 UID、要创建时间、要判定哪个是后门。

---

## Windows

### 四法交叉，单用任何一个都会漏

#### ① `net user`（会漏隐藏账号）

```cmd
net user                    :: 列出所有账户
net user <username>         :: 看单个账户详情（上次登录、本地组成员资格）
```

> ⚠️ **`net user` 看不到以 `$` 结尾的隐藏账户**。这是最常见的失手点——只用 `net user` 会得出"没有异常账户"的错误结论。

#### ② `lusrmgr.msc` / 计算机管理（能看到隐藏账号）

```cmd
lusrmgr.msc
:: 或：计算机管理 → 本地用户和组 → 用户
```

名称**以 `$` 结尾**的即为隐藏账户（如 `admin$`、`shadow$`）。

#### ③ 注册表 SAM（**唯一能查克隆账号的方法**）

```cmd
regedit
:: 定位 HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users
```

SAM 默认无读取权限，需先放权：

1. 右键 `SAM` → 权限 → 高级 → 勾选
   - 「允许父项的继承权限传播到该对象和所有子对象」
   - 「用在此显示的可以应用到子对象的项目替代所有子对象的权限项目」
2. 使当前用户获得 SAM 读取权限
3. 按 `F5` 刷新，即可展开子项

**克隆账号检测原理**：`Users` 下每个以 `00000` 开头的项对应一个账户，其 `F` 值（`V` 结构里的权限/组成员信息）应当唯一。

```cmd
:: 逐个导出所有 00000* 项，与 000001F4（Administrator 固定 RID 500）的 F 值比对
:: F 值相同 ⇒ 克隆账号
```

`000001F4` = Administrator（RID 500）。**任何其他账户的 F 值与它相同，就是克隆账号**——该账户在用户管理界面看起来是普通用户，实际已有管理员权限。

#### ④ `wmic`（拿 SID，便于横向比对）

```cmd
wmic useraccount get name,sid
```

SID 以 `-500` 结尾的是 Administrator。出现非预期账户、或 SID 规律异常（如 **RID 小于 1000 的非系统账户**）都值得关注。

### 辅助工具

- **D盾** 集成克隆账号检测（《指南》第 6 章点名）
- **LP_Check** 直接扫克隆账号（挖矿章节用它查出 `admin$`）

### 答题时通常要给

账户名 / SID / **创建时间**（→ `40-log-analysis.md` 事件 ID **4720**）/ 是否在 Administrators 组（**4732**）/ 是否克隆（F 值）。

---

## Linux

### 五个必查项

```bash
# ① UID=0 的特权账户（正常情况下只有 root）
awk -F: '{if($3==0)print $1}' /etc/passwd

# ② 可登录的账户（有 shell 的）
cat /etc/passwd | grep -v "nologin" | grep -v "false"
# 或只看 bash： cat /etc/passwd | grep '/bin/bash'

# ③ 空口令账户（shadow 第二字段为空）
awk -F: 'length($2)==0 {print $1}' /etc/shadow

# ④ 除 root 外还有谁有 sudo 权限
more /etc/sudoers | grep -v "^#\|^$" | grep "ALL=(ALL)"

# ⑤ 近期新增/变动的账户
grep "useradd" /var/log/secure
grep "userdel" /var/log/secure
```

`/etc/passwd` 字段含义：

```
root:x:0:0:root:/root:/bin/bash
用户名:密码占位:UID:GID:说明:家目录:登录shell
```

- 第二字段为 `x` = 密码在 `/etc/shadow`；**为空则该账户可能无密码**
- `/etc/shadow` 第二栏以 `!` 开头 = 已锁定（`usermod -L` 的效果）

### 判读要点

- **UID=0 的账户除 root 外一律重点排查**
- **例外**：FreeBSD 默认有 `toor`（UID=0，官方定义为 root 替代用户），属可信
- 隐藏文件手法对账号无效——`/etc/passwd` 里的账户用 `cat` 一眼可见，**Linux 侧的重点是"多出来的那个"而非"藏起来的那个"**

### 处置命令

```bash
usermod -L <user>       # 锁定账户（shadow 第二栏变 ! 开头）
userdel <user>          # 删除账户
userdel -r <user>       # 删除账户及家目录
```

### 攻击者加账号的手法（对照理解，用于判读痕迹）

```bash
# 一句话加普通用户
useradd guest; echo 'guest:123456' | chpasswd
useradd -p "$(openssl passwd -1 123456)" guest

# 加 root 账户（-o -u 0 是关键字：允许重复 UID 且指定 0）
useradd -p `openssl passwd -1 -salt 'salt' 123456` guest -o -u 0 -g root -G root -s /bin/bash -d /home/test
```

> **判读信号**：看到 `useradd` 带 `-o -u 0` 就是明确的提权后门；`/var/log/secure` 里这条命令的时间就是账户创建时间。

---

## 时间线取证

账号相关日志（Linux）：

```bash
# 新增用户（含 UID/GID/家目录/shell 全字段）
grep "useradd" /var/log/secure
# 输出样例：
# Jul 10 00:12:15 localhost useradd[2382]: new user: name=kali, UID=1001, GID=1001,
#                                     home=/home/kali, shell=/bin/bash
# Jul 10 00:12:58 localhost passwd: pam_unix(passwd:chauthtok): password changed for kali

# 删除用户
grep "userdel" /var/log/secure

# su 切换
# Jul 10 00:38:13 localhost su: pam_unix(su-l:session): session opened for user good by root(uid=0)

# sudo 授权执行
sudo -l
# Jul 10 00:43:09 localhost sudo: good : TTY=pts/4 ; PWD=/home/good ; USER=root ;
#                            COMMAND=/sbin/shutdown -r now
```

Windows 对应的安全日志事件 ID：**4720**（创建用户）、**4722**（启用）、**4724**（重置密码）、**4726**（删除）、**4728/4732**（加入全局组/本地组）。见 `40-log-analysis.md`。

---

## 常见问法与答法

| 问 | 答什么 |
|---|---|
| 攻击者新建的账号名？ | 账户名 + 依据（`net user` / `lusrmgr` / `awk -F: '$3==0'` 输出） |
| 哪个账号是克隆的？ | 账户名 + **F 值与 `000001F4` 相同**这个依据 |
| 账号创建时间？ | Windows 看 4720 事件时间；Linux 看 `/var/log/secure` 的 `useradd` 行时间 |
| 该账号是否管理员？ | Windows 看是否在 Administrators（4732）或 F 值判定；Linux 看 UID 是否 0 或 sudoers |
| 有几个后门账号？ | 全部列出，别只报一个 |

---

## 相关文档

- `40-log-analysis.md` — 账号相关事件 ID 与日志命令
- `30-file-artifacts.md` — 家目录、`~/.ssh`、`.bash_history` 等账号关联痕迹
- `events/cryptomining.md` — `k8h3d` 类挖矿蠕虫后门账户实例
