# Playbook 手贴短清单 · 2026-10-11 天津（渗透 + 应急响应）

> 用途：`~/.vulnclaw/playbooks/` 里有 311 篇笔记，但**副驾模式（单轮 chat）不会自动注入**
> （`solver.py:2271` 的 `_inject_prior_playbooks` 只在 solve 循环里跑；实测自动注入还会拿
> 高分噪声笔记，见 `IR-PROMPTS.md` §0.3）。所以要复用就得**手动贴**。
> 这张卡把那 311 篇里**贴合本赛两段赛制**的挑出来，按"看到什么 → 贴哪篇"组织。
>
> 挑法：先剔掉 117 篇 `AutoNotes <hash>` / `ctf2:practice:<uuid>` 自动噪声（名字里带
> 实例哈希、内容是某次运行的原始记录，无复用价值），余下 194 篇手工/整理笔记里按
> 场景相关性打分。**每篇文件路径都是 `~/.vulnclaw/playbooks/<文件名>`。**

---

## 0. 怎么用（30 秒）

```powershell
# 列与当前题目关键词相关的笔记（按文件名粗筛）
ls ~\.vulnclaw\playbooks\*upload*,~\\.vulnclaw\\playbooks\\*ssti*
```

副驾会话里说的话（照抄，把 `<关键词>` 换掉）：

```
补充：本机 ~/.vulnclaw/playbooks 里有历史同类题解法。请先用 lookup_playbook 查
"<关键词>" 这个类别的笔记，再结合我贴的输出给下一条命令。
```

> ⚠️ 两条纪律（都是实测）：
> ① **别整篇贴进去**——一篇 2–5 KB，贴三篇就把提示词撑爆，且会把无关细节当约束。
>    只贴 `STEPS`/`ANGLES` 里当下用得上的那几行。
> ② **历史 flag 一律作废**：笔记里记的 `CTF2{…}` / `flag{…}` 是**别的实例**的，只学手法，
>    不复用答案（`helpdesk-legacy-v1-idor` 那类笔记自己就写着"不得复用历史 flag"）。

---

## 1. 应急响应段（12:20–15:30）—— 本段最赚，笔记最对口

| # | 什么时候贴 | 贴哪篇 | 关键手法 |
|---|---|---|---|
| IR-1 | **开场就贴**（通用排查清单，10 场演练浓缩） | `ir-triage-checklist-ten-drills.md` | 十条排查面逐条过：轮转日志 → 进程名会撒谎 → 持久化六面 → 隐藏账号锚 uid → 劫持四层 → 外带三证据 → 备份源 → 勒索密钥残留 |
| IR-2 | 题目是**勒索**（`*.locked` / `*.crypt3d` / `README_RESTORE.txt`） | `ir-drill-linux-ransomware-openssl-aes-256-cbc.md`<br>`linux-ransomware-ir-drill-crypt3d-3des-re-encryp.md` | 算法从 `enc.sh` 判定（`openssl enc -aes-256-cbc -salt` / `-des3`）→ 密钥残留 `/tmp/.x/.key`、`/var/tmp/.ssl_cache/.session_key` → **先备份密钥再解密**；隐藏 uid0 账号 `sysupdate` / `systemd-coredump` |
| IR-3 | 题目是**挖矿**（CPU 100%） | `ir-drill-linux-cryptomining-ssh-brute-force-syst.md` | `ps aux --sort=-%cpu \| head` → `/usr/local/bin/.system_cache_d` → `cat` 出矿池 `pool.minexmr.com:4444` → 持久化在 systemd 单元 + `multi-user.target.wants` 软链 |
| IR-4 | 题目是**外带/泄露**（问"泄露了多少文件"） | `ir-drill-internal-data-exfiltration-curl-upload.md` | `.bash_history` 还原动作链 → `/var/tmp/.media_index/` 隐藏归档 → `tar -tzvf` **数文件数**作答 → `.upload.log` 给外带时间与目标 |
| IR-5 | 题目是**webshell 上传 + crontab** | `autonotes-127-0-0-1-2222.md` | 六问格式（路径/IP/时间/漏洞行/持久化/清除）；`ls -al` 才看得见点开头隐藏马 |
| IR-6 | 题目是**SSH 爆破 + systemd 挖矿**（七问） | `autonotes-127-0-0-1-2223.md` | 同上，答七问 |
| IR-7 | 给了 **pcap**（流量分析） | `godzilla-webshell-pcap-rsa-fermat-shadow.md`<br>`autonotes-4a1c33e4ebf3929c71df9c599ae7c5bdf0d2ae.md`<br>`webshell-pcap-encrypted-rar5-del-as-backspace-pa.md` | 哥斯拉改版：RSA Fermat 分解 → 会话密钥 `md5($p)[:16]` → AES-CBC 零 IV → `cat /etc/shadow` 响应 → 爆破 root → **flag = md5(root密码)**；RAR 题注意 `0x7f` 当退格 |
| IR-8 | 给了 **Windows 内存镜像 / 离线表格** | `ir-ram-snapshot-masquerade-pid-token-triage-console.md` | pslist 找**路径不对的伪装进程**，cmdline(PEB) 表给真身与 token；提交要带 `sync=` 前缀 |
| IR-9 | 取证含 **Firefox / 浏览器凭据** | `firefox-forensics-key4-db-logins-json.md` | `key4.db` 解主密钥 → 3DES 解 `logins.json` |
| IR-10 | **流量劫持**（DNS/hosts 被改） | `ir-triage-checklist-ten-drills.md`（第 7 条）`dns-tunnel-exfiltration.md` | 四层：`/etc/hosts` → `resolv.conf` → `iptables -t nat -L` → `/etc/profile.d` + `http_proxy` |

> 应急段的**答题纪律**（`ir-triage-checklist` 末尾）：每题一张卡（`Q<n>:` 开头），
> evidence 引靶机**原样输出**，answer 写结论不写过程，全部落卡后自检卡数=题数。

---

## 2. 渗透段（9:30–12:00）—— 按"打点入口"选

### 2.1 一看到就先试的手工三连（不需笔记）

`?id=1'` 报错 / `?file=../../../../etc/passwd` / `?ip=127.0.0.1;id` —— 见 `IR-PENTEST-CARD.md`。
命中后**再按下面的指纹贴对应笔记**。

### 2.2 上传点（最高频，三篇互补）

| 指纹 | 贴哪篇 | 绕过判据 |
|---|---|---|
| 只有**前端 JS 白名单**（`.jpg\|.png\|.gif`） | `actf2020-upload.md` | 直接抓包改名 `.phtml`；或 `.PHp` 混合大小写 |
| 服务端**黑名单**（`php/php3/php4/php5/pht`）+ 查 `<?` 内容 | `geek2019-upload.md` | `.phtml` 放行；内容用 `<script language="php">` 避开 `<?` |
| 黑名单查 `php` 子串、`phtml` 不含它 | 任意上传篇 | **`.phtml`** 常是通解；Apache 配了 `AddType` 就执行 |
| 能传 `.htaccess` | `enterprise-cms-upload-htaccess-addtype-rce.md` | 传 `AddType application/x-httpd-php .txt` 再传 `cc.txt` |
| 上传要**竞态**（flag 在会被删的文件里） | `unlink-race-upload-file-php-flag-in-testfile-txt.md` | 10–16 线程猛 GET `/testfile.txt` 撞 200 |

### 2.3 注入 / 包含 / 模板

| 指纹 | 贴哪篇 | 要点 |
|---|---|---|
| PHP `include $_GET['file']` 无过滤 | `buu-lfi-course-1-php-include-arbitrary-file-read.md` | `?file=/flag` 直接读；或 `php://filter/...` |
| `?lang=` 进 include（ThinkPHP） | `thinkphp-6-multi-language-lfi-rce-lang-pearcmd.md` | pearcmd `config-create` 写马到 `/tmp/shell.php` |
| 登录页 + WAF 提示 | `waf-sqli-login-bypass-family.md` | **`admin'-- -`** 通常就够（403 只是 WAF 默认签名）；不够再 `Content-Encoding: gzip` |
| `?query=` 回显数组（SUCTF 类） | `suctf2019-easysql.md` | `*,1` 让结果集带上 flag 列 |
| **Jinja2 SSTI**（`{{7*7}}` → 49） | `n1book-flask-ssti-password-param-rce-arbitrary-f.md`（无过滤）<br>`flask-jinja2-ssti-blacklist-bypass-via-dict-frag.md`（有黑名单）<br>`ezssti-jinja2-ssti-blacklist-bypass.md` | 无过滤直接 `lipsum.__globals__['os'].popen(...)`；有黑名单用 `(dict(gl=1)\|first)` 拆词 + `truncate` 造下划线 |
| `?ip=` → `ping`（命令注入） | `gxyctf2019-ping-ping-ping.md` | `;id` / `\|id`；`&&` 常被挡 |
| PHP 反序列化 / 对象注入 | `geek2019php-2019-php.md` | `__wakeup` 用 **CVE-2016-7124**（改属性个数）绕过 |
| Python/Node 沙箱逃逸 | `coderunner-python-sandbox-escape-filter-bypass.md`<br>`node-js-vm-runinnewcontext-sandbox-escape.md`<br>`vm2-3-9-17-cve-2023-37466-sandbox-escape-e2-04.md` | 看禁的是字符还是关键字，两条绕法不同 |

### 2.4 组件 / CVE（内网横移时最省事）

| 指纹 | 贴哪篇 |
|---|---|
| Tomcat Manager 默认口令 | `apache-tomcat-8-0-43-manager-default-creds-war-d.md` |
| ActiveMQ `/fileserver/` WebDAV | `apache-activemq-5-11-1-cve-2016-3088-fileserver-.md` |
| WebLogic → `wls-wsat` | `weblogic-10-3-6-wls-wsat-blind-rce-cve-2017-1027.md` |
| Struts2 S2-001 | `struts2-s2-001-ognl-rce.md` |
| GeoServer WFS JXPath | `geoserver-cve-2024-36401-wfs-jxpath-rce-www-exfi.md` |
| Supervisor XML-RPC | `supervisor-3-3-2-cve-2017-11610-xml-rpc-attribut.md` |
| Nexus Repository 3 | `nexus-repository-manager-3-cve-2024-4956-vulhub.md` |
| Langflow / Next.js RSC | `langflow-1-2-0-cve-2025-3248-unauthenticated-rce.md` / `react2shell-rce-cve-2025-55182-next-js-rsc-unaut.md` |

### 2.5 业务逻辑（要"读懂应用"的那类）

| 指纹 | 贴哪篇 | 要点 |
|---|---|---|
| 旧版 API 无归属校验 | `helpdesk-legacy-v1-idor-ticket-note-flag-split.md` | `/api/v1/*` 横向越权；flag 切两段按序拼 |
| 只填用户名就能登录 + 商品 id | `flash-buy-coupon-shop-free-purchase-of-flag-prod.md` | 直接买 `product_id=999` 的 Flag 商品 |
| 报表导出 `filename` 进 shell | `enterprise-report-engine-export-filename-shell-i.md` | 文件名未转义，内容反而转义了 |
| 内网探测服务的 SSRF | `internal-asset-probe-ssrf.md` | 十进制 IP 记法绕过 |
| 会话 token 里漏 flag | `internal-knowledge-base-flag-leaked-in-session-t.md` | 直接看 `Set-Cookie` |

---

## 3. 明确**不要**贴的（噪声，贴了帮倒忙）

这 117 篇是自动记录，**名字即实例哈希**、内容是某次运行的原始 dump，无复用性：

- `AutoNotes <40位hex>.md`、`AutoNotes <hash>.http-ctf2.dasctf.com.md`、`AutoNotes ctf2:practice:<uuid>:…`
- `Quoted-printable 解码 (practice …) — UNVERIFIED flag claim`
- 名字带 `— UNVERIFIED` / `— stalled` / `— unsolved` / `flag UNACCEPTED` 的（如 `RCTF2019 disk … flag UNACCEPTED`）

> 判据：`head -6` 看 frontmatter，`fingerprint:` 是一串哈希或某次 URL 的 → 跳过。
> 这些笔记**召回得还不准**（实测自动注入会挑出 `安洵杯2019 easy misc` 这种无关 RAR 题），
> 所以"不要自动注入"这条结论也适用于手贴场景。

---

## 4. 与本仓库其它卡的关系

| 卡 | 管什么 |
|---|---|
| `IR-FIELD-CARD.md` | **现场动作**（开场 30 分钟、A/B 分岔、收工清单） |
| `IR-PROMPTS.md` | **每条消息怎么写**（四个槽、四种场景模板、八句纠偏、知识工具白名单） |
| `IR-PENTEST-CARD.md` | **渗透段的命令**（侦察/打点/上传/提权，全部 ≤120 字符可粘贴） |
| **本卡** | **哪篇历史笔记在什么时候贴**（311 篇 → 精选 ~45 篇） |

> 本卡只做索引，不复制笔记正文（正文在 `~/.vulnclaw/playbooks/`，是**机器本地资产**、
> 不在仓库里，`git` 也跟踪不到）。要新增/更新笔记用 `vulnclaw` 的 `save_playbook`。
