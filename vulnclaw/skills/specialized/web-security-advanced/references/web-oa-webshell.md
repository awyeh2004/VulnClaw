# OA / 产品化 Web 系统：拿漏洞 → 植入 webshell

> 适用：目标是**成套产品**（OA、协同办公、门户、CMS）而不是自研小站——它们有固定指纹、
> 固定上传点、固定解析特性。赛题形态："获取 OA 系统漏洞并植入 webshell"，拿到 shell 后再找 flag。
>
> 纪律：**只打授权目标**；flag 由选手手工提交（见 `IR-RUNBOOK.md` 第五节）。
> 本卡给的是**方法 + 落点 + 判据**，不是可以直接照抄的 exp —— 具体路径/参数
> **必须在现场核版本、核响应**（POC 一律先只读验证，别拿生产参数盲打）。

## 一、指纹先行（30 秒确定是哪套产品）

| 产品 | 常见指纹（现场核对） |
|---|---|
| 泛微 e-cology | `/wui/index.html`、`/mobile/plugin/1/ofsLogin.jsp`、Cookie `ecology_JSessionid`、登录页"泛微"字样 |
| 致远 A8 / A8+ | `/seeyon/index.jsp`、`/yyoa/`、`/ctp.log`（日志泄露）、8081/8082 管理端口 |
| 通达 OA | `/ispirit/`、`/general/`、`/static/`、Cookie/路径含 `MYOA`、`/logincheck` |
| 蓝凌 EKP | `/sys/ui/extend/varkind/custom.jsp`、`/data/sys-common/`、`/ekp/` |
| 用友 / 金蝶 / 其他 | 登录页 title、`favicon.ico` hash、`Set-Cookie` 名、`Server` 头版本 |
| 无法确定 | 目录爆破 + `robots.txt` + JS 里的接口路径；老系统往往是 **Struts2 / Fastjson / Log4j** 栈 |

**判据**：同一产品的指纹必须**至少两条互相印证**（路径 + Cookie 名/标题），
单靠 favicon 或标题会误判成"另一个产品"，后面的上传点就全错了。

## 二、能拿到 shell 的漏洞族（按命中概率）

| 族 | 典型形态 | 为什么值 |
|---|---|---|
| ⭐ **任意文件上传 / 前台上传** | 节点升级、附件上传、`sys/ui/component` 类接口 | 直接落 webshell；OA 类产品最高频 |
| **未授权 / 越权接口** | `/api/...` 不校验登录态、`*.jsp` 直连 | 常与上传/RCE 组合，先拿到入口 |
| **任意文件读取 / 下载** | 读配置、读数据库口令 → 后台 → 后台上传 | 二级跳板，稳定 |
| **SQL 注入**（老 ASP/PHP 模块） | 参数注入 → 读管理员口令 / `INTO OUTFILE` 写马 | 老 OA 常见 |
| **反序列化 / 组件漏洞** | Java 反序列化、Struts2、Fastjson、Log4j | 直接 RCE，不需要上传点 |
| **SSRF** | 读云元数据 / 探内网 / 打内部未授权服务 | 内网横向起点 |
| **后台功能滥用** | 模板编辑、数据源、导入导出、备份还原 | 有后台就能写文件 |
| **默认 / 弱口令** | `admin/admin`、`system/123456`、数据库空口令 | 最低成本入口 |

> 公开 POC 检索（现场用 `space_search` / `web_fetch` 取精确路径与参数）：
> 泛微前台文件上传、通达 OA 文件上传、蓝凌 `sys/ui/component` 上传在公开 POC 库
> （如 afrog 的 `landray-oa-sysuicomponent-fileupload.yaml`）里有成型的请求形态；
> **照抄参数前先确认版本与响应体特征**，别把"公开 POC 存在"当成"目标可利用"。

## 三、上传 → 落地（决定成败的工程细节）

**1. 后缀与解析**

- 目标栈是 Java（OA 绝大多数）：`jsp` / `jspx` / `jspf` / `war`；PHP 站则 `php` / `phtml` / `php5`
- 白名单绕过思路（**逐个试，记录哪个通**）：
  - 大小写、双后缀（`x.jsp.jpg`、`x.jpg.jsp`）、`;` 与 `%00` 截断、`%20`/`%2e` 变形
  - 服务器解析差异：IIS 分号、Apache 多后缀从右往左、Nginx `path_info`、Tomcat `;jsessionid=`
  - 压缩包/文档类白名单：上传 zip（含 jsp）后再用产品自身解压功能落地
- 黑名单绕过：`.jsp` → `.jspx`、`.jspf`、`.jspx%00.jpg`、大小写混写、等价标签

**2. 上传目录能不能访问**

- 上传成功 ≠ 能执行：先找**静态映射路径**（`/upload/`、`/attachment/`、`/data/`、`/files/`），
  用 `fetch` 直接请求刚上传的文件名，看返回是 200 还是 403/404
- 若目录不可解析 → 换思路：写进 Web 根（路径穿越/配置里指定的白名单目录）、
  **日志写马**（把 payload 写进 access.log 再用 LFI 包含）、**数据库写文件**
  （`INTO OUTFILE` / `xp_cmdshell`）

**3. 无回显时的验证（别急着宣布成功）**

- `?cmd=id` 回显；不行就时间盲（`sleep`）、带外（DNSLog/HTTP 回连目标）、写文件再读
- 最小 webshell 优先（一句话），确认可用后再换功能更全的（比赛里没必要）

**4. 落马后的取证与纪律**

- 第一条命令固定：`id; hostname; pwd; uname -a`（**这就是证据**，别只截 "shell OK"）
- 追加 `whoami /all`（Windows）、`cat /etc/passwd`（Linux）判断权限与横向价值
- **不要**用 shell 去删日志/改配置——比赛要留痕，且改坏了现场无法复现
- 目标上找 flag：先看题面提示，再按 `incident-response/references/flag-landing-spots.md`
  的五步（内容搜 → 时间圈定 → 进程/环境 → 服务侧 → 变形解码）

## 四、常见坑（按踩坑频率）

1. **指纹误判**：把 A 产品当 B 产品，拿错了上传点，浪费十几分钟。
2. **上传成功但不可解析**：只看 HTTP 200 就宣布 getshell —— 必须**实际执行**一条命令拿回显。
3. **会话依赖**：上传接口要登录态/Cookie/CSRF token；漏带就是 401/403，误判成"漏洞不存在"。
4. **WAF/安全狗拦截**：payload 关键字被拦 → 分块/编码/换等价写法；先 `?cmd=id` 这种最小探测。
5. **公开 POC ≠ 可利用**：版本不匹配、路径已被改、参数名不同；**以响应为准**。
6. **打穿边界**：只碰题目给的 OA 目标；横向到别的机器要有题面依据（比赛按题给分，越界算违规）。
7. **提交纪律**：flag 由**人**在平台提交；agent 只报告。猜错 = 非有效操作风险。

## 五、最小作业顺序（10 分钟版）

```
1) 指纹（两条印证）→ 锁定产品
2) 未授权接口 / 弱口令 / 已知上传点，逐个只读验证
3) 拿到上传 → 试后缀与解析 → 上传最小 webshell
4) fetch 上传路径确认可访问 → 执行 id/hostname 拿回显【证据】
5) 有 shell 后：找 flag（题面提示 → flag-landing-spots.md 五步）
6) flag 交给人提交 → 解锁下一题
```
