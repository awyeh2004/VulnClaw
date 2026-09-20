# 网页篡改 / 流量劫持应急响应

网页篡改最直观——"一打开网站就知道出事了"。但**现象可见不代表原因好找**：篡改可能来自文件、数据库、中间件配置、或第三方 JS，**四层都要查**。

**主流程**：`初步预判 → 系统排查 → 日志排查 → 网络流量排查 → 清除加固`

---

## 一、篡改手法分类（先定性，再定往哪查）

| 手法 | 落点 | 典型现象 |
|---|---|---|
| **文件篡改** | 首页文件、图片、JS | 首页内容/图片被换 |
| **隐藏目录挂黑页** | Windows 隐藏属性 + IIS 压缩缓存 | 目录里看不到文件但 URL 能访问 |
| **数据库注入** | CMS 数据表（友情链接、广告位、模板） | 链接被挂、页面渲染出恶意内容 |
| **中间件配置** | `nginx.conf` / `VirtualHost.conf` | 特定 URL 被反代到博彩站 |
| **第三方 JS 加载** | 页面里的 `<script src=...>` | 跳转、弹窗、暗链 |
| **代码包含** | `include` / `require` 指向隐藏文件 | 首页正常但特定来源被劫持 |

> ⭐ **关键心法**：篡改点 ≠ 植入点。**首页被改，但根因可能在数据库或中间件配置。**

### 检测技术（了解对手怎么发现你）

1. **外挂轮询** —— 独立程序轮询读取网页，与真实网页比对
2. **核心内嵌** —— 篡改检测模块内嵌 Web 服务器，网页流出时实时完整性检查
3. **事件触发** —— 通过文件系统/驱动接口，文件被修改时合法性检查

（反过来用：**这些也是你要模仿的取证思路**——与"干净基线"比对。）

---

## 二、⭐ 四个具体案例（含落地手法）

### 案例 A：批量挂黑页 + IIS 压缩缓存残留

**现象**：友情链接模块被挂大量垃圾链接，网站出现不该有的目录，里面全是博彩网页。链接可访问、**直接访问物理路径也能看到文件，但打开网站目录却找不到这些文件**。

```
http://www.xxx.com/upload/aomendduchangzaixiandobo/index.html
http://www.xxx.com/upload/aomendduchangzaixian/index.html
http://www.xxx.com/upload/aomenzhengguidubowangzhan/index.html
```

**原因**：开源 CMS 高危漏洞（0day）批量拿站上传黑页。

**处理**：

1. 文件夹选项 → 取消勾选「隐藏受保护的操作系统文件」，选「显示隐藏的文件、文件夹和驱动器」
2. 复查 → 看到**半透明的隐藏文件夹** → 清除隐藏文件夹及所有页面
3. ⭐ **清除 IIS 临时压缩文件**（否则文件删了链接还能访问）：

```
C:\inetpub\temp\IIS Temporary Compressed Files\WEBUI\$^_gzip_D^\WEB\WEBUI\UPLOAD
```

4. 投诉快照，申请删除搜索引擎收录

> ⭐ **判据**："文件删了链接仍可访问" → 找**缓存残留**（IIS 压缩缓存 / Nginx `proxy_cache` / CDN）。
> **这是最容易漏的一步**，也是最容易被问"为什么删了还访问得了"的地方。

```cmd
:: 查隐藏属性（attack 用 attrib +h 隐藏）
dir /a /s /b C:\inetpub\wwwroot | findstr /i "upload"
attrib -h -s /s /d C:\inetpub\wwwroot\upload\*
```

```bash
# Linux 侧对应：查 . 开头的隐藏目录
find /var/www -name ".*" -type d
ls -la /var/www/html/upload/
```

### 案例 B：搜索引擎劫持 + 隐藏目录 include

**现象**：直接打开网址正常，**但从搜索引擎结果页点进来会跳转**到博彩/虚假广告。

**分析**：

1. 对 `index.php` 代码分析 → 发现该文件对**来自搜狗和好搜的访问**进行流量劫持
2. 跟着 `include` 函数往下看 → `index.php` **包含 `/tmp/.ICE-unix/../c.jpg`**
3. 进 `/tmp` 目录 → 发现 `c.jpg` 等文件包含**一整套博彩劫持程序**

> ⭐ **两个判据**：
> - **`include`/`require` 的目标后缀不是 `.php`（这里是 `.jpg`）** ⇒ 高度可疑
> - **路径含 `/tmp/` 或以 `.` 开头的隐藏目录**（`.ICE-unix`）⇒ 藏匿痕迹
>
> `.ICE-unix` 是 Linux `/tmp` 下的**默认存在目录**（还有 `.Test-unix`、`.X11-unix`、`.XIM-unix`）——
> **攻击者利用它的隐藏属性**（`ls -l` 看不到，必须 `ls -al`）把马藏进去。

```bash
# 排查 include/require 指向的可疑目标
grep -rnE '(include|require)(_once)?\s*\(?[^;]*\.(jpg|png|gif|txt|ico|dat)' /var/www/
# 排查 /tmp 下的隐藏内容
ls -al /tmp/ ; ls -al /tmp/.ICE-unix/
```

```bash
# 按 Referer / UA 判断劫持逻辑
grep -rnE 'HTTP_REFERER|\$_SERVER\[.HTTP_USER_AGENT' /var/www/ | head
```

### 案例 C：Nginx 配置反代劫持

**现象**：某新闻源网站首页广告链接被劫持到博彩站（三个广告专题链接）。

**分析链条**：

```
1. 抓包 → 返回页面已被劫持，加载了第三方 JS
   http://xn--dpqw2zokj.com/N/js/dt.js
2. dt.js 又加载另一条 JS → http://xn--dpqw2zokj.com/N/js/yz.js
3. 最终跳转 https://lemcoo.com/?dt → 博彩导航站

4. ⭐ 找到 url 对应文件位置 —— 即使文件被删除，链接依然可以访问
5. 发现三条链接都以 "sc" 后缀结尾
6. ⭐ 排查 Nginx 配置 → VirtualHost.conf 被篡改
   通过反向代理匹配以 "sc" 后缀的专题链接，劫持到 http://103.233.248.163
7. 删除恶意代理后，专题链接访问恢复
```

> ⭐ **判据**：**"文件删了链接仍可访问" + URL 有共同特征（后缀/前缀）** ⇒ 查**中间件配置的反代规则**。

```bash
# 排查 nginx 配置中的可疑 proxy_pass / rewrite / return
grep -rnE 'proxy_pass|rewrite|return\s+(301|302)|add_header' /etc/nginx/
nginx -T 2>/dev/null | grep -nE 'proxy_pass'      # 打印完整生效配置（含 include）

# 看配置文件修改时间，找最近的改动
ls -lat /etc/nginx/ /etc/nginx/conf.d/ /etc/nginx/sites-enabled/
find /etc/nginx -name '*.conf' -mtime -30
```

```cmd
:: IIS 侧
%SystemRoot%\System32\inetsrv\config\applicationHost.config
%SystemRoot%\System32\inetsrv\config\administration.config
:: 查 URL Rewrite 规则、反向代理
```

### 案例 D：移动端劫持 + 加载第三方 JS

**现象**：PC 端正常，**手机打开跳转赌博网站**。

**分析**：抓包发现恶意 JS —— `http://js.zadovosnjppnywuz.com/caonima.js`
该 JS **判断手机访问来源（UA）**，劫持移动端（手机/iPad/Android）流量，跳转到 `https://262706.com`。

```bash
# 找页面里的外部 JS 引用
grep -rnoE '<script[^>]+src=["'"'"']https?://[^"'"'"']+' /var/www/ | grep -vE 'localhost|自己的域名'

# 找按 UA 判断的劫持逻辑
grep -rnE 'navigator\.userAgent|isMobile|Android|iPhone|iPad' /var/www/*.js /var/www/*.php | head
```

**判据**：**页面引用了非本站、非已知 CDN 的第三方 JS** ⇒ 重点排查。

### 附：首页被篡改（图片替换型）

**现象**：首页图片被换（复制原图 PS 后替换）。

**时间线推演（教科书级）**：

```
① 确认篡改时间：查看被篡改图片 → 2018-04-18 19:24:07
② 访问日志溯源：该时间节点 → 可疑 IP 113.xx.xx.24（代理 IP，无法追真实来源）
                  该 IP 访问了 image.jsp（脚本木马），随后访问了被篡改的图片地址
③ ⭐ 全量日志审查（日志范围 2017-04-20 ~ 2018-04-19）：
   image.jsp 一共只有两次访问记录：
     2018-04-18（篡改当天）
     2017-09-21（一年前）
   ⇒ 推断 image.jsp 在 2017-09-21 之前就已上传，潜藏半年以上
④ 找真相：网站根目录发现 ROOT.rar 全站源码备份（备份时间 2017-02-28 10:35）
   解压后，源码中存在与日志可疑文件名一致的脚本木马 image.jsp
⑤ 但访问日志中并无 ROOT.rar 的下载记录（日志只保留近一年）
   ⇒ 无法确定原始入侵点
```

> ⭐ **三个可复用的点**：
> 1. **某脚本文件访问次数极少且间隔很久 = 长期潜藏的 Webshell**
> 2. ⭐ **网站根目录下的源码备份包（`ROOT.rar` / `www.zip` / `.git`）是重大隐患** ——
>    可作为证据源，也可能本身就是入侵途径。**排查时一定要查根目录有无备份包**
> 3. **日志保留期不足时，只能给出时间的下界**，必须明确说明（"该马在 2017-09-21 之前就已存在"）

```bash
# 查根目录/站点下的备份包与版本控制残留
find /var/www -maxdepth 3 \( -name '*.rar' -o -name '*.zip' -o -name '*.tar.gz' -o -name '*.7z' -o -name '*.bak' -o -name '*.sql' \) -ls
ls -la /var/www/html/.git /var/www/html/.svn /var/www/html/.hg 2>/dev/null
# 备份包的时间可能比入侵时间更早，是还原早期状态的依据
```

---

## 三、系统排查

**篡改通常伴随 Webshell 或系统后门**——篡改只是结果，要往回找入口。

| 面 | 查什么 | 文档 |
|---|---|---|
| 首页/模板文件 | 与干净基线做 hash 比对 | `../30-file-artifacts.md` |
| 数据库 | CMS 的广告位/友情链接/模板表 | 本文第四节 |
| 中间件配置 | `nginx.conf` / `web.config` / URL Rewrite | 本文第二节案例 C |
| 页面 JS | 非本站的第三方 JS 引用 | 本文第二节案例 D |
| Webshell | 完整性校验（免杀马只能靠这个） | `webshell.md` |
| 系统后门 | 账号/进程/服务/启动项 | `../20-accounts.md`、`../25-process-service.md` |

### 文件完整性校验（定位被改的文件）

```bash
# 与纯净源码比对，输出新增/修改/删除
diff -c -a -r /path/to/pristine_cms /var/www/html

# 或按时间定位（改动时间 = 篡改时间）
find /var/www/html -type f -newermt "2024-01-01" -ls
find /var/www/html -type f -mtime -7 -ls
```

### 图片/文件类篡改的时间证据

```bash
stat /var/www/html/images/index_banner.jpg    # 看 Modify 时间
exiftool /var/www/html/images/index_banner.jpg   # 看 EXIF 元数据（可能留原图时间）
```

---

## 四、数据库侧排查（CMS 常见落点）

**友情链接、广告位、模板、文章内容**都可能被写进数据库——**只查文件会漏**。

```sql
-- 通用：先找含可疑特征的字段
-- 博彩类关键词
SELECT * FROM <前缀>_links WHERE url LIKE '%bo%' OR name LIKE '%赌%' OR name LIKE '%博彩%';
-- 常见 CMS 的广告/友情链接表
SELECT * FROM <前缀>_myad;        -- DeDeCMS 广告位
SELECT * FROM <前缀>_mytag;       -- DeDeCMS 自定义标签（可存 PHP 代码！）
SELECT * FROM <前缀>_flink;       -- 友情链接

-- ⭐ 查含代码注入的字段（落库型 Webshell 的痕迹）
SELECT * FROM <前缀>_myad  WHERE normbody LIKE '%eval%' OR normbody LIKE '%<script%';
SELECT * FROM <前缀>_mytag WHERE expbody  LIKE '%eval%' OR normbody LIKE '%file_put_contents%';

-- WordPress
SELECT * FROM wp_options WHERE option_value LIKE '%<script%' AND option_name NOT LIKE '%transient%';
SELECT * FROM wp_posts WHERE post_content LIKE '%<script src="http%';
```

> ⚠️ **和 `webshell.md` 的落库型后门联动**：DeDeCMS 的 `dede_myad` / `dede_mytag` 表
> 既能存广告内容，**也能存 PHP 代码生成 Webshell**。
> **清除时必须同时清数据库记录**，否则删了文件会被重新生成。

---

## 五、日志排查

```bash
# ① 篡改时间点前后的访问
grep "<篡改日期>" access.log

# ② 找可疑来源（按时间窗）
awk '$4 ~ /18\/Apr\/2018/ {print $1,$7}' access.log | sort | uniq -c | sort -rn | head

# ③ 全量统计某脚本的访问记录（判潜藏时长）
grep "image.jsp" access.log
grep -c "image.jsp" access.log

# ④ 从搜索引擎来的访问（搜索引擎劫持的验证）
grep -iE 'baidu|sogou|so\.com|google|bing' access.log | grep "<被劫持的URL>"

# ⑤ 反代场景无真实 IP 时 → 用浏览器指纹
grep "<User-Agent 指纹>" access.log | awk '{print $1,$4,$7}'
```

**Web 日志位置**见 `../40-log-analysis.md` 的组件位置表。

---

## 六、清除加固（7.5.5）

```
① 恢复被篡改内容 —— ⭐ 但必须同时审计源码，确认没有遗漏的恶意添加
② 若涉及隐藏目录/缓存 → 清文件 + 清缓存（IIS 压缩缓存 / Nginx 缓存 / CDN）
③ 若涉及数据库 → 清数据库记录
④ 若涉及中间件配置 → 恢复配置到已知正确状态
⑤ 清除 Webshell 及系统后门
⑥ 修补植入漏洞
⑦ 确认安全后恢复上线
```

> ⭐ **只恢复可见内容 = 治标**。攻击者的后门还在，下次还能改。

### 错误处置方法（7.3，书里单列了一节）

| 错误做法 | 后果 |
|---|---|
| 直接覆盖/删除被篡改文件后不停留取证 | **丢失唯一的入口线索**，无法溯源 |
| 只恢复页面内容，不审计源码 | 后门残留，反复被篡改 |
| 只删文件不清数据库 | 落库型后门会重新生成 |
| 只删文件不清缓存 | URL 仍可访问 |
| 不修漏洞就恢复上线 | 立刻被二次入侵 |

### 防御要点（7.1.5）

1. **服务器补丁升到最新**（OS、应用、数据库）
2. **封闭未使用但已开放的服务端口**（Windows TCP/IP 筛选器；Linux iptables）
3. **使用复杂管理员密码**（系统/数据库/FTP/网站管理员都要，改掉默认密码）
4. **网站程序设计合理**：
   - 只读权限脚本与只写权限脚本**分开放置**
   - 避免采用第三方不明开发插件
   - 程序命名有规律，便于识别
   - 代码侧约束输入、过滤攻击字符串、**特殊权限页面加身份验证**
5. **设置合适的网站权限**：
   - 每个网站目录/文件创建**专属访问用户**
   - ⭐ 原则：**仅需要写权限的目录给写权限，其他一律只读**
6. **防 ARP 欺骗**（装 ARP 防火墙、手动绑定网关 MAC）

### 管理制度（7.1.6）

1. **网站数据备份** —— 入侵/硬件故障都能靠备份快速恢复
2. **安全管理制度** —— 技术手段要有人执行，制度要配套
3. **应急响应处置措施** —— 备好检查/记录/恢复工具，规范步骤，**必要时演练**；
   出事时做好记录总结，**必要时保护现场并报案**

---

## 七、常见问法与答法

| 问 | 答什么 | 依据 |
|---|---|---|
| 被篡改的内容在哪 | 具体文件路径 / 数据库表字段 / 中间件配置文件 | 完整性校验、SQL 查询、配置 grep |
| 什么时候被篡改的 | 文件 `Modify` 时间 / 图片 EXIF / 日志时间窗 | `stat`、`exiftool`、日志 |
| 谁篡改的 | 访问日志源 IP（注意代理/反代） | 日志 |
| 通过什么篡改的 | Webshell / 后台弱密码 / 数据库注入 / 配置篡改 | 日志 + 代码审计 |
| 为什么删了文件还能访问 | 缓存残留（IIS 压缩缓存 / Nginx 缓存 / CDN）或 中间件反代规则 | 案例 A / C |
| 有没有后门残留 | 完整性校验输出 + 数据库记录 + 系统排查 | 本文第三/四节 |
| 是不是从搜索引擎进来才跳转 | 按 Referer 判断的劫持逻辑 | 案例 B |
| 为什么手机才跳转 | 按 UA 判断的劫持 JS | 案例 D |
| 怎么彻底清除 | 恢复内容 + **审计源码** + 清缓存 + 清数据库 + 修漏洞 | 第六节 |
| 根源是什么 | 开源 CMS 漏洞（0day）/ 弱密码 / 未授权访问 | 日志 + 漏洞排查 |

---

## 相关文档

- `webshell.md` — 篡改的上游：Webshell 排查与落库型后门
- `../30-file-artifacts.md` — 完整性校验、时间戳判据、隐藏文件
- `../40-log-analysis.md` — Web 日志位置、浏览器指纹溯源
- `../10-system-basics.md` — 中间件配置与自启动
- `../casebook.md` — 更多完整案例
