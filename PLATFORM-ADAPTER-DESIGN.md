# 平台适配层重构设计（CTF2 / GCS → 平台中立）

> **关于本文档的来历（必须照实说明）**
>
> 本文档的原始版本写在 `.test-tmp/PLATFORM-ADAPTER-DESIGN.md`，而 `.test-tmp/`
> 在 `.gitignore:110` 里——也就是说它从未进过 git。2026-09-23 该文件消失且无法
> 恢复（`conftest.py::_prune_stale_test_root` 已豁免顶层 `*.md`，但仍未幸免；
> 具体触发者未能确定，见 §13）。
>
> 现在这份是按当时的决策记录 + 后续提交事实**重写**的，不是原文。原文里逐条的
> 「候选方案 / 取舍 / 实测数字」讨论无法逐字复原；保留下来的是**已经生效的决策、
> 不变量、实测数据、以及进度与断点**——这些都有代码与提交作为证据。凡我无法
> 凭证据确认的，都标了 `[重写时无法核实]`，没有编造。
>
> 教训：**设计文档不能放在会被清理的、未纳入版本控制的目录里。** 因此它现在
> 在 `docs/`，受 git 保护。

---

## 1. 要解决的问题

改造前，平台相关代码是**每个平台一套平行的整套实现**：

- `vulnclaw/ctf_platform/`（CTF2，DASCTF 系列）与 `vulnclaw/gcs_platform/`（西湖论剑
  GCS）各自拥有自己的 client、tools、schema、渲染、环境生命周期；
- agent 的工具面同时挂着两套**平台命名**的工具（`ctf2_submit_flag`、
  `gcs_submit_flag`、`ctf2_start_environment`、`gcs_build_env` …），模型必须**自己
  选平台**；
- 目标与环境连接信息（host/port/TLS）由各平台自己拼装，措辞与判据互不相同。

由此产生三类问题：

1. **选错平台在语言上是可表达的**：工具名自带平台，模型看错一行就会把 CTF2 的
   flag 提到 GCS 去，而提交是**不可逆**动作。
2. **token 成本**：两套 schema 同时在场（实测每请求 2187 token），而其中大部分
   是同一件事的两份描述。
3. **约束靠约定而非机制**：`nc_ssl` 这类平台原生字段直接裸露给上层，靠调用方
   自己注意——这正是 f278f16 那次 20 分钟误判的成因（把
   `access_type: "tcp"` 当成 transport，而同一份 payload 里 `nc_ssl: true`）。

## 2. 不变量（实现与测试的判据）

| 编号 | 不变量 | 落地位置 / 证据 |
|---|---|---|
| **I1** | 模型只**回显** ref，从不自己构造；平台身份唯一来自 ref，因此"调错平台"在语言上不可表达 | `platforms/refs.py`；6 个中立工具名里不含任何平台名 |
| **I2** | 平台返回的**不完整** payload 必须被标成不可用 | `render._render_incomplete`；`EnvInfo.complete` |
| **I3** | transport 永不默认 `tcp`；无法判定就是 `unknown`，让调用方去探测 | `normalize.normalize_transport` 返回 `TRANSPORT_UNKNOWN`；`test_transport_from_scheme` |
| **I4** | 提交是唯一不可逆动作：所有路径都必须过闸且限次 | `platforms/submit_guard.py` + `tools.submit_flag_via`（唯一提交策略出口） |
| **I5** | 平台工具不受 goal 关键词 schema 裁剪影响 | `builtin_tools._ALWAYS_KEEP_TOOLS` 钉住 6 个核心名 |
| **I6** | 未配置/被停用的平台不注册给 agent | `registry.configured_adapters`（fail-closed）；`CompetitionConfig.expose_legacy_tool_names` 默认 `False` |
| **I7** | `gateway_proxy` 与平台解耦（它服务的是 **LLM** 上游，不是 CTF 平台） | **未完成**，见 §12 第 6 项 |
| **I8** | 已跑通的路径行为不变 | 迁移期保留了旧工具名开关；`tests/ctf_platform/test_target_state_guidance.py` 与新渲染器断言同一套措辞 |

## 3. ref 语法

```
<platform>:<kind>[:<group>][:<id>]
```

只有 `platform:` 前缀是通用强制的，尾部由平台自己的 `parse_ref` 解释。刻意**不统一
元数**：强行统一会让 GCS 形式出现空字段（`gcs:exercise::10662`）只为好看，而模型
从不手工构造 token，所以按平台各自的形状来是零成本的诚实。

| ref | 含义 |
|---|---|
| `ctf2:practice:<pid>` | 一个题库（刷题场本身） |
| `ctf2:practice:<pid>:<cid>` | 题库内的一道题 |
| `ctf2:stage:<sid>:<cid>` | 比赛阶段内的一道题 |
| `ctf2:daily[:<cid>]` | 每日一题 |
| `gcs:exercise` | 整个练习树（GCS 没有中间层） |
| `gcs:exercise:<eid>` | 一道 GCS 题 |

解析**严格**：畸形 token 是错误，不是猜测（`RefError`）。

## 4. 环境状态

规范化状态集合：`none` / `starting` / `running` / `stopped` / `expired` /
`not_required` / `unknown`。

要点：

- `expired` 必须有自己的分支，且**早于**通用的"还没好"分支判断——否则过期的目标
  会被渲染成"还在启动，继续轮询"，把调用方送回去打一个死地址。
- 空状态映射到 `starting`（而不是 `unknown`）：这是迁移前 CTF2 渲染器的行为，也是
  更安全的一侧——它给出的是可执行的下一步（继续轮询）。
- `complete` 是"这个 payload 现在不能信"的机器可读形式：只要 payload 缺少连接细节
  就是 `False`。

## 5. 两个 API 面（实测，别混淆）

| 平台 | 面 | 认证 | 说明 |
|---|---|---|---|
| CTF2 | Open API `/api/open/v1/user` | `X-CTF2-API-Key` | 只读；**看不到** target 地址 |
| CTF2 | 会话 API `/api/v1` | `Bearer` JWT | target 生命周期与提交 |
| GCS | `/slab-match/api/v1/agent` | `X-Agent-AccessKey` | 单一面；信封 `{"code":"00000","data":...}` |

CTF2 的 `read_env` / `stop_env` **必须有会话 token**，否则明确报错（`CTF2Error`），
而不是静默返回"没有目标"。

## 6. 模块布局（本次新增 `vulnclaw/platforms/`）

| 文件 | 职责 |
|---|---|
| `refs.py` | token 语法、`ChallengeRef` / `CorpusRef`、严格校验 |
| `base.py` | `Challenge` / `EnvEndpoint` / `EnvInfo` / `SubmitResult` / `PlatformAdapter` 协议 |
| `normalize.py` | 平台原生值 → 适配层词汇（`normalize_transport` / `transport_from_url` / `normalize_status` / `state_from_flags` / `split_host_port`） |
| `render.py` | 渲染环境信息（I2 / I3 变成模型读到的文字） |
| `registry.py` | 注册、启用开关（fail-closed）、`adapter_for(token)` |
| `submit_guard.py` | 提交闸 + 尝试计数（I4） |
| `ctf2.py` / `gcs.py` | 两个适配器 |
| `tools.py` | 6 个核心工具 + 能力门控的可选工具；`submit_flag_via` 是唯一提交策略 |
| `bootstrap.py` | 内置适配器注册（幂等、懒加载；注册是代码，暴露是配置） |

## 7. 实测数据（迁移的收益与代价）

| 项目 | 数值 | 来源 |
|---|---|---|
| 10 个旧平台工具 schema | 1209 token | 实测 |
| 7 个中立工具 schema | **978** token | 实测 |
| 两者**同时在场** | **2187** token/请求 | 实测 ← 这才是删除旧名的真正收益 |
| 环境轮询渲染 | 326 → 429 token（+102） | 实测，已从 +138 精简 |
| ref 在 goal 里出现次数 | 8 → 2 → **1** | `897ff65`、`393631e` |
| schema 快照上限 | 1100 token | `tests/platforms/test_schema_snapshot.py` |

> 曾经的错误结论：我一度说"省 token 只有 19%，不值得删"。那是拿**旧 vs 新**比的；
> 实际成本是**共存 2187**，所以删掉旧名的收益远大于 19%。结论已更正。

## 8. 进度

已完成（按提交）：

1. **I4 收口** —— 所有提交入口共用 `submit_flag_via`，堵掉 GCS 那条不过闸的提交路径。
2. **中性工具面** —— 6 个 `platform_*` 核心工具 + 能力门控的可选工具；`builtin_tools`
   分发与 `_ALWAYS_KEEP_TOOLS`（I5）。
3. **旧工具名 schema 门控** —— `CompetitionConfig.expose_legacy_tool_names`（默认
   `False`，fail-closed）；`ctf2_tools_enabled()` / `gcs_tools_enabled()`。
4. **flag 正则唯一来源** —— `18faa48`：`finding_parser` 的副本已漂移到 3/17，抽成
   `ctf_mode.FLAG_PREFIX_PATTERNS`。
5. **schema 快照测试** —— `94ade58`：守住 −1209 token/请求的收益。
6. **goal 里 ref 只留一份** —— `897ff65`（ctf2 / gcs）、`393631e`（competition；
   原来 2~4 次）。
7. **`_competition_solve` ref 驱动 + 独立测试** —— `04d1033`，测试补齐于 `393631e`。
8. **真实解题验证** —— 见 §9。
9. **HTTP 目标渲染修正** —— `80fa955`，见 §10。

## 9. 真实解题验证（2026-09-23）

题目：CTF2 practice `b9bbb32f-f186-458f-b90b-12440c0f6aea` 的
`[极客大挑战 2019]BabySQL`（challenge `30c90c3e-2227-4263-8218-9494728f4c38`）。

**结果：拿到 flag** `CTF2{9f113b92-cb26-424a-8003-aa8ef322e092}`（evidence e026）。

路径：`check.php` 的 GET `username` 注入；过滤是**删除**（不是拦截）
空格/`and`/`or`/`select`/`from`/`where`/`substr`/`mid`/`hex`/`ascii`；用无空格
`select(x)from(t)where(c)` + 关键词双写（`seselectlect`、`frfromom`、
`infoorrmation_schema`、`passwoorrd`）绕过；错误回显用
`extractvalue(1,concat(0x7e,...))`，因其输出上限约 32 字符，长串改用
`right(left(s,pos+n-1),n)`。最终 dump 到 `b4bsql` 表 `id=8`：username `flag`，
password 即 flag。

三点验证结论：

| 待验证行为 | 结论 |
|---|---|
| 旧工具名已从 schema 隐藏 | ✅ 全程只用 `platform_read` / `platform_start_env` / `platform_read_env` / `platform_stop_env` / `platform_submit`，**没有出现 `unknown tool`**（playbook 里残留的旧名字也没有造成误调） |
| URL scheme 回退出 transport | ⚠️ 生效但**措辞错**，见 §10（已修） |
| 路径停滞保护是否触发 | ❌ **未被触发**：整个 run 只有 5 个 LLM step（31 次工具调用），远未到阈值 8。保护逻辑仍未在真实 run 里跑过 |

run 结束原因：`platform_submit` 返回 `[platform_submit_disabled]`（提交默认关闭），
agent 因此 `ask_user` 并释放了环境。

### 9.1 提交验证：被平台的人机验证挡住（未完成）

用户批准打开提交闸后，用已拿到的 flag 走真实 `submit_flag_via` 路径，**仍未能确认**。
实测过程与结果：

| 检查 | 结果 |
|---|---|
| 该题的提交前置条件 | `requires_running_target_for_submit = true`（`max_attempts = 0`，即不限次） |
| 目标起起来后再提交 | **仍然 400** —— 所以不是"没起环境"这个前置条件的问题 |
| Open API `/practice/<pid>/challenges/<cid>/submit/` | 400 `INVALID_REQUEST`。不给 `confirmation` 时 params 提示 `{"confirmation": true}`；给了之后 params 为 `null`（另一处校验失败）→ **字段名没写错** |
| 会话 API 同一路径 | **HTTP 429 + 验证码**：`{"data":{"risk_action":"challenge","risk_challenge":{"image":"data:image/png;base64,..."}}}` |
| 会话 API `/challenges/<cid>/submit/` | 404（路由不存在） |

**结论：CTF2 把 flag 提交放在人机验证（风控）之后，自动化提交走不通。** flag
`CTF2{9f113b92-cb26-424a-8003-aa8ef322e092}` 至今**未经平台确认**，需在浏览器里手动提交。

我**没有**去解那个验证码，也不会：这是平台对**计分动作**的反自动化控制，工具去绕过
它越界了。另一种可能读法照实说明：这次风控也可能是我今天反复 start/release 触发限流
后的临时升级，而不一定是永久闸门——但两种读法下"交给人在浏览器提交"都是对的，所以
无需先区分就能行动。

顺手修掉的两个**信息错误**（都不影响功能，所以任何测试都不会变红）：

1. 提交闸的拒绝文案让人去设 `VULNCLAW_COMPETITION__ALLOW_FLAG_SUBMISSION=true`，
   而 `_overlay_env` **从来没读过这个变量**——照做的人看到一模一样的拒绝，会以为闸门
   坏了而不是变量被忽略。已补上处理，并加了"文案 advertise 的名字 == overlay 真正读的
   名字"的守护测试（两者分居两个文件，是这类 bug 的温床）。
2. 验证码响应没有顶层 `error`，原先只报 `429 Too Many Requests`——这是最坏的读法：它
   暗示"慢点重试"，而对着人机验证重试永远不可能成功、只会像在规避风控。新增
   `_risk_control_note()` 明确说出 HUMAN-VERIFICATION、**不要**循环重试、去浏览器提交。

目标环境已释放（确认 `state=none`）。

## 10. 渲染措辞：HTTP 目标不是"裸 TCP"

真实解题时抓到的错误。running 的 web 目标被渲染为：

```
endpoint: http://03ac8797e2ae410f0e8a11dc.http-ctf2.dasctf.com:80
  (transport: tcp — plain TCP is fine)
```

而平台 payload 是 `access_type: "http"`、`nc_ssl: null`、URL 是 `http://...:80`。

`tcp` 这个判定**是对的**——它回答的是"要不要套 TLS"，答案是不用。错的是措辞：
`plain TCP is fine` 读起来像"直接开裸 socket 就行"，而这是一道 web 题。

修法（`80fa955`）：`_render_running` 的 TCP 分支按 endpoint URL 的 scheme 区分服务
类型（scheme 本来就在 endpoint 上，**不新增 transport 取值、不动 I3 的封闭集合**）：

- `http://` / `https://` → `(transport: tcp — HTTP service, no TLS wrapper needed)`
  + "Speak HTTP (curl / requests / a browser). A bare socket gets no banner from a
  web server, which looks like a dead service."
- 无 scheme（实测的 pwn 形式 `host:port`）→ 保持 "plain TCP is fine"。
- `https://` 仍解析为 TLS，TLS 分支不被遮住。

回归测试把**那份真实 payload 原文**喂给 `normalize_target_payload` 再渲染
（`tests/platforms/ctf2_payloads.py::WEB_RUNNING_PAYLOAD`、
`test_env_render.TestWebTargetIsNotCalledPlainRawTcp`）。

## 11. 决策记录

七项设计决策（Q1–Q7）经用户逐条确认，按**原推荐**采纳。`[重写时无法核实]`：原文
逐条的备选方案与取舍论证已随原文丢失；下列为已生效的结论。

1. **一个中立工具面**，工具名不带平台；平台只能来自 ref（I1）。
2. **保留旧工具名作为开关**（默认关闭），而不是直接删除代码——迁移期可回退，
   I8 才有保证；token 收益靠 schema 门控拿到，不靠删代码。
3. **transport 三值封闭集** `tcp`/`tls`/`unknown`，宁 `unknown` 不猜 `tcp`（I3）。
4. **环境状态含 `expired`** 且必须先于通用分支判断。
5. **提交闸默认关闭**，所有路径共用 `submit_flag_via`，并限次（I4）。
6. **`gateway_proxy` 从 `gcs_platform/` 移出**（它服务 LLM 上游，与 CTF 平台无关）。
7. **渲染层集中承载 I2 / I3 的措辞**，适配器不再各写一份。

## 12. 断点：还没做的事

1. ~~**`gateway_proxy` 迁移（决策 6 / 不变量 I7）**~~ —— **已完成**（`af…` 见 git log）。
   从 `vulnclaw/gcs_platform/gateway_proxy.py` 移到 **`vulnclaw/utils/gateway_proxy.py`**。

   ⚠️ **与当初记录的决策有出入，照实说明**：设计时写的目标是 `vulnclaw/config/`。改放
   `utils/` 的理由是——`vulnclaw/utils/` 是**设计之后**才由另一会话新建的中立基础设施包
   （`atomic_write.py` / `http_client.py` / `subprocess_text.py`），而 `gateway_proxy` 本来
   就已经在 `import vulnclaw.utils.http_client`。放 `utils/` 同时满足决策的**意图**
   （与平台解耦）和包的实际职责；放 `config/` 则会把一个运行时 HTTP 服务器塞进"配置
   schema/settings"里，还多一层与 settings 的循环导入风险。

   已更新：`agent/core.py`（2 处导入）、`config/schema.py` 的注释、两个测试文件的导入；
   `tests/gcs_platform/test_gateway_proxy.py` → `tests/utils/test_gateway_proxy.py`。

   新增架构守护 `tests/meta/test_llm_gateway_proxy_is_platform_free.py`（7 例）：
   模块在 `utils/` 下、两个入口可导入、**旧路径是真的删掉而不是留 shim**（shim 会把
   错位的模块留在树里并悄悄恢复那条导入，正是要防的事）、平台包内不再提及该文件名、
   以及 `agent/core.py` 不再引用任何平台包。

   关于"core 是否还会间接拉进平台包"——**会**：`import vulnclaw.agent.core` 仍会通过
   `vulnclaw/agent/builtin_tools.py`（承载遗留的平台工具面）把 `ctf_platform` 与
   `gcs_platform` 拉进 `sys.modules`。所以守护测试查的是 **core 自身的引用**，而不是
   `sys.modules`——后者会因为这个不变量管不着的原因而失败。`builtin_tools.py` 是
   `agent/` 下**唯一**还剩的平台导入者，这一点也被一个显式测试钉住（等遗留工具面删掉时
   它会开始失败，届时应当**刻意**删除该测试）。
2. **路径停滞保护未在真实 run 里验证过**：本次 run 只 5 步，没到阈值。
   已知它依赖 `_no_path_open_angles(agent) == 0` 才升级到 `ask_user`，这条分支也
   没被真实触发过。
3. **`_competition_solve` 的 ref 解析测试**用了 stub adapter；真实 adapter 的
   `parse_ref` 与 CLI 的联调仍未测。`[重写时无法核实]` 是否有意如此。
4. **`gcs.tools_enabled` 的 schema 描述**还没补弃用说明（一次编辑被 fs-observation
   守卫挡下，当时选择跳过）。
5. **`finding_parser.confirmed_markers` 与 `ctf_mode.detect_verification_success`**
   可能语义重复，需要先确认语义再合并。
6. ~~flag 未提交验证~~ —— 已尝试，被平台风控挡住且不可自动化；改由人在浏览器提交，
   见 §9.1。**这一项不再是"待做"，而是"已查明做不到"。**
7. **Open API 提交路由为何 400 仍未定论**：`confirmation` 给了之后 params 为 `null`，
   说明还有第二处校验失败。继续探这个接口会继续加激风控，因此**主动停止**，没有查下去。

## 13. 未查明：设计文档为何消失

`conftest.py::_prune_stale_test_root` 明确豁免顶层 `*.md`（第 40 行，注释里还点名了
`PLATFORM-ADAPTER-DESIGN.md`），但文件仍然没了。已排除：

- 不是 git 操作（`.test-tmp/` 被 `.gitignore:110` 忽略，从未入库，也从未被 `git clean` 扫到——
  同目录的 `tmp-*` 与 `vulnclaw-home` 都还在）；
- 不是 conftest 的 prune（豁免逻辑正确，且我的 3 个 `.txt`/`.py` 文件与几百个
  `tmp-*` 目录都活着）。

**结论：触发者未查明。** 但无论原因，结论一样——**设计文档必须放在受约束的
路径**。这就是它现在在仓库根目录（而不是已被 `git add -f` 硬塞进 `docs/`）的原因，
详见提交 `6ac4bee`。

---

## 14. 路径停滞保护：一次真实的"构造停滞"验证与由此发现的漏洞

### 14.1 为什么要构造

停滞保护至今**没有在真实解题里触发过**：两次成功 run 分别只用 3 和 5 个 step，
离阈值 8 差得远。它是当时风险最高的未验证机制，所以专门构造了一次。

### 14.2 构造方法（可复现）

靶机：一个**故意无产出**的本地 HTTP 服务（`127.0.0.1:18871`）——任何路径、任何方法、
任何参数、任何请求体，都返回**同一个 92 字节响应**（实测 `/`、SQLi payload、目录
穿越、`/flag` 四者的 sha256 完全一致）。它不是死端口：连接立刻成功，所以"停滞"
是**缺少进展**，不是超时。

为了在一次有界的 run 内看到事件，`competition.stall_turns` 调到 3（阈值本就是可配
的旋钮）；停滞本身是**真实的**——agent 在 15 分钟、53 条 evidence 里对目标零进展。

### 14.3 实测结果：保护**没有**拦住它，而且能解释为什么

run 的表现：8000+ 路径爆破、10 万级目录穿越变体、408 个 HTTP 方法、568 个 Host 名、
TLS/条件头/重复请求/协议升级全套 fuzz，结论每次都是"响应完全相同"。然后它**换了
方向而不是停下**——开始搜本机文件系统找 flag（`E:\vulnclaw`、`C:\vulnclaw`、harness
的 work/report 目录），命中的全是测试文件和以前几次解题的日志。

15 分钟内**没有任何 `ask_user`**。原因（读代码 + 事件顺序对上）：

**漏洞 1：把"新开 angle"当成进展。** 指纹原本是
`(confirmed_facts, len(angles), decided_angles, last_lock)`。agent 在此期间
`blackboard_set_lock` 一次、`create_angle` 三次、`miss_angle` 两次——**每次注册都把
`path_stall_streak` 归零**。注册 angle 是一个**无限、免费**的动作，所以一个不停开
新战线的 agent 可以**永久**压住守门器，尽管它离目标一点没近。

**漏洞 2：只要有 open angle 就永远不升级给用户。** `ask` 的唯一条件之一是
`_no_path_open_angles() == 0`。既然 agent 能无限注册 angle，这个条件**永远不成立**，
于是即使 streak 真的涨上去，也只会反复 hint（而且 hint 还受 `hint_sent` 限制只发
一次），**永远不会**回到操作者——正好违背"当其他路也走不下去了返回给我们确认"这个
原始意图。

**漏洞 3：hint 对操作者不可见。** `stall_guard_message` 只经
`add_correction_hint()` 与 `context.add_user_message()` 进入 **agent 的 prompt**；
`emit()` 只在 `--stream` 下接线（否则 CLI 传 `on_event=None`）。所以控制台里
**看不到守门器介入过**——agent 被告知了，人没有。这本身就是缺陷：被干预的 run 和
单纯卡住的 run，对操作者完全一样。

### 14.4 修法

1. **指纹不再计入"注册 angle"**（`_path_progress_fingerprint` 去掉 `len(angles)`）。
   进展 = 新确认事实 **或** 新决定的 angle（HIT/MISS）**或** LOCK 变化。开一个面只是
   *承诺*去看，**解决**它才算进展。
2. **hint 被无视后即使还有 open angle 也要升级**（`_stall_guard_decision` 新增分支）。
   措辞保持诚实：报出"N 个 angle 仍处于 open 且从未被决定，黑板无法区分它们值得
   追还是已被排除"，**不**再声称"没有未尝试的路径了"。
3. **hint 与 ask 都对操作者可见**：新增 `_notify_operator()` + 两个 sink 的
   `on_notice()`（终端打印黄字，TUI 发一条 log 事件），并额外 `emit("stall_guard", ...)`。

### 14.5 测试怎么改的（这点必须说清楚）

有两条**旧测试断言的正是漏洞本身**，它们是这套机制看起来"已经验过"的原因：

- `test_a_new_angle_changes_it` 断言注册 angle 会改变指纹 → 改成
  `test_opening_an_angle_is_not_progress` 断言**不会**；
- `test_an_open_angle_means_a_path_is_left` 的后半句断言 hint 之后**必须
  `("silent", "")`** → 改成 `test_an_ignored_hint_with_angles_still_open_does_ask`
  断言必须 `ask` 且措辞不许overclaim。

这两条不是我"改测试让它通过"，而是**它们固化的行为被实测证伪了**；改动理由都写在
测试 docstring 里。另外新增 `tests/agent/test_stall_guard_visibility.py`（9 例）
覆盖 `_notify_operator` 与两个 sink 的 `on_notice`。

### 14.6 复跑验证（A/B，已完成）

同一靶机、`stall_turns=2`、`--max-steps 8` 重跑，**三条都验到了**，run 按设计提前结束：

```
[stall guard] Path stall: this path has produced no new confirmed fact and no angle
decision for 2 turns. Record the current angle as a MISS on the blackboard and try a
DIFFERENT angle rather than probing this surface again. ...

[stall guard] handing back to the operator: The current path has not advanced for 3
turns, and nudging it toward a different angle changed nothing. 3 angle(s) on the
blackboard are open and never decided, so nothing there distinguishes a path worth
pursuing from one already ruled out. Give a concrete next step or scope, or confirm
that the run should stop.

⊘ 未达成 — steps=8 evidence=49 tools=51
```

逐条对应：

| 修补 | 实测证据 |
|---|---|
| 1. 开 angle 不算进展 | 旧逻辑下这一轮的三次 `create_angle` 会把 streak 清零；新逻辑下 streak 正常累计到 2 并触发 |
| 2. hint 可见 | 出现了 `[stall guard] ...` 行（修补前控制台**完全没有任何信号**） |
| 3. hint 被无视后即使有 open angle 也升级 | 第 3 轮以 **3 个 angle 仍 open** 的状态交回操作者 —— 旧代码在这里会永久 `silent` |

而且 **agent 对 hint 做出了预期反应**：收到提示后立刻 `blackboard_miss_angle` 并把方向换成"Host/vhost 枚举"，即"告诉它这条路难走、让它先走别的路"这个原始意图成立，且**没有终止 run**。

### 14.7 复跑暴露的第 4 个问题（已修）

同一次复跑的末行暴露了措辞自相矛盾：

- handback 消息说 "3 angle(s) ... are open and never decided"，
- 而 run 摘要的 `reason` 说 "stalled with no untried path remaining"。

同一件事的两行互相打架。原因是 loop 里 `reason` 只有二分（thin / 否则即"没有未尝试的路径"），而升级分支现在有第三种情形。已抽成 `_stall_handback_reason()` 三值（外加"没有黑板可判断"这第四种），并加了"reason 与消息不得矛盾"的测试。

至此**停滞保护可以说是验证过了**（单元 + 一次真实 A/B）。

关于 `stall_turns` 默认值 8：本次为了在有界 run 内看到事件用了 2，但**默认值不需要再跑一遍
来确认**——这个旋钮只决定"多久开口"，与判定逻辑无关（逻辑已被单测覆盖，且与阈值无关）。
8 是从"成功 run 的步数"标定出来的，而现在的实测样本是：两次成功解题 3 / 6 步，`easyre`
5 步，`不一样的flag` 5 步，BabySQL 5 步——**每一次有产出的 run 都在 8 步以内结束**，所以 8
仍稳在"任何有进展的连续段"之上。再跑一次默认阈值只会多花时间，不会多出信息。

### 14.8 这一轮顺带暴露的、与停滞保护无关的两个额外发现

1. **`competition.predownload_attachments` 曾是死配置 —— 已接上。** 它在
   `config/schema.py` 里声明为 "At match start, download all challenge attachments so a
   slow backend never blocks analysis"、**默认 True**，但全代码库没有任何一处读它（`grep`
   只命中声明那一行）；能力其实存在，只是被埋在内联在 `competition download` 命令里的
   那段代码中。**留一个骗人的开关比没有更糟**——它让人以为保险已经上了。

   处理方式：**接上，而不是删掉**（一个文档化的、默认开的保险功能，删掉是更破坏性的选择）。
   - 把那段内联下载逻辑抽成 `vulnclaw/platforms/attachments.py`（`download_attachment` /
     `resolve_url` / `safe_name` / `attachment_dir`），**批量命令与新路径共用同一份实现**，
     避免"批量下一套、解题下另一套"的漂移；
   - `ctf2()` 与 `_competition_solve()` 在把目标交给 agent **之前**按该开关预下载本题附件，
     并把**本地路径**写进 goal（agent 因此完全不必访问文件托管站）；
   - 全程 best-effort：失败只降级成"agent 自己去下"（即这个改动之前的行为），**绝不让
     保险弄坏一次解题**。

   抽取代码时**自己引入并当场抓到一个回归**：`AttachmentDownload.ok` 对"尺寸不符"也是
   False，于是 `if not result.ok` 会把"已写入但可能被截断"的文件判成**失败**，而原内联
   版本是 `[warn]` 且计入 ok。已恢复原语义（保留文件、warn、计 ok），并加了三个测试把
   "成功 / 硬失败 / 尺寸不符"三种结果钉开——**抽取代码正是这种静默行为改变最容易藏身的地方**。

   真实验证：对 `不一样的flag` 的实际附件跑通整条新路径——9204 字节与平台声明的 size
   **完全一致**、magic 为 `PK\x03\x04`、CJK 题名在文件名里完整保留、TLS 校验保持开启
   （文件托管站证书有效）。顺带记录：批量命令里那个 `verify=False` 是**既有**行为，为
   不改变已跑通的路径而保留，已就地加注说明并列为后续单独处理项。

2. **卡住的 agent 会去翻本机找答案**（§14.2/§14.3 的现象，与停滞保护无关的真漏洞）——
   已按"答案必须来自目标"修掉：prompt 规则 + `python_execute` 机械兜底，见提交 `1ba36bf`。

---

## 15. "疑似语义重复"那条的结论：不是重复，但底下埋着两层真问题

§12 第 5 项原本的怀疑是「`finding_parser.confirmed_markers` 与
`ctf_mode.detect_verification_success` 可能语义重复」。**先把语义问清楚，结论是：不重复。**

| | `finding_parser.confirmed_markers` | `detect_verification_success` |
|---|---|---|
| 产出 | **抽取事实**（改写 state） | **判断真假**（返回 bool） |
| 用途 | 往"已确认事实"里记东西 | 决定 `flag_verified`，进而决定 run 是否结束 |
| 词汇 | **技术层**：`payload 差异`、`SLEEP() 耗时`、`UNION 成功`、`布尔/报错` | **目标层**：`找到flag`、`the flag is`、`提交成功`、`challenge solved` |

两者只在一小部分短语上重叠（"验证成功"、"确认…"），而那种重叠是**对的**：同一句话既可以是
一条已确认事实，也可以是一次"我已验证 flag"的声明。**整并这两个函数是错的**，所以没并。

但顺着查下去发现两层**真**问题，都在 `ctf_mode` 内部：

### 15.1 词汇表被维护了**三**份（不是两份）

`update_ctf_state` 里还有第三份内联列表（31 条），就在
`detect_verification_success(response_text) or any(...)` 这个 `or` 的另一侧——而那是该函数
**唯一**的调用点。实测差异：

- 只在函数里：`the flag is`、`captured`、`成功破解`、`confirms the flag`（8 条）
- 只在内联表里：`challenge solved`、`got the flag`、`submission successful`、`flag acquired`
  → 等 10 条
- 两份重叠 **21** 条

也就是说那个函数的实际贡献只有它独有的 8 条，两份词汇表在**静默漂移**——和 `FLAG_PREFIX_PATTERNS`
那次一模一样（它的 `finding_parser` 副本已经漂到 3/17）。已合成唯一来源
`VERIFICATION_CLAIM_MARKERS`，`update_ctf_state` 只调用谓词。

### 15.2 **两份实现都不处理否定**，而子串匹配会把意思**读反**

实测假阳性（原文是在**否认**成功）：

| 文本 | 命中的标记 |
|---|---|
| `无法验证成功` | `验证成功` |
| `尚未验证成功` | `验证成功` |
| `not confirmed` | `confirmed` |
| `the flag is not the correct one` | `the flag is` |

后果不只是记错一条：`update_ctf_state` 把它变成 `flag_verified`，而 `flag_verified` 在
**两轮之后让 run 结束**——也就是**模型刚说完"我没验证成功"，运行器却据此收工**。
已加否定感知：标记两侧各看一小段窗口（前 24 / 后 12 字符），命中否定线索就不算声明；
窗口刻意开小，否则"验证成功。未发现其他问题。"这种真声明会被误杀（有测试守着）。

同一类缺陷在事实抽取侧表现为**语义反转**：`未确认该漏洞存在` 命中 `确认.*存在`，产出的
"已确认事实"是 **`确认该漏洞存在`**——正好相反，而且它会被当成已确认知识写进状态。
已加同一套否定守卫（顺带把 `re.findall` 换成 `re.finditer`，否则拿不到匹配位置）。

**残留（照实说明）**：否定处理是启发式，不是句法分析。例如 `确认漏洞不存在` 这类
"否定在匹配区间内部"的写法仍会产出事实——只是那条事实的文本自身就写着"不存在"，
危害远小于上面那种整体反转。要彻底解决需要句法级判断，不在本次范围内。

测试：`tests/agent/test_verification_claim_markers.py`（38 例）覆盖否认/真声明两侧、
两份旧列表的独有标记都能被唯一谓词识别、标记不重复、内联副本不得复活（源码断言）、
`_is_negated` 的窗口边界，以及抽取侧的反转案例。


