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
agent 因此 `ask_user` 并释放了环境。**即 flag 已拿到但未提交验证平台是否接受**——
这是唯一还悬着的一环，需要用户决定是否打开
`competition.allow_flag_submission: true`。

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

1. **`gateway_proxy` 迁移（决策 6 / 不变量 I7）—— 未开始。**
   现状：`vulnclaw/gcs_platform/gateway_proxy.py`，被 `vulnclaw/agent/core.py:55`
   与 `:364`（**agent 核心**）导入，`config/schema.py:729` 仅注释提及；
   测试在 `tests/gcs_platform/test_gateway_proxy.py` 与
   `tests/platforms/test_platform_client_timeouts.py`。
   问题：agent 核心依赖 GCS 平台包，是遗留耦合。
   ⚠️ 另一会话最近改过它（`b852c6b`、`8cf5be7`），动手前先确认对方不再改。
2. **路径停滞保护未在真实 run 里验证过**：本次 run 只 5 步，没到阈值。
   已知它依赖 `_no_path_open_angles(agent) == 0` 才升级到 `ask_user`，这条分支也
   没被真实触发过。
3. **`_competition_solve` 的 ref 解析测试**用了 stub adapter；真实 adapter 的
   `parse_ref` 与 CLI 的联调仍未测。`[重写时无法核实]` 是否有意如此。
4. **`gcs.tools_enabled` 的 schema 描述**还没补弃用说明（一次编辑被 fs-observation
   守卫挡下，当时选择跳过）。
5. **`finding_parser.confirmed_markers` 与 `ctf_mode.detect_verification_success`**
   可能语义重复，需要先确认语义再合并。
6. **flag 未提交验证**：见 §9 末尾。

## 13. 未查明：设计文档为何消失

`conftest.py::_prune_stale_test_root` 明确豁免顶层 `*.md`（第 40 行，注释里还点名了
`PLATFORM-ADAPTER-DESIGN.md`），但文件仍然没了。已排除：

- 不是 git 操作（`.test-tmp/` 被 `.gitignore:110` 忽略，从未入库，也从未被 `git clean` 扫到——
  同目录的 `tmp-*` 与 `vulnclaw-home` 都还在）；
- 不是 conftest 的 prune（豁免逻辑正确，且我的 3 个 `.txt`/`.py` 文件与几百个
  `tmp-*` 目录都活着）。

**结论：触发者未查明。** 但无论原因，结论一样——**设计文档必须放在受版本控制的
路径**。这就是它现在在 `docs/` 的原因。
