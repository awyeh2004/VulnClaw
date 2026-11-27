# 竞态条件参考（授权测试）

## 1. 两种并发原语

竞态的关键是让请求落在**同一个窄窗口**。顺序发送永远无效。

- **相同副本竞态（limit overrun）**：同一请求同时发 N 份。适用于优惠券、礼品卡、余额、
  一次性配额、投票。成功 = N 份里有 ≥2 份返回 2xx/成功语义。
- **不同请求竞态（partial construction / TOCTOU）**：一组不同请求在同一窗口发出，重复多轮。
  适用于“对象已创建但未完成初始化”的窗口，例如注册后确认、邀请接受、创建后立即使用。

```text
# 部分构造示例（只在自有测试账号上）
Request A: POST /register  csrf=...&username=hacker&email=test@own.example&password=pw
Request B: GET  /confirm?token=        (空 token)
A 与 B 同窗发送，重复 ~20 轮
```

## 2. 目标清单

```text
/vote /upvote /like /favorite
/redeem /apply-coupon /use-code /claim
/purchase /checkout /confirm-order /pay
/transfer /withdraw /send-money
/invite /referral /accept-invite
/upgrade /activate /trial
/delete /deactivate /cancel
/follow /subscribe
```

状态机观察点：读状态 → 校验 → 写状态。读写之间的间隔就是窗口。

## 3. 环境信号

- 响应头：`X-RateLimit-*`（限速存在但未必原子）、`X-Request-Id`（每请求独立追踪）、
  无 `Cache-Control`（有状态操作）。
- 前端模式：按钮点击后 `disabled`、乐观 UI（先置已使用再等服务端）、无锁的连续 await。
- 后端栈：Rails 无 `with_lock`、Node async 读写分离、PHP 无 `SELECT ... FOR UPDATE`、
  Redis 计数无 Lua/INCR 原子性、微服务跨服务校验、异步履约。

## 4. 工具

- **Burp Repeater → Send group in parallel**（HTTP/2 单包）。
- **Turbo Intruder**：`engine=Engine.BURP2` + gate 同步。
- **curl 并行**（仅作粗测，受连接建立影响）：

```bash
seq 1 20 | xargs -P20 -I{} curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST "https://$TARGET/redeem" \
  -H "Cookie: $SESSION" -d "code=TESTCODE"
```

- **Python asyncio**：预建连接、同时 `write`、再统一 flush；比线程更可控。

先确认 HTTP/2：

```bash
curl -sI --http2 "https://$TARGET" | grep -i "HTTP/2\|h2"
```

单包攻击要点：把所有请求预编码，**最后一个字节同时发出**；HTTP/2 多路复用让它们在同一
TCP 包/同一时刻到达。没有 HTTP/2 时用多连接 + 末字节同步，成功率下降。

## 5. 测试步骤

1. 枚举一次性/限额动作，选测试资源（自己的券/账号/库存）。
2. 画状态机：读什么、写什么、校验在哪。
3. 正常执行一次，记录基线（券已用、计数 +1）。
4. 用并行原语发 5–20 份相同请求。
5. 看响应：多个 200、重复成功文案、唯一约束报错（说明打到了最后防线）。
6. **查真实状态**：余额、计数、库存、订单列表。响应成功不等于状态成功。
7. 降低并发（10→5→3→2）测窗口宽度与成功率。
8. 换账号类型/套餐/负载条件复测。
9. 5 次独立复现，记录成功率与所需并发数。

## 6. 常见根因

- check-then-act 无原子操作；
- ORM `find` 而非 `SELECT ... FOR UPDATE`；
- 乐观并发无版本号校验；
- 微服务 TOCTOU（A 校验、B 执行）；
- 仅前端禁用按钮；
- 计数在事务外 `+= 1`；
- 异步履约：同步校验通过、异步任务未完成；
- 缓存未失效：第二次读到旧 `false`。

## 7. 假阳性与降级

- **幂等成功**：接口重复返回 200 但状态只变一次 → 不是漏洞。
- **仅 UI 重复提示**：前端 toast 重复，后端已去重 → 不成立。
- **客户端重试**：网络层自动重试导致重复请求，但服务端幂等 → 不成立。
- **唯一约束报错**：说明竞态窗口存在但被数据库兜住；只有出现实际状态异常才升级。
- **一次成功**：没有 ≥2 次实际生效 → 不成立。
- **低并发不可复现**：记录窗口极窄，按 Low/ informational 处理，不夸大为稳定利用。
- 真实用户资源上的超发一律不测试；用测试资源的结果外推时注明假设。

## 8. 影响与定级

- 资金/余额/库存可重复扣加：Critical（按可提取金额评估）。
- 一次性权益重复获取（券、试用、邀请奖励）：High。
- 投票/信誉/计数操纵：Medium–High（看业务影响）。
- 限速/OTP 并发绕过：High（若导致 ATO）否则 Medium。
- 仅窗口存在、状态未异常：informational。

## 9. 证据清单

- 并发原语与请求数量、时间戳；
- 每份请求的响应（状态码/关键 body）；
- 状态前后对比截图或 API 输出（余额、计数、库存、订单）；
- 5 次复现的成功率与并发阈值；
- 未成立分支（幂等/唯一约束/仅前端）与降级理由。
