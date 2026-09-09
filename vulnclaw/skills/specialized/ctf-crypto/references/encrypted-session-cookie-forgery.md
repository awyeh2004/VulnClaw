# Web 加密 Session Cookie 伪造（cut-and-paste）

CTF `Web × Crypto` 交叉题的实战方法：当 Web 应用的 session cookie 加密后（hex/base64 的 AES 密文），
通过**可控注册/登录** + **块级拼接**伪造任意用户（通常是 `admin`）的会话，无需破解密钥。

典型题目：n1book "Encrypted Flask"（`/login /register /worlds /world/N`，session 为 AES-ECB hex）。
本方法在该题及 DASCTF CTF2 多实例上验证通过。

## 一、先逆向 cookie 明文格式与加密模式（不改密钥就进攻）

用"可控输入 → 观测 cookie 长度/重复块"反推结构，**不要一上来就想着爆 key**（全局 key 通常拿不到）。

1. **判模式**：注册两个仅末字节不同的等长用户名，若 cookie 只有最后一块不同 → **ECB**；
   若整串密文都变 → CBC/流式。更直接：注册 `A*16 / A*17 / A*32`，看 cookie 长度与尾部重复块
   （`A*16` 与 `A*32` 若尾块相同 → 相同明文块出相同密文块 → ECB）。
2. **推明文布局**：不同用户名长度 → cookie 长度变化，反推
   `pt = 固定前缀(如 token/uid, 16 字节) || 长度字节 || username || PKCS7`。
   常见 Flask session 类题的明文 = `T16(token) + len(username)单字节 + username + pad`。
   - 字节数 = username 长度 + 1(len 字节) → 决定 PKCS7 pad 长度，能从 cookie 总块数精确推出。
3. **识别常量头/tag**：换账号重新登录，看 cookie 第一块是否随账号变。若 A、B 两账号的
   第一块互换后仍能解析出"别人的用户名"，说明第一块是**账号无关的常量头**（如全局 token/T16），
   可直接借用来做前缀。

## 二、cut-and-paste 伪造 admin（核心）

目标是构造 `pt = T16 + 0x05 + "admin" + 0x0a*10`（len=5 对应 `0x05`，PKCS7 补齐到块边界），
使解密后 username 恰好是 `admin`。用**注册 donor 账号**把 `admin` 推进到块边界，再拼上真实 token 前缀。

```
B = http://<目标实例>
1) 注册 donor：username = A*15 + \x05 + admin + \x0a*10  (即 "AAAA...AAAA\x05admin\n\n\n...")
   → 该 donor 的 cookie 第 2 块 = E_k(0x05 + "admin" + \x0a*10)   # admin 落在块首
2) 注册另一个正经账号，取其 cookie 前 32 个 hex 字符 = T16 (token/常量头)
3) forged = T16_hex + donor_block2_hex
4) 带 Cookie: session=<forged> 访问管理员接口（如 /world/6 的隐藏 url 字段）→ 取 flag
```

- **为什么可行**：ECB 下块独立可重排；`admin` 块由 donor 的注册直接 `E_k()` 产出，无需解 key。
- **若拼接后 500**：说明明文里还有校验字节/长度字节没对齐——回到第一步精修布局（len 字节位置、token 是否可变）。
- **别名兜底**：精确 `admin` 被注册黑名单拦截时，用等长别名（如 `guest`，len=5 同样对应 `0x05`）
  或大小写/尾随 NUL 变体绕唯一性，再让解析端去除/截断得到 `admin`。

## 三、常见坑（本次实战踩过）

1. **显示名带着 `\x06/\x0a` 控制字节 → 被判 Anonymous**：拼接时若把中间 PKCS7 pad 字节漏进
   "显示用户名"区间，服务端会拒绝。务必让被显示的名字只含可见字符，pad 留在最后一块。
2. **同一登录内重复明文块 → 相同密文块**（ECB 铁证），但**跨登录密文会变**（有全局 key 之外
   的随机 IV/tag 参与首块）——不要被跨会话密文不一致误导。
3. **tag/常量头是否可互换**要实测：`[A.tag][A.c1][B.c2]` 能成功而 `[A.tag][A.c1][B.c2]` 里换成
   其他块就 500，可区分"常量头（可互换）" vs "链式（不可互换）"。
4. 目标实例过期（404 "Target not found"）时，用已构造好的 forged payload 直接换新 host 重放，
   不必重推结构。

## 工具链

`python_execute`（requests 构造 + 块切分/hex 拼接）+ `http_probe_batch`（批量对比多拼接变体）
+ `evidence_search`（回看已测的 cookie 结构证据）。必要时 `crypto_decode` 做 hex/base64 互转。
