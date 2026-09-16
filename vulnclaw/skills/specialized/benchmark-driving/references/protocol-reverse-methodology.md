# 协议流量逆向方法论

> 适用场景：拿到 pcap 流量样本的 CTF/红队题（协议还原、固件分析、C2 流量解析、
> "ghostpatch" 类协议利用题）。核心思想：**先找协议文档，再做二进制分析**。

## 一、第一原则：先找"说明书"

出题人/开发者经常把完整协议规范以明文形式埋在流量里：

- **内部 wiki 页面**：HTTP 明文流里的 `GET /ops/xxx.html`、`/docs/`、`/wiki/`
- **遗留通道的废弃说明**：新旧版本并存的协议，旧通道常整段引用新协议规范
  （ghostpatch 实例：8888 明文通道整段写了 9999 加密通道的帧格式/握手/密钥派生）
- **调试日志**：`DEBUG`/`VERBOSE` 级别的帧打印
- **错误消息**：解析失败的报错常泄露字段名和期望格式

**操作**：pcap 到手先跑一遍 ASCII 可读扫描（`strings` 或流重组后 grep
`deprecated|documentation|runbook|wiki|spec|protocol|example`），
命中即整段提取——一次调用替代 20 轮盲猜。

## 二、流量结构还原（无说明书时的兜底）

1. **流聚合**：按 TCP 四元组合并 payload，保持方向（c2s/s2c 分开）
2. **定界符识别**：找 `\n`、`\x00`、固定长度模式；magic 字符串
   （`FGT/1.0 READY`、`HTTP/1.1`）即帧边界
3. **长度前缀判定**：`[u16be len][data]` / `[u32be len][data]` / 
   `[u8 type][u16be len][data]` —— 用"首字节+claim长度==剩余长度"验证
4. **字段语义推断**：固定位置递增 → seq；32 字节固定长 → hash/session；
   变长 + 前缀 len → 字符串/数据
5. **工具**：scapy 流重组（`defaultdict(lambda: bytearray())` 按 TCP 流拼接）
   + tshark `--follow tcp,ascii`；没有 tshark 时 scapy 纯 Python 即可

## 三、加密层剥离

### 握手弱点检查清单（按优先级）

| 弱点 | 识别特征 | 利用 |
|------|---------|------|
| 小模数 DH | `p` 十六进制 < 64 bit（如 `p=8348d41a7225`） | `sympy.discrete_log(p, A, g)` 秒解 |
| 硬编码 g=2/5 | 握手明文含 generator | 配合小 p 直接算 |
| 无认证 DH | 握手无签名/MAC | MITM：分别与双方协商，改写流量 |
| RC4/异或流密码 | K=SHA(shared)[:16] 模式 | 已知明文恢复 keystream |

### 会话密钥派生确认

K 的派生方式用已知明文验证：拿一对明文/密文帧，按候选派生
（`SHA256(str(shared))[:16]` / `SHA256(long_to_bytes(shared))[:16]` /
`MD5(shared)`）生成 RC4 keystream，比对首个字节即可确认。

## 四、帧类型利用的优先级

还原帧类型后，按"攻击面价值"排序：

1. **SHELL/EXEC/CONSOLE 类帧**（type 07/09/0A）→ 直接命令执行，最高价值
2. **GET/DATA 文件读取** → 路径遍历绕过（`../`、编码变体、通配符）读敏感文件
3. **META/LIST 枚举** → 收集文件清单找 flag 命名规律
4. **管理/调试帧**（patchd debug 模式、selftest）→ **内存地址泄露**
   （ghostpatch 实例：selftest 直接输出 `build=0x… table=0x… slots=7`）

加密通道里的帧必须先解决密钥协商，**但注意**：如果调试守护进程（如
patchd debug 模式）开了 selftest/verbose，泄露的地址本身就是利用材料。

## 五、完整案例：ghostpatch

pcap（3.5MB/3563 包）→ 三条流：
- 8888 明文（FGT/0.9 DEPRECATED）：整段协议文档 + patchd 调试入口说明
- 9999 加密（FGT/1.0）：`p=8348d41a7225 g=5` + RC4 会话样本
- 80 HTTP：内部 wiki 页面（Firmware Patch Policy）

利用链：小模数离散对数 → RC4 会话密钥 → SHELL 帧进 patchd 2.4.1 控制台 →
selftest 泄露堆地址 → stage/hotfix 漏洞开发。

实测：从"拿到 pcap"到"进控制台"约 15 分钟（含协议文档阅读）；
对照纯逆向路线预估 2+ 小时。

## 六、常见陷阱

1. **pcap 端序**：先确认 magic（`d4c3b2a1` = 小端，`a1b2c3d4` = 大端），
   时间戳和长度字段读反会满盘皆错
2. **TCP 流重组**：直接按包拼会乱序/重复——用 scapy 的
   `sessions(TCPSessions)` 或按 seq 排序去重
3. **Keystream 复用**：RC4 每方向独立流——c2s 和 s2c 用同一个 K 但各自
   从头开始，不能用 c2s 的 keystream 解 s2c
4. **帧内多类型**：一个 TCP 段可能包含多个完整帧 + 下一帧的开头——
   按 claim 长度切帧，剩余字节留给下一帧
