---
name: urh-radio-analysis
description: 无线电/SDR 信号分析与协议逆向 — 用 URH(Universal Radio Hacker) 对 IQ 采样做调制识别、解调、解码链还原、协议字段与校验逆向、信号重放/仿真。覆盖 HackRF/RTL-SDR/LimeSDR/PlutoSDR/AirSpy/USRP 等设备、.complex/.wav 采样文件、Sub-GHz(433/315/868MHz) 遥控与传感器协议。适用于已授权频谱测试、CTF 无线题、自有设备信号复现。
routing:
  target_types: [wireless, ctf]
  task_types: [ctf, reverse]
  aliases: [urh, universal radio hacker, sdr, software defined radio, hackrf, rtl-sdr, rtlsdr, 无线电, 无线信号, 射频, 信号分析, iq 采样, iq采样, 解调, 调制识别, sub-ghz, subghz, 433mhz, 315mhz, 868mhz, 遥控信号, 无线重放, 频谱分析, 无线协议, flipper zero]
---

# 无线电 / SDR 信号分析与协议逆向 (URH)

URH (Universal Radio Hacker) 是开源的无线协议分析工具：把一段 IQ 采样（来自 SDR 设备或文件）
还原成**比特 → 报文 → 协议字段/校验**，并能重新生成信号发射。本 Skill 是 URH 的实战用法库。

## When to Use

- 手上有一份无线采样（`.complex*` / `.wav` / SDR 实时流），要知道它是什么协议、载荷是什么
- Sub-GHz 设备（433/315/868MHz 遥控器、门禁、无线传感器、TPMS）的信号复现与重放
- CTF「硬件/Misc」类无线电题：给了 IQ 文件或调制描述，要提 flag
- 需要构造/篡改无线报文并发射验证（自有设备或已授权频谱）
- 用 URH 做**无 GUI 的脚本化批量分析**（见 `05-python-api.md`）

**Don't use for：**

- WiFi / 蓝牙 / ZigBee 等**标准栈**的协议分析 → 用 Wireshark / Ubertooth / Scapy 等；URH 面向
  **自定义/私有 Sub-GHz 时序协议**
- 纯编码解码（base64/hex）→ 用 `crypto-toolkit`
- 未授权频段的嗅探或发射 —— 见 `06-ctf-and-troubleshooting.md` 的合规边界

## 核心原则

1. **先录/先载，再自动，最后人工确认。** `auto_detect()` 给出的是**假设**，必须看频谱/波形核对。
2. **一次只改一个参数。** 采样率、每符号采样数(sps)、中心/容差互相耦合，同时改就分不清因果。
3. **仿真优先，再上硬件发射。** 用 Simulator 在纯软件里跑通报文交互，最后才 Tx。
4. **发射只对自有/授权设备与频段。** 这是硬约束，不是建议。

## 五步工作流

| 步骤 | 目标 | URH 位置 | 参考 |
|---|---|---|---|
| 1. 采集/加载 | 拿到 IQ 采样 | `Record signal` / 拖入 `.complex`/`.wav` | `01-workflow-sop.md` |
| 2. 参数检测 | 噪声门限、中心、sps、调制 | Signal 视图 → Autodetect | `01-workflow-sop.md` |
| 3. 解调解码 | 波形 → 比特 | Interpretation 视图 + Decoding 链 | `03-modulation-and-decoding.md` |
| 4. 协议逆向 | 比特 → 字段/校验/地址 | Analysis 视图 + awre 引擎 | `01-workflow-sop.md` |
| 5. 生成/发射/仿真 | 复现或篡改报文 | Generator / Fuzzing / Simulator | `04-devices-and-plugins.md` |

## 场景路由

| 场景 | 参考文档 | 核心内容 |
|---|---|---|
| 完整工作流 SOP | `01-workflow-sop.md` | 五步操作细节、判断标准、参数含义 |
| 命令行/批处理采集与发射 | `02-cli-reference.md` | `urh_cli` 全参数表 + 场景配方 |
| 调制类型与解码链 | `03-modulation-and-decoding.md` | ASK/FSK/PSK…、Manchester/NRZ、12 个解码操作符 |
| SDR 设备与插件 | `04-devices-and-plugins.md` | 11 种原生设备、GNU Radio 后端、6 个插件 |
| 脚本化/无 GUI 分析 | `05-python-api.md` | Python API + **已验证**的 headless 往返脚本 |
| CTF 无线题 + 安装排错 | `06-ctf-and-troubleshooting.md` | 采样文件格式、提 flag 套路、安装与常见报错 |

## 调用方式（agent 一律走 CLI，不用 GUI / 不用快捷方式）

任何平台装了 urh 后的通用入口：

```bash
urh          # GUI  (entry point: urh.main:main)
urh_cli -h   # 无 GUI 命令行 (entry point: urh.cli.urh_cli:main)
```

**本机（Windows，用户 `伟`）的便携版 —— agent 直接用这两条绝对路径命令：**

```bash
# 1) urh_cli：命令行采集 / 发射 / 批处理
D:\urh-portable\python\python.exe D:\urh-portable\urh_cli_launch.py -h

# 2) headless 信号分析：直接跑自己的脚本（推荐路线，见 05-python-api.md）
D:\urh-portable\python\python.exe <你的脚本>.py
```

- 自带嵌入式 Python 3.13.7 + urh 2.10.0，**不依赖也不污染系统 Python**（isolated 模式，外部注入的 `PYTHONPATH` 对它无效）。
- `urh_cli_launch.py` 等价于 `Scripts\urh_cli.exe`，但**不依赖 pip 启动器壳里硬编码的解释器路径**，目录搬移后仍可用。
- **不要**调 `Scripts\urh.exe`（GUI，agent 无窗口可用），**也不需要桌面快捷方式**。
- 安装与排错见 `06-ctf-and-troubleshooting.md`。⚠️ PyPI 上 urh 2.10.0 只有 **cp313** 有
  Windows wheel，其他 Python 版本会退化成源码编译并失败。

## Common Pitfalls

1. **把 `auto_detect()` 的结果当成结论。** 它内部走 `AutoInterpretation.estimate()`，在低信噪比或
   非 OOK 信号上会选错调制/中心。务必回看频谱图与波形，必要时手工调 `center` / `tolerance` / `sps`。
2. **`Signal.save_as(path)` 在 headless 下会硬崩。** 实测（2.10.0 / Windows）退出码 127 且**无
   traceback**。要落盘请直接用 numpy 写 float32 交错 I/Q（见 `05-python-api.md`）。
3. **`Message` 没有 `.bits` 属性。** 用 `msg.decoded_bits_str`（解调+解码后）、`msg.plain_bits_str`
   （解调后未解码）或 `msg.encoded_bits_str`。
4. **`ProtocolAnalyzer.decoded_to_str_list(view_type)` 必须传参**（0=bits, 1=hex, 2=ascii）；
   不想传参就直接读属性 `pa.decoded_proto_bits_str` / `pa.decoded_hex_str` / `pa.decoded_ascii_str`。
5. **`Encoding.encode/decode` 收 `list[int]` 而不是字符串**，传 `"1011"` 会 `TypeError: cannot use
   a str to initialize an array with typecode 'B'`。
6. **采样文件布局搞错会让解调结果全是噪声。** `.complex` = **float32 交错 I,Q**，不是 complex64
   直接 `tofile()`。写成 `complex64` 会得到 2 倍长度且完全无法解调。
7. **解码链顺序有语义。** `Invert`/`Differential Encoding`/`Edge Trigger` 等操作符是**按顺序**作用的，
   顺序错了就是解不出。先用内置的 NRZ/Manchester 组合，再逐步加操作符。
8. **发射前不仿真。** 直接 Tx 一个没验证的报文，在真实设备上可能触发未知状态或干扰合法设备。

## Verification Checklist

- [ ] 采样已确认：`sample_rate` 与实际采集一致（不一致则所有时间量都错）
- [ ] 噪声门限落在**波形空白区**（不是信号中），中心线落在符号电平之间
- [ ] `samples_per_symbol` 使每个符号边界清晰可辨（可放大波形目视）
- [ ] 解出的比特串**稳定可重复**（同一份采样解两次结果相同）
- [ ] 解码链变更后解出的报文长度符合预期（如固定长度协议应恒定）
- [ ] 若断言为某已知协议：字段语义（地址/命令/校验）能被采样间的差异解释
- [ ] 发射前已用 Simulator 或空载测试验证
- [ ] 目标频段与设备为**自有或已授权**
