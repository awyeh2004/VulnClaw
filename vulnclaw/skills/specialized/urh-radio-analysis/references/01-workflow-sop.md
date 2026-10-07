# URH 五步工作流 SOP

GUI 视图与代码模块的对应关系（来自 urh 2.10.0 包结构）：

| 视图 | 对应模块 | 用途 |
|---|---|---|
| Signal | `ui/ui_main.py`, `signalprocessing/Signal.py`, `Spectrogram.py` | 看波形/频谱、定噪声门限与中心、设 sps 与调制 |
| Interpretation | `ui/ui_tab_interpretation.py`, `signalprocessing/Encoding.py`, `Message.py` | 切消息、加解码链、把比特变成可读的字段 |
| Analysis | `ui/ui_analysis.py`, `ProtocolAnalyzer.py`, `MessageType.py`, `FieldType.py`, `ChecksumLabel.py` | 字段类型、校验、消息类型、awre 自动逆向 |
| Generator / Fuzzing | `ui/ui_generator.py`, `ui/ui_fuzzing.py`, `Modulator.py` | 生成/篡改报文，扫参数域 |
| Simulator | `ui/ui_simulator.py`, `simulator/` | 纯软件跑报文交互，不碰硬件 |
| Send/Receive | `ui/ui_send_recv*.py`, `dev/` | 设备参数与实时收发 |

---

## 步骤 1 — 采集 / 加载

**实时采集**：`Send/Receive` 视图选设备（见 `04-devices-and-plugins.md`），设 `center_freq`、
`sample_rate`、`bandwidth`、增益，录制到文件。**先宽后窄**：先大带宽粗看频谱，定位到目标后
把 `sample_rate` 降到刚够覆盖信号（降采样率 = 降噪声、提速）。

**文件加载**：直接打开 `.complex` / `.complex16s` / `.complex16u` / `.complex32s` / `.complex32u`
/ `.wav`。格式细节见 `06-ctf-and-troubleshooting.md`。**第一件事是确认 `sample_rate` 填对了** ——
填错则后面所有时间量（符号宽度、报文长度）全错。

## 步骤 2 — 参数检测（决定成败的一步）

调用 **Autodetect**（底层就是 `Signal.auto_detect()` → `AutoInterpretation.estimate()`）。它一次性给出：

| 参数 | 含义 | 判断标准 |
|---|---|---|
| `noise_threshold` | 噪声门限（幅度） | 必须落在**波形空白区**，不能切进信号 |
| `center` | 判决中心（0/1 之间的分界） | 落在两个符号电平**正中** |
| `samples_per_symbol` | 每符号采样数 | 放大波形后每个符号边界应清晰、等宽 |
| `tolerance` | 允许的符号长度抖动 | 符号长度不均时调大 |
| `modulation_type` | 调制类型 | 与频谱形态一致（见下表） |

**必须人工核对。** 实测中，一个纯 ASK 的合成信号在**载入时** `modulation_type` 报告为 `FSK`，
`auto_detect()` 之后才纠正为 `ASK`——所以"没调 auto_detect"和"调了不看"都会错。

频谱速判（用于核对自动结果）：

| 频谱形态 | 通常对应 |
|---|---|
| 单峰、无载波时近乎无能量 | **OOK / ASK**（有载波=1，无载波=0） |
| 双峰、围绕中心对称 | **FSK / GFSK**（两个频偏点） |
| 单峰但相位在跳变 | **PSK** |
| 平坦宽带噪声状 | 扩频或噪声，**不是**简单时序协议 |

## 步骤 3 — 解调 / 解码

`ProtocolAnalyzer.get_protocol_from_signal()` 把信号按检测参数切成 **Message** 列表。每个
Message 有三层比特：

| 属性 | 阶段 |
|---|---|
| `plain_bits_str` | 解调后的原始比特（未解码） |
| `decoded_bits_str` | 应用解码链后的比特 |
| `encoded_bits_str` | 编码链编码后的比特（生成用） |

**逐步加解码链**：从内置的 `Non Return To Zero (NRZ)` 起步，一次加一个操作符
（`Invert` / `Differential Encoding` / `Remove Redundancy` / `Remove Data Whitening (CC1101)` /
`Change Bitorder` / `Edge Trigger` …），每次看解出的报文是否**变得更稳定/更可读**。操作符与
典型协议见 `03-modulation-and-decoding.md`。

## 步骤 4 — 协议逆向

在 Analysis 视图，URH 会自动推断字段类型并运行 `awre` 引擎：

| awre 引擎 / 模块 | 作用 |
|---|---|
| `FormatFinder` / `ProtocolGenerator` | 从多条报文推断字段布局、生成协议描述 |
| `AutoAssigner` | 自动把标签分配到消息上 |
| `MessageTypeBuilder` | 按取值把报文分组为"消息类型" |
| `AddressEngine` | 识别地址字段（多设备场景的关键） |
| `ChecksumEngine` / `LengthEngine` / `SequenceNumberEngine` | 识别校验/长度/序号字段 |
| `CommonRange` / `Histogram` / `Preprocessor` | 统计与预处理 |

配合工具：`util/GenericCRC.py`（CRC 参数穷举）、`util/WSPChecksum.py`（EnOcean WSP 校验）、
`ChecksumLabel` / `FieldType` / `MessageType` / `ProtocolGroup`。

**逆向的判据**：同一设备重复采集 → 应有一段字段**恒定**（地址/设备 ID），一段**随按键变化**（命令），
一段**满足固定关系**（校验）。采样≥3 条才能开始区分。

## 步骤 5 — 生成 / 发射 / 仿真

1. **Simulator 优先**：在 `simulator/` 里用 Participant / Rule / Message 搭出设备交互，
   `start()` / `simulate()` / `get_full_transcript()` 看逻辑是否闭合。纯软件，零风险。
2. **Generator**：按目标报文的调制参数生成 IQ。`Modulator` 提供 `get_default_parameters()`、
   `estimate_carrier_frequency()`、`modulate()`。
3. **Fuzzing**：扫字段/校验域。**只对自有或已授权设备**。
4. **Tx**：用 `urh_cli ... -tx`（见 `02-cli-reference.md`）或 Send/Receive 视图发射。

⚠️ 发射是**唯一不可撤回**的步骤。频段合规、功率、目标授权三者确认无误再执行。

---

## 参数耦合速查

```
samples_per_symbol  ← 由 sample_rate 与符号速率共同决定
                    符号速率 = sample_rate / samples_per_symbol
symbol 边界         ← tolerance 放宽可吸收抖动, 但过宽会合并相邻符号
noise_threshold     ← 影响比特判决, 调高 = 更容易判 0
center              ← 0/1 判决门限, 应与噪声门限拉开
```

改任何一个之前，先记录当前的**解出比特串**作为基线，改动后对比是否更稳定。
