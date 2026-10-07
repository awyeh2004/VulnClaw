# SDR 设备、后端与插件

## 原生设备支持（`urh/dev/native/`）

urh 2.10.0 自带以下设备后端（文件名即设备名）：

| 设备类 | 收/发 | 备注 |
|---|---|---|
| `RTLSDR` | 仅收 | 最便宜的入门设备，**不能发射** |
| `RTLSDRTCP` | 仅收 | 走 `rtl_tcp` 远程/网络化的 RTL-SDR |
| `AirSpy` | 仅收 | 灵敏度好，**不能发射** |
| `SDRPlay` | 仅收 | RSP 系列，**不能发射** |
| `HackRF` | 收+发 | Sub-GHz 渗透最常用的收发一体设备 |
| `LimeSDR` | 收+发 | 全双工，带宽大 |
| `PlutoSDR` | 收+发 | 性价比高的收发一体设备 |
| `BladeRF` | 收+发 | 收发一体 |
| `USRP` | 收+发 | Ettus，高端 |
| `Rad1o` | 收+发 | 基于 HackRF 的徽章板 |
| `SoundCard` | 收+发 | **用声卡做 IQ**，适合低频/有线场景与无 SDR 时的验证 |

> **只分析不发射**的场合，`RTLSDR` 足够；**要重放**就必须有 `HackRF` / `LimeSDR` /
> `PlutoSDR` / `BladeRF` / `USRP` / `SoundCard` 这类带 TX 的设备。

设备能力与取值范围在 `urh/dev/config.py` 的 `DEVICE_CONFIG` 里定义（含
`DEFAULT_FREQUENCY` / `DEFAULT_SAMPLE_RATE` / `DEFAULT_BANDWIDTH` / `DEFAULT_GAIN` /
`DEFAULT_IF_GAIN` / `DEFAULT_BB_GAIN` / `DEFAULT_FREQ_CORRECTION` 等默认值）。
选设备前先查这里的上下限，**不要凭记忆填参数**——不同设备的 `center_freq` / `sample_rate` /
`bandwidth` 范围差异很大。

## 后端：native vs GNU Radio

- **`native`**（默认）：URH 直接调用设备厂商的驱动库，无额外依赖，最省事。
- **`gnuradio`**：走 GNU Radio 的源/汇。设备支持更广（含 GNU Radio 社区实现的设备），
  代价是要装 GNU Radio 环境。相关代码在 `urh/dev/gr/`（`ReceiverThread` / `SenderThread` /
  `SpectrumThread`）。

命令行用 `-db native` 或 `-db gnuradio` 选择。

## 插件（`urh/plugins/`）

| 插件 | 用途 |
|---|---|
| `FlipperZeroSub` | **读写 Flipper Zero 的 `.sub` 文件** —— 把 Flipper 录的信号直接拖进 URH 分析，或把 URH 分析结果导出给 Flipper 发射 |
| `RfCat` | 对接 RFCat 固件的 CC1111/CC1110 dongle（可收发 Sub-GHz） |
| `NetworkSDRInterface` | 通过网络访问远端 SDR（类似 rtl_tcp 的通用化） |
| `InsertSine` | 向信号里插入正弦分量（合成/调试用） |
| `MessageBreak` | 在消息边界处插入/处理间隔 |
| `ZeroHide` | 零值隐藏（减少存储/展示冗余） |

`PluginManager` 负责加载；设置界面在各插件目录的 `settings.ui`。

### Sub-GHz 实战中的插件组合

对 433/315/868MHz 这类 Sub-GHz 目标，最常见的一条链是：

```
Flipper Zero 录一段        → FlipperZeroSub 插件导入 .sub → URH 分析
或 RfCat 实时收发          → RfCat 插件
或 HackRF 直采             → 原生后端
```

`FlipperZeroSub` 的价值在于：**Flipper 的 `.sub` 是原始时序记录**，导入 URH 后能直接进
"参数检测 → 解码链 → 协议逆向"流程，不用自己写解析器。

## 远程 / 无本机硬件的情形

没有 SDR 硬件时，三条可行路径：

1. **纯文件分析** —— 拿到别人给的 IQ 文件，走 `05-python-api.md` 的 headless 链路（本机已实测）。
2. **`SoundCard` 设备** —— 用声卡当 ADC/DAC，可覆盖音频段的"有线无线"信号（这也是 URH
   教程里经典的入门方式）。
3. **`NetworkSDRInterface` / `RTLSDRTCP`** —— 把远端设备的流引进来（需网络可达）。
