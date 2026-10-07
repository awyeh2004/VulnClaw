# 调制类型与解码链参考

## 调制类型

urh 2.10.0 支持（源码内出现的调制族）：**ASK / OOK / FSK / GFSK / PSK / QAM**。
（`OOK` 是 `ASK` 的 1 bit/symbol 特例，在 URH 中单独作为一个 `modulation_type` 取值。）

| 调制 | 频谱特征 | 典型用途 |
|---|---|---|
| OOK | 单峰，无载波时几乎无能量 | 最廉价遥控器、门磁、无线开关 |
| ASK | 单峰，幅度多电平 | 多档位/多按键遥控 |
| FSK | 双峰，围绕中心对称 | 门禁、无线传感器、TPMS |
| GFSK | 双峰且边缘平滑 | 蓝牙类、CC1101 系列 |
| PSK | 单峰、相位跳变 | 更高数据率的自定义协议 |
| QAM | 单峰、幅度+相位星座 | 一般不用于 Sub-GHz 遥控 |

`bits_per_symbol` 与调制绑定：OOK/2FSK 通常为 1，4FSK/16QAM 为 2 或 4。URH 的
`ProtocolSniffer` 签名里 `modulation_type` 与 `bits_per_symbol` 是**分开**的参数。

## 内置解码链

URH 的默认解码链集合（`settings` / `ProjectManager.load_decodings()` 的 fallback）：

| 解码链 | 说明 |
|---|---|
| `Non Return To Zero (NRZ)` | 电平直接映射比特（1=高，0=低）。**起点，先试它** |
| `Non Return To Zero + Invert` | NRZ 再加 `Invert`，处理反相线路 |
| `Manchester I` | 曼彻斯特，边沿方向编码 |
| `Manchester II` | 曼彻斯特变体 |
| `Differential Manchester` | 差分曼彻斯特，抗极性反转 |

**顺序**：先 `NRZ` 看原始比特长什么样，再按需叠加操作符。Manchester 系列本身已含边沿判定，
通常还要配合 `Edge Trigger`。

## 解码操作符（12 个）

来自 `settings.DECODING_*`，在解码链中**按顺序**作用：

| 操作符 | 作用 | 何时用 |
|---|---|---|
| `Invert` | 整体取反 | 解出来是反的（0/1 颠倒） |
| `Edge Trigger` | 按边沿而非电平判决 | Manchester 类、需要边沿同步 |
| `Differential Encoding` | 差分编码（用相邻变化表示比特） | 差分 Manchester、抗极性反转 |
| `Change Bitorder` | 比特序翻转（MSB/LSB） | 字节内位序反了、`lfsr` 类扰码 |
| `Remove Redundancy` | 去除重复/多数表决比特 | 每比特发 3 次的冗余协议 |
| `Remove Data Whitening (CC1101)` | 去 CC1101 白化 | TI CC1101 系列芯片 |
| `Remove Carrier` | 去除载波/直流分量 | 有强直流偏置的信号 |
| `Substitution` | 码字替换表 | 自定义映射（查表） |
| `External Program` | 调外部程序解码 | 已有专用解码器脚本 |
| `Wireless Short Packet (WSP)` | EnOcean WSP 解码 | EnOcean 无源传感器 |
| `Cut before/after` | 按位置裁剪比特 | 去掉固定前导/尾随 |
| `Morse Code` | 摩尔斯电码 | 手工/业余台信号 |

对应可单独调用的方法：`code_invert` / `code_edge` / `code_differential` / `code_lsb_first` /
`code_redundancy` / `code_data_whitening` / `code_carrier` / `code_substitution` /
`code_externalprogram` / `code_enocean` / `code_cut` / `code_morse`，另有 `lfsr`（扰码）、
`str2bit` / `bit2str` / `hex2str` / `charstr2bit`。

## 常见 Sub-GHz 编码约定（工程经验，非 URH 专有）

> ⚠️ 以下是通用工程常识，**不是** URH 的固有属性，也不保证适用于你的目标设备；
> 只作为"下一步该试哪个操作符"的出发点，最终必须用采样验证。

| 现象 | 常试的解码链组合 |
|---|---|
| 固定前导 + 每次重发完全相同 | `NRZ` → 再考虑 `Remove Redundancy` |
| 解出比特长度是 2 倍预期、成对出现 | `Manchester I` 或 `Manchester II`（+ `Edge Trigger`） |
| 同一按键每次解出结果不同、但相邻变化有规律 | `Differential Encoding` |
| 解出字节内位序明显反了 | `Change Bitorder` |
| 数据看起来像随机噪声但同步头正常 | `Remove Data Whitening (CC1101)` |
| 比特是 3 的倍数且每组重复 | `Remove Redundancy` |

**判据永远是"解释力"**：一套解码链能同时解释多条采样之间的**差异**（哪个字段变、哪个不变、
校验怎么算），才算找对了。

## 扰码 / 校验工具

| 工具 | 位置 | 用途 |
|---|---|---|
| `GenericCRC` | `urh/util/GenericCRC.py` | 穷举 CRC 参数（多项式/初值/反射/异或）匹配未知校验 |
| WSP 校验 | `urh/util/WSPChecksum.py` | EnOcean WSP |
| `ChecksumLabel` | `urh/signalprocessing/ChecksumLabel.py` | 把校验字段挂到消息上参与自动推断 |
| `lfsr` | `Encoding.lfsr` | LFSR 扰码/解扰 |

挑 CRC 的正确姿势：先固定已知字段（地址+命令），只留下末尾 1~2 字节去拟合，参数空间小得多。
