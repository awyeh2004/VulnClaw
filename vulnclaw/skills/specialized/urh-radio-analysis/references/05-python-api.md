# URH Python API —— 无 GUI 脚本化分析

> 版本基线：**urh 2.10.0**。本文件所有签名与结论都在 2.10.0 / Windows / 嵌入式 Python 3.13.7 上
> **实际运行验证**过，不是从文档抄的。

URH 的 GUI 对 agent 不可用，但它的 `signalprocessing` 层是**纯 Python + numpy**，可以完全
headless 跑通「采样文件 → 自动检测 → 解调 → 比特/十六进制」这条链。

## 已实测通过的完整往返脚本

下面这段脚本实测输出 `RESULT: ROUNDTRIP OK`，且解出的比特与构造的原始比特**逐位一致**：

```python
"""URH headless 往返: 造 OOK -> 写 .complex -> 载入 -> auto_detect -> 解出比特"""
import os
import numpy as np
from urh.signalprocessing.Signal import Signal
from urh.signalprocessing.ProtocolAnalyzer import ProtocolAnalyzer

SPS = 100
BITS = [1, 0, 1, 1, 0, 0, 1, 0]
path = os.path.join(os.getcwd(), "urh_demo.complex")

# 1) 造 OOK 基带, 写成 URH 原生 .complex (float32 交错 I,Q)
baseband = np.concatenate([np.full(SPS, 0.8 if b else 0.0, dtype=np.float32) for b in BITS])
iq = baseband.astype(np.complex64)
np.column_stack([iq.real, iq.imag]).astype(np.float32).ravel().tofile(path)
# 800 个复采样 -> 6400 字节 (2 * 800 * 4)

# 2) 载入 + 自动检测
sig = Signal(path, "demo")          # (filename, name='Signal', modulation=None,
                                    #  sample_rate=1e6, timestamp=0, parent=None)
sig.auto_detect()                   # -> True; 内含 AutoInterpretation.estimate()
print(sig.samples_per_symbol, sig.modulation_type, sig.center, sig.tolerance)

# 3) 解调成消息
pa = ProtocolAnalyzer(sig)          # (signal, filename=None)
pa.get_protocol_from_signal()
print(len(pa.messages))             # -> 1
print(pa.messages[0].decoded_bits_str)   # -> '10110010'  (= 原始 BITS)
print(pa.decoded_proto_bits_str)    # -> ['10110010']
print(pa.decoded_hex_str)           # -> ['b2']
print(pa.decoded_ascii_str)         # -> ['²']
```

**实测输出**（节选）：

```
bytes       : 6400 == expect 6400
loaded      : sps=100 mod=FSK noise=0.0000
auto_detect : True
detected    : sps=100 mod=ASK center=0.2793651223182678 tolerance=1
messages    : 1
  msg0 decoded_bits_str=10110010
decoded bits: ['10110010']
decoded hex : ['b2']
RESULT: ROUNDTRIP OK
```

注意 `loaded` 行里刚载入时 `modulation_type` 是 `FSK`（默认值），`auto_detect()` 之后才被纠正成
**ASK**——**自动检测是会改结论的，必须调用它，且必须核对**。

## 核心类与已验证签名

| 类 | 入口 | 说明 |
|---|---|---|
| `Signal` | `Signal(filename, name='Signal', modulation=None, sample_rate=1e6, timestamp=0, parent=None)` | 一段 IQ 采样 |
| `Signal` | `Signal.from_samples(samples, name, sample_rate)` | 从 numpy 数组建（**`name` 必传**） |
| `Signal` | `auto_detect(emit_update=True, detect_modulation=True, detect_noise=False) -> bool` | 自动检测调制/噪声/中心/容差 |
| `Signal` | `estimate_frequency()` / `quad_demod()` / `crop_to_range()` / `filter_range()` / `eliminate()` | 频谱估计与区间操作 |
| `ProtocolAnalyzer` | `ProtocolAnalyzer(signal, filename=None)` | 把 Signal 切成消息并解码 |
| `ProtocolAnalyzer` | `get_protocol_from_signal()` | 执行解调 → 生成 `messages` |
| `ProtocolAnalyzer` | `from_binary(...)` / `from_xml_file(...)` / `get_protocol_from_string(...)` | 不从信号而从比特/工程建协议 |
| `ProtocolAnalyzer` | `auto_assign_labels()` / `update_auto_message_types()` | 自动字段类型推断 |
| `ProtocolAnalyzer` | `to_pcapng()` / `to_binary()` / `to_xml_file()` | 导出（含 PCAPNG） |
| `Encoding` | `Encoding(chain=None)` | 解码链，如 `Encoding(["Manchester I", "Edge Trigger"])` |
| `Encoding` | `get_chain()` / `set_chain(...)` / `decode(...)` / `encode(...)` | 链操作与编解码 |
| `Modulator` | `Modulator(name)`；`modulate()` / `get_default_parameters()` / `estimate_carrier_frequency()` | 生成 IQ |
| `Message` | `from_plain_bits_str(...)` / `from_plain_hex_str(...)` / `get_duration()` / `get_byte_length()` | 单条报文 |
| `Message` | `decoded_bits_str` / `plain_bits_str` / `encoded_bits_str` | **属性**，不是 `.bits` |
| `Simulator` | `simulate()` / `start()` / `stop()` / `reset()` / `check_message()` / `send_message()` / `get_full_transcript()` | 离散事件仿真 |

`Message` 上**没有** `.bits`；可用的比特属性只有
`plain_bits` / `plain_bits_str` / `encoded_bits` / `encoded_bits_str` / `decoded_bits` / `decoded_bits_str`。

## 解码链用法（实测）

```python
from urh.signalprocessing.Encoding import Encoding

enc = Encoding(["Non Return To Zero (NRZ)"])
enc.get_chain()                    # -> ['Non Return To Zero (NRZ)']

# ⚠️ encode/decode 收 list[int], 不是字符串
enc.encode([1, 0, 1, 1, 0, 0, 1, 0])   # -> array('B', [1, 0, 1, 1, 0, 0, 1, 0])
enc.decode([1, 0, 1, 1, 0, 0, 1, 0])   # -> array('B', [1, 0, 1, 1, 0, 0, 1, 0])

Encoding(["Manchester I", "Edge Trigger"]).get_chain()
# -> ['Manchester I', 'Edge Trigger']
```

单步编码函数也可单独调用：`code_invert` / `code_differential` / `code_carrier` /
`code_data_whitening` / `code_enocean` / `code_redundancy` / `code_substitution` /
`code_externalprogram` / `code_morse` / `code_edge` / `code_cut` / `code_lsb_first`，
以及 `lfsr`（扰码）、`str2bit` / `bit2str` / `hex2str` / `charstr2bit`。

## 深挖：`auto_detect` 背后是谁

```python
# signalprocessing/Signal.py
def auto_detect(self, emit_update=True, detect_modulation=True, detect_noise=False) -> bool:
    ...
    estimated_params = AutoInterpretation.estimate(self.iq_array, **kwargs)
```

即 `urh.ainterpretation.AutoInterpretation`（同目录还有 `Wavelet.py`）。当自动检测结果可疑时，
可以直接调用它做参数扫描，而不是盲信一次 `auto_detect()`。

## 已知 headless 陷阱（全部实测复现）

| 现象 | 原因 | 处理 |
|---|---|---|
| `Signal.save_as(path)` 进程**直接消失**，退出码 127，**无 traceback** | 该方法在无 GUI 环境下硬崩（2.10.0 实测） | 用 numpy 直写 float32 交错 I/Q；或 `IQArray(...).tofile(path)` |
| `TypeError: Signal.from_samples() missing 1 required positional argument: 'sample_rate'` | 签名为 `(samples, name, sample_rate)`，`name` 不能省 | 显式传 name |
| `AttributeError: 'Message' object has no attribute 'bits'` | 属性名不是 `bits` | 用 `decoded_bits_str` 等 |
| `TypeError: decoded_to_str_list() missing 1 required positional argument: 'view_type'` | 必须给 0/1/2 | 或直接读 `decoded_proto_bits_str` 等属性 |
| `TypeError: cannot use a str to initialize an array with typecode 'B'` | `encode/decode` 要 `list[int]` | 传 `[1,0,1]` |
| 解调结果全是噪声 | 采样文件不是 float32 交错 I/Q | 见 `06-ctf-and-troubleshooting.md` 的文件格式表 |

## 环境注意（Windows）

- Python < 3.13 上装 urh 2.10.0 会走源码编译（PyPI 只有 cp313 的 Windows wheel）。
- 若从带 `PYTHONPATH` 注入的 shell 里跑**系统** Python，可能被外部 `_internal` 目录里的
  `_socket.pyd` 污染而报 `Module use of python311.dll conflicts with this version of Python`。
  URH 的便携版走 `python313._pth` 隔离模式，不受影响；直接跑系统 Python 时先清掉
  `PYTHONPATH` / `PYTHONHOME`。详见 `06-ctf-and-troubleshooting.md`。
