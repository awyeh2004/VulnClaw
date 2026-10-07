# CTF 无线题、采样文件格式、安装排错与合规

## 采样文件格式（`urh/util/FileOperator.py`）

> ⚠️ **命名反直觉**：后缀里的数字是 **I+Q 合计位宽**，不是单通道位宽。
> `.complex16s` 是"两个 8 位有符号"，不是 16 位。

| 后缀 | 磁盘内容（`IQArray.from_file` 的 dtype） | 每采样字节数 |
|---|---|---|
| `*.complex16u` / `*.cu8` | 两个 **8 位无符号**整数 | 2 |
| `*.complex16s` / `*.cs8` | 两个 **8 位有符号**整数 | 2 |
| `*.complex32u` / `*.cu16` | 两个 **16 位无符号**整数 | 4 |
| `*.complex32s` / `*.cs16` | 两个 **16 位有符号**整数 | 4 |
| `*.complex` | **float32** | 8（2×4） |
| `*.wav` / `*.wave` | WAV 容器（`wave` 模块） | — |
| `*.sub` | Flipper Zero 时序记录（经 `FlipperZeroSub` 插件） | — |

**布局一律是"交错 I,Q"**（`IQArray` 内部存成 `(n,2)`，`[:,0]`=I、`[:,1]`=Q），
行主序即 `[I0, Q0, I1, Q1, …]`。

### numpy 读写配方

`.complex`（**已实测往返成功**）：

```python
import numpy as np

# 写: complex64 数组 -> float32 交错 I,Q
iq = baseband.astype(np.complex64)
np.column_stack([iq.real, iq.imag]).astype(np.float32).ravel().tofile("sig.complex")
# 800 个复采样 -> 6400 字节

# 读: 交错 float32 -> complex64
raw = np.fromfile("sig.complex", dtype=np.float32)
iq  = raw[0::2].astype(np.float32) + 1j * raw[1::2].astype(np.float32)
```

其余整型格式按同一交错原则改 dtype（依据 `from_file` 的 dtype，未逐一实测）：

```python
np.column_stack([iq.real, iq.imag]).astype(np.int8 ).ravel().tofile("sig.cs8")   # complex16s
np.column_stack([iq.real, iq.imag]).astype(np.uint8).ravel().tofile("sig.cu8")   # complex16u
np.column_stack([iq.real, iq.imag]).astype(np.int16).ravel().tofile("sig.cs16")  # complex32s
```

反向导出工具在 `IQArray` 上：`tofile()`、`export_to_wav(filename, num_channels, sample_rate)`、
`save_compressed(filename)`（tar+bz2）。

### 采样率对不上的后果

**这是无线题最常见的坑。** 采样率填错不会报错，只会让解调结果变成噪声或长度诡异。拿到文件
第一件事：**在题目描述/文件名/README 里找 `sample_rate`**；找不到就用"符号宽度应整除"反推：

```
sample_rate ≈ 符号宽度(采样点数) × 符号速率(baud)
对 433.92MHz 遥控器, 常见组合是 sample_rate=2M, sps=100  (=> 20 kbaud 量级)
```

## CTF 无线题解题套路

典型题面：「给你 `signal.complex`（或 `.wav`），找出隐藏的 flag」。

1. **确定采样率**（见上）。没有就给几个量级试探，或直接看波形判断符号宽度。
2. **确定调制**：跑 `auto_detect()`，再用频谱形态核对（见 `01-workflow-sop.md` 的速判表）。
   单峰=OOK/ASK，双峰=FSK。
3. **解调**：`ProtocolAnalyzer(sig).get_protocol_from_signal()` 拿消息。
4. **看比特怎么排**：先看 `plain_bits_str`（未解码），按 8 位一组 `decoded_ascii_str` 看能不能
   读成文本；读不出就依次试 `Invert` / `Manchester I/II` / `Change Bitorder` / `Differential
   Encoding`（见 `03-modulation-and-decoding.md`）。
5. **找 flag 格式**：`flag{...}` / `CTF{...}` 的 ASCII 码点通常是明显的明文段；若无，考虑
   Base64（大小写+数字+`=`）、或题目自定义前缀。
6. **多比特映射**：若 flag 是逐 bit 编码，注意前面的前导/同步码要去掉（用 `Cut before/after`）。

**本机已跑通的纯脚本模板**（把文件换成题给的那份即可）：

```python
from urh.signalprocessing.Signal import Signal
from urh.signalprocessing.ProtocolAnalyzer import ProtocolAnalyzer

sig = Signal("challenge.complex", "chal")
sig.auto_detect()
print("sps=%s mod=%s center=%s tol=%s" % (
    sig.samples_per_symbol, sig.modulation_type, sig.center, sig.tolerance))

pa = ProtocolAnalyzer(sig)
pa.get_protocol_from_signal()
print("messages:", len(pa.messages))
print("bits :", pa.decoded_proto_bits_str)
print("hex  :", pa.decoded_hex_str)
print("ascii:", pa.decoded_ascii_str)
```

跑法（本机便携版）：

```bash
D:\urh-portable\python\python.exe analyze.py
```

> ⚠️ 用**系统** Python 跑时若被 `PYTHONPATH` 注入污染，会报 `python311.dll conflicts`——见下节。

## 安装

### 方式 A：pip（前提是 Python 版本对）

```bash
pip install urh
```

> **Windows 上必须用 Python 3.13。** urh 2.10.0 在 PyPI 上**只有 `cp313-cp313-win_amd64`
> 这一个 Windows wheel**；用 3.10/3.11/3.12 都会退化成下载 sdist 并**源码编译**，没有 MSVC
> 就直接失败。urh 自身声明 `Requires-Python: >=3.9`，但 wheel 覆盖不到。
>
> Linux/macOS 有其他版本 wheel，不受此限。

### 方式 B：便携安装（无需管理员、不动系统 Python）

适用于"系统 Python 坏/版本不对/公司机器不能装"的场景。本机 `D:\urh-portable` 就是这么装的：

```bash
# 1) 干净的 Python 3.13 embeddable（华为镜像)
curl -L -o python.zip "https://mirrors.huaweicloud.com/python/3.13.7/python-3.13.7-embed-amd64.zip"
mkdir python && tar -xf python.zip -C python

# 2) 打开 site 支持: 把 python313._pth 里的 "#import site" 改成 "import site"

# 3) 装 pip（bootstrap.pypa.io 通; 清华/阿里镜像上 get-pip.py 路径 404）
curl -L -o get-pip.py "https://bootstrap.pypa.io/get-pip.py"
./python/python.exe get-pip.py -i https://pypi.tuna.tsinghua.edu.cn/simple

# 4) 装 urh（清华镜像, 约 110MB 依赖: PyQt6-Qt6 78MB + numpy + cython + psutil）
./python/python.exe -m pip install urh -i https://pypi.tuna.tsinghua.edu.cn/simple

# 5) 验证 CLI（agent 用 GUI 无法显示窗口, 一律走 CLI / 脚本）
./python/Scripts/urh_cli.exe -h              # pip 壳, 能用但搬移后失效
./python/python.exe ./urh_cli_launch.py -h   # 引导脚本, 推荐(可搬移)
```

`urh_cli_launch.py` 只有几行（见下方"搬移陷阱"），建好后 `D:\urh-portable\python\python.exe
D:\urh-portable\urh_cli_launch.py -h` 就是本机 agent 的调用姿势；不需要任何快捷方式。

### ⚠️ 搬移陷阱：pip 启动器壳会硬编码解释器路径

`pip` 生成的 `Scripts\urh.exe` / `urh_cli.exe` 是**启动器壳**，里面写死了安装时的
解释器绝对路径。**把便携目录搬移/改名后这两个 exe 会静默失效**——退出码 `1`、**没有任何
输出**（不带 traceback），极易被误判成"安装坏了"。新路径更长，因此也没法原地改字节打补丁。

两种处理方式：

```bash
# 方式 1: 搬移后重跑一次安装, 重写启动器壳（不动依赖）
./python/python.exe -m pip install --force-reinstall --no-deps urh
```

```bat
rem 方式 2 (推荐): 绕开壳, 用运行时解析路径的引导脚本 —— 目录可随意搬移
@echo off
rem 注释只用 ASCII: 控制台是 GBK(936) 而 .bat 是 UTF-8 时,
rem 中文注释会被 cmd 逐字节误解析成命令并报错。
set "PYTHONPATH="
set "PYTHONHOME="
start "" "%~dp0python\pythonw.exe" "%~dp0urh_launch.pyw" %*
```

`urh_launch.pyw` / `urh_cli_launch.py` 只做一件事：`from urh.main import main; main()`
（CLI 版是 `urh.cli.urh_cli.main`，并顺手把 `sys.argv[0]` 设成 `urh_cli` 以让 `-h`
打印干净的 usage）。`%~dp0` 在**运行时**解析，所以整目录可自由搬移。

把镜像写进 `python/pip.ini` 可让后续安装默认走清华：

```ini
[global]
index-url = https://pypi.tuna.tsinghua.edu.cn/simple
trusted-host = pypi.tuna.tsinghua.edu.cn
timeout = 60
```

## 排错

| 报错 / 现象 | 原因 | 处理 |
|---|---|---|
| `ImportError: Module use of python311.dll conflicts with this version of Python` | `PYTHONPATH` 指向某个**别的版本** Python 的运行时目录（内含该版本编译的 `_socket.pyd` 等），它盖掉了当前解释器的标准库扩展。**不是 Python 装坏了** | 清环境：`set PYTHONPATH=` + `set PYTHONHOME=` 后再跑；或用不受影响的便携版 |
| `pip install urh` 卡在 building wheel / `Microsoft Visual C++ 14.0 required` | Python 不是 3.13，PyPI 无对应 Windows wheel | 装 Python 3.13，或用 `05-python-api.md` 的便携方案 |
| GUI 起来但设备列表为空 | 驱动没装 / 设备被其他程序占用 | Windows 上 RTL-SDR/HackRF 通常需用 Zadig 装 WinUSB 驱动；确认没有 SDR# 等程序占着设备 |
| `Signal.save_as()` 进程无输出直接退出 | 2.10.0 在无 GUI 环境下该方法硬崩 | 用 numpy 直接落盘（见上文 numpy 配方） |
| 搬移/改名便携目录后 `Scripts\urh.exe` 直接退出、无任何输出 | pip 启动器壳把安装时的解释器绝对路径写死在 exe 里；新路径更长无法原地打补丁 | 重跑 `pip install --force-reinstall --no-deps urh` 重写壳，或改用 `%~dp0` 引导脚本（见"搬移陷阱"） |
| `.bat` 里的中文注释报"不是内部或外部命令" | 控制台代码页是 GBK(936) 而 `.bat` 存成 UTF-8，中文被逐字节误解析 | `.bat` 注释只用 ASCII（`chcp 65001` 救不回已读入的行） |
| 解出的比特每次都不一样 | 采样率/sps 不对，或信噪比太低，或符号边界没对齐 | 回步骤 2 重核参数；先保证波形目视清晰 |
| 解出的长度固定但内容乱码 | 编码链错了 | 逐项试 `Invert`/`Manchester`/`Change Bitorder`/`Differential Encoding` |

## 合规边界（硬约束）

- **只对自有设备，或书面授权的目标**做采集与发射。未授权频段的发射在多数司法辖区**违法**。
- 发射前的工程自保：优先用**假负载 / 屏蔽箱**，功率压到最低，确认不会干扰邻近合法系统。
- **绝对不要**在 航空、GPS、应急通信（含 121.5/243MHz）、蜂窝上行、医疗频段 做发射测试。
- 采集（RX）本身也可能涉及通信秘密，同样以授权为前提。
- CTF/靶场题在题目给定的文件或虚拟环境里做，不要拿真实空口信号当练习对象。
