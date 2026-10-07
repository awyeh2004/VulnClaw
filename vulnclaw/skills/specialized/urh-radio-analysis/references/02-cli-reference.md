# urh_cli 命令行参考

> 入口：`urh_cli`（`urh.cli.urh_cli:main`）。GUI 入口是 `urh`（`urh.main:main`）。
> 下表的参数名与取值**直接来自 `urh_cli -h` 的实测输出**与 `urh/cli/urh_cli.py` 的 argparse 定义。

## 完整用法（实测输出）

```
usage: urh_cli [-d DEVICE] [-di DEVICE_IDENTIFIER] [-db {native,gnuradio}]
               [-f FREQUENCY] [-s SAMPLE_RATE] [-b BANDWIDTH] [-g GAIN]
               [-if IF_GAIN] [-bb BASEBAND_GAIN] [-a]
               [-fcorr FREQUENCY_CORRECTION] [-cf CARRIER_FREQUENCY]
               [-ca CARRIER_AMPLITUDE] [-cp CARRIER_PHASE] [-mo MOD_TYPE]
               [-bps BITS_PER_SYMBOL] [-pm PARAMETERS [PARAMETERS ...]]
               [-sps SAMPLES_PER_SYMBOL] [-bl BIT_LENGTH] [-n NOISE]
               [-c CENTER] [-cs CENTER_SPACING] [-t TOLERANCE] [--hex]
               [-e ENCODING] [-m MESSAGES [MESSAGES ...]] [-file FILENAME]
               [-p PAUSE] [-rx] [-tx] [-rt RECEIVE_TIME] [-r] [-h] [-v]
               [project_file]
```

## 参数分组（按功能归类）

### SDR 设备参数

| 参数 | 含义 |
|---|---|
| `-d DEVICE` | 设备名，如 `HackRF` / `RTLSDR` / `LimeSDR` / `PlutoSDR` / `USRP` / `SoundCard` |
| `-di DEVICE_IDENTIFIER` | 多设备时指定串号 |
| `-db {native,gnuradio}` | 后端：`native`（自带驱动）或 `gnuradio` |
| `-f FREQUENCY` | 中心频率 |
| `-s SAMPLE_RATE` | 采样率 |
| `-b BANDWIDTH` | 带宽 |
| `-g GAIN` | RF 增益 |
| `-if IF_GAIN` | 中频增益（仅部分设备，如 HackRF） |
| `-bb BASEBAND_GAIN` | 基带增益（HackRF，仅 RX） |
| `-a` | 自动增益标志 |
| `-fcorr FREQUENCY_CORRECTION` | 频率校正（晶振偏差 ppm） |

### 调制参数

| 参数 | 含义 |
|---|---|
| `-mo MOD_TYPE` | 调制类型（`ASK` / `OOK` / `FSK` / `GFSK` / `PSK` / `QAM`） |
| `-cf CARRIER_FREQUENCY` | 载波频率（相对中心） |
| `-ca CARRIER_AMPLITUDE` | 载波幅度 |
| `-cp CARRIER_PHASE` | 载波相位 |
| `-bps BITS_PER_SYMBOL` | 每符号比特数 |
| `-pm PARAMETERS ...` | 调制参数的附加键值 |
| `-sps SAMPLES_PER_SYMBOL` | 每符号采样数 |
| `-bl BIT_LENGTH` | 比特长度（符号持续时间） |

### 解调 / 嗅探参数

| 参数 | 含义 |
|---|---|
| `-n NOISE` | 噪声门限 |
| `-c CENTER` | 判决中心 |
| `-cs CENTER_SPACING` | 中心间距 |
| `-t TOLERANCE` | 符号长度容差 |
| `--hex` | 以十六进制呈现数据 |

### 数据 / 动作

| 参数 | 含义 |
|---|---|
| `-e ENCODING` | 解码链（如 `"Non Return To Zero (NRZ)"`） |
| `-m MESSAGES ...` | 要发送的报文（一个或多个） |
| `-file FILENAME` | 读/写的信号文件 |
| `-p PAUSE` | 报文之间的间隔 |
| `-rx` | 接收模式 |
| `-tx` | 发送模式 |
| `-rt RECEIVE_TIME` | 接收时长 |
| `-r` | 附加开关（见 `urh_cli.py` 实际定义） |
| `project_file` | 位置参数：直接运行一个已保存的 URH 工程 |

## 调用链（便于排错时定位）

`urh/cli/urh_cli.py` 内部按顺序构造各部件，出错时报错点基本落在这里：

```
create_parser() -> parse_project_file()
                -> build_device_from_args()
                -> build_backend_handler_from_args()
                -> build_modulator_from_args()
                -> build_protocol_sniffer_from_args()
                -> build_encoding_from_args()
                -> read_messages_to_send() -> modulate_messages()
```

设备致命错误由 `on_fatal_device_error_occurred()` 上报；进度条为 `cli_progress_bar()`。

## 场景配方（模板）

> ⚠️ 以下为**参数模板**：请按实际设备/频段替换，并且**必须接上对应 SDR 硬件**才能跑通。
> 它们没有在无硬件环境下实测（本机验证范围见 `05-python-api.md`）。

**接收并落盘一段 433.92MHz OOK 信号**

```bash
urh_cli -d HackRF -db native \
        -f 433.92M -s 2M -b 2M -g 32 \
        -mo OOK -sps 100 -n 0.005 -c 0.05 -t 20 \
        -rx -rt 5 -file capture.complex
```

**把已知报文发射出去（重放）**

```bash
urh_cli -d HackRF \
        -f 433.92M -s 2M -g 40 \
        -mo OOK -sps 100 -bl 0.0001 \
        -e "Non Return To Zero (NRZ)" \
        -m 1011001000110101 -tx -p 0.05
```

**跑一个已保存的 URH 工程（用工程里的设备/调制/报文设置）**

```bash
urh_cli myproject.urh            # 位置参数
```

**先看帮助确认你这台机器上的取值范围**

```bash
urh_cli -h          # 参数与取值以本机实测为准
```

## 注意

- `-rx` / `-tx` 是**方向开关**；发送前务必确认频段与目标授权（见 `06-ctf-and-troubleshooting.md`）。
- `-s`（采样率）必须与信号带宽匹配：低于信号带宽会混叠，远高于则浪费算力并引入更多噪声。
- `-rt`（接收时长）要覆盖**完整的一次报文重复周期**，否则可能只录到半条。
- 文件后缀决定编码：`.complex` 是 float32，`.cs8`/`.cu8` 是 8 位，见 `06-ctf-and-troubleshooting.md`。
