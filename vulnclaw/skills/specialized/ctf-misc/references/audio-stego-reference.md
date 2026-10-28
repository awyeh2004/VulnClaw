# 音频隐写（MP3 / WAV / 波形 / 频谱）实战参考

> 实测来源：2026-10-27 DASBOOK 第 7.3 章连续 3 题（MP3隐写 / 波形图04 / 频谱图 hear_with_your_eyes）
> 全部 11 分钟超时。失败原因已定位，本文按"先便宜后昂贵"的顺序写，照着做可以少走那两个坑。

## 0. 先认格式和元数据（1 分钟）

本机 **没有 ffprobe**（只有 ffmpeg），用 `-i` 看元信息。ffmpeg 不在 PATH 上，用绝对路径或先记下来：

```bash
"<repo>\.ir-tools\bin\ffmpeg.exe" -i input.mp3
"<repo>\.ir-tools\bin\ffmpeg.exe" -i input.wav
```

> 提示词的能力卡里会给出该工具的绝对路径；没有再全盘找。

### ID3v2 标签（MP3 的第一线索）

`mutagen` 未安装，不要 pip 装；纯 Python 解析足够（COMM/TXXX 常带密码提示）：

```python
data = open(path, "rb").read()
if data[:3] == b"ID3":
    size = (data[6] << 21) | (data[7] << 14) | (data[8] << 7) | data[9]
    body, i = data[10:10 + size], 0
    while i + 10 <= len(body):
        fid = body[i:i + 4]
        if not fid.strip(b"\x00"):
            break
        fsz = int.from_bytes(body[i + 4:i + 8], "big")
        payload = body[i + 10:i + 10 + fsz]
        print(fid, payload[:300])       # COMM/TXXX/APIC/USLT 都看
        i += 10 + fsz
```

实测：MP3隐写 的 COMM 帧写着 `password is 123456`——这是 MP3Stego 的口令，不是 flag 本身。

## 1. 追加数据 / 多余 chunk（第二线索，便宜）

```python
data = open(path, "rb").read()
print(len(data))
for magic, name in ((b"PK\x03\x04", "zip"), (b"\x1f\x8b", "gzip"),
                    (b"7z\xbc\xaf", "7z"), (b"Rar!\x1a\x07", "rar")):
    pos = data.find(magic)
    if pos > 0:
        print("suspicious", name, "at", pos)
print(data[-512:])                       # 尾部是否有可疑字符串
```

有 `binwalk` 就 `binwalk -e file`。WAV 还要检查 RIFF chunk 列表
（`LIST`/`INFO`/自定义 chunk 里的 `data` 块之外的内容）。

## 2. 视觉：频谱图与波形图（最常用的两条路）

```bash
FF="<repo>\.ir-tools\bin\ffmpeg.exe"
# 频谱图：文字类隐写（hear_with_your_eyes 这种）看这张
"$FF" -y -i in.mp3 -lavfi "showspectrumpic=s=1920x1080:legend=0:scale=log" spec.png
# 波形图：包络/Morse/静音间隔 看这张
"$FF" -y -i in.wav -lavfi "showwavespic=s=1920x800:colors=white" wave.png
# 光谱图（逐帧瀑布）适合持续时间短、位置不明的信号
"$FF" -y -i in.wav -lavfi "showspectrumpic=s=1920x1080:legend=0" spec_lin.png
```

读图顺序（重要，别一上来就写模板匹配）：

0. **`showspectrumpic` 出来的文字常常上下颠倒**（低频在底、时间轴方向）；
   读不出来先 `PIL.ImageOps.flip(img)` 再试，别急着换参数——实测 2026-10-27
   频谱图题就是靠 `flip` + 3 倍放大才逐字读对；
1. **"自己看图"这个动作有具体工具**，模型本身看不见 PNG：
   ```
   ocr(image_path="spec.png", method="llm",
       prompt="Is any letter or word shaped in this spectrogram? Transcribe it exactly, else answer NO_TEXT.")
   ```
   `method=llm` 才走视觉模型；`auto`/`easyocr` 只认印刷体，对"画出来的字"回空，
   回空不等于图里没字。**用 numpy 读像素、打 ASCII art 不算看图**——2026-10-28
   波形图题连续 4 个 run 就是这样把 11 分钟预算烧光的；
2. 图里字形小/糊时，再用 ffmpeg 裁剪放大：`-vf "crop=w:h:x:y,scale=iw*3:ih*3"`，
   然后**再问一次视觉模型**（同一张整图问不出东西时，窄窗裁切常常一问就出）；
3. 最后才 easyocr（`easyocr.Reader(['ch_sim','en'], gpu=False)`），并给字符白名单
   （hex 题只保留 `0-9a-f{}`）。

实测（频谱图 hear_with_your_eyes）：run 已把字形成功二值化，卡在"用 Windows 字体做模板匹配"
这一步，11 分钟到点被杀。**字形干净时优先视觉读数，不要先写模板匹配**。

## 3. PCM 级分析（转 WAV 之后，最便宜的一批检查）

```bash
"$FF" -y -i in.mp3 -ac 1 -ar 44100 -sample_fmt s16 out.wav
"$FF" -y -i in.mp3 -map_channel 0.0.0 L.wav  # 立体声分声道（旧语法）
"$FF" -y -i in.mp3 -af "pan=mono|c0=c0" L.wav
"$FF" -y -i in.mp3 -af "pan=mono|c0=c1" R.wav
```

```python
import wave, numpy as np
w = wave.open("out.wav"); a = np.frombuffer(w.readframes(w.getnframes()), dtype="<i2")
lsb = a & 1
for start in (0, 1):                     # 采样偏移
    for order in ("msb", "lsb"):         # 位序
        bits = lsb[start:]
        if order == "msb":
            bits = bits[::1]
        packed = np.packbits(bits.astype(np.uint8))
        print(start, order, packed[:80])
```

必查项：

- **LSB**（16-bit PCM，注意位序与起始偏移；WAV 头之外还有 chunk 时要算准 data 起点）；
- **左右声道差分**（`L - R` 常藏波形图/文字）；
- **静音间隔**（幅度阈值切段 → 段长转 Morse：短=点、长=划、更长=词间隔）；
- **过零率 / 包络**（波形图题：把包络画出来就是答案）；
- **反向播放**（`-af areverse`）；
- **变速**（0.5x / 2x 再听或再出频谱）。

## 4. 专用信号

| 信号 | 做法 |
|---|---|
| DTMF 拨号音 | 逐段 Goertzel 检测 697/770/852/941 × 1209/1336/1477/1633 |
| SSTV | 需要 qsstv / rx-sstv（本机未装，先看频谱是否为 1500–2300Hz 扫频） |
| Morse | 频谱图里看长短划，或静音间隔切段 |
| 低频/高频藏字 | `showspectrumpic` 打开 `scale=log`，关注 0–2kHz |

## 5. MP3Stego（MP3 隐写的专用工具，本机已装）

**安装状态（2026-10-27）**：已装到 `E:\vulnclaw\tools\mp3stego\bin\`，能力卡里直接给绝对路径。

- 构建方式：用仓库自带 i686 工具链编译经典 1.1.17 源码，**32 位静态版**；
  64 位构建实测解不出数据（往返失败），不要重建 64 位版。
- 入口（已改为按“exe 所在目录”找 `tables/`，任意 cwd 都能跑）：
  - `E:\vulnclaw\tools\mp3stego\bin\decode.exe -X -P <password> in.mp3`
    → 生成 `in.mp3.txt` 与 `in.mp3.pcm`
  - 同目录 `encode.exe -E hidden.txt -P <password> in.wav out.mp3`（仅自测用）
  - PowerShell 里调用带空格/参数的可执行文件要加调用符：
    `& "E:\vulnclaw\tools\mp3stego\bin\decode.exe" -X -P 123456 in.mp3`
- 自测往返已验证：`encode → decode` 逐字节一致（`flag{roundtrip_test_123}`）。
- 口令线索：先读 ID3v2 COMM/TXXX（见 §0；实测 MP3隐写 写着 `password is 123456`）。

**两个实测坑**：

1. **官方 1.1.19 生成的样本与本机 1.1.17 不兼容**：拿官方 `svega_stego.mp3`
   （口令 `pass`，期望 `Hello world!`）解出的是乱码——这不是口令错，是版本差异。
   遇到同样现象不要换着口令反复试。
2. **不是所有“MP3 隐写”都用 MP3Stego 格式**：若 `-X` 只输出几个字节或乱码，
   说明该题可能是自定义/裸位嵌入（例如直接把 parity 位当文本读）。
   这时回到 §2/§3：频谱图、追加数据、PCM-LSB 才是正确路线；
   手写解析只作为最后的核实手段，不要一上来就写 11 分钟的解码器。

## 6. flag 卫生（三条硬规则）

1. **同一候选不要换外壳反复提交**。实测该 run 把同一串分别包成 `flag{...}` 和
   `DASCTF{...}` 各交一次，两次都拒——浪费了提交次数与时间；
2. **平台在 3 次自动提交后会锁提交**（2026-10-27 实测原文）：
   `after 3 automatic attempts this challenge requires human confirmation before
   another submit. Do not retry automatically.` 锁掉之后训练中被判"未完成"。所以：
   **提交不是验证手段**——每次提交前必须已经做完字符级核对；同一题第 3 次提交
   必须是"已核对到逐字符"的候选，否则把机会留给人工确认；
3. 外壳格式从**题目证据**里取（题目描述、已解出题目的 flag、平台说明），不要猜；
4. 拿到候选先做**字符级核对**：大小写、下划线/空格、`@` 与 `a`、
   `l/1`、`O/0`、`6/b`、`8/b`、`d/b`（OCR 与频谱读图最常见的错），核对后再提交。

实测（频谱图 hear_with_your_eyes，2026-10-27）：run 前两次提交的是 OCR 误读
`e53536b7...`，被拒两次后第 3 次触发平台锁；最终从频谱图逐字复核得到的正确串是
`e5353bb7b57578bd4da1c898a8e2d767`（差异在位置 6：`3` 被读成 `6`）。
**先核对再交，3 次机会很多但错 3 次就没有了。**

同题人工确认后的第 4 次提交（`attempt: 4`）以 **`flag{e5353bb7b57578bd4da1c898a8e2d767}`**
被接受（`accepted: true, is_solved: true`）。两条可复用结论：

- **DASBOOK 书题的外壳是 `flag{...}`**：光谱里写 `flag: <hex>` 时，提交 `flag{<hex>}`
  （不要包 `DASCTF{}` / `CTF2{}`，那是别处练习场的形制）；
- 3 次自动失败后平台只接受**人工确认**的下一次提交，所以前 3 次必须用在
  已经逐字核对过的候选上。

## 7. 时间预算

音频类不是 3 分钟题：

- 频谱/波形读图：**预留 15–20 分钟**（含生成图、放大、读数、核对）；
- 若当前 run 的步数/时间预算只有 ~11 分钟，先做第 0–2 步并把中间产物
  （图、候选、待办）写进黑板，再到点续跑；不要从零重来。

## 8. 最小检查清单（可直接照抄执行顺序）

1. `ffmpeg -i` + ID3 标签；
2. 追加数据/多余 chunk；
3. 频谱图 PNG → 视觉读数（不是 OCR 优先）；
4. 波形图 PNG → 包络/Morse/静音；
5. 转单声道 WAV → LSB（两种位序）/声道差分；
6. 反向、变速、DTMF、SSTV；
7. MP3Stego（需要口令 + 工具，缺工具就上报）；
8. 候选字符级核对后再提交。
