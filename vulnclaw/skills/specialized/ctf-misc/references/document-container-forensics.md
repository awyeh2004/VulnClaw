# 文档/容器类隐写与取证：PDF、Office、压缩包、磁盘镜像

面向"给一个文件，flag 藏在里面"的题型。核心原则：**先穷尽结构化位置，再谈破解**。
绝大多数题不需要算法突破，只需要把文件按格式切开、逐个流解压、逐个元数据字段读完。

## 0. 十秒钟分诊（按成本从低到高）

```bash
file 附件                     # 真实类型，和扩展名不符就换思路
binwalk 附件 | head -40       # 嵌入/追加/复合
strings -n 6 附件 | head -50  # 明文残留
exiftool 附件                 # 作者/注释/时间/自定义标签
```

只要这四步里有任何一条给出 flag 形状的字符串，就直接核对提交，不要继续"深入分析"。

## 1. PDF

PDF 的载荷几乎总在这几个位置，按顺序看：

| 位置 | 怎么看 | 说明 |
|---|---|---|
| 未压缩的字符串对象 | `strings f.pdf \| grep -i "flag\|pass"` | 最便宜 |
| `/Info` 与 `/Metadata` | `exiftool f.pdf`、`pdfinfo` | 作者/主题/关键词常直接放 flag |
| 注释 `/Annots` | `grep -a "/Annots" -A5 f.pdf` | 批注内容 |
| 对象流 `ObjStm` | 解压后看纯文本 | 现代 PDF 把正文压进 ObjStm，`strings` 看不到 |
| 内容流 `FlateDecode` | `zlib.decompress(stream)` | 文本/图片都在这里 |
| 图片 XObject | 抽出来丢给 `ocr` 看 | 有时 flag 是渲染出来的字 |
| 增量更新残留 | 比对 `/Prev` 与旧对象 | 改过的 PDF 会保留旧版本对象 |
| 末尾追加数据 | `tail -c 2000 f.pdf \| xxd` | `%EOF` 之后还有东西 |

解析模板（不解压也能先看结构）：

```python
import re, zlib
d = open("f.pdf", "rb").read()
# 所有流对象的原始字节
for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", d, re.S):
    raw = m.group(1)
    for data in (raw,):
        try:
            out = zlib.decompress(data)
            print("FLATE:", out[:400])
        except Exception:
            pass
# 未压缩字符串
print([s[:200] for s in re.findall(rb"\(([^)]{3,200})\)", d)][:40])
```

**空白/制表符编码**（波形题常考的近亲）：文本行尾的空格数、行首 tab 数可以编码
比特。逐行统计 `line.count(" ")`、`line.count("\t")`，把奇偶或数值映射成 0/1，
按 8 位一组解 ASCII。判据是"数量分布集中在 2~8 之间且与正文无关"。

## 2. Office / 文档（Word、Excel、PPT）

`.docx/.xlsx/.pptx` 都是 zip：

```bash
unzip -o f.docx -d f_docx
grep -ril "flag" f_docx | head
# 隐藏文字、批注、修订、页眉页脚都在 XML 里
grep -a "w:vanish\|w:comment\|w:instrText" f_docx/word/document.xml | head
```

要点：
- `word/document.xml` 里 `w:vanish`（隐藏文字）、`w:instrText`（域代码）常是藏点；
- `word/comments.xml`、`word/footnotes.xml`、`docProps/*.xml` 都要看；
- 图片在 `word/media/`，抽出来按图片隐写处理；
- 老式 `.doc`（OLE 复合文档）用 `olefile` 看 `WordDocument` 流，或 `strings -el`（UTF-16）。

## 3. 压缩包

| 现象 | 判断 | 处理 |
|---|---|---|
| `7z l` 报 "Encrypted"，但数据段没有加密头 | 伪加密 | 改标志位（见下） |
| 每个文件 CRC32 已知，内容很短 | CRC32 碰撞 | 爆破内容，见 `encoding-chain-reference.md` |
| 有密码但题目给了提示 | 字典/掩码/暴力 | `zip2john` → `john`，或 `fcrackzip -D -p 字典` |
| 包里还有包 | 嵌套 | 递归解，注意 zip 套 zip 的伪加密每层都要清 |

伪加密的判据永远是**本地头与中央目录标志位不一致**：

```python
import struct
d = bytearray(open("f.zip", "rb").read())
# 本地文件头 flag 在 PK\x03\x04 + 6；中央目录 flag 在 PK\x01\x02 + 8
for magic, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
    i = 0
    while (i := d.find(magic, i)) != -1:
        print(magic, hex(struct.unpack("<H", d[i+off:i+off+2])[0]))
        i += 4
```

修复只需清掉中央目录的第 0 位：`d[cd+8:cd+10] = struct.pack("<H", flag & ~1)`。
解压时按中央目录给的 `csize/usz/crc` 与 `lho` 偏移取数据，用 `zlib.decompress(buf, -15)`
解 raw deflate，最后 `zlib.crc32(out) == crc` 自校验——**校验通过再谈提交**。

## 4. 磁盘/镜像取证

```bash
mmls disk.img              # 分区表
fls -r -o 2048 disk.img    # 递归列文件（offset 来自 mmls）
icat -o 2048 disk.img 3 > out.bin   # 按 inode 取文件
photorec / testdisk        # 删除文件雕刻
```

要点：
- **被删除的文件优先**：`fls -d` 只看已删除项；
- 文件雕刻（carve）看文件头签名，`binwalk -e` 与 `forensic-carve` 都行；
- Windows 镜像看注册表 `SAM/SYSTEM/SOFTWARE`，`regipy` 已在 `.ir-tools` 里；
- 时间线常常就是答案（题目问"最先/最后"）。

## 5. 判据与自检（提交前必做）

- flag 候选必须**在本次 run 的工具输出里逐字出现过**，不能靠题名/章节名补；
- 从图片或文档渲染图读出的字符要二次确认（6/5、0/O、1/l、}/]）；
- 解压/解码成功有客观信号（crc 校验、zlib 无异常、magic 头正确），
  拿这个信号当"读到了"的依据，而不是"看起来像"。

## 6. 网络受限时的替代路径

题目附件是最短路径。只有在附件里确实挖空之后，才去做外部检索：

```
fetch("https://www.bing.com/search?q=<题名+关键词>")
```

检索到的 flag 对动态实例无效，**价值只在方法**：把别人的步骤在本机对本题重跑一遍，
用本题的证据重新产出 flag。查不到就换关键词（用报错原文/函数名/文件名，而不是中文题名）。
