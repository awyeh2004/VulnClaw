# 杂项家族速查 —— 先判家族，再按指针走

很多杂项题的失败点不是技巧不够，而是**没认出这是哪一族**：一开始就去写解码器，而载荷其实
在完全不同的层。这张表只做一件事：用题面/附件的可观测特征把题归到一族，再给该族的入口。

| 可观测特征 | 家族 | 入口 |
|---|---|---|
| 音频 + 频谱图/波形图，或题名带"听/看" | 画出来的字 | `audio-stego-reference.md`；playbook `audio-spectrogram-waveform-drawn-text-vision-route` |
| 音频 + 只有一段音，像摩斯/DTMF/慢放 | 编码在声音里 | `audio-stego-reference.md` 的 PCM 检查段 |
| MP3 附件 + ID3 里有密码字样 | MP3Stego | `audio-stego-reference.md` MP3 段 |
| PDF 附件 | PDF 结构化隐写 | `document-container-forensics.md`；playbook `pdf-structured-stego-triage` |
| docx/xlsx/pptx 附件 | OOXML = zip | `document-container-forensics.md` Office 段 |
| 压缩包 + `7z l` 说加密 | 先判伪加密 | playbook `zip-general-purpose-flag-bit0-in-cd-only` |
| 压缩包 + 需要口令 | 字典/掩码/暴力 | playbook `zip-password-attack-and-crc32-collision` |
| 压缩包 + 给了每项 CRC32 和长度 | CRC 碰撞反推 | playbook `zip-password-attack-and-crc32-collision` |
| 磁盘镜像（img/dd/E01） | 已删除文件 + 时间线 | `document-container-forensics.md` 磁盘段；playbook `disk-image-forensics-fls-icat-carve` |
| pcap/pcapng + USB 抓包 | HID 键鼠 | 键盘：playbook `usb-hid-pcapng-tshark`；鼠标：playbook `mouse-usb-hid-coordinate-drawing` |
| pcap + HTTP 里有 webshell 请求体 | webshell 流量解密 | playbook `godzilla-webshell-pcap-rsa-fermat-shadow`、`666-chopper-webshell-pcap-hidden-jpg-password-en` |
| 两张图（原图 + 加水印图） | 盲水印（频域） | playbook `blind-watermark-frequency-domain` |
| 图片 + IHDR 高度/CRC 异常 | 尺寸篡改 | playbook `dabai-png-height-tampering`、`ctf-png-ihdr-height-tamper` |

## 使用约定

- playbook 用 `lookup_playbook(fingerprint="...")` 取：`fingerprint` 填**题面可观测特征**
  （附件格式 + 工具名 + 报错原文），不要填题名里的中文口号——召回是按声明的 identity token 算的。
- 标注 `📝 draft` 的条目**未在本环境验证过**，按它的步骤做时要自己先验证前提（文件名/工具是否
  存在、格式是否真如它所说）；标注 `✅ validated` 的才是跑通过一次的。
- 技能参考（`*.md` in this dir）是**每轮注入**的确定性文本；playbook 是**召回**出来的，可能不出现。
  所以先读技能参考，再决定要不要查 playbook。
- 任何一路的 flag 候选都必须在本 run 的工具输出里逐字出现过才提交；从题名/章节名补出来的串会被
  提交闸门拒绝（实测拦下过 `flag{air123}`、`flag{pass is air123}` 两次猜测）。
