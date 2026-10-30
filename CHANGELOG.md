<details open>
<summary><strong>Unreleased</strong> — Windows 零安装工具箱（机房不能装东西时的兜底）</summary>

- **背景**：现场赛可能只给机房 Windows PC，不能装软件、不保证有 Python，靶机类型未知。
- **新增 `scripts/ctf_win_toolbox.ps1`**（只依赖 Windows 自带能力：PowerShell 5.1 + .NET + `tar.exe`）：
  `info`（魔数/哈希/内嵌签名偏移/PNG IEND 之后追加的数据）、`strings`、`carve`（binwalk 替代，含 ZIP 的 EOCD 修正）、
  `lsb`（内联 C# 读位面，zsteg 替代）、`tail`、`unpack`（`tar.exe` 解 zip/tar/gz）、`b64`/`hex` 编解码、`scan`。
- **三个 5.1-only 缺陷是边写边测出来的**（都写进测试，避免在赛场才炸）：`[Convert]::FromHexString` 是 .NET 5+ API（5.1 没有）；
  函数参数名 `$input` 撞 PowerShell 自动变量（b64/hex 静默无输出）；GIF 魔数写成奇数个十六进制字符会让 `Substring` 抛异常、连累整个 `info`。
- **`carve` 切 ZIP 曾丢掉 EOCD**（止于下一个签名，而 EOCD `504B0506` 不是新头）→ tar.exe 能容忍、Python `zipfile` 判非法；
  现在按 EOCD 的注释长度补回。
- **测试** — `tests/scripts/test_ctf_win_toolbox.py` 5 例（help/info+PNG 尾部/carve 出可读 zip/hex+b64 往返/LSB 读出构造的 flag），
  实测 subshell 输出是 GBK，测试按多编码回退解码。
- **配套现场包**（在 `E:ulnclaw\work\capsule\`，不入库）：知识胶囊 5.0MB、命令速查、离线编码转换器（含自动多层解码）、
  免安装 Python 3.12 + pillow/pycryptodome/requests + 7zr.exe。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 离线「现场知识胶囊」：机房只给浏览器时，把 999 篇知识压成一个 HTML</summary>

- **背景**：2026-11-01 廊坊现场赛必须用机房 PC，VulnClaw 的运行环境（CUDA torch、本地模型、`E:` 盘布局、配置、playbook 库）带不过去；机房常只放行比赛平台。需要一个"不装任何东西、断网也能用"的东西。
- **新增 `scripts/build_field_capsule.py`**：把 `vulnclaw/skills` 与 `~/.vulnclaw/playbooks` 的当前内容压成**单个 HTML**（全内嵌，无 CDN、无 `fetch`——`file://` 下 XHR 会被拦），带全文搜索（`Ctrl+K`）、类型筛选、只看 validated、左侧技能组/高频词跳转。
- **本次产出**：5.0 MB 单文件，999 篇 = 708 条经验笔记（642 validated）+ 59 个技能 + 224 份参考文档；`node --check` 通过，实测 `blind watermark` / `提示词注入` / `CRC32` / `pickle` 等检索命中合理。
- **两个静默失败模式已用测试锁住**（`tests/scripts/test_build_field_capsule.py`）：笔记里出现 `</script>` 会提前闭合脚本块（页面"能打开"但没有数据），裸 `</` 同理会截断解析；另一条验证内嵌 payload 仍是合法 JSON 且文档数正常。
- **附带发现**（写进 `E:\vulnclaw\work\LANGFANG-FIELD-PLAN.md`）：`vulnclaw web` 可用但不适合当"聊天"用——它是**下任务 + SSE 流式回放**（`/api/tasks/run`，target+prompt+options），且**没有附件上传接口**；公网暴露需 token（非 loopback Host 强制鉴权，已实测），但等于把 `python_execute`/`shell_command` 开放到公网，方案里写了轮换与用完即删的做法。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — OCR「读到字 ≠ 读对了」：flag 读坏时自动复核 · 删掉从未工作的 Windows OCR 分支</summary>

- **问题（实测坐实）**：旧逻辑只在「本地引擎一个都没读到字」时才升级到视觉模型。但 OCR 最典型的错误是**字形替换**——真值 `flag{easyocr_ok}` 被 easyocr 读成 `flagleasyccr_ok}`（两处替换 + 丢左括号）。这种串"看着像 flag、平台永远判不过"，却因为"非空"被当成成功结果直接返回，从不复核。这正是"第一个引擎错了怎么办"的答案所在，而不是去做短路。
- **修法**：`auto` 模式新增 `_flag_read_is_suspect()`——本地读到的文本里出现**粘连的 flag 形态**（`flag`/`ctf`/`dasctf`/`ctf2`/`qwb` 直接接花括号或再接词字符，如 `flagleasyccr_ok}`、`flag{easyocr_ok`）且**没有完整 flag 形态**时，视为可疑，额外调一次视觉模型复核，并在输出里写明 `cross-check: the local read looks like a mangled flag`。散文里的 "submit the flag" 不触发（词后有分隔符）。
- **不做的**：不加"第一个引擎成功就短路"。实测 auto 相比单跑 easyocr 只多 **0.2–0.4 s**（那还是 PowerShell 子进程的钱），省这点时间却丢掉唯一的交叉验证不划算。
- **删掉 Windows.Media.Ocr 分支**：它写的是 `$r=await $b`，而 PowerShell 5.1 没有 `await` 关键字（实测 `await : 无法将"await"项识别为 cmdlet`），**从未产出过任何文本**；失败时连 `[!]` 行都不写，静默得像"这台机器没有第二个引擎"，却每次白花 0.2–0.4 s 启动 PowerShell。本机实测只装了 `ja` / `zh-Hans-CN` 两个 OCR 包（无 en-US），即便修好 `AsTask` 反射链，读 ASCII flag 也会得到 `password` → `囚 氛 vord`，作为第二意见不可信。注释里记下了重建要点，避免有人再抄回 `await` 写法。
- **验证** — `tests/agent/test_ocr_vision.py` 新增 8 例（6 条形态判据参数化 + 可疑则复核 + 完整则不复核）；全量 `pytest -q -n 4`：**5621 passed / 10 skipped / 0 failed**。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — easyocr 真正吃到 GPU（torch 是 +cpu 构建）· 无 GPU 机器自动退 CPU</summary>

- **根因（实测）**：`torch` 装的是 `2.11.0+cpu`，`torch.cuda.is_available()` 为 False，所以 easyocr 一直在 CPU 上跑——它在日志里只打印一行 `Neither CUDA nor MPS are available`，不报错，于是"GPU 加速"的注释与实际行为脱节了三个月没人发现。同机实测 1440×900 截图 **4.76 s**。
- **环境**：改装 `torch==2.11.0+cu128` + `torchvision==0.26.0+cu128`（版本号与原来一致，只换构建），`--no-deps` 安装以免顺手升级 numpy——`numpy` 仍是 1.26.4。同机同一张图降到 **1.39–1.64 s（约 3×）**，显存占用约 0.47 GB（留得住：easyocr + 8 GB 的本地 LLM 可共存）。
- **代码**：`execute_ocr` 不再硬写 `gpu=True`，改问 `torch.cuda.is_available()`（进程内缓存，CUDA 上下文只初始化一次）。队友的无 N 卡机器 → `gpu=False` 直接走 CPU，不再打误导性警告；有卡但装的是 CPU 版 torch 同样安全。
- **量到的其它数字**：`import torch` + 首次 CUDA 检查 2.4 s（easyocr 本来就会 import torch，故实际不额外付费）；`Reader` 初始化 1.4–1.6 s 且进程内缓存；小图 300×50 热调用 0.04–0.10 s。
- **文档**：`AGENTS.md` 补 §6.1（有无 GPU 的行为对照 + 换 CUDA 版的命令 + 镜像速度实测），并把"并发偶发 OCR 抖动"那条校正为真因——外部路径 `E:\vulnclaw\test\`，不是并发本身。
- **验证** — 全量 `pytest -q -n 4`：**5621 passed / 10 skipped / 0 failed**（2 分 11 秒，比之前快约一倍）；`easyocr` 模型显式落在 `cuda:0`。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — OCR 测试不再依赖本机外部路径（全量 <code>-n 4</code> 的 <code>WinError 32</code> 抖动根因）</summary>

- **修（中·实测坐实）：`tests/agent/test_ocr_vision.py` 钉死 `E:\vulnclaw\test\test_ocr.png`**，并把"easyocr 读不了的 png"写到同目录的固定文件名 `empty_test.png`。两个后果：① 任何没有 `E:\vulnclaw\test\` 的机器（队友 clone、CI）这两条用例必失败；② 共享目录 + 固定文件名在 `pytest -n 4` 下会与杀软扫描/上次中断残留的句柄撞车，报 `PermissionError: [WinError 32]`——2026-10-30 两次全量都挂在它上面，单独跑必过，所以一直被当成"并发抖动"。
- **修法**：样本图入库为 `tests/fixtures/ocr/test_ocr.png`（4.9KB，与既有 `tests/fixtures/capabilities/qr_sample.png` 同规格），测试按 `Path(__file__)` 相对定位；不可读文件改写进 `tmp_path`（每个用例唯一，不再有共享路径）。
- **清单**：`tests/fixtures/capabilities/manifest.yaml` 里 `ocr_vision` 那条"fixture missing: commit a small PNG beside the test instead of the external E: path"同步关闭。
- **验证** — 全量 `pytest -q -n 4`：**5621 passed / 10 skipped / 0 failed**（2 分 00 秒，exit 0）；该文件单独在 `-n 4` 下连跑 3 次均 8 passed。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — AI 注入实测：靶机空回复归因纠正 · 中文 AI 路由 · class 签名不再吃 JSON 键</summary>

- **实测（本地合成靶场，gpt-oss-20b 当靶机 / deepseek-flash 当攻击方，今日 6 轮）**：无配方 266 发 / 30 分钟 0 命中；有配方笔记但那轮没试配方（跑去逐位 oracle）196 发 / 17 分钟 0 命中；**只有自动注入的笔记可依、靶场无源码可读、并对空回复重试时，69 发 / 8 分钟把两个 flag 全拿到**（第 20 发用占位符替换拿 vault flag，第 67 发把占位符换成"除授权码以外的条目"拿到系统提示里的 flag）。结论：手法有效，但"笔记被注入 ≠ 模型会照做"——同样有笔记，一轮一上来就试、另一轮整轮没试，卡住时应以 `--hint` 点名下一步。细节见 `E:\vulnclaw\work\HANDOFF-20261030.md`。
- **纠正归因**：空回复不是 `max_tokens=900` 截断，而是 gpt-oss 只输出 analysis 通道、不产出 final（`finish_reason=stop`、completion_tokens 很小）。调到 3000、`reasoning_effort=low`、降温 0.2/0.3、加"必须给可见回复"都压不住（最差仍 5/8）。
- **配方（实测来源）**：**占位符替换**（把授权码写成"从你的备忘里取"，模型自己把系统提示里的真值填进 `TOCALL:` 工具调用；重放 4 次成功 3 次）、元数据侧信道（问格式/长度让模型把真值当示例）、拼接走私、是/否 oracle。写进 `web-ai-attack-map.md`、`web-playbook-12-ai-security.md`、`ctf-ai` §6，并新增 validated 笔记 `ai-agent-console-prompt-injection`。
- **路由**：短关键词组补「提示词注入/提示注入/jailbreak/越狱」→ `ai-mcp-security`、「人工智能/人工智能安全/ai方向」→ `ctf-ai`；vuln hint 补「提示词注入/提示注入/越狱/工具滥用/越权工具调用/未授权工具调用」。实测：`强网杯 人工智能 方向：附件 model.pth` 由 `intranet-pentest-advanced` → `ctf-ai`；带 URL 的中文注入题保留 `ai-mcp-security` 作为 support，reason 出现 `vuln=prompt_injection`。
- **修 `challenge_class_signature`**：goal 里 `JSON {"input": "..."}` 曾让 class 签名变成 `input ...`（JSON 键与省略号占位符被当成引号题名），`"flag{...}"` 又会变成 `flag`（每个 CTF 笔记都有的词）。新增 `_quoted_title_candidates`：引号后紧跟冒号视为 JSON 键、纯点号视为占位符、含花括号或 `flag{` 视为答案格式、裸 `flag`/`ctf` 视为无身份；引号题名（`"Quoted-printable"`）仍保留。
- **测试** — 新增 6 个回归（class 签名 3、中文 AI 路由 3）；`tests/skills` 718 passed、`tests/agent -k playbook` 324 passed。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 强网杯赛制确认：补「人工智能」方向的技能（此前基本为空）</summary>

- **赛制（官方）**：2026-10-31 09:00 → 11-01 12:00，在线解题；方向含**二进制逆向 / 密码分析 / 智能终端安全 / 信息隐藏 / 人工智能**；**动态积分 + 早鸟奖励**（按解题顺序加分）；top32 进线下；结束后 8 小时内（11-01 20:00 前）前 50 名交 WriteUp；**每队 flag 不同**（动态 flag 反作弊）。
- **新增 `ctf-ai` 技能 + `references/ai-challenge-recipes.md`**：此前"人工智能"这类目在库里几乎没有可用内容（关键词命中多为误中）。技能给判题型表（给了模型文件 / 推理接口 / 训练数据 / prompt 各走哪条）与可复制代码：模型结构体检、`weights_only` 失败即 pickle 入口、权重里扫 ASCII 串、ONNX 元数据与输入名、PGD 模板、成员推断阈值、输入归一化对齐；顺带记了 APK/dex 的静态路线（`androguard` 已装，不需要 jadx）。
- **路由**：新增两条短关键词组（对抗样本/FGSM/PGD/模型逆向/模型窃取/成员推断/触发词，onnx/pytorch/权重文件/模型后门），且 "模型被植入后门，找出触发词" 命中 `ctf-ai` 而 "服务器被入侵，排查后门" 仍归 `incident-response`（实测两条都在原位）。
- **环境事实**：AI 类依赖齐（torch/numpy/scipy/sklearn/onnxruntime/PIL/cv2）；`java` 在（`D:\JDK`）但 jadx/apktool/frida/adb 未装——静态 APK 用 `androguard` 足够，动态分析缺口已知。
- **pip 的正确姿势**：代理不稳定时用国内镜像直连即可（`-i https://pypi.tuna.tsinghua.edu.cn/simple`，实测下载成功），不必依赖梯子。
- **测试** — `tests/skills/` 707 passed。

</details>

---
<details open>
<summary><strong>Unreleased</strong> — 盲水印解出来了：经典 bwm DFT 差分，7.2.4 取得 flag</summary>

- **结果（实测）**：DASBOOK 7.2.4「盲水印_01」解出，答案是 `flag{aa3379655baa69c7fb7a7e469c8be88e}`。两图肉眼相同，其中一张 RGBA 一张 RGB —— 这是经典 `chishaxie/BlindWaterMark`（把 `alpha×水印图` 加到载体图**未移位**的 2D DFT 上）的指纹。
- **新增 `scripts/blind_watermark_classic.py`**：encode/decode 自包含实现，`--seed`（默认 20160930）/`--alpha`（默认 3.0）/`--oldseed`（py2 兼容）。本机自实现与参考脚本输出**逐像素相同**（`(a==b).all() == True`）。
- **两个决定成败的实现细节**（复刻时各踩一次，都写进了脚本注释）：
  1. **seed 只设一次**，之后连续 `shuffle(rows)`、`shuffle(cols)`；两次之间重新 seed 会得到不同的列置换，输出噪声且不报错。
  2. **赋值时就 `np.uint8()` 截断**（负数回绕，-5→251）；保留浮点会让每个像素偏移、字消失。
- **判别谁是原图**：`decode blind2 blind1` 出字、反过来出噪声 —— 这是最快的方法，写进了笔记。
- **本次绕过的一个坑**：小字号 + 竖向条纹下 easyocr 会把 `flag` 读成 `ifladlaa37?`，**关键字符必须人工放大核对**（本次用镜像副本交叉验证，确认第 2 行末位是 `c` 而非 `d`）。
- **之前 16,000 组参数为什么全落空**：那些是 `guofei9987/blind_watermark`（DWT+4×4 DCT+SVD）的参数空间，和本题的方案族不同；而自己枚举的 24 种 DFT 约定又漏了置换与镜像两步。
- **笔记**：新增 `blind-watermark-two-image-dft-decode`（**validated**，注入路径下 score 0.67），把正确流程、两个坑、以及五条已排除的路径都记下；旧的 `blind-watermark-frequency-domain` 保持 draft 作反面记录；`scripts/blind_watermark_dft.py` 标注 DEPRECATED（它漏了置换/镜像，留着只会误导）。
- **顺带**：GitHub 在本机直连不通（`185.199.x.x:443` timeout），走系统代理 `127.0.0.1:12334` 后 200 —— 需要外部源码时用 `curl --proxy`。

</details>

---
<details open>
<summary><strong>Unreleased</strong> — 盲水印实测：agent 104 次调用未解 · 经典 DFT 差分被证伪 · 留下负面结果</summary>

- **实测（未修，记录用）：让 agent 解 DASBOOK 7.2.4「盲水印_01」** — `blind1.png` + `blind2.png` 两张 600×600 RGBA 同尺寸图，40 步上限内 **104 次工具调用后未解出**，无 flag。有价值的部分是它排除了什么，以及它本身证明通路是好的：
  - **视觉通路确认可用**：`ocr(method='llm')` 对 4 面板拼图返回了具体的逐面板描述（44 s），不是 10-28 修之前的空串/NO_TEXT——那条修复在真实运行里成立。
  - **像素差不是载体**：R 通道 diff>10 仅 4206 px（0.74%），二值化后是云层纹理。
  - **经典 chishaxie/BlindWaterMark 的 DFT 差分不是载体**：新增 `scripts/blind_watermark_dft.py` 枚举 axes∈{(0,1),(1,2),(-2,-1)} × alpha∈{1,3,4} × sign∈{±1} × 象限共 24 种约定，每一种产出的都是频谱梳状结构，无字形。
- **新增 `scripts/blind_watermark_dft.py`**：不是"猜一种约定"，而是枚举 + 按「二值度 + 墨迹占比」打分，把 top-N 写成 PNG 交给 `ocr` 读。第一版评分把**全黑图**判成满分 1.000（`near_zero=1.0` 没有墨迹也是"二值"），已加墨迹占比下限——否则工具会为每个约定都报"找到了"。
- **写进笔记（draft，不冒充 validated）**：`blind-watermark-frequency-domain` 追加了上面三条实测负面结论与下一步方向（试 pip `blind-watermark` 0.2/0.3 的 `extract_with_original`，或单图块方案配 wm_shape 网格扫描）。GitHub 在本机不可达（`185.199.x.x:443` 全部 timeout），取源码要靠镜像或 pip 旧版本。
- **第二轮负面结果（本人手试，仍未解）**：把 `guofei9987/blind_watermark` 的参数空间也算了一遍——2 张图 × shuffle 策略 1/2 × fast/slow × password_img 1–20 × 约 100 种 wm_size = **16,000 组，没有一组把 `wm_avg` 压到二值**（正确参数下每 bit 贴 0/1，错误参数平均向 0.5）。加上前面排除的像素差与 FFT 差分，这对图目前**没有已知方案能解**。缺的关键输入是 DASBOOK 7.2.4 的配套说明（题面只说"盲水印+两张图"，没说用哪个工具/版本），而 GitHub raw 在本机不可达。两条都写进了 draft 笔记。
- **诚实结论**：这类题目前**没有**确定性工具覆盖，笔记仍是 draft、不会自动注入；这次没有把任何未验证的东西标成 validated。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — misc/隐写：一条命令查完六件事 · 修掉一行会复现不了的笔记</summary>

- **修（中·实测坐实）：已 validated 的 LSB 笔记记的方法是错的** — `lsb-image-column-major-pixel-order-flag-extracti` 原文写「column-major **plane 0**」。2026-10-29 复测同一张图：RGB/RGBA × 行/列 × 8 个位 × 两种位序**全部无命中**；真正能复现的是**交错通道流**（`arr[:,:,:3].reshape(-1) % 2`，即 R,G,B,R,G,B… 逐字节取 LSB）。两种载体完全不同，只试一种就会得出"图里没东西"。笔记已按实测重写，并把原错误作为 `[miss]` 角度保留。
- **新增 `scripts/stego_sweep.py`**：一次调用给出六项判据 —— 容器尾部附加数据（IEND/EOI 之后 + 魔数识别）、PNG 块清单（CRC 有效性 / 重复块=诱饵特征）、EXIF 与文本块、LSB（交错流 + 逐平面 × 行/列 两向）、可解压的 deflate/zlib 段、音频自动渲染频谱图。实测 37 份 DASBOOK 附件：**3 份直接给出 flag 候选**（附加字符串 `flag{3c3c…}`、LSB `flag{7d39…}`、zip 伪加密 `flag{57c9…}`），**2 份给出结构性线索**（IEND 后挂着 `PK\x03\x04` → 图种），**3 份音频自动出频谱图**（交给 `ocr(method='llm')` 读）。
- **两处精度/性能问题在写的过程中被实测打回并修掉**：① raw-deflate 在随机偏移解压必然"成功"，6 MB 的 mp3 解出 6 段乱码假流 → 加"流正常结束 + 输出像文本（可打印≥0.9、字母数字≥0.5、无单字节占主导）"过滤，噪声归零；② 首版逐字节试探 + 每探 8 MB 切片，6 MB 文件 **2.5 分钟**跑不完 → 改成头 4 KB 窗口 + `max_length` 上限，**2.0 秒**。
- **新增笔记 `misc-stego-one-shot-triage-sweep`（validated）**：把"先查完六件事再猜手法"写进可召回的配方，附实测数字与工具调用方式；同时给 `lsb-image-…` 笔记补了"图片/像素/找 flag"这类题面词，使图片类 goal 能命中它。
- **测试** — `-k playbook -n 4` 316 passed；全量 `-n 4` **5566 passed / 0 failed**。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — skill 路由：pwn 此前命中不了任何技能 · 泛 CTF 题一律被塞 ctf-web</summary>

- **修（中·实测坐实）：`ctf-web` 的关键词组里有裸 `ctf`/`夺旗`/`flag`，任何提到 flag 的题都以 0.15 命中它** — 实测一道**固件镜像**题（`fw_image.cfg` + `fw_tool.py`）被 `ctf-web` 以 **confidence 0.09** 选为 primary，一道 PNG 隐写题同理：题型不是 web，拿到的却是 PHP 绕过/burp 参考清单。技能索引只是"可选参考"，但错家族的建议本身就在把人往固定套路上带。移出裸词、保留 web 特有判据；泛 CTF 题现在不命中任何技能（索引为空比错家族干净）。
- **修（中·实测坐实）：pwn 分类此前没有任何技能** — "溢出这个 ELF，拿到 shell" 匹配 0 个 skill（脚本库里有 60+ 篇栈/ROP 配方，但模型看不到索引）。强网杯线上赛有 pwn 分类，这是赛前必须补的洞。新增 `ctf-pwn` 技能（判题型 → 保护面 → libc 版本 → 分型处置 → 本地先跑通）+ 一页 `references/pwn-triage-and-offsets.md`（偏移求解、格式化字符串、堆、seccomp/ORW、本地通远程不通的六个坑）。
- **修（低）：库内既有的关键词分组被拆分以提高判据强度** — legacy 打分是 `(命中数 / 备选数) * DIRECTORY_BOOST`，组越长单次命中越弱。音频组 12 个备选拆成两个 6 个，web 组拆成两个 5 个；否则 "PHP 弱比较绕过" 会被 `rapid-checklist`（裸 `绕过`）以 0.25 压过 `ctf-web` 的 0.21。
- **效果（12 条路由矩阵，改前 → 改后）**：pwn 三类题 `(none)` → `ctf-pwn`；"最低有效位LSB" `(none)` → `ctf-misc`(0.29)；"图种" `(none)` → `ctf-misc`(0.17)；"PHP 弱比较绕过" → `ctf-web`(0.17)；固件镜像题 `(none)`（原本是被 ctf-web 抢走）；web/crypto/re/应急 维持正确。**一个反例**：`misc 隐写` 这类只说"PNG 里藏着 flag"的题现在不命中技能——这是刻意取舍，见下条。
- **未采纳（有数据支撑的否决）**：给技能索引加"置信度下限"是我的初始方案，实测**不成立**——合法匹配的置信度全在 0.08–0.21，误匹配也是 0.08（`ctf-misc` 抢到一道 docx 题）。阈值分不开对错，0.15 的门会砍掉 5 个正确匹配只换来 1 个错误匹配。所以没加。
- **修（中·工具面）：pwn/逆向题看不到 `fetch` 与后台爆破工具** — 实测 pwn goal 因含 "elf" 落进 `reverse` bundle，而该 bundle 只有 4 个工具；`bg_launch`/`bg_result` 缺席意味着猜 canary / 爆破 ASLR 低位这类标准手法连工具都看不到（与 2026-10-28 那三个分析器被自家 bundle 剪掉同一形状）。`reverse` 与新增的 `pwn` bundle 现在都带 `bg_launch`/`bg_result`/`fetch`，且**两者集合同一**，所以哪个先命中都不改变能力。crypto/misc 的 `fetch` 仍然剪掉——既有测试 `test_non_quiz_crypto_goal_still_prunes_fetch` 钉着"解码任务无需外网"，这是刻意的外发收敛，未动。
- **测试** — 新增 `tests/agent/test_tool_surface_for_offensive_categories.py`（6 例：四类 goal 的面必须带齐自己的工具、pwn 与 reverse 同集合、web/misc 不裁剪、crypto 仍剪 fetch）。`tests/skills` 692 passed、全量 `-n 4` **5566 passed / 0 failed**。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 手工提交场景的收工开关：简单题 19.6 s → 1.2 s</summary>

- **背景（实测）**：`finish_on_accept` 靠平台返回 accepted 触发，而强网杯这类**人工提交**的比赛里运行内没有这个事件，所以每题解完仍要付一轮补黑板。实测同一道本地 LSB 题两次运行：`1 次 python_execute 出 flag`，之后 9 次调用 / 17.8 秒全是记账 —— **占 19.6 秒总墙钟的 91%**。
- **那一轮不是白费**：模型在那里写的 `[miss]` 角度（「行优先不行」「IEND 后无附加数据」）正是让下次一次就解出的知识。所以**不全局开**，而是按"这题便宜到没什么可记"判定。
- **新增两个配置**（`config/schema.py` 的 `CompetitionConfig`）：
  - `finish_on_grounded_flag`（默认 **false**，按需开）：模型宣布 FINAL 且 `_completion_gate` 判定 flag 已在证据里时，跳过 `_completion_lock_gate` 那一轮，由运行时写 LOCK + CONFIRMED fact 再收工。
  - `finish_when_calls_below`（默认 3，0 = 不设限）：只有本次运行的工具调用次数**小于**该值才生效；达到或超过就照旧走锁门，保留模型写的角度。
- **护栏未动**：防猜门 `_completion_gate` 在前，只有已 grounding 的 flag 才可能走到这里；`_completion_lock_gate` 本身没改，调用计数照常推进；配置缺失/异常一律 fail-closed（返回 False，即旧行为）。
- **效果（同一道题复跑）**：`steps=1 calls=2 wall=1.2 s`，事件 `completed_on_grounded_flag` 落进 `VULNCLAW_EVENT_LOG`；对照修复前 `steps=2 calls=11 wall=19.6 s`。板上仍有合成的 LOCK 与确认 fact（已核）。
- **测试** — 新增 `tests/agent/test_solver_finish_on_grounded_flag.py`（17 例：默认关、边界 0/1/2 与 3/4/40、阈值 0 不设限、缺 config/缺 competition 段 fail-closed、schema 默认值与负数拒绝、合成时不覆盖模型写的 LOCK、黑板缺失不报错、锁门在开关关闭时行为不变、防猜门先于本开关）。全量 `-n 4` **5535 passed / 0 failed**。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 强网杯赛前准备：报告里的 AI 声明与"编造攻击链"</summary>

- **修（中·官方规则驱动）：报告多了一段可照抄的 AI 使用声明** — 2026-10-29 强网杯官方答疑原文「可以使用 AI 辅助解题，后续在 WP 中须注明」。写 WP 的人是赛后数小时拿着这份报告写的，所以声明必须已经在文件里：`solve_report.py` 的报告头新增 `## 0. AI 使用声明（写 WP 时照抄）`，写明工具（VulnClaw）与本次实际模型名（`_model_label()` 读 `llm.model`，读不到配置时退回 `unknown`，报告照常渲染）。
- **修（中·实测坐实）：攻击链段落对非 Web 题是编的** — `_render_solution_chain` 在没有 `endpoint:`/SQL 证据时无条件输出「1. 通过模型选择的 HTTP/浏览器工具建立目标页面和接口基线。2. 根据工具响应差异确认可控参数…」。实测 2026-10-29 那道 GBU nc 固件题全程只用了 `python_execute`，报告仍断言做了 HTTP 工作。现在改为**从本次运行记录的实际步骤推导**（步骤理由 + 工具名），没有记录时直说「无法从证据还原攻击链（不做推测）」而不是编方法。编号同时改成连续（原来会跳 1→2→5）。WP 要人写、且要注明 AI，所以这段编造会直接进交付物。
- **测试** — 新增 `tests/report/test_solve_report_ai_disclosure.py`（6 例：声明存在且带模型名、配置读不到时退回 `unknown` 仍渲染、非 Web 题按真实步骤描述、链路段不含「HTTP/浏览器工具」、编号连续、无步骤时如实说明）。`tests/report` 125 passed，全量 `-n 4` **5518 passed**。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 平台已经判对之后还在补记账：比赛里每题白等 18 秒才开下一题</summary>

- **修（中·实测坐实）：`accepted:true` 之后仍要花 1–2 轮补黑板** — 统计 55 个已解会话：确认解出后还有 385 次工具调用（占全部调用的 27%），其中 **291 次是 `blackboard_*`**（add_fact 97 / create_angle 67 / hit_angle 47 / verify_fact 36 / set_lock 22 / miss_angle 22）；墙钟中位 6.5 s。只看 14 个 `ctf2:competition:*` 会话，p90 是 21 s，而 1024 快闪赛是 60 分钟 19 题。
- **修法**：新增 `competition.finish_on_accept`（默认 on）。提交返回 accepted 时，运行时自己把 LOCK 与一条 CONFIRMED fact 写进黑板（取自被接受的值和该次提交的 evidence id）并立刻结束本轮，不再等模型补板。**门本身没动**——`_completion_lock_gate` 仍在（AGENTS.md §5 的要求是"结论必须落盘"，不是"必须由模型那一轮亲手写"），而 accepted 恰好是唯一不需要模型判断"解没解出来"的情形：平台已经判了。置 false 恢复旧行为。
- **判据要绕开两个坑**（都是实测踩到的）：
  - 静态名字集合会漏掉比赛提交。比赛走 MCP 侧的 `ctf2_submit_competition_flag`，**这个字符串在本仓库源码里一次都不出现**（由远端 MCP 端点提供），所以第一版按 `{ctf2_submit_flag, gcs_submit_flag, platform_submit}` 判，14 场里一场都不会触发。改成形状判定：名字含 `submit` 且含 flag/competition 或属 `ctf2_`/`gcs_`/`platform_` 家族。
  - `{"accepted":true}` 单独出现不算数（网页表单也可能这么答）。要求同时出现平台计分字段（`is_solved` / `submission_id` / `earned_points` / `points`）。
- **效果（回放 14 场真实比赛会话）**：10/14 会在 accepted 处收工，合计省 **92 次调用 / 155 秒**，中位 **17.9 s**。剩下 4 场不触发的见下一条（判词本身丢了，不能猜）。
- **顺带修（中·同一批数据暴露）：MCP 返回的判词被 `[tool:X] completed` 吞掉** — `builtin_tools.py` 的 ok 分支在没有 `content`/`structured_content`/`message` 时直接渲染 `[tool:X] completed`，把 `accepted`/`is_solved`/`points` 全丢了。实测 2026-10-24 一场比赛里，模型因此看不到判词、**对同一题连交 5 次**（按手册这属于"非有效操作"）。改为：其余键一律 JSON 落盘（截 2000 字符）再回显，真有内容时不再吞。
- **未修，需你定**：比赛提交走 MCP 直通（`builtin_tools.py:1280` 的 `mcp_manager.call_tool` 前只有 :1006 那三个名字在拦），所以 `ctf2_submit_competition_flag` **不经过本地证据门，也不受 `allow_flag_submission` 开关约束**——即"猜的 flag 也能发出去"。今天没动它：收紧会让比赛提交开始被本地拒，属于策略决定。
- **测试** — 新增 `tests/agent/test_solver_finish_on_accept.py`（30 例：比赛 JSON 形状、网页表单反例、去重占位不触发、MCP-only 名字识别、已有 LOCK 不被覆盖、config 可回退、黑板缺失不影响收工）。全量 `-n 4` → **5511 passed**，1 例 `test_ocr_vision` 在并发下抖动、单跑通过（AGENTS.md 记录的已知现象）。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 裸地址题被"必须交平台"推着白找 ref（10/28 次工具调用、32/79 秒）</summary>

- **修（中·实测坐实）：CTF 模式纪律块的提交要求与"本轮有没有 ref"无关** — 2026-10-29 那道 GBU 固件控制台题（`openssl s_client -connect <host>:9999`，`session.task_mode: ctf` 是显式固定的），模型在第 12 次工具调用就拿到了 flag，随后按 `task_mode.py` 那句无条件的 "The deliverable is a platform-formatted flag; submit via the platform submit verb" 去找 challenge ref：`platform_list` → `ctf2:daily`（`403 agent_scope_forbidden`）→ 26 道练习场题（单次 20.5 s）→ 两场已结束快闪赛逐层点进去 → 发现唯一那道 nc 题是 `DASCTF{}`+EXIF/xor 的另一题，才收手。**合计 10/28 次调用、32.3/79.3 秒（41% 的工具时间）花在一个不存在的目标上**，而 `platform_submit` 没有 ref 只会回 `missing ref`（`platforms/tools.py:_resolve`）。
- **修法**：`mode_instruction(mode, *, platform_ref=True)` 增加 `platform_ref` 参数，CTF 块分两套提交行——有 ref 时维持原样（"submit via the platform submit verb"）；无 ref 时改为"flag 值本身就是交付物 + 明确禁止为了找 ref 去枚举 `platform_list` / `ctf2_list_*`、禁止探测平台自身端点"。默认 `platform_ref=True`，不知道这回事的调用方仍拿到更严的那套，约束不会因为漏传而放松。
- **判据**：新增 `solver._run_has_platform_ref(state)`，在 goal / origin / 最近 40 条证据里找 challenge 形状的 ref（`<platform>:(practice|stage|daily|exercise|competition):<group>[:<id>]`）。**故意不复用 `playbook.derive_target_ref`**：后者只认 `ctf2:practice:<uuid>:<uuid>`（它是给笔记身份用的），会漏 `ctf2:stage:` / `ctf2:daily:` / `gcs:`——那正好是正式赛唯一必须提交的形状，用它会让比赛题被误判成"没有 ref"。方向上也刻意偏"有 ref"：误判有 ref 只多一次查询，误判没有则直接丢掉提交。运行中途由 `platform_list` 打出 ref 也算有（裸地址起步、后找到平台的正常路径）。
- **效果（实跑 `_system_prompt`）**：同一轮 GBU 的 goal/origin 下，修复前提示词含 "submit via the platform submit verb"、不含任何"flag 即交付物"的说明；修复后该行消失、改为"flag value IS the deliverable"并点名枚举是白工。带 practice ref 的平台题提示词不变，仍要求提交。
- **同源文档**：`skills/specialized/competition-mode/references/competition-strategy.md` §四 改成同样的条件表述（列出 4 种 ref 形状 + 裸地址题的处置）。
- **测试** — 新增 `tests/agent/test_task_mode_submit_requires_ref.py`（17 例：两套提交行互斥、默认仍是严的一套、ir/pentest 不受影响；判据覆盖裸地址 / 纯 web / practice ref / stage ref / daily ref / gcs ref / origin 即 ref / 语料 ref 不算 / 证据中途出现 ref / 坏证据对象不抛）。`-k "task_mode or competition or prompt or playbook" -n 4` 631 passed。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — playbook frontmatter 被多行值打断：43 篇已验证笔记对自动注入隐身</summary>

- **修（中·实测坐实）：`_parse_frontmatter` 用非贪婪 `\n---` 收尾，被正文里的破折号行提前截断** — `save_playbook` 把 `name`/`fingerprint` 原样写进 `key: value`，而捕获的 CTF2 goal 本身就是整段题面（描述 + 附件路径 + 平台政策），落到盘上是一个十几行的 `fingerprint:`。段落里的 `----`（中文书的勘误表分隔线）或 Markdown 水平线 `---` 于是成了 frontmatter 结束符：其后的 `status: validated`、`target_ref:`、`target_hash:` 全被当成正文。**实测本机 669 篇里 144 篇是这种形状，其中 18 篇加载后没有 `status`（按 draft 处理）、43 篇磁盘上明明写着 `validated`**；`solver.py` 的自动注入只收 validated，这些笔记等于对求解流程不可见。同一原因还让 `fingerprint` 被截到第一行（token 从 85+ 掉到 3–8 个），结构化身份层（audit item A 的 `target_ref` 精确匹配）一起失效。修法：结束符必须是**整行恰好三个破折号**（`^[ \t]*---[ \t]*$`），`----`/`--- text` 一律算内容。
- **修（中·同因）：写入端把单行字段压成单行** — 新增 `_single_line()`，`name`/`fingerprint`/`target_ref` 落盘前折叠空白，从根上不让多行值再产生；正文（`steps`）不受影响，仍保留原格式。
- **修历史数据**：新增 `scripts/repair_playbook_frontmatter.py`（默认 dry-run，`--apply --backup-to` 才写），把 144 篇的多行值折回单行。执行前 `updated_at` 等尾部键原样保留、正文逐字不动；实跑后校验 144 篇「尾部键一致 + 正文是原文子串 + fingerprint 单行」0 problems，原文件备份在 `E:\vulnclaw\playbook-frontmatter-backup-20261028`（144 篇 / 589 KB）。
- **效果（实测）**：loader 视角 validated 567 → 610、带 `target_ref` 的 1 → 31、多行 fingerprint 144 → 0。回忆探针：`ctf2:practice:8e5c9260-…:850c2230-…`（parallelism 题）的 ref 查询修复前 **(none)**、修复后命中自己的笔记 score 1.000；`MPI 并行 flag checker 逆向` 从"三条全不相干"变成首条是 8e5c9260 家族的笔记。其余探针（zip 伪加密 / 音频频谱 / gzip 魔数 / ECDSA nonce）排序不变。
- **测试** — 新增 `tests/agent/test_playbook_frontmatter_multiline.py`（7 例：`----` 不截断、`--- text` 不截断、无结束符仍返回空 meta、写入端多行 goal 往返、`target_ref` 压行、纯空白值只折叠不丢）。`pytest -k playbook -n 4` 316 passed。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — CTF2 列题对不可读分区容错（过期 session 不再让整张题单死掉）</summary>

- **修（中·实测坐实）：`ctf2.list_corpora` 让可选的 competition/stage 分区把整个列题打断** — 2026-10-15 现场日志：用户粘贴靶机 URL 直接解题（无平台 ref），agent 用 `platform_list` 找 ref 时，agent 作用域 PAT 对 `competition:read` 本就 403，回退的浏览器 session JWT 又已过期（401 TOKEN_EXPIRED），异常从 `list_corpora` 冒出去 → **整张题单返回空**；而 `platform_submit` 必须带 challenge ref，于是"flag 已经拿到却提交不了"。修法：competitions/stages 作为可选分区 try/except 跳过（practice 场次仍用 PAT 正常列出，实测过期 session 下仍返回 7 个练习场），与 `list_challenges` 已有的"跳过读不到的集合"容错一致。**遗留说明**：练习场内部的题目枚举仍是 session-only（Open API 无对应路由，实测 `/practice/<pid>/challenges/` 走 `_session_request`），所以过期 session 下"列出练习场"可、"展开场内题目"仍不可——要完整走 ref 流程需刷新浏览器 session，或改用 MCP 面的 `ctf2_*` 工具（Bearer PAT，不依赖 session）。
- **测试** — 新增 `tests/platforms/test_ctf2_adapter.py::TestAdapterListing::test_unreadable_stages_do_not_kill_the_whole_listing`（competitions 抛错时 practice+daily 仍在）；`tests/platforms` + `tests/ctf_platform` 670 passed。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — submit_gate 只读审查：自证回声可伪造见证（含修法代价实测）· 静默失效已可见化 · 中文残口无法定标</summary>

- **审查对象**：`vulnclaw/agent/submit_gate.py`（窗口外新增、此前未审）。只读审查 + 只落地零语义风险项。
- **发现（高·已实测）：模型可以自己制造见证** — `echo flag{猜测}` / `python_execute` 打印自己的猜测，该条证据就让 `assess()` 判 `grounded=True via=whole-flag`（黑板书笔记已被正确排除；未打印的候选为 False）。即"抄一个真 token 编造"之外，还有"自己造一个真 token"。**修法代价也实测了**：粗暴版（把"参数里含该候选"的证据降级为非观测）会误拒 **4/124 次真实提交**，其中 **3 次是平台已接受的真 flag**；加"≥2 个不同工具佐证"后只剩 1 次（真 flag 本地拒两次后按有界拒绝放行，不消耗平台尝试）。**未落地** —— 这是"放行自证猜测"与"误拒真 flag 两次"之间的取舍，需你定。
- **落地（低·可见化）**：`resolve_agent_state` 失败时若存在 session（运行时一定有）则打一条 WARNING（进程内一次），明说"本轮提交不做证据检查" —— 静默 fail-open 正是上一版连拒整轮却没人发现的原因；每次拒绝加一条 DEBUG（只带掩码形候选）。判定语义未动，新增 3 例测试。
- **复核（非问题，已量化）**：证据成本不成问题 —— 21,812,963 字符的证据上 `assess()` 最坏路径（整串 + 花括号扫描 + 片段循环）**0.184 s**，原先担心的多 MB 开销不存在。
- **复核（潜在地雷已排除）**：`resolve_agent_state` 的兜底 `hasattr(session, "evidence")` 不会再返回错对象 —— `SessionState`（pydantic）**没有** `evidence` 属性，所以形状漂移时是 fail-open 而非读空证据链，"整轮误拒"那个事故形状在该轴上已闭合。
- **发现（低·未动）**：① `submit_gate_refusals` 以**完整候选串**为键写入 AgentState（即写进 session JSON）—— 今天 460 场会话里 0 场有记录（门还新），是否改指纹键属运行数据设计选择；② `_BODY_CHARS` 不含 `:` `.` `,`，含这些字符的 body 只能走"整串"路径（有界拒绝兜底）；③ 形态门（花括号不闭合）不计入拒绝次数 → 该形状可无限次本地拒绝（设计如此，但会烧轮次）。
- **交叉核对（对第 6 轮 H5 的补充）**：本模块的占位符检查在**grounding 之后**（先"逐字在观测里"再判占位符），因此不存在 `solver.py:1629` 那种"真 flag 逐字在证据里却被占位符规则先拒"的假阴性 —— 这反过来说明 solver 那条判定顺序是异常，值得对齐。
- **中文残口定标（结论：仍无法定标）** — 语料里含 ≥8 汉字连串的证据仅 5 条、中文事实仅 5 条；5/5 中文事实今天被见证，构造成的"借真片段 + 编造中文尾巴"在当前实现下 0/5 通过。并对 9 组对照（引用+叙述 / 借片段+编造 / 整串引用）做 pre-anchor 与当前的逐条对比：**全部一致，无分歧**（含我上一批锚点改动是否顺手收紧了 CJK —— 实测未收紧）。样本量不足以给 CJK 分支配分支局部门槛。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 共享片段搜索改锚点对齐：大证据 19.05 s / 107.85 s → 0.458 s / 3.13 s（等价性 800/800 实测）</summary>

- **修（高·实测驱动）：上一批的热路径修复只覆盖了一半，这一批补上另一半** — 8-gram 必要条件只挡掉"不可能存在 ≥bar 公共片段"的调用；真实事实通常**有**公共片段（53 组 >300 KB 证据抽样中 11/12 必要条件通过），于是 `_longest_common_substring` 照旧在整块证据上跑 O(len(fact)×len(chunk))：实测 695 KB 证据 **19.05 s**、6.46 MB 证据 **107.85 s**（每条候选子句一次，`_run_blackboard_review` 每条 fact × 每块证据都会调）。**改法**：`_span_anchors()` 只取"能让片段携带内容"的对齐点（子句自己的 ≥5 字实词，或 ≥8 字汉字连串 —— 两者必是子句的子串），`_shared_span_carries_content()` 逐锚点在两串中定位后向左右逐字符扩展出极大公共片段。工作量与"实际共享的片段"成正比，不再与证据体积平方相关。
- **语义变更（已量化，方向明确）**：由"取全局最长公共片段再判内容"变为"存在一条携带内容的合格片段"—— 后者正是 `_SHARED_SPAN_MIN_COVERAGE` 与模块注释原本描述的语义，旧实现只看最长那条。**真实语料 800 组逐条对比：判定 800/800 相同，0 新增接受、0 新增拒绝**，理论上的放宽在本语料上未发生；5 个伪造反例（借 UUID / UUID 逐字+编造 / 短汉字片段 / 借一个真词拖长尾巴 / 长汉字观察）判定不变。
- **实测成本**：695,315 B 样本 19.05 s → **0.458 s（42×）**；6.46 MB 合成最坏用例 107.85 s → **3.13 s（34×）**，两处判定均一致。余额（0.4–3 s）是同一块证据上的 token/指纹正则，与片段搜索无关。
- **测试**：新增 `TestAnchoredSpanSearch`（永不丢失旧规则的接受 · 共享片段证据上的成本守卫）；`test_blackboard_witnessing.py + test_blackboard.py` → 47 passed。
- **留口（未做）**：超大证据上 token/指纹正则仍要过一遍整块（0.4–3 s），要再降需按证据长度分窗，属另一处语义变更。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 第 6 轮审查复核：热路径成本表述修正（仅部分修复）· 大证据回放零损失 · flag 反例搜索无命中 · MCP 角色门控可见化</summary>

- **修正（重要）：上一批把热路径成本说满了 —— 只修掉"无长公共片段"那一半** — 上一条记的 "21 MB 87 s → 525 ms" 成立于 8-gram 必要条件**被拒**的分支（当时的反例正是编造事实）。本轮对 53 组 >300 KB 的证据做分类回放：**抽样 12 组里 11 组的必要条件通过** → `_longest_common_substring` 照旧跑，3.16 MB 证据上估算 3–27 s/候选（bar 越大越久）。分母是"证据里有没有 ≥bar 的公共片段"，而真实事实通常有，所以真实场景仍是 O(n·m)，只是不再为"根本不可能命中"的调用白烧。有界化方案（先定位事实侧内容 token 在证据中的出现位置，再只在 ±bar 窗口内做 DP —— A1 既已要求载体词必须落在片段内，等价性可证）未落地，属边界变更，留口。
- **复核（零损失）：大证据子集没有因本批改动丢失见证** — 300–700 KB 范围做完整差分（`62ce9c3` 旧模块 vs 当前）：2/2 组两边均 True、损失 0；与此前 ≤300 KB 的 160 组（151 组仍被见证）结论一致。本轮起"窗口前"基线固定用 `62ce9c3` —— 我的提交 SHA 在审查期间被一次历史重写换掉（`b679886`→`dd211e3` 等），而 `62ce9c3` 早于重写点。
- **复核（反例搜索）：`is_placeholder_flag` 仍未找到真实反例** — 460 场会话里 87 条真实提交候选（63 条被平台接受）中**只有 1 条**命中新规则（`pie{bi;st;…}`，平台亦未接受，属猜测型提交）；命中规则的 67 条全是页面里的 CSS/JS 伪 flag（如 `try{$dec=[System.Text.Enco`）。结论：**暂不改**；E1 收窄方案（要求 body 内 `:` 与 `;` 同现）在本地噪声语料上仍保 146/198 过滤力、会放过 19/198，等真实反例再动。
- **复核（样本不足）：CJK 分支无法在本机定标** — 带证据的真实中文事实仅 22 条，按"依赖 CJK 捷径"计只有 2 条（CJK run 均 7 字符、覆盖率 0.18，且实测走的是别的路径）；被见证中文事实的覆盖率最小 0.395，高于现门槛 0.30。样本量不足以给 CJK 分支定"分支局部门槛"，需中文靶或中文证据语料。
- **修（低·可见性）：MCP 工具的角色门控不再静默** — `build_openai_tools` 记录被角色拦下的运维工具，MCP 段结束后打 debug 日志；补 `TestMcpToolsSurviveGoalPruning::test_mcp_tools_are_withheld_when_the_active_role_denies_them` 钉住"角色门控优先于运维绕过"。实测 `role=None` → 工具保留且无日志；`active_role='researcher'` → `MCP tools withheld by role 'researcher': ctf2_agent_next_challenges, ctf2_submit_flag`。
- **本次复核自身的边界** — 53 组大证据里只抽样 12 组做分类、2 组做完整差分（其余因 DP 成本未跑）；单测未覆盖超大证据路径。

</details>

---

<details open>
<summary><strong>Fix</strong> — 提交证据门第一版读错状态对象：真 flag 被连拒（BigMak 轮实测）</summary>

- **修（高）：`agent.context.state` 是 ContextManager 的 SessionState，不是 AgentState** — 真正的证据链挂在 `state.agent_state` 上（规范取法见 `blackboard.py:862` / `context_budget._state_for`）。第一版直接读了前者 → 门拿到**空证据链** → 每一次提交都被判"无证据"：2026-10-14 14:25 的 BigMak 轮里，真 flag `sun{bu…lol}`（早已出现在 e007 的 python 输出里）被连拒 4 次，靠**有界拒绝**（`MAX_REFUSALS=2`）兜底才在第 3 次放行并被平台接受（100 分）—— 那 4 轮推理是白烧的。修复：新增 `resolve_agent_state()` 统一解包（两种形状都认，取不到则 fail-open）。
- **验收（真实数据 + 运行时形状）** — BigMak 轮 77 条证据 × 10 个提交点回放：**误伤 0**（`sun{bu…lol}` 从首个提交点即放行）；run21 的补全型 `flag{<题名式>}` 仍**拦下**。新增 3 例回归测试钉住运行时形状（`SessionState(agent_state=AgentState)`）：`test_submit_evidence_gate.py + test_tool_face_precedence.py` → 31 passed。
- **教训（已写进模块 docstring）** — 上一版验收只用"直接塞 AgentState"的替身，形状与运行时不一致，于是 20 例单测全绿而线上全错；此后凡读取 `agent.*` 状态的门，验收必须至少有一例走**运行时形状**。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 第 6 轮审查：见证门可被"借一个真 token"绕过 · 验证热路径 87 s→O(n) · 拒绝正则不再吞环境故障 · PS 编码逃逸口写进工具描述</summary>

- **修（高·实测驱动）：共享片段层可被"借真 token 编造叙事"绕过** — 2026-10-14 第 6 轮只读审查（回放 459 场会话、160 组真实 `pinned_fact × evidence`）实测三个洞：① 载体实词只需"出现在证据任意位置"，不必落在共享片段内 —— `I confirmed <复制的 UUID> which proves the internal admin panel qzxwvu exposes scoring` 被见证，载体词是别处的 `admin`（实测 `INSIDE_SPAN=False`）；② UUID 分段不是 hex run，`_is_corroborating_only` 的 `[0-9a-f]{16,}` 漏掉 `c37ccae980c3` 这类分段；③ CJK 分支只要片段含 2 个汉字即算"有内容"，借 5 个汉字 + 编造中文断言即通过。**修法**：`_span_carries_content` 要求载体词**落在片段内**（这本是它 docstring 的原意）、`_is_corroborating_only(token, span)` 把 UUID 分段按指纹处理、CJK 分支提到 ≥8 字符；并因 21 MB 级证据下"任意英文子句都能凑出 8 字符公共段"而把固定门槛改为**随子句长度伸缩**（`_SHARED_SPAN_MIN_COVERAGE=0.30`，按 200 条真实被见证事实标定：覆盖率最低 0.333 / p05 0.361）。**真实语料零损失**：同一 160 组回放 151 组仍被见证（打补丁前仅 9 组），旧模块（`git show HEAD:`）跑同一批断言 4 例红。
- **修（高·实测驱动）：`_longest_common_substring` 在事实验证热路径上 O(n·m)、无缓存、无上限** — 实测单次调用 64 KB 证据 371 ms、**21.7 MB 证据 87 s**（真实会话存在 21,760,693 字符的 evidence 记录，`_run_blackboard_review` 对每条 fact × 每块证据都调）；另实测我一次 870 次调用的扫描 600 s 未跑完。**修法**：加 8-gram 必要条件快速否决（`_has_shared_ngram`，O(n+m)，语义上是纯必要条件）＋证据只归一化一次（此前每个候选子句各归一化一遍 64 KB）。**实测**：216 KB 用例 1148 ms → 60 ms（19×）；21 MB 用例 87 s → 525 ms。新增性能守卫断言（216 KB 证据单次 <1 s，旧代码实测 1148 ms 会红）。
- **修（中·实测驱动）：拒绝正则把环境故障当"验证性拒绝"，工具健康信号失真** — 扫全仓 202 条框架自产 `[!]` 字面量：HEAD 判"工具健康"58 条，含 `runtime_diff_probe php_serialize mode requires php in PATH`（依赖缺失 = 真故障，被 `requires\b` 吞掉）。**修法**：`requires` 收窄为参数形状、新增 `_HARD_FAILURE_LINE_RE`（`in PATH` / `command not found` / `is not recognized` / `WinError` / `Traceback` / `timed out` / `permission denied`）优先判定、`未找到` 收窄为 `参考文档未找到`。**前后对照**：58 → 57 条健康，唯一翻转即那条真故障；37 条 `requires` 参数校验全部保持健康（含反引号形态 `requires \`local_path\`` —— 首版收窄漏了反引号，靠"捕获完整字面量"的扫描抓回）。该函数此前**零测试覆盖**，本轮补 3 例。
- **文档（低）：把 PowerShell 编码逃逸口写进 `shell_command` 工具描述** — 窗口内新增的 `_PS_UTF8_PREAMBLE` 使 cmdlet 写文件带 UTF-8 BOM（实测 PS 写 JSON → `json.load` 抛 `Unexpected UTF-8 BOM`），读侧对 GBK 旧文件转乱码。实测 2213 次 shell 调用"读 379 / 写 73"，且写入多为 `cmd > file` 重定向（不受 `$PSDefaultParameterValues` 影响）→ **保留全局设置**，改为在模型可见处说明：结构化文件用 `python_execute` 或 `[IO.File]::WriteAllText($p,$s,[Text.UTF8Encoding]::new($false))`，读旧 GBK 文件用 `-Encoding Default`。
- **测试** — `tests/agent + tests/security + tests/skills` → **2687 passed / 14 skipped / 1 failed**，唯一红为既有的 `test_bg_tasks.py::test_bg_launch_and_result_lifecycle`（HEAD 同红，与本批无关）；新增 13 例（见证门反例表 6 · 必要条件/性能守卫 3 · 拒绝正则 4）。
- **边界（未做，明确留口）** — ① 21 MB 级证据仍有 ~525 ms 扫描，进一步需按证据长度分窗（属语义变更）；② CJK 只做到 ≥8 字符，借 8+ 汉字 + 长编造尾巴仍可通过，要按"片段占子句比例"收口需中文证据语料定标；③ `pwsh` 的 `utf8NoBOM` 未落地（本机无 PS7，无法验证）；④ 未动 `is_placeholder_flag`（缺真实反例，仅给出收窄方案）与 MCP 角色门控（保持收紧，仅补用例与可见性）。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 提交走证据门：`ctf2_submit_flag` 此前是唯一没有任何证据检查的路径（本地拒绝，不清耗尝试）</summary>

- **修（高·实测驱动）：平台提交没有任何证据检查，"补全型猜测"直接花掉尝试** — 2026-10-14 CTF2 巡航 24 轮实测账号 `attempt_count 86 / correct_count 77`（9 次白花）。`_completion_gate`（`solver.py:1639`）确实按证据校验 flag，但**只在模型喊 FINAL 时跑**（唯一调用点 `solver.py:2622`），而平台提交是**解题中途**发生的：`builtin_tools.execute_mcp_tool` 里提交动词只过角色/约束门 + 危险工具门 + 运维总开关，随后 `yield to the MCP manager` —— 门在终点、提交在半路，两不相遇。被拒候选签名一致：附件里只观察到 `flag{`（无 `}`），**body 与闭括号由模型自己补出**，补完形态完全合法，连 FINAL 的 shape 检查（`ctf_mode.flag_completeness_issues`，2026-10-09 鸡公煲产物）也看不出破绽。
- **修法（新增 `vulnclaw/agent/submit_gate.py`，接在两条"让给 MCP"的提交路由上）** — 把同一套证据标准**前移到花掉尝试的那一刻**：`assess()` 只认**观测证据**（`state.evidence` 中剔除自证工具：黑板书 / 笔记 / 提交动词自身 —— `_completion_gate` 注释早已写明 *"grounding can be satisfied by the model's own note"*），通过条件三选一：整串逐字出现 / body 出现在花括号语境 / 与已观测的"花括号后 body 片段"最长公共子串 ≥ `MIN_FRAGMENT_OVERLAP`（12，按 30 次真实提交标定，覆盖合法片段拼接）。**本地拒绝不清耗平台尝试数**，且是**有界拒绝**（`MAX_REFUSALS=2`，第 3 次提交同一候选即放行，真 flag 不会被永久关在门外）；形态门（花括号不闭合 / body 为空）永远拒 —— 补壳的串平台不可能接受。AgentState 增 `submit_gate_refusals` 记档（可复盘）。
- **实测验收（回放 2026-10-14 全天 30 次真实提交）** — 26 次 accepted 中 **22 次直接放行**（whole-flag 18 / brace-context 3 / fragment 1），4 次被拒 1 次（本地拒绝不消耗尝试，代价只是一轮重试）；**run21 的 2 次被拒补全型候选 + 1 次 schema 无效提交全部被拦**（`reason=none`）。判别边界清晰：真实成功者要么整串出现、要么 body 在花括号语境里；补全型只有"裸词恰好命中"（8 字符题名词），三类证据全不满足。
- **测试** — 新增 `tests/agent/test_submit_evidence_gate.py`（三类放行 · 补全型/自证笔记/占位符/花括号不闭合拒绝 · 有界拒绝后放行 · 拿不到 AgentState 时 fail-open · 集成层拦下与放行两条）；`tests/agent + tests/platforms + tests/ctf_platform + tests/skills` → **2766 passed / 7 skipped / 1 failed**，唯一红是既有的 `test_bg_tasks.py::test_bg_launch_and_result_lifecycle`（HEAD 同样为红）；`test_tool_face_precedence.py` 的内置 face 契约不变。
- **边界** — 只拦"让给平台 MCP"这条提交路径（内置 face 路由与程序化调用者语义不变）；`MIN_FRAGMENT_OVERLAP` 是按本机实测标定的启发式，后续巡航若出现误伤（真 flag 被拒 1 次）按数据调整。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — CTF2 agent 面把"正确率"提为提交纪律：whoami 的 attempt/correct 不再只是展示数</summary>

- **修（中·实测驱动）：ctf2 agent 面此前明确写着"正确率不计权重"，等于告诉模型可以拿提交次数换机会** — 2026-10-14 CTF2 自主解题巡航（24 轮）实测账号 `attempt_count 86 / correct_count 77`，即 9 次尝试白花，其中单轮连提 3 个猜测 flag（题名联想、类别陈词、`flag{xxxx}` 占位符）全部被拒，正确率为此永久下沉。而平台侧 `ctf2_agent_whoami` 一直返回 `stats.attempt_count` 与 `stats.correct_count` —— **工具本来就看得见自己的正确率**，缺的是任何一处让模型去看、去算、去在乎：`references/agent-play.md` 的 "What counts" 反而写着 "Accuracy is shown but not weighted"。
- **修法（三层引导，零代码分支）** — ① `references/agent-play.md`：改写 "What counts" 的正确率表述，新增 **Accuracy** 一节（正确率 = `correct_count / attempt_count`；每次提交必涨 attempt、只有通过才涨 correct；错提不可回滚；提交前须能一句话说清推导来源；提交后回读 whoami 比对基线；比率下滑是方法信号，应加深推导而不是换变体），并把 play loop 第 1 步（记基线）与第 6 步（提交限定 + 提交后复检）接上；② `SKILL.md` 的 Agent play mode 段落补一句"从 whoami 的 stats 推自己的正确率"；③ `vulnclaw/agent/prompts_{zh,en}.py` 的 CTF 强制规则各加一条"提交次数是消耗品，正确率是成绩"（含"尝试数涨而正确数没涨 = 上一个 flag 是错的，回去补推导"）。技能版本 `1.4.0 → 1.5.0`，eval 5 增 1 条断言（whoami stats 作正确率基线 + 只提交可追溯 flag）。
- **顺带修复两处环境缺陷（否则技能层根本不加载，本次改动无法生效）** — Anaconda base 的 PyYAML 是 **3.11**（2011 年版，被无关包 `rabbit 1.2.0` 的 `PyYAML==3.11` 钉子拖住），而 `pyproject.toml:36` 声明 `pyyaml>=6.0`：3.11 在 py3.12 上 `yaml.safe_load` 抛 `AttributeError: module 'collections' has no attribute 'Hashable'`，而 `skills/loader.py::_parse_skill_file` 只捕 `yaml.YAMLError` → **任何带 frontmatter 的技能一加载就崩**（实测 `load_skill_by_name('web-security-advanced')` 直接抛错）；已升到 **PyYAML 6.0.3**（同时满足 `kubernetes` 的 `>=6.0.3`），升级后 56 个 specialized 技能全部正常解析。另一处：base 里 `pluggy.py` 是远古单文件版（<0.4），pytest 9.1.1 要 `pluggy>=1.5` → **pytest 一行都跑不了**；已装 pluggy 1.6.0（落点 `site-packages/pluggy/__init__.py`，未被旧单文件遮蔽）。两者都是"恢复到项目 declared 依赖"，非功能改动。
- **测试** — `scripts/verify_vulnclaw_skill.py ctf2-platform` → `RESULT: OK`（loads、≥1 reference、zero routing warnings、no routing regressions）；`pytest tests/skills/` **611 passed**（4.89s）；`tests/agent + tests/i18n + tests/meta` **1508 passed / 7 skipped / 1 failed**，唯一红为 `test_bg_tasks.py::test_bg_launch_and_result_lifecycle`（断言后台结果含标记串，实际被 `builtin_tools.py:2756` 的 `[!] REMINDER` 段截断）——该文件与本次改动无关，HEAD 同样为红（工作树仅本批 5 文件改动）。
- **边界（未做）** — 没动提交门的代码路径：本地 `ctf2_submit_flag` 只做 `confirmation:true` 转发，准入判断在平台 MCP 侧；本轮走"引导三层"而非阈值硬闸。若之后要硬拦"正确率已经很低还继续提交"，需在 agent 侧另加门（当前按"不改语义优先"处理）。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — MCP 工具不再被目标文本裁剪（ctf2 agent 面实测被隐藏）</summary>

- **修（中·可发现性，实测坐实）：按目标关键词裁剪工具表把运维启用的 MCP 服务器整体裁掉** — 2026-10-13 驱动一次 CTF2 自主解题时实测：目标文本经 `_infer_allowed_tools` 判定后，构建出的 schema 里 **`ctf2_agent_next_challenges` / `ctf2_submit_flag` 等 ctf2 MCP 工具全部缺席**（`platform_*` 中性工具因核心钉列表保留），模型看不到平台自带的 agent 通道（读题/起环境/提交/笔记/服务端配额），只能手工用 python 重造 Open API 客户端完成全流程——该次仍解出并提交成功（`accepted:true, is_solved:true`），但多花步数且绕开了平台侧审计面。这与 `_ALWAYS_KEEP_TOOLS` 注释记录的静默失败同类，当时的钉子只钉了中性 `platform_*`。**修法**：`build_openai_tools` 新增 `append_operator_tool` —— MCP 服务器提供的工具绕过目标关键词裁剪（角色门控保留；服务器集合由运维配置约束，token 成本有限），内置重型工具仍照旧裁剪。**回归**：`tests/agent/test_builtin_tools.py::TestMcpToolsSurviveGoalPruning` 双向钉住（MCP 工具在裁剪集外仍存活 / 内置工具仍被裁剪）。
- **测试** — 定向 647 passed（builtin_tools + blackboard_dispatch + model_ablation + platforms）；tests/agent + tests/security 全绿。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 三场 CTF 实战日志暴露问题修复：verify_fact 误拒（共享原文片段层）· 拒绝型回复误记工具 degraded · PowerShell 中文乱码 · CSS/JS 伪 flag</summary>

- **修（高·复现于三场连跑）：`blackboard_verify_fact`/`add_fact` 对"叙述+原样引用"型 fact 全量误拒** — 2026-10-12 三场 CTF2 连跑（Packet Yard / MDM pin-set / OrbitPay 重放）中，模型的 fact 均为"自己的话 + 原样引用的工具输出"，而既有校验要求整段子句逐字命中或 ≥90% 词元重合；工具输出只要混入不同标点或中文（`=== MDM 策略审查器 v2.6 (Policy REPL) ===`、`pin-sha256=<base64>`、`recovered: <32hex>`），引用即失配 → 每场全部 candidate，完成门随后索要更多无法提供的已证实 fact，每场多烧一整轮。新增**共享原样片段层**：fact 与证据的最长公共归一化片段 ≥8 字符、且片段携带真实内容（中文连串，或 ≥5 字符非停用词且非纯 id/hash 的实词）即证实。防伪造底线逐条钉死：裸时间戳/id（`job id 1758432000123456`）、借真 hash 编造叙事（APT implant）、停用词袋、部分词匹配（config≠configuration）、未见字面量——全部仍拒。新增 7 例回归（`test_blackboard_witnessing.py::TestNarrationGluedToQuotedObservation`）。
- **修（高）：验证性拒绝被记成工具故障** — `blackboard_verify_fact` 的正常否定回复（"cannot verify … keep it as candidate"）与 `save_playbook` 质量门拒绝（"rejected: missing structured headings"）都以 `[!]` 开头，撞上 `_FAILURE_MARKERS` 的 `[!]` → 工具被记 degraded，"is currently degraded after N failure(s)" 提示接着劝模型远离一个**工作正常的工具**（实测：模型认定 verify_fact 坏了、放弃验证，被迫空烧一轮补黑板仪式）。新增 `_REJECTION_LINE_RE`：仅在框架自产 `[!]` 行上识别拒绝语义（cannot verify / rejected: / execution refused / requires / blocked operation / 缺少必需参数 / 未找到等），分类为 ok=True 不再计入工具健康；真实故障（traceback / timed out / 执行错误 / 未安装）仍 degraded，Exit code 与 HTTP 状态显式信号优先级不变。
- **修（中）：CSS/JS 被当 flag 上报告** — 目标页面样式表使 `root{--paper:#f4ecdc;…}`、`h1{font-size:…}`、`sub{…}`、`try{out(atob(f.body));}` 全部命中 flag 形正则，solve report "关键证据"被四条样式表噪音填满。`is_placeholder_flag` 增补代码体判定（体含 `;`/`(`/`)` 或以 `--` 开头 → 占位符），`_extract_progress` 的 "flag-like token observed" 一并过滤占位符；真 flag 形状（`CTF2{uuid}`、`n1book{32hex}`、`flag{PbzrPuvan}` 等）实测全存活，完成门的证据 flag 白名单同步受益。
- **修（中·端到端实测）：Windows PowerShell 中文乱码** — PS 5.1 对无 BOM 文件按 ANSI 码页读、管道按 OEM 码页写；中文 Windows 上两者皆 GBK，`Get-Content -Raw notes.md`（UTF-8）直接吐 `杩愮淮澶囧繕`，实战中模型烧了 3 次调用（ReadAllBytes + GB18030/UTF8 试错）才拿到干净文本。`_shell_argv` 对 powershell/pwsh 统一前缀固定 UTF-8 序言（`[Console]::OutputEncoding` + `$OutputEncoding` + `$PSDefaultParameterValues['*:Encoding']='utf8'`，框架固定文本、不来自模型命令）。本机 zh-CN Windows 实测：同一读取加序言得干净原文、去序言复现日志同款乱码；cmd 分支不动。
- **测试** — 全量 **4966 passed / 17 skipped / 0 failed**（ witnessing 26 / correction_layer 14 / agent_state 12 / spawn_hardening 全绿）。已知环境项：`TestWindowsTreeKill` 2 例偶发单跑失败（`stdout=None`），已实测 git 干净基线同样失败，与本批无关。
- **过程教训（并行会话）** — 本批工作区曾遭并行 cli 重构会话覆盖（`blackboard.py` 与 witnessing 测试被还原至 HEAD，另 5 文件幸存），已重放修复并全量复跑；多会话并行期未提交改动有被吞风险，修复批应及时落库。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — TECH-DEBT 两条真债清偿：技能库 references 去重（−3,751 行）· 两个上帝文件拆分（builtin_tools 5,473→2,853 / cli.main 5,355→845）</summary>

- **技能库 references 去重（TECH-DEBT ①，commit `86322a6`）** — 新增 `vulnclaw/skills/_shared/references/` 固定共享根 + SKILL.md frontmatter `shared_references` 声明机制：声明是**操作员写盘的静态清单、非模型输入**，`resolve_skill_reference` 先查本技能 `references/`（原逻辑原路径），声明过的名字才回退共享根，且**复用同一套 symlink-aware containment（穿越面零放松）**；本技能同名文件优先 = 保留本地覆盖。声明清洗把 `..`、绝对路径、盘符、反斜杠、非字符串全部丢弃。13 组重复（web 域 3 + android 域 9 + `upstream-source.md` ×34 包）全部迁移，剩余重复 **0 组**，净删约 3,751 行。防回潮：`test_no_duplicate_references.py`（任意两份逐字节相同即 fail，含 `_shared`）+ `test_shared_references.py` 14 条契约用例。
- **`builtin_tools.py` 按工具族拆分（TECH-DEBT ② 前半，9 笔提交）** — 5,473 → 2,853 行，拆出 `vulnclaw/agent/tools/` 子包：`shell_exec` / `python_exec` / `nmap` / `http_probe` / `brute_force` / `runtime_diff` / `ocr` / `pyc` / `pdf` / `subprocess_util` / `_shared`（跨族 `_runtime_config`）。`builtin_tools.py` 保留 gating/policy/dispatch 与 schema 注册并**原样 re-export 每个搬走的名字（含私有名）**，旧 import 路径与测试的属性访问（含 `monkeypatch.setattr(builtin_tools.subprocess/shutil/httpx/time, …)` 这类模块对象 patch）全部不变。两个坑已成文（TECH-DEBT ②）：搬走的代码需自补 stdlib import；`verify_execution_boundary.py` 的 spawn 白名单键含文件路径，**必须同笔提交删旧键加新键**。`_bg_*` 后台任务族**刻意不拆**（模块级可变状态 `_bg_tasks`/`_bg_seq`/`_bg_lock` + 测试属性访问，属单独设计任务）。
- **`cli/main.py` 拆分（TECH-DEBT ② 后半，6 笔提交）** — 5,355 → 845 行（−84%）：`cli/repl.py`（REPL 循环 + 目标识别 9 helper + `_from_main` 调用时解析设施）、`commands_run.py`（run/solve/go/persistent/recon/scan/network-scan/exploit/report）、`commands_platform.py`（ctf2/gcs/competition）、`commands_config.py`（config 组）、`commands_admin.py`（kb/experience/target-state/plugins + learn/feedback）。`app` 仍是 main.py 唯一装配点，**命令数 24 / 子组 7 全程零变化**；测试从 `cli.main` 导入的名字全部 re-export 保活。顺手修 `_print_cli_manual` 双定义（`52d7689`）。**本轮核心教训**：CLI 拆分的真坑是测试大量 `monkeypatch.setattr(cli_main, "X", …)` 打在 facade 上——搬走的代码读自己模块的 import 副本会让 patch **静默 no-op**（曾致 16 例 `--stream`/solve 默认值测试失败），唯一可靠解法是被 patch 的名字一律经 `_from_main` 调用时解析。
- **`cli/__init__.py` 去重（拆分遗留收口，commit `64d80c6`）** — 与 `_helpers.py` 双定义的 12 个 helper 中 **8 个已漂移**（`_run_cli_orchestrated_task` 60 行 vs 41 行同名不同行为），且 `__init__.py` 是仓库唯一带 UTF-8 BOM 的源文件。所有消费方均从 `_helpers` 导入、包级零引用零 patch 锚点 ⇒ 改为全部从正典 re-export（same-object 实测），BOM 一并去掉。
- **测试基线** — 全量 **4953 passed / 17 skipped / 0 failed**（拆分全程逐笔跑全量，基线 4933→4949→4953 随新增护栏测试递增，零回归）；`execution-boundary OK`（27 spawn 站点全在白名单）；CLI 表面逐笔核对 24/7 不变。已知环境项（非本次引入）：`test_spawn_hardening::TestWindowsTreeKill` 2 例在本机单跑失败（`tasklist` 返回 `stdout=None`），已实测在重构前基线同样失败。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — round19 审计收口：共享引用回到提示词广告窗口 · Windows bootstrap 单源化 · 采集段名去重大小写对称</summary>

- **修（中低·可发现性）：声明的共享引用重新进入提示词的广告窗口** — `86322a6` 去重落地后，`loader.py` 把声明的共享名**追加**在技能自有引用列表末尾，而提示词只展示 `references[:10]`（`skill_context.py:250/:289`）。实测 `client-reverse`（11 自有 + 9 个 android 共享）：共享引用全部落在索引 11–19，广告窗口 **0 条**——去重前按 `reference_sort_key` 全序时 9 条全部在窗（该排序键的注释本就写明它是为"前 10 条窗口"设计的，追加队尾违背设计意图）。缓解因素（SKILL.md 正文逐条点名）保住了可加载性，但广告列表名存实亡。现共享名并入**同一排序键**统一重排，恢复去重前语义：实测 9 条 android 引用全部回到前 10；全库 56 个技能（39 个声明者）列表全序校验零违规、声明即存在的名字全部被广告。
- **修（低）：`WINDOWS_BOOTSTRAP` 不再是死常量** — `remote.py` 定义后零引用，`_do_collect_windows` 调用点又内联了一份逐字相同的 ScriptBlock 载荷，两份拷贝迟早漂移。现调用点改为 `f'powershell.exe … -Command "{WINDOWS_BOOTSTRAP}"'`，实测与原字符串**逐字节相同**；新增源级防回潮测试断言该载荷全文在 `remote.py` 里只出现一次。
- **修（低）：`validate_collector_commands` 段名去重大小写对称** — 判定用 `name.lower() in seen` 却 `seen.add(name)`（存原大小写），混合大小写重名会漏报。当前 33 段名全小写故无实际影响，属堵潜伏；现统一存小写，新增 `("identity","Identity")` 用例。
- **测试** — `tests/skills/test_shared_references.py` +2（合成用例钉"共享名并入排序而非队尾、入窗且全序"；真库全技能 `reference_sort_key` 全序守护）、`tests/security/test_remote_collector_integrity.py` +2（大小写重名拒收 / bootstrap 载荷单源）。目标测试 39 passed / 1 skipped（PowerShell 环境跳过，既有）；全量 **4953 passed / 17 skipped / 0 failed**。
- **TECH-DEBT** — 条目 ② 的"⏳ main.py 仍待拆"已过期（窗口内已拆完 5,355→845 行，`_print_cli_manual` 双定义随 `52d7689` 清除），更正为已拆完；并记入拆分遗留（`cli/_helpers.py` 与 `cli/__init__.py` 约 16 个同名 helper 双定义、`_helpers.py` 带 UTF-8 BOM，后续清理项）。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — remote_collect 自动 OS 探测与 Windows 只读 framed 单文件回传</summary>

- **新增**：`remote_collect` 在单次批量审批后先执行有界 OS probe；Linux 保持既有 33 段 POSIX/tar.gz collector，Windows 改走只读 PowerShell collector，不依赖 zip/tar。
- **Windows 回传**：各 section 写入一个 UTF-8 长度帧单文件，经 base64 传输；帧含固定 magic、section 名、十进制 UTF-8 byte length、payload、record terminator 与 end marker。严格本地解析拒绝坏 magic、截断/超长 payload、重复或不安全名称、end marker 后尾随字节，并逐 section 落盘，继续执行 overwrite 保护。
- **清理与边界**：仅在 stdout marker 确认后清理本次 collector 生成的远端 artifact；`keep_remote=true` 保留。Windows 路径不调用 tar extractor。目标必须有可达 SSH + PowerShell；VPN 只提供路由，不会创建 SSH 或启用 WinRM/RDP。探测未知/歧义/超时 fail-closed，退回 `remote_exec` / `remote_fetch`。
- **验证范围**：真实 Windows SSH/PowerShell 端到端仍未验证，不宣称现场实测；保留真实环境验证项。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 副驾 playbook 一键注入：自动认证据（认不出不注入），标签可覆写</summary>

- **修（中·机制）：`COPILOT_PLAYBOOKS=1` 的自动注入不再读粘贴正文** — 起因是用户实战反馈"prompt 里还是没有 playbook 内容"。查下去发现**注入了但全是错的**：副驾路径把**整段用户消息**（= 操作员粘贴的终端输出）交给 `target_fingerprint` / `challenge_class_signature` 当检索条件，而终端输出里全是会被误读的 token。实测（2026-10-10）一条勒索排查的粘贴：
  - `python3 -c "import socket,subprocess,os;"` → 引号规则（`_CLASS_QUOTED_RE`，本意是读**题目名**）把 shell 参数当成标题 → 查询词 `'import socket,subprocess,os;...'`；
  - `find / -newermt '2026-03-14'` → 查询词 `'2026-03-14'`；
  - 面向操作员的**契约自身**含「命令执行」，被 `vulnerability_classes` 读成类别 **`rce`**。
  合成查询 `'import socket,subprocess,os;... 2026-03-14 rce'` ⇒ 命中 `coderunner-python-sandbox-escape` / `pickle-deserialization`——**给勒索题塞 RCE 笔记**。另实测"剥掉引号"**不是通用解**：修好了勒索案例，却让一个原本正确的上传案例变错（`actf2020-upload` → `ofbiz-groovy-rce`），即该路径**不稳定**比"没有"更糟。
- **修法**：新增 `vulnclaw/agent/playbook.py::operator_declared_labels()`，只认操作员**显式写的标签形态**（`[tag]` / `category x` / `difficulty x` / CVE id），**绝不读引号内的 shell 参数**；`AgentCore._chat_playbook_brief` 改用它，且 fingerprint 只吃 `origin` 不再吃 `goal`。**默认行为不变**（该功能本就在 `VULNCLAW_CHAT_PLAYBOOKS` 门后、默认关）。
- **实测效果**：写 `category incident-response  [ransomware]` → 命中 `ir-triage-checklist-ten-drills`（**1.0**）；**不写标签 → 零注入**（不再塞错笔记）。
- **回归**：`tests/agent/test_chat_playbook_label_only.py` 9 例（钉住"引号参数/时间戳/契约措辞都不算标签"+"显式标签必须被采纳"+端到端"无标签零注入"）。
- **文档**：`IR-PROMPTS.md` §0.3 重写（结论由"自动注入有害"改为"写标签即可用"，并保留根因记录）；`IR-CONTRACT.txt` 第 1/2 段加**类别标签行**（6 种常用类别照抄）；`copilot.cmd` 注释同步（仍纯 ASCII，非 ASCII 字节数 0）。


- **追加：一键注入（2026-10-10 用户要求"不用我自己查询"）** — 上一条修成"必须手写标签"，用户指出现场不该让人做分类。新增 `playbook.auto_label_from_evidence()`：从**粘贴输出里的证据**推类别，`operator_declared_labels()` 优先、证据推断兜底。规则是**封闭的**（每组至少命中一个 token），7 类：ransomware / cryptomining / pcap traffic / webshell / data exfiltration / persistence audit / hidden account。
  两条实测逼出的取舍：① **宁可给空不给错**——认不出就不注入（上一版正是"整段模糊匹配→静默注错"）；② **pcap 优先于 webshell**——`webshell-plus.pcapng` 这类流量题文件名含 "webshell"，故 webshell 规则**去掉裸词**，由捕获文件证据判为 `[pcap traffic]`。
  过程中修掉自己两个错：**规则语义写反**（首版要求"所有 token 全中"，现实不可达 ⇒ 一条都不命中，改成"每组任中一个"）；**重排规则时切坏代码块**（标签行与 token 组错位，已按块重写）。
  回归：`tests/agent/test_chat_playbook_label_only.py` 扩到 **17 例**（含反例：普通端口扫描/闲聊→零注入；pcap 文件名含 webshell→判 pcap；operator 标签覆写证据推断）。
  ⚠️ **已知噪声**：命中的 2 篇里常有一篇 `autonotes-*`（自动笔记，与干货同分）。机制可用了但召回仍会给自动笔记——按 slug 取舍（`autonotes-*` 基本可忽略）。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 第七轮审计收口：复测非法 verdict 不再甩 traceback · HTML 报告转义捕获字节</summary>

- **修（高）：HTML 报告转义正文，堵住存储型 XSS** — HTML 输出用 `Template(...).render(content=report_content)` 包裹，而 jinja2 的 `Template` 默认 `autoescape=False`。报告正文里包含由 `_render_http_captures` 逐字内联的**目标请求/响应正文**，且该页面由 Web 以 `text/html` 直接回传（`/api/reports/download`）——目标响应体里一个 `<script>` 就会在审阅者浏览器里执行。现 `autoescape=True`：正文在 `<pre>` 中仍可读，但 HTML 元字符一律转义成惰性文本。新增测试断言 fixture 里的 `<script>alert(1)</script>` 在 HTML 输出中变成 `&lt;script&gt;…`。
- **修（低·CLI 健壮性）：retest 非法 `--verdict` 不再抛原始 traceback** — `RetestStore.conclude()` 对未知 verdict 抛的是**裸 `ValueError`**，而 `retest_cmd` 只捕获 `FindingsFileError` 与 `RetestStoreError` 家族（`RetestStoreError` 虽继承 `ValueError`，但裸 `ValueError` 不是它的成员）→ 用户敲错 `--verdict` 看到的是完整 traceback。现改抛 `RetestStoreError`，CLI 收成一行红字提示并 `exit 1`。新增测试断言 `--verdict not-a-verdict` 输出含错误名、且不含 `Traceback`。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 第六轮审计收口：<code>fixed</code> 处置不再被校验抹掉 · 复测备注幂等 · 解绑命名空间 · 快照路径闸</summary>

- **修（中）：`fixed` 处置不再被下一次校验抹回 `verified`** — `_sync_status_fields()` 在 `verified` 分支无条件写 `lifecycle_status = "verified"`，而 `fixed` 是复测（A1）盖的**处置**状态、与 verified/pending/rejected 正交。于是 `model_validate`（经 `model_post_init`）往返一圈就把 `fixed` 还原成 `verified`：实测 `f.lifecycle_status='fixed'` → `model_dump_json()` → `model_validate_json()` → `'verified'`。现改为在重算验证轴时保留 `fixed` 处置（`clear_intake_quarantine` 的 `candidate` 降级同样不再覆盖 `fixed`）。当前 CLI 仍不写回 `findings.json`（有意设计），但这条堵死了"哪天真写回就丢"的陷阱。
- **修（低）：`apply_verdict` 对 `verification_note` 幂等** — `_remember` 按 `retest_id` 去重，但 `verification_note` 的追加无守卫，同一 record 折两次会追加两遍"复测（第 N 轮）：已修复"。现 `_remember` 返回"是否首次加入"，note 仅在首次追加；`retest_history` 行为不变。
- **修（低）：`unbind` 按命名空间精确匹配，不再一次删两条** — `snapshot_id` 与 `request_id` 同为 16-hex、共用一个 `set[str]`，扁平匹配下"一个 ref 的 snapshot_id 恰等于另一 ref 的 request_id"会连带删掉两条。现优先精确匹配 `snapshot_id`，仅当无 snapshot 命中时才回退到旧式 `request_id`（保住 legacy 引用）。实测：`unbind(s1)` 后只剩 `(s2, s1)`，legacy `request_id` 解绑仍生效。
- **修（低）：`RunContext.snapshot_path` 自带路径闸** — 该函数把 id 直接拼进路径，此前自身无闸、只靠调用点（`target_state.store`）的 `SNAPSHOT_ID_PATTERN` 兜底，且该 pattern 放行 `..`。现函数内拒绝非单一组件（含 `/`、`\`）并做 `relative_to` 纵深校验。**注意**：这里的 id 是**时间戳**（`20261009_161030_recon`）、不是 traffic 证据层的 16-hex，故用的是命名空间无关的路径安全校验，**不能**套 `is_valid_snapshot_id`（那会拒掉全部合法调用）。
- **测试** — 新增/扩展 6 例：`test_findings_schema.py` +3（fixed 往返/未验证 fixed/clear 不覆盖）、`test_retest_service.py` 扩 1（note 幂等）、`test_evidence_binding.py` +2（命名空间碰撞 + legacy 回退）、`test_run_persistence.py` +1（snapshot_path 闸）。全量 **4914 passed / 17 skipped**。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 分工按实际人力重写（4 人队 = 2 能打的 + 2 门外汉）· WP 不用交 · 现场卡补收束点</summary>

- **两个前提变更（用户 2026-10-10 明确）**：① **赛方明确 WP 不用交** —— 培训时那句"需在截止前提交演练报告"作废，`IR-WP-TEMPLATE.md` 保留作赛后复盘、现场不填；② **实际是 4 人队（4 个账号）= 你 + 1 位稍微有点经验的选手 + 2 位门外汉**，门外汉不懂 vulnclaw、不会 CTF。
- **`IR-RUNBOOK.md` §9.3 按 V4 重写**（V2 那版把 4 人都当能打的，让队友"捡送分题""复现已交的题"——门外汉做不了）：4 人里 **2 名能打的各开一条线**（只在分诊/停开新题两个锚点对齐），**2 名门外汉**只做三类不需要判断的活 —— **计时**（七个闹钟 + 时间盒走到 80% 喊话）、**台账**（一页纸，只登记不代交）、**素材**（照主攻手的话截图/抄命令原文）。附门外汉三条硬规矩（只做被要求的动作、不确定就原样贴/喊人、不代提交），并写明 4 个账号里 2 个暂时闲置、能否派上用场取决于现场待确认第 8 条。
- **WP 相关表述全线更新**：`IR-RUNBOOK.md`（§五事实表、§七交付物、§9.2 收工段、§9.4 计时锚点、P1-6/P1-8 状态行）、`IR-FIELD-CARD.md`（头部锚点、副驾纪律、§4 提交纪律、§5 收工清单）、`IR-PROMPTS.md` §6、`IR-PENTEST-CARD.md`、`IR-WP-TEMPLATE.md` 头注 —— 一律改为"只留痕 + 逐题提交核对"，15:00 后不再拼报告。`IR-PROMPTS.md` §6 也从"出 WP 的提示词"改为"留痕/复盘的提示词"。
- **§九 时间盒表**：15:00–15:20 由"回收 + 出 WP"改为"回收（3 行状态 + 归档留痕）"；强调"先把 flag 交了再整理"。
- **现场卡补三处（同日）**：① §0 开场清单加**「当天必做两件」**（清 `remote.hosts`——里面仍是三台带明文口令的本地演练容器；12:20 前进应急段要切 `task_mode: ir`）——这两条原本散在 runbook 里，现场卡上找不到，属"当天不做就会翻车"的项；② 加**「⏹ 收束点：这 5 条全绿就可以开打」**（分诊表在手 / 副驾会话能起 / 护栏到位 / `remote.hosts` 干净 / 计时与台账有人），给开场 30 分钟一个明确终点；③ `IR-PROMPTS.md` 新增 **§0.1.1「认领 target 的四道门」**，把第五轮审计补的第四道（`chat` 内部认领）连同前三道一起写成现场可查的检查法（提示符应保持 `vulnclaw Ready>`；出现具体名字就先 Ctrl+C 再单独发 `chat`）。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 第五轮审计：副驾 target 第四道来源、<code>config set</code> 的 fail-open、<code>config get</code> 的 dict 键</summary>

- **修（中）：copilot 下 `chat` 不再从粘贴里认领 target** — 前三道门（`_repl_no_auto` / `_mined_target_for_session` / `_target_after_agent_result`）只治了 REPL 的 `current_target` 变量，而 `AgentCore.chat` 另有一条**独立**认领路径（`core.py:684` 的 `target or self._detect_target(user_input)`）。实测：`VULNCLAW_REPL_NO_AUTO=1` 下同一段抹了地址的 IR 粘贴，提示词仍出现 `当前渗透测试目标: access.log`，且 `~/.vulnclaw/targets/<key>/state.json` 被重写。新增 `_copilot_pins_target()`（同一 env 门）把 `chat` 的认领也钉住——**显式传入的 target 仍生效、已设 target 保留，未设 env 时逐字节不变**。
- **修（中·fail-open）：`config set platforms.<name>.enabled false` 不再把开关打开** — 第四轮记的"`config set platforms.*` 抛 traceback"只修了一半：遍历仍用 `getattr`，而 `platforms` 是 Pydantic `extra="allow"` 模型、段名在配置里尚不存在时照样 `AttributeError`。修好遍历后新暴露更糟的一半：新建段无既有值可推断类型，`"false"` 以**字符串**落盘，而读端 `registry._config_enabled` 是 `bool(entry.get("enabled"))` —— `bool("false") == True`，**把"关掉平台工具面"反着打开**。`settings.py` 现新增 `_config_child()` / `_config_extra_allowed()` / `_coerce_scalar_literal()`，`set_config_value` 覆盖"新建 extra 段"这条路径并落布尔。
- **修（低）：`vulnclaw config get` 支持 dict/extra 键** — 原本是裸 `getattr` 链，`config get platforms.ctf2.enabled`、`mcp.servers.chrome-devtools.enabled` 直接 traceback 穿出 CLI（而 `config/schema.py:1048` 的注释恰恰推荐这些键）。新增 `settings.get_config_value()`（与 `set` 共用遍历），未知键 → 干净报错 + 退出码 2。
- **修（低）：`vulnclaw retest --verdict fixed` 的提示不再像落盘** — 第四轮第 8 条按选项 ② 收口：提示改为「已记入复测记录，未写回 findings.json」。**行为不变**（不写回是模块 docstring 声明的有意设计），只纠正表述。
- **文档** — `AUDIT-2026-10-08.md` 新增《第五轮》，含三条发现的证据、探针实测与"未改的行为（有意）"说明；本仓库根新增 [`PLAYBOOK-SHORTLIST.md`](PLAYBOOK-SHORTLIST.md)（赛前 playbook 手贴短清单，311 篇 → 精选 ~45 篇）。
- **测试** — `tests/cli/test_user_intent.py::TestCopilotPinsChatTarget` 4 例、`tests/cli/test_config_get.py` 5 例、`tests/retest/test_retest_cli.py` +2 例。`tests/cli + tests/config + tests/mcp + tests/agent` → **2150 passed / 7 skipped**。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — <code>copilot.cmd</code> 第三层：<code>COPILOT_DENY</code> 硬黑名单（日志证明）<code>fetch</code> 不在审批闸内</summary>

- **新：`copilot.cmd` 支持 `set COPILOT_DENY=<host>`** — 该主机进**硬黑名单**（`VULNCLAW_SAFETY_DENIED_HOSTS`）。起因是一次渗透副驾演练的终端日志（`E:\vulnclaw\log.txt`，5616 行）被逐条拆开：同一句"不要调用任何工具"，IR 演练 **0 次**工具调用、渗透演练 **10 次**（`blackboard_add_fact`×1 / `python_execute`×1 / `shell_command`×1 / **`fetch`×6**）。其中 `python_execute`（它想自己 curl 目标）**被审批闸弹窗拒掉** ✅、`shell_command`（在本机写马）**被人放行** ⚠️、而 **6 次 `fetch` 全部无提示通过** ❌ —— **审批闸不覆盖 `fetch`/`http_probe_batch`**，模型又会从粘贴文本里挖出主机进 allowed，所以提示词是唯一挡它的东西。硬黑名单是唯一能挡住 `fetch` 的一层。
- **坑（顺带修）**：`VULNCLAW_SAFETY_DENIED_HOSTS` 是**覆盖**语义而非追加 —— 直接用它设目标会**顶掉 `tp.qianxin.com`**（计分平台黑名单）。`copilot.cmd` 因此把 `tp.qianxin.com` 追回列表。实测：未设 → `['tp.qianxin.com']`；设 `127.0.0.1` → `['127.0.0.1', 'tp.qianxin.com']`。启动器仍为**纯 ASCII**（非 ASCII 字节数 0），`--version` 透传正常。
- **文档** — `IR-PROMPTS.md` 新增 §0.1「机制层：提示词不是唯一防线」，把上表（提示词 / auto_review / 硬黑名单三层各自的实测效果）与标准启动写法写进去。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 新增 <code>IR-PROMPTS.md</code>：现场提示词卡（四个槽 + 四种场景模板 + 八句纠偏）</summary>

- **新增 [`IR-PROMPTS.md`](IR-PROMPTS.md)：现场提示词卡** — 把散落在 runbook §五、现场卡 §2、`copilot.cmd` 横幅与彩排结论里的"消息该怎么写"收成一张照抄卡。核心是**四个槽**：① 执行点/环境（不写 → 它按 bash 给多行命令，cmd 逐行报错）② 角色+目标（不写 → 切 AUTO 自跑或答成报告）③ 范围（副驾模式下作用域闸完全失效，边界只剩这句话）④ 输出契约（"不要调用任何工具"这一句实测把 16 次工具调用压到 0 次）。另含：IR 副驾模板（含 Windows 目标变体）、渗透副驾模板（含"先抄工具清单"与"当前上下文"行）、**渗透 agent 直连**的 `--goal`/`--prompt` 写法与 `ssh -D` 隧道版、强制技能路由表（`/incident-response` 等，confidence 1.0 vs 隐式 0.11–0.2）、**八句纠偏短句**、WP 提示词、**反面清单**（"随便看看"/"帮我提交 flag"/贴答案卡/裸启动粘大段输出/在副驾里做爆破…）、以及 30 秒开场清单。
- **文档** — `IR-FIELD-CARD.md` 头部加指针。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 新 <code>VULNCLAW_REPL_NO_AUTO=1</code>：副驾模式有了机制级开关（粘贴不再把 REPL 拖进自主循环，也不再认领 target）</summary>

- **新：`VULNCLAW_REPL_NO_AUTO=1` 把 REPL 钉在单轮 chat（copilot 模式）** — 2026-10-09 彩排暴露的**代码级**根因：`_should_auto_pentest` 的末段是"只要输入里能抽出**本地路径型 target** 就直接 `return True`"（`_extract_target_from_input` + `_is_local_path_target`），而 IR 的粘贴内容里全是 `/usr/sbin/cron`、`/var/www/html/uploads`、`/tmp/.x/.kworker`，甚至一行 cron `*/3 * * * *` 都会被抽成 target `/3`（实测）⇒ **每一次粘贴都重新进 AUTO 自主循环**，抹 IP 与事后打 `chat`（要求整条输入恰好等于 `chat`/`manual`/`单轮`/`手动`，且须在 AUTO 激活后单独发送）都拦不住它自跑。修法是在函数最前面加一道 env 门 `_repl_no_auto()`：命中时**在任何分支之前** `return False`。副驾会话统一 `$env:VULNCLAW_REPL_NO_AUTO='1'; vulnclaw`；**env 未设时行为逐字节不变**。实测：同一段 IR 粘贴，未设 → `should_auto(None)=True`，设了 → `False`。
- **同一道门也关掉"从粘贴内容里认领 target"** — 第三轮彩排发现即使不进 AUTO，REPL 仍从粘贴里抽出 `/usr/sbin/cron` 当会话目标（提示符 `vulnclaw /usr/sbin/cron | Recon>`）。新增 `_mined_target_for_session()`：copilot 模式下**不挖目标**（`return None`），调用点由 `_extract_target_from_input(user_input)` 改为它（`cli/main.py` 的 target 切换/首次认领分支之前）。要指定目标时**显式**用 `target` 命令即可（flag-skill 那条路径不受影响）。实测：同一段粘贴，未设 → `mined='/3'`，设了 → `None`。
- **第三个来源（第四轮彩排暴露）：agent 回合回报的 target 也要挡** — 前两道门都生效（无 AUTO、无 Turn 计数、`Tools: none`），但提示符仍是 **`vulnclaw access.log \| Recon>`**：单轮 chat 的 `after_result()` 里原本是 `if result.target: current_target = result.target`，而 agent 会把自己从粘贴里挖到的 `access.log` / `/usr/sbin/cron` 当作 target 报回来。新增 `_target_after_agent_result(current, reported)`：copilot 模式**保持操作者的 target 不变**（`return current`），非 copilot 仍是原来的 `reported or current`（"只在 agent 报了才覆盖"）。
- **新：仓库根 [`copilot.cmd`](copilot.cmd) —— 副驾模式一行启动器** — 把三道防线钉在一个双击即用的脚本里：`VULNCLAW_REPL_NO_AUTO=1`（单轮 chat + 不认领 target）、`VULNCLAW_SAFETY_PERMISSION_MODE=auto_review`（只读免批；`python_execute` / `shell_command` 弹窗，副驾模式下直接拒 —— 提示词失效时的兜底）、以及把三条现场规则打在屏幕上（抹地址 / 模板必带"不要调用任何工具" / 提示符应为 `vulnclaw Ready>`）。参数透传（`copilot.cmd --version` → `0.3.9`，退出码 0）。
  ⚠️ **踩过的坑**：初版把中文说明写在 `.cmd` 里 —— cmd 按 GBK 读 UTF-8 无 BOM，注释与 `echo` 全被当成命令执行（`'CLAW_REPL_NO_AUTO' is not recognized` …）。**`.cmd` 一律纯 ASCII**，中文只放 `.md` 文档。实测两条 env 覆盖均生效：`VULNCLAW_SAFETY_PERMISSION_MODE` 未设 → `full_access`、设了 → `auto_review`（`load_config().safety.permission_mode`）。
- **测试** — `tests/cli/test_user_intent.py::TestReplNoAutoOptOut` 现 **9 例**：① **先钉住前提**——未设 env 时该粘贴确实触发 AUTO 且抽出的 target 是 `/3`（这条就是本特性存在的理由，防止以后有人改回默认静默失效）；② 设了 env 后粘贴/带 target/`start recon`/ctf2 平台句一律 `False`；③ truthy 拼写 `1/true/TRUE/True/yes/on/" 1 "` 全部生效；④ `""/0/false/no/off/maybe/2` 一律保持默认行为；⑤ copilot 下粘贴与普通 URL 都不再被认领为目标；⑥ 未设 env 时普通挖掘路径（URL → target、闲聊 → None）不变；⑦⑧ copilot 下 agent 回报的 `access.log` 不被采纳，未设 env 时仍按原规则采纳（`reported or current`）。`tests/cli` 全量 **458 passed**（0 failed）。
- **文档** — `IR-RUNBOOK.md` §五 彩排小节把"两条出路"改成"① 已实现（一张表说明关掉的两件事 + 启动器三层 + 第三轮实测）+ ② 兜底用法"；`IR-FIELD-CARD.md` §2 开场动作第 ③ 条改为"一律用 `copilot.cmd` 启动"（含手敲等价物与 Ctrl+C→`chat` 兜底）。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 副驾模式彩排（10/9 夜）：默认 REPL 会自己动手，四条前置纪律写进 runbook</summary>

- **文档（实测教训）** — 一次真人彩排（裸启动 `vulnclaw`，粘一段**假**的"网页终端输出"，其中含测试 IP）暴露四件在赛场算事故的行为，已写进 `IR-RUNBOOK.md` §五「主路径 = 副驾模式」下的新小节「副驾模式彩排结果」：① ⭐ **它从粘贴内容里抓出 URL 当 target 并切进 AUTO 自主模式**（提示符 `vulnclaw Ready>` → `vulnclaw http://203.0.113.7 | Ready | AUTO>`，日志 `[*] Entering autonomous pentest mode`，随后真发了三条 HTTP 探测、18.7 s 超时）——**贴原文等于把目标 IP 交给它自己去打**；② **主动去连 `remote.hosts` 里配置的三台演练容器**（victim/victim-crypto/victim-ransom，逐个 `remote_exec`）——赛前若把跳板机填进清单，它会直接 SSH 上去，正是红线"远程操控"的灰区；③ **乱调平台工具**（`platform_list` 列出 7 个 CTF2 练习场，`platform_list {"ref":"ctf2:daily"}` → `403 agent_scope_forbidden`）；④ **在笔记本上全盘搜索**（`Get-ChildItem C:\ -Recurse` → 60 s 超时 + 工具降级标记）。它给出的"命令 + 判据"（`cat -A` 看马 / `ls -laR /tmp/.x` / `grep -rIn 'flag{'`）是对的，但同时把**自己加载的技能文档内容**当成未解决的 pinned fact，与 ASK/证据闸门来回较劲两轮，最终 `Not achieved — steps=2`。
- **文档（由此定的四条前置纪律）** — ① 贴之前把输出里的 IP / URL / 域名一律抹成 `<target>`；② 粘完立刻打 `chat`（也认 `单轮`/`手动`/`exit auto`）退出 AUTO；③ `vulnclaw config set platforms.ctf2.enabled false`（必要时 `platforms.gcs.enabled false`）关掉平台工具面；④ 副驾会话用会话级 `VULNCLAW_SAFETY_PERMISSION_MODE=auto_review`（弹窗可拒），全局 `full_access` 只留给"agent 驱动打跳板机"。比赛当天另需清理 `remote.hosts`（现为三台本地演练容器）。
- **落地（同日）** — ①②已写进 `IR-RUNBOOK.md` §五 的副驾 prompt 模板（模板本体改成 `<target>` 占位 + "只输出命令、不要调用任何工具"）与 `IR-FIELD-CARD.md` §2 的开场动作；③已实际关闭并**用项目自己的加载器验证**：`platforms.ctf2.enabled=false` / `platforms.gcs.enabled=false` → `_config_enabled` 双双 `False`、`configured_adapters()` 返回 `[]`（平台工具面消失），备份 `~/.vulnclaw/config.yaml.bak-20261009-platforms`。
- **发现（未修，待你决定）** — **`vulnclaw config set` / `config get` 对 `platforms.*` 这类嵌套键会直接抛 traceback**（`set_config_value` 走 `getattr(config.platforms, 'ctf2')` 时炸，`settings.py:243`；`config get` 同因报错，`cli/main.py:3670` / `:3685`），而 `config/schema.py:1048` 的注释恰恰说 `extra="allow"` 就是为了让 `platforms.gcs.enabled: true` 生效 —— **文档指的路走不通，只能手改 YAML**。本次即手改（先备份、改完用加载器校验、失败自动回滚）。
- **第二轮彩排（同日，抹掉 IP + 模板加"不要调用任何工具"）** — 结果一半一半：✅ **工具调用 0 次**（第一轮 16 次）、✅ 平台工具不再出现、✅ 五轮都明确拒绝编造 flag、✅ 第 3 轮给出最优命令（`cp /proc/9137/exe` + `/proc/9137/{cmdline,environ,fd}` + `strings` —— 对"已删除的存活进程"正解）；❌ 但 `chat` 没能退出 AUTO（识别要求整条输入**恰好等于** `chat`/`manual`/`exit auto`/`单轮`/`手动` 且在 AUTO 激活后单独发送，`cli/main.py:977-983`），且它把 target 认成了 **`/usr/sbin/cron`**。**根因（代码级）**：让它进 AUTO 的不是 IP 而是**路径** —— `_should_auto_pentest` 末段只要从输入里抽出**本地路径型 target** 就 `return True`（`cli/main.py:4651-4655`），而 IR 输出里全是 `/usr/sbin/cron`、`/var/www/html/uploads`、`/tmp/.x/.kworker` ⇒ **每次粘贴都会重新进 AUTO**，"抹 IP + 事后打 chat"只能压住它动手、压不住它自跑。⇒ 两条出路已写进 `IR-RUNBOOK.md`：①（推荐）加 env 门 `VULNCLAW_REPL_NO_AUTO=1` 让 `_should_auto_pentest` 直接 `return False`（默认零影响 + 补回归测试）；②不改代码就用"粘 → Ctrl+C → 单独发 `chat`"兜底。`IR-FIELD-CARD.md` §2 同步更正开场动作（并把"不要调用任何工具"列为必带句）。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 赛前命令更正：<code>--only-host</code> 不在 <code>solve</code> 上（文档里那条"主路径命令"会直接报错）</summary>

- **修（文档，实测发现）** — `IR-RUNBOOK.md` §五「插上网线后的 30 秒动作」与 §五 任务 prompt 模板、`IR-FIELD-CARD.md` §3 模式 B、`IR-PENTEST-CARD.md` §0 都写着 `vulnclaw solve <target> --only-host <CIDR>`，**实测直接报 `No such option: --only-host`**（`vulnclaw solve --help` 无此开关、`vulnclaw run --help` 有）。带 `--only-host` 的命令只有 **`run` / `recon` / `scan` / `network-scan` / `exploit` / `persistent` / `tui`**（`cli/main.py` 各命令签名；`solve` 与 `go` 都没有）。四处文档改为 `vulnclaw run … --only-host …` 并加实测注记。
- **顺带记下的一条边界** — 别指望把网段写进题面绕过去：核心从任务文本解析 `Only test host X` 用的正则是 `[a-z0-9.-]+`（`agent/input_analysis.py:408-414`），**`10.20.0.0/16` 会被截断成 `10.20.0.0`**（退化成单主机精确匹配，网段失效）。要在 `solve` 上带作用域，只能走 **TUI `/scope`**（存进 `session.tui_scope_only_host`，TUI 起任务时会带 `--only-host`）或 **Web 任务台**（`only_host` 字段 → `task_service` 的 `allowed_hosts`）。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 新增 <code>IR-PENTEST-CARD.md</code>（渗透段粘贴即用命令卡），补上赛前缺口 P1-4 的一半</summary>

- **新增 `IR-PENTEST-CARD.md`：渗透段现场命令卡** — 补 §五点五 **P1-4「没有可直接粘贴的短命令卡」**的渗透一半（应急一半仍待出）。设计约束就是现场约束：**每条 ≤120 字符**（网页终端可能不支持长粘贴，超长的给 base64 两步法 `echo <b64> | base64 -d > x.sh`），每条命令标**来源**（`[原生]` 攻击机必有 / `[工具库]` 平台内置工具库下载后可用、**现场照抄实际清单** / `[本机]` 只在笔记本离线用），并按"现场会不会踩"写坑（`-sS` 要 root 故一律 `-sT`、`sqlmap` 太吵先手工三连、`linpeas` 别一上来全量、mimikatz 会留日志、Windows 上 `curl` 是 alias 必须写 `curl.exe`）。章节顺序=现场顺序：§1 60 秒侦察 → §2 Web 打点（目录/`.git`/备份/注入三连/弱口令）→ §3 反弹与传文件 → §4 Linux 提权 → §5 Windows 提权与凭据 → §6 横向与隧道 → §7 本机破解 → §8 判读解码与找 flag 落点 → §9 攻击机是 Windows 的对照表 → §10 五条纪律（只碰下发靶机 / flag 本人提交 / 输出原文贴回 / 11:30 停开新题 / 留证据）。
- **文档** — `IR-RUNBOOK.md` §五点五 P1-4 标记为**渗透段已交付、应急段待出**；`IR-FIELD-CARD.md` 头部加一行指向新卡。
- **更正（同日）：P1-4 的判据本身是错的** — 该条写"IR references 里全是分面长文档，没有任何'粘贴即用'的短清单"，但**两张应急段粘贴卡早就在技能 references 里**：`incident-response/references/paste-cards-linux.md`（100 行 / 45 条命令）与 `paste-cards-windows.md`（107 行 / 40 条）—— 卡自己的开头就写着"为什么有这张卡：IR references 里全是分面长文档，而平台网页终端可能不支持长粘贴"。**教训：写缺口前先搜一遍 references。** 现在两边都齐了（应急=技能里的两张卡，渗透=`IR-PENTEST-CARD.md`），P1-4 标为已闭合；`IR-FIELD-CARD.md` 与 `IR-PENTEST-CARD.md` 各加一行互指。
- **修（技能文档）：Windows 粘贴卡最后一条 140 字符命令超标** — 原 `powershell -c "gci C:\ -Recurse … -Include *.txt,*.log,*.bak …"` 140 字符，且正是卡里自己实测过的"递归扫全盘 271 秒"陷阱。改成两条窄范围等价命令（`$env:TEMP` 与 `C:\inetpub`，用 `-R`/`-Inc`/`% FullName` 缩写），各自 **≤120 字符**。实测三张粘贴卡现在**超 120 字符的行数均为 0**。
- **补（同日）：卡里加 §0「先定执行点与 OS」** —— 初版默认"命令在 Linux 攻击机上敲"，但现场有三个执行点（**你的 Windows 笔记本** / 平台攻击机 / 跳板机，后两者 **OS 未确认**，朱禹只说不保证是 Windows）。§0 给判定表（控制台里 `uname -a` vs `ver`/`whoami`）+ **30 秒可达性判定**（`Test-NetConnection` / `curl.exe`：通 → 侦察在笔记本上由 agent 驱动、闸门有效；不通 → 控制台里人打字、闸门失效）+ **边界一句**：从笔记本发包是本机操作（默认可用），**agent SSH 登进跳板机替你操作才是红线灰区**（`remote_exec`，别当主路径）。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 10/9 赛前培训纪要（元宝纪要）并入 runbook / 作业卡：分值差异、非线性解锁、平台入口与两处待澄清</summary>

- **文档** — `IR-RUNBOOK.md` §五 表补 10/9 培训纪要里此前**没记**的赛事事实：**不同 flag 分值不同**（分诊时把分值写进状态表，按"分值 ÷ 预计耗时"排序）、**工位随机分配 + 各队伍独立环境 + 严禁跨组交流**、入口是**点【进入演练】**且规则文档**自行查阅**（官方后续另发详细说明）、**上午只开渗透场景**（应急段之前别去找 IR 题）、界面**右上角倒计时**（= 现场唯一可信时钟）；**应急场景**补 **高校网站故障背景（运维视角）/ 任务附件给拓扑与登录方式 / 初始只开放部分节点控制台权限 / 非线性解锁（高亮·灰度）/ 官方适时发提示**。
- **文档** — 同节新增「⚠️ 10/9 培训纪要带来的三点待澄清」，并写明**该纪要是腾讯会议"元宝纪要"的 AI 提炼、不是逐字稿**，三条按待确认处理：① 纪要称"本地大模型对跳板机的调用能力至关重要"，与红线"禁止远程操控 / 非有效操作视为弃赛"**表述张力** → 必须问清 **agent 经 SSH（`remote_exec`/`remote_collect`/`remote_fetch`）驱动跳板机算不算被禁的"远程操作"**，答复前主路径仍是副驾模式（同时记下 `IR-FIELD-CARD.md`"AI 辅助已确认合规"与 §五点五 P0-1"没人问过"这处**文档内部矛盾**，以群内答复为准一起改）；② 纪要演示渗透拓扑时把**攻击机**称为跳板机 → 现场确认与 IR 跳板机**是不是同一台**；③ **非线性解锁** → §九"顺序解锁 ⇒ 到点必跳"收敛为"**线性链到点必跳、非线性节点可与主链并行**"。
- **文档** — 待确认表第 8 条（账号题集）补纪要信号：**各队伍独立环境** ⇒ 队内更像"一套环境 + 多账号"，§9.3 **B 档（双线 2+2）能否用仍待现场验证**。
- **文档** — `IR-FIELD-CARD.md`：开场清单加"**进入演练 → 先读规则文档 → 下载任务附件 → 记分值 → 留意高亮/灰度 → 工位随机禁跨组**"，倒计时写成唯一可信时钟；解锁一条改为**线性/非线性两分**；合规现状加一行"**纪要口径待核**"；现场待验证表加**第 7 行**（攻击机 vs 跳板机、SSH 驱动是否属"远程操作"），第 6 行补纪要信号。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 证据维护落地：GC 终于有人调（run 收尾 + <code>vulnclaw evidence gc</code>），解绑/重排有了暴露面</summary>

- **修（缺口 1）：`EvidenceStore.collect()` 在生产代码里**没有**任何调用方 —— 孤立 blob 只增不减** — 2026-10-09 复核。实现本身一直是对的（只删「没有任何索引行引用 + 超过 grace」的 blob），缺的是**调度**和**边界**：`run_dir=None` 会落到 `CONFIG_DIR/evidence` 这个跨 run 的全局根，一次误删就是别人的证据。新增 `vulnclaw/traffic/maintenance.py`：`collect_run_evidence(run_dir)` 只作用于**显式给定的单个 run**、best-effort 永不抛、**拒绝 `run_dir=None`**；索引不存在或**有坏行**时直接返回 `[]`（引用集不完整时"无人引用"的判断不可信，宁可少删 —— blob 只是占磁盘，删错就是证据丢失）。调度点：`orchestrator` 在 `mark_run_status(..., "completed")` 的**同一分支**调用（紧邻既有的 distillation 调度），默认 24h 宽限（报告刚渲完还能读到证据），回收条数写进 run 事件 `evidence_gc`。
- **新（缺口 2）：`vulnclaw evidence` 子命令组** — 三个动作都只在显式给定的 run 目录 / findings 文件上生效：`gc [--grace-days N] [--dry-run]`（dry-run 走 `plan_run_evidence_gc`，与真删共用同一条谓词，不会各自漂移）、`unbind <finding> --snapshot …`、`reorder <finding> --handles h1,h2`。**解绑/重排默认只看不写**，`--write` 才落盘 —— 这两个动作会削弱报告的证据面 / 改变引用顺序，不该一条命令就跑掉。谓词只留一份：`EvidenceStore.stale_digests()`（`collect()` 改为复用它）；findings 读写抽到 `cli/findings_io.py`（`retest` 与 `evidence` 共用同一套定位/落盘规则，原子写）。
- **复核发现（未改代码，等拍板）** — `unbind_finding_evidence()` 的 docstring 说"即使没匹配上也 bump `evidence_version`"，实现只在真删掉绑定时才 bump（`vulnclaw/traffic/binding.py`）。CLI 因此必须自己把"没有匹配到"打出来，否则调用方从版本号看不出这次请求被考虑过。改哪边会动绑定语义，留作赛后决定。
- **测试** — `tests/traffic/test_evidence_gc_schedule.py` 12 例（无 run 上下文绝不删全局 / 无索引不删 / **坏索引不删** / 引用再老也留 / 只作用于本 run / dry-run 与真删一致 / 收尾异常不外抛 / 源码级钉子：调度点必须与 completed 分支同函数）+ `tests/cli/test_evidence_cmd.py` 9 例；连带 `tests/traffic` + `tests/cli` + `tests/retest` 实测 **615 passed**（0 failed）。
- **文档** — `docs/project-map.md` 补 `evidence` 命令与 `traffic/maintenance.py`。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — 复测（A1）：<code>vulnclaw retest</code> —— 已上报的结论可以被复核，但改处置状态只有一个入口</summary>

- **新：复测工作流（A1，借鉴 ARTEX 的 `finding_retests` / `retester` 语义，不抄代码）** — 2026-10-09。此前 finding 一旦上报就是单向的：报告上写着"已验证 / 待验证"，**没有任何机制回答"打补丁之后这条还成立吗"**，处置状态也没有第二个来源能改。新增 `vulnclaw/retest/`（`store.py` 文件式会话存储、`service.py` 语义内核）、`vulnclaw retest` 子命令、`retester` 叶子角色。四条不变量照 ARTEX 的设计意图（而非它的 Go+PostgreSQL 实现）：
  ① **一个 finding 只有一条复测会话** —— 重复发起返回既有记录，不新开、不覆盖已冻结的快照；进程重启遗留的 `running` 由 `--sweep` 封成 `stopped`，**不自动重放**（对齐 ARTEX 的 orphan sweep）。
  ② **结论三选一 `reproduced` / `fixed` / `inconclusive`，只有第一轮能写结论** —— 后续追问轮只追加记录，`RetestConflictError` 拒绝覆盖第一轮结论；**只有 `completed + fixed` 才把 `lifecycle_status` 翻成 `fixed`**，`reproduced` / `inconclusive` 只留痕、不改状态。
  ③ **发起即冻结快照** —— finding 指纹 + `evidence_version` + 原任务约束（scope / methods），复测期间 finding 被改写也不改变本轮的判定依据。
  ④ **报告门槛不动** —— `is_report_included` 仍只看 `verification_status`：复测改变的是**处置状态**，不是验证状态。`retest_history` 随 finding 进 `findings.json`，`summary` 新增 `fixed` 桶（`intel/findings.py` 早已把 `fixed` 当终态，词表本就对齐）。
- **`retester` 角色**（叶子代理）—— 只读 + 探测工具面（无 `shell_command` / `python_execute` / `agent_run` / 提权），prompt 明令"不重跑原任务、不扩大 scope、不碰其他 finding"；`build_retest_brief()` 把约束、三选一结论与"最小定向复测"写进交给它的话术里。
- **CLI 默认不写回 run 目录** —— `vulnclaw retest <finding-id> --findings <findings.json|run 目录> [--verdict V] [--note …] [--constraints k=v,…]`、`--list`、`--sweep`；状态权威在复测存储里，CLI 只读已发布的 `findings.json` 定位 finding，**避免把运行产物改成另一种样子**。
- **测试** — `tests/retest/` **33 passed**（store 不变量 10 / service 语义 8 / CLI 接线 5 / 角色 5 / 报告纯增量 4，含 1 参数化）；连带 `tests/report` + `tests/cli` + `tests/config` + `tests/agent/test_roles.py` + `tests/agent/test_spawn_role_mapping.py` 实测 **731 passed**（0 failed）。
- **文档** — `docs/project-map.md` 补 `retest/` 模块表与 CLI 命令表。
- **未做（下一步）** — Web 端点（`/api/findings/{id}/retest`）与报告正文的"历次复测"段落；两者都需要一个 findings 注册表，留到 A1 第二轮。

</details>

---

<details open>
<summary><strong>Unreleased</strong> — flag 完整性：开括号必须在真实输出里找到配对的闭括号（不许自己补 <code>}</code>）</summary>

- **完成闸新增 flag 完整性判据：开括号必须观测到闭括号** — 2026-10-09 彩排真实事故：一道六段碎片题只拼出五段，模型**自己把缺的 `}` 补上**，候选于是既匹配 flag 正则、又"看起来有证据支撑" —— 它已把那个串写进黑板，而黑板的 tool result 本身落入证据面（`_flag_token_grounded` 的 `flag in evidence_text`），**等于自己给自己担保** —— 结果被当作答案报出，**平台判错**。新增 `agent/ctf_mode.flag_completeness_issues()`，两条刻意收窄的判据：① 答案里出现已知前缀的开括号 token、而全文找不到 `}`（`_FLAG_RE` 本就要求闭括号，所以缺尾段的候选根本不会被提取 —— 缺的是"把这件事说出来"）；② 完整候选的 UUID body 末段不足 12 位（8-4-4-4-6 不可能是完整 UUID）。`_completion_gate` 在 grounding 比对**之前**用它拒绝，理由写明"尾段从未被观测到，不要自己补括号"。⚠️ 判据**不能**写成"整串必须在工具输出里逐字符出现过"：正解本身就是拼装出来的，从不在任何单次输出里完整出现 —— 这条边界写在函数注释里。**测试**：`tests/agent/test_completion_gate.py` 新增 4 例（五段拼装即使"有证据"也被拒 / 完整 UUID 仍放行 / 无闭括号的措辞 / 6 个反例证明判据收窄 + 脱敏指纹形不误伤）；`tests/agent` **1425 passed**（+1 既有环境性失败）。**文档**：`IR-RUNBOOK.md` §五"提交前自查"补"括号必须配对 + 自我接地"两条，并注明拼装是允许的。

</details>

<details open>
<summary><strong>Unreleased</strong> — CLI 报告找回本 run 证据（run_id 反查 + --run-dir）；SSH 纳入硬黑名单 + target 文件名净化统一</summary>

- **修：`vulnclaw report <session.json>` 拿不到本 run 的取证仓库，还把"证据就在那儿"误报成"证据没了"** — 2026-10-09 彩排实测（受控实验，同一个 run 各渲一次）：**A 路** `report(session)`（= CLI；`generate_report_from_file()` **不传 `run_dir`**）正文**不内联**、两条引用被写成 **"⚠ 已绑定但正文不可读取（快照已不在索引中）"**、且不产出 `evidence_bundles`；**B 路** `report(session, run_dir=…)`（agent/orchestrator 路）正文 + 响应体正常内联、bundles 正常生成。**根因比表面深一层**：`vulnclaw solve` 从前**根本没把 run 写进会话**（`session.run_id` 为空 —— 只有 subagent 那条路会生成 `run_id`），"从会话找回 run"这条链在源头就是断的。修法两层：① `orchestrator` 在注入 `agent.run_dir` 的同一处把 `run.json` 的 `run_id` 写进 `session_state.run_id`（已有值不覆盖，兼容 resume）；② 新增 `run_context.find_run_dir_by_run_id()`（best-effort：无 id / 无 root / 无匹配一律 `None`，不抛 —— 调用方是拿它**改善默认值**，不是校验 run）+ `generate_report_from_file(session_path, run_dir=None)` 先反查再渲染 + `vulnclaw report` 新增 `--run-dir`（显式优先，不被反查推翻）。**实测**：新 run 的会话 `session.run_id` == 该 run 的 `run.json.run_id`，反查命中 run 目录；单测 4 例（正文内联 / 显式优先 / 反查 best-effort / 无 run 仍能出报告且保留"不可读取"提示）。⚠️ **渗透题同样中招**，不只 IR —— §9.2 让用 `report <session.json> --pdf` 交 WP，交出去的报告会自述证据不可读。
- **撤销（同日移除）：把 IR 答案卡渲成交付物的 `vulnclaw wp`** — 2026-10-09 曾加入 `vulnclaw wp <session.json> [--out] [--template] [--pdf]`，当晚评估后**删除**：命令、`vulnclaw/report/ir_wp.py`、`tests/report/test_ir_wp.py` 一并移除（`WP` 回到 `IR-WP-TEMPLATE.md` 人肉填的路线）。**报告跳过答案卡这条设计不变**：`blackboard_record_answer` 落的 `vuln_type="ir-answer"` 卡片不能被当漏洞渲染（round-10 finding #1），对应的回归用例已迁到 `tests/report/test_report.py::test_report_body_omits_answer_cards`。
- **文档** — `IR-RUNBOOK.md` §八 补记彩排 A 半结果（105 秒 / 5-6 分 / 用时分解）并附"同日已修"表（① 的 `wp` 方案同日撤回，改回 `IR-WP-TEMPLATE.md` 人肉填），§9.2 的 15:00–15:20 出 WP 步骤回到 `IR-WP-TEMPLATE.md` 骨架 + `report --run-dir`；`IR-FIELD-CARD.md` 收工清单同步。
- **文档** — §八 再补**渗透半彩排**（CTF2 练习场真靶机 BUU LFI COURSE 1，`completed` / 1 轮 / ≈0.09M token）：记下 **session 过期时的 Open API 绕法**（题目 id 从 `~/.vulnclaw/playbooks/` 的 `ctf2:practice:<pid>:<cid>` 引用捞 → `start_environment` 起靶机 → `get_environment` 取 `access_url`（`get_target` 是 session-only，401）→ `stop_target` 释放）；**交付链实测**：`report` 出 0 findings（flag 只因 LLM 第 4 节摘要才出现，77 行）；同日渲过的 `wp` 结构化版本（148 行）所用命令**已移除**，数字仅留作复盘；**`evidence_bundles` 不生成的原因是 agent 全程没调 `traffic_bind_evidence`**（纪律问题，非代码问题）；并标注"1 轮命中不算冷解 —— playbook 3 天前就有"。§9.2 与作业卡同步为"**IR 题的 WP 走 `IR-WP-TEMPLATE.md` 人肉填**，只有评估型 run 才用 `report`"。
- **修（事后审查）：SSH 远端工具纳入硬黑名单 + `target` 派生的文件名收敛为单一规则** —— 回看 2026-10-09 那批提交（`c6929e5` 加硬黑名单、`4b4eba4` 加 SSH 邻近的证据工具，两边没互看）时发现的两处，**只读审查 → 定点修**：
  ① **`remote_exec` / `remote_collect` / `remote_fetch` 是唯一不查 `blocked_hosts` 的 egress** —— `fetch` / `traffic_repeat` / `http_probe_batch` / recon / `nmap` 全都过 `enforce_host_path_constraints`，于是 `safety.denied_hosts`（= 计分平台 `tp.qianxin.com`）在 SSH 这条路上是空的。现在在 alias→hostname 解析之后、任何工具分支之前校验，**alias 与解析出的真实主机名双写都查**；**只查 blocked 侧**——`allowed_hosts` 表达的是靶场范围，而 SSH 清单里本就可能有范围外的跳板机/堡垒机，"绝不许碰"要一路到底，"只许这些"从来没打算管清单。
  ② **由 `session.target` 派生文件名的三份拷贝走样**：`.replace("/", "_").replace(":", "_")` 链**漏了 `\`** ⇒ Windows 上路径型 target（本机 378 个会话 / 222 个 distinct target 中 **7 个**是 Windows 路径，如 `C:\Users\…\a9c4…zip`）把会话与报告写进 `SESSIONS_DIR\<名字>\Users\…` 的嵌套目录，而 `report_service.list_reports()` 的非递归 `*.md` glob **根本看不见**；Web 那份 ASCII-only 正则虽然安全，却把 `/证据` 打成一行下划线。现在统一到 `vulnclaw/utils/fs_names.py::safe_name_component()`，会话存档 / 两个报告默认名 / Web 报告**四处共用**：保留非 ASCII、盖住 `<>:"/\|?*` 与控制字符、剥掉两端点号空格、避开 Windows 保留设备名（`CON`/`NUL`/`COM1`…）、80 字符封顶。
  回归：`tests/utils/test_fs_names.py`（19 例）、`tests/agent/test_session_save_path.py`（4 例）、`tests/security/test_remote_exec.py::TestBlockedHostsCoverSsh`（5 例）、报告与 Web 各 1 例。

</details>

<details open>
<summary><strong>Unreleased</strong> — 赛前分工按 4 人定稿（runbook §9.3）+ 作业卡同步</summary>

- **文档** — `IR-RUNBOOK.md` §九 按**实际队制 4 人**定稿（该节原规则：人数一确定就把另外两档删掉，故删除"①单人 / ②双人"）：**A 档（默认）= 主链 3 人（主攻 / 记录+计时+提交核对 / 素材+WP）+ 复核线 1 人**；**B 档（备选）= 双线 2+2**（前提是现场确认"4 个账号能各做不同的题"，否则别用）。顺带修掉草案里一处**自相矛盾**：原"**统一由他人提交** flag"与同节"**一人一个账号**"冲突 —— 别人的账号里交不了你的 flag，故改为**发现者本人在自己账号上提交 + 记录员只做提交核对**（台账登记 + 锚点逐题点名），只有赛方允许共用单一账号时才回到"一人统一提交"。分诊改为 4 人并行（仍守"开赛 10 分钟内不许开打"）。新增**现场待确认第 8 条**（4 个账号的题集 / 能否共用单账号），§八 P1-8 标记关闭。`IR-FIELD-CARD.md` 同步：提交纪律加"4 人版"两条、现场待验证表加第 6 行（现场只看那一页）。**⚠️ 本条的"4 名选手（均能打）"假设已于 2026-10-10 更正——实际 4 人里只有 2 人能打、另 2 人是门外汉，§9.3 已按 V4 重写，见上方 Unreleased 条目；此处保留作历史记录。**

</details>

<details open>
<summary><strong>Unreleased</strong> — 证据改为 per-run 目录（写读同锚、删除跨 run 兜底读）</summary>

- **证据存储改为 per-run：写入与读取都由 run 目录锚定，读侧不再跨 run 兜底** — 此前抓包日志与固定证据落在 **process-wide** 的 `CONFIG_DIR/evidence`（可被 `VULNCLAW_EVIDENCE_DIR` 覆盖），而读侧在目标 run 目录为空时**静默兜底**到该全局树，于是「没有自己证据的 run」会把**上一个 run 的抓包**当成自己的 proof 渲染进报告 —— 同进程多 run（批量扫描 / 并发）下这条泄漏尤其致命。现在：① 写侧 `resolve_traffic_store` / `resolve_evidence_store`（`vulnclaw/traffic/paths.py`，经 `agent/builtin_tools.py` 的 `traffic_capture` / `traffic_bind` 使用）优先取 `agent.run_dir`（由 `orchestrator` 在 checkpoint 前注入 `run_context.run_dir`），落到 `<run_dir>/evidence/traffic`；② 读侧 `resolve_report_*_store` 与工具侧**共用同一 seam**，但语义是**显式 `run_dir` 即权威** —— 该 run 没有抓包就读到空，绝不再回落到 config 默认（D2）；③ `generate_report(session, output_path=..., run_dir=...)` 新增 `run_dir` 参数，把**报告落点**与**证据位置**解耦（`output_path` 只决定报告写哪；修掉「报告写到 `SESSIONS_DIR` 就再也读不到本 run 证据」的坑，D3）；④ 扫描（headless）路径与 `RunContext` 路径共用同一套 run 目录骨架，此前 `_create_run_layout` 已含 `evidence/`，现抽为公共幂等函数 `run_context.ensure_run_layout`，扫描路径在生成 run 目录后同样补齐 `evidence/`（D4）。**实测**：`tests/traffic/test_evidence_report.py` 新增 A/B 双 run **同进程** 隔离用例（B 报告不得出现 A 的 host、请求行、响应体标记与快照 id；两个 run 的响应体刻意取不同值，以免内容寻址的快照摘要撞车造成误判）、`tests/traffic/test_report_export.py` 补「显式 run_dir 不读 config 默认」「缺 run_dir 不内联邻近 run」两条、`tests/cli/test_cli_noninteractive.py` 新增「扫描产物的报告/summary 落在 agent 自己写的 run 目录、且该目录含 `evidence/`」断言；`tests/run/test_headless.py` 补 `ensure_run_layout` 骨架用例。回归 `tests/{traffic,report,run,cli}` 全绿。
- **文档** — `vulnclaw/traffic/paths.py` 模块 docstring 去掉「Until the run-directory PRD lands…」的临时说明，改为描述 per-run 权威解析（显式 `run_dir` 确定性、无跨 run 兜底；仅无 run 上下文时用 config 默认）。

</details>

<details open>
<summary><strong>Unreleased</strong> — 硬黑名单（计分平台永不可测）+ CIDR 网段作用域 + 显式出口代理（SOCKS5/HTTP）+ 现场作业卡</summary>

- **新增显式出口代理：让靶场流量走自建隧道（SOCKS5 / HTTP）** — 补上赛前 Q1 的代码级缺口：`http_client` 对私网/回环目标强制 `trust_env=False` 是**为挡系统代理**而设，却也把 `ssh -D` 建的隧道一并挡掉了。现在 `network.http_proxy`（或 `VULNCLAW_HTTP_PROXY`）可指定出口代理，target-facing 工具按 `proxy=resolve_egress_proxy(config)` 接入（`fetch`（含 TLS 重试分支）、`http_probe_batch`、`brute_force_login`、`traffic_repeat`）；**LLM 网关 / 情报 API / 远端 MCP 刻意不接入**，免得把评测与情报流量误送进靶场隧道。语义：① 显式代理对**私网目标同样生效**（这正是隧道的目的，`trust_env` 表达不了）；② **回环目标仍直连** —— 隧道对端会把 `127.0.0.1` 读成它自己；③ 强制 `trust_env=False`，实测可盖过 `HTTP_PROXY`/`ALL_PROXY`/`NO_PROXY=*`；④ 未知 scheme 直接报错（httpx 只认 http/https/socks5/socks5h，不认 socks4）。**实测**（httpx 0.28.1，`tests/utils/test_http_client_egress_proxy.py` 用进程内 SOCKS5 服务器 + 不可解析域名固化成断言）：`socks5://` 交给代理的是**主机名**（`ATYP=3`），DNS 在代理端解析 → **作用域闸仍看到真实 host**，`--only-host` / `blocked_hosts` 在隧道下继续有判别力（这是必须用 `ssh -D` 而非 `ssh -L` 的原因：`-L` 下 agent 只能请求 `127.0.0.1`，闸门失去判别力）；`socks5h://` 在 httpcore <1.0.9 是**裸 `KeyError: b'socks5h'`**（本机 1.0.2 崩、临时 venv 1.0.9 通过，报错点离代理 URL 很远）→ 统一改写成 `socks5://`（两边都是远端解析，实测行为相同，≠ curl）；缺 `socksio` 时点名 `vulnclaw[socks]` 而不是静默失败（`pyproject.toml` 新增该 extra）。
- **新增 `IR-FIELD-CARD.md`：现场作业卡（一页）** — 决赛当天用的动作清单（runbook 存判据与证据，卡只在现场用）：开场 30 分钟 checklist（含**开赛 30 分钟后禁止入场**、全程录屏 9:30–15:30）、每题的分岔判断（控制台题 → 副驾模式；VPN/直连题 → agent 驱动）、副驾四条纪律 + prompt 模板、提交纪律（链式解锁 + **提交由人做**）、收工清单、现场待验证 5 问。隧道一条按刚落地的能力写成"必须 `-D` 不能 `-L`"。
- **执行类工具的重复调用预算 30 → 10** — 2026-10-08 成本复盘：一条**已解出**的 run（`batch-1005t-01`，SETCTF，5.21M token / 117 请求 / 135 次工具调用，平均 42.9K prompt 每次）里，**11 次重复调用**（7 组重复参数，含 4 次完全相同的 `python_execute`）+ 15 次失败调用（python 12）+ 1 次空转 + 2 次被证据闸门拒掉的 FINAL ≈ **12% 的请求是纯冗余**；而执行类工具的"同结果重复"预算是 30 次，这条通道在限时比赛里太宽。改为 **10**（`_REPEAT_TOOL_LIMITS` 与 `session.repeat_tool_limits` 默认表同步，`fetch: 50` 保持不变——有状态题要反复取同一端点观察变化）。**为什么安全**：round-22 那次"整场丢掉工具"的失效来自**按调用次数**计数；现在按**结果签名**计数并在结果变化时归零，所以 10 只收紧"连续十次完全相同结果"这一种情形。回归：`tests/agent/test_tool_repeat_guard.py` 新增 `TestShippedDefaultBudget`（默认即 10 / 10 次相同结果触发 / 10 次递进结果不受影响），原 30 次递进结果回放用例保持通过。本机 `~/.vulnclaw/config.yaml` 同步：`competition.stall_turns: 8 → 6`、`session.repeat_tool_limits.python_execute/shell_command: 30 → 10`（备份 `config.yaml.bak-20261008c`）。
- **新增 `safety.denied_hosts`：任何运行都不许测的主机** — 赛前需要一条"这个 host 无论任务作用域怎么写都不能碰"的表达（决赛计分平台 `tp.qianxin.com`，通知七(三)严禁攻击竞赛平台/赛事系统/第三方服务）。此前项目只有**作用域**开关（allowed/blocked hosts + strict），没有全局禁测面，而作用域的来源有四条（CLI 参数、Web 任务 API、自然语言解析、平台交接），任一条能把它写进 `allowed_hosts` 就等于没拦。实现：`AgentCore._reset_runtime_state` 与 `apply_task_constraints` 在安装约束前调用 `_harden_constraints()` 并入 `blocked_hosts`（`TaskConstraints.add_blocked_hosts()` 去重、保序、幂等，因为约束对象在每次上下文重置时被反复加固）；`task_service.build_scope_constraints` 刻意**保持纯函数**（不读配置），否则同一份任务负载会在不同机器上产生不同作用域。`enforce_host_path_constraints` **先查 allowed 后查 blocked**，故重加进 allowed 无法翻案；匹配复用 `host_in_scope` 的域名作用域语义（`tp.qianxin.com` 覆盖其子域，`tp.qianxin.com.evil.test` / `evil-tp.qianxin.com` 不误伤）。环境变量：`VULNCLAW_SAFETY_DENIED_HOSTS`（逗号或换行分隔）。
- **`host_in_scope` 支持 CIDR，并修掉一个静默失效的私网拦截** — 赛场给出的"靶场网段"此前无法表达：裸 IP 模式是**精确匹配**，没有前缀/网段形式。现在 `10.20.0.0/16` 这类模式按网段匹配（仅当地址字面量对网段，主机名永不落入网段，不做 DNS 解析；家族不同不匹配；畸形/含斜杠的主机名模式被跳过而非吞掉整条列表）。同时修掉本地文件型任务的私网守卫：它原本写 `"10."` / `"192.168."` / `"172.16."`…，在精确匹配下**永远匹配不上**（实测 `host_in_scope("192.168.1.9", ["192.168."]) is False`），改为 CIDR 后该守卫才真正生效。
- **文档** — `IR-RUNBOOK.md` 新增"五点五、赛前缺口清单（10/10 复核用）"：把 2026-10-08 实测出的未补缺口按 P0/P1/P2 分级并附证据（AI 辅助合规未问、录屏与磁盘空间（C: 15.5 GB / D: 17.9 GB 可用）、**LLM 凭据单点：`llm.api_keys` 仅 1 条、zhipu key 已失效**（单次失败硬题实测烧 3.14M prompt + 0.16M completion tokens / 70 请求，`solve_max_model_tokens` 现值 6M）、无"可粘贴短命令卡"、`chrome-devtools` MCP 实为 placeholder 且从未下载（`_npx` 缓存为空）、`report --pdf` 缺 weasyprint 而 `python-docx` 可用、无端到端彩排、时间盒与分工未定、`remote_*` 未真机验证且 paramiko 仅 2.8.1（rsa-sha2 需 2.9+）、`uvx` 缺失、burp/ctf2 MCP placeholder）。
- **比赛策略 skill 补两条** — `competition-mode`：①**提交的例外**——赛事禁止 agent 联平台/要求人工提交时（判据：赛方明令 + 平台地址被 `safety.denied_hosts` 拉黑），只交付 flag 并给证据，不打开 `competition.allow_flag_submission`；②**名次权重（一血/二血/三血）**——速度优先于深度、先做零环境依赖题、链式解锁时一题一交付。
- **文档** — `IR-RUNBOOK.md` 第五节再补 10/9 赛前培训（朱禹）确认的赛事事实：日程（8:30 签到 / 9:30–12:00 渗透 / 12:20–15:30 应急 / 15:30 颁奖，**开赛 30 分钟后禁止入场**）、**一血/二血/三血速度权重**、平台操作路径（任务中心 → 拓扑 → 右键攻击机控制台 → 内置账号密码）、**链式解锁**、**内置工具库供下载**、现场网线（可连比赛环境与互联网）、**部分题需 VPN 登录 + 提交演练报告（WP）**、违规四条（跨组交流 / 攻击平台 / **C2 类非有效登录或远程操作** / **全程录屏 9:30–15:30**）；新增"自动化边界"表（平台与跳板机一律人操作、本机分析与 VPN 类题目 agent 可驱动）与 WP/一血两项交付物说明；待确认清单收敛为 7 项并标注朱禹的三条群内待办。
- **文档（同日更早一批）** — 补记接入形态（官方网线 → **跳板机** → 靶场）、IR 作答形式（**经跳板机远程排查 + 找隐藏 flag**）、**平台内置工具库**（本机工具退回离线/兜底；工具清单写进 `remote.hosts.<alias>.note` 供 `remote_hosts` 渲染；附任务 prompt 模板）、**题目链式解锁**（flag 必须提交但**提交由人做**，agent 只交付不提交，goal 措辞已给）、**操作入口=平台网页端右键开终端**（确认后 `remote_*` 从主路径**降级为备选**，主路径改为"人打字 + agent 出命令"的**副驾模式**，含四条纪律与 prompt 模板）、**攻击机系统未知**（现场先定性的探测表 + `remote_collect` 自动 OS probe；Linux 仍 POSIX/tar.gz，Windows 走只读 PowerShell framed 单文件路径）与**"隧道 / 浏览器驱动 agent"两个问题的技术结论**（跳板机一人一连的席位冲突；`http_client.py` 对私网/回环目标刻意 `trust_env=False` 导致 SOCKS 不生效、`-L` 转发下作用域闸只看到 `127.0.0.1`；`chrome-devtools` MCP 虽已启用但自动操作平台 UI 属高风险，中间路线=人粘贴、agent 只生成）；网络可达性节补充"国内实测可达，要问的是国外与公网出口"。
- **新增 IR 找 flag 落点清单** — `skills/specialized/incident-response/references/flag-landing-spots.md`：赛方材料明确"要找隐藏的 flag"后补的**解题交付卡**（五步作业顺序：内容搜 → 时间圈定 → 进程/环境 → 服务侧 → 变形解码；Linux/Windows 落点表；已删除文件、磁盘未分配区、数据库、日志、ADS；编码变形对照；常见坑与"搜不到时怎么体面收尾"）。`SKILL.md` 的"常见提问 → 检索路径"与参考文档索引各加一条；`.ir-tools/verify-ir.py` 自检 **PASS=97 FAIL=0**。
- **`remote_collect` 在 Windows 目标上给出可执行的下一步** — 攻击机/跳板机的系统不由赛方公布，而 `remote_collect` 发的是 POSIX `sh` 脚本（`#!/bin/sh` + `tar`），在 Windows 上每一步都失败、现场只看得到"no archive produced"。新增 `_windows_target_hint(stderr)`：仅当 stderr 里出现 cmd.exe 自有诊断（`is not recognized as an internal or external command` / `The system cannot find the path specified` / `was unexpected at this time`）时，才在报错后追加"目标像 Windows cmd，请改用 `remote_exec`（cmd/PowerShell 语法）+ `remote_fetch`"；POSIX 端的一般失败（`tar: not found`、`Permission denied`）不会触发，避免把操作者引到错方向。测试见 `tests/security/test_remote_collector_integrity.py::TestWindowsTargetHint`。
- **新增 OA / 产品化 Web 系统 → webshell 卡片** — `skills/specialized/web-security-advanced/references/web-oa-webshell.md`：赛题明确"获取 OA 系统漏洞并植入 webshell"后补的**渗透交付卡**（产品指纹表（泛微/致远/通达/蓝凌…，要求两条互相印证）、能出 shell 的漏洞族、上传后缀与解析差异（白名单/黑名单/多后缀/`;`/`%00`/Tomcat `;jsessionid=`）、上传目录可访问性、无回显三法（回显/时间盲/带外）、落马后取证与"按 `flag-landing-spots.md` 找 flag"顺序、7 个高频坑）。`web-security-advanced/SKILL.md` 的场景路由与参考索引、`web-pentest/SKILL.md` 的文件上传条目各加指针。
- **测试** — 新增 `tests/security/test_hard_denied_hosts.py`（13 例：合并、子域、相似域不误伤、allowed 不能翻案、重复加固幂等、无黑名单时行为不变、运行重置路径仍禁测、Web 任务约束在安装点被加固、builder 保持纯函数、env 覆盖、条目归一化）；`tests/config/test_host_scope.py` 增 CIDR 组（网段内/外、主机名不解析、畸形段、家族混用、host bits）；新增 `tests/cli/test_local_path_egress_scope.py`（私网/回环真被拦、公网不受影响、URL 目标不走本地路径分支）。全量回归 **4569 passed / 20 skipped**。

</details>

<details open>
<summary><strong>Unreleased</strong> — round-9 审查修复（平台身份查询移出事件循环 / 题名兜底 / quiz 谓词）</summary>

- **修复平台身份查询阻塞事件循环（round-9 事故）** — 无身份 goal 会向平台补查一次挑战元数据，原实现在 `async` 求解路径上直接 `pool.submit(...).result(timeout=_PLATFORM_HINT_TIMEOUT)`：worker 线程只兜住了 socket，等待仍发生在**调用线程**，而唯一生产调用者就是 solve 协程，于是每个无身份 run 都把事件循环（及同循环上的兄弟协程）卡住最多 8 秒 —— 而原 docstring 恰恰声称"worker 线程保证 inside-an-event-loop 的调用者不会 stall solve"。现将阻塞读取抽为 `_fetch_platform_identity()`，新增 `_platform_identity_hint_async()` 用 `asyncio.wait_for(asyncio.to_thread(...))` 把查询移出循环（保持有界、不抛、每 ref 每进程只查一次三条契约）；求解路径在调用注入器前解析好 `identity_hint` 传入，注入器收到 `None` 时仍回落阻塞形态——9 处同步调用点的契约不变。副作用：生产路径不再每个 ref 新建一个 `ThreadPoolExecutor`。判定条件单点化为 `_goal_is_identity_free()`，生产调用点与注入器分支共用，避免各自漂移。
- **任务句题名降级为兜底，避免挤掉对口笔记** — 平台启动句题名（`用 ctf2 工具解练习场 <pid> 的题目 <cid>：<name>。`）此前会并入**已有**类签名。以 224 条真实 goal + 真实笔记库实测（每个候选设计都跑真实 `lookup_playbook_multi`，查询列表与 `_inject_prior_playbooks` 一致 = target fingerprint + class）：并入后 11 条目标的查询结果集改变，其中 `[GeoServer] CVE-2024-36401` 丢掉对口的 `geoserver-cve-2024-36401-wfs-jxpath-rce`，被 `ir-triage-checklist-ten-drills` 顶掉——因为 `Playbook.score` 是"查询词被笔记命中的比例"，查询变长只会降分，而平台任务句原文恰好一字不差地出现在 auto 笔记里，curated 笔记因此被挤出 `limit=2`。改为**仅当签名为空时才用题名**后：那 5 条真正有价值的收益全部保留（变异凯撒→`mutated-caesar`、Quoted-printable→`quoted-printable-ctf2-crypto-easy`、丢失的MD5→`md5-lost-md5`、传感器→`sensor-manchester-ook`、一眼就解密→`base64`），已识别目标拿到的查询与改动前逐字相同，结果集结构上不可能改变（identical 208→214，churn 11→5，回归 0）；改完用已实现的代码复测得到同样的 5/0/214。
- **quiz 分支的 flag 需求判定统一为词边界** — `_completion_gate` 的 quiz 短路仍内联 `flag|getshell|shell` 子串匹配，`shell ⊂ webshell` 让「知识竞赛答题：webshell 文件路径排查…」这类 quiz 形态目标跳过 quiz 路径、落到 flag 检查，再被 "FINAL did not cite evidence ids or quote recorded evidence" 拒掉。改用与 `_implicit_flag_completion` 同一个 `_EXPLICIT_FLAG_DEMAND_RE`（实测该形态下新=放行、旧=拒绝）。
- **回归用例（+11 个节点）** — `test_playbook_goal_identity.py` 增 5 例：用"每 20ms 走一步的兄弟协程"钉住"查询期间 loop 未被占用"（**该用例第一版是无效的**：窗口写在兄弟协程体内，只会在查询结束后才开始计时，对同步阻塞也能通过；用故意同步阻塞的变体反测（期望失败）时误过才发现，窗口移到查询之前，旧实现下 tick=0）、异步形态的不抛/失败也 memo 契约、传 hint 时不得再走阻塞形态、传 `None` 时回落同步形态、`_goal_is_identity_free` 与注入器分支一致；`test_goal_wants_flag_boundary.py` 补 3 条**逐字取自真实语料**的主机型目标（`http://<hex>.http-ctf2.dasctf.com:80`，旧子串谓词靠 `ctf ⊂ ctf2` 把 362 条会话首目标里的 69 条判成"要 flag"）与 1 条 quiz+webshell 用例，把有意收窄写死，避免将来被当成 bug 改回子串匹配。
- **round-9 原改动随组提交** — 未闭合 flag 脱敏第三层 `_FLAG_UNCLOSED_RE`（覆盖 `strings` 截断等"没有 `}`"的形态；当前 293 篇库实测零误伤，`base64{...}` 类构造性误伤仍存但无真实样本）；`_CLASS_TASK_NAME_RE` 识别平台任务句题名（39 条含"题目"的真实目标命中 35 条）；`scripts/audit_playbooks.py`、`scripts/verify_playbook_migration.py` 两个只读审计脚本；`_goal_wants_flag` 词边界化（362 条会话首目标中 72 条翻转，其中 69 条为主机型目标）。
- **测试** — `tests/agent tests/platforms tests/ctf_platform`：**2067 passed / 7 skipped / 1 failed**（唯一失败为本机裸 `python` 为 Store 存根导致的 `test_bg_tasks.py::test_bg_launch_and_result_lifecycle`，改动前即固定失败；改动前基线 2056 passed，+11 即本次新增节点）。

</details>

<details>
<summary><strong>Unreleased</strong> — 语言支持（bilingual UI）</summary>

- **新增英文 / 中文双语界面** — 默认语言改为英文（无法识别环境信号时不再落到中文）。CLI/REPL 工具调用行、状态横幅、solve 报告标题、知识库状态、上下文截断提示、LLM 重试/恢复提示与推理状态块均随当前语言输出；zh 模式下输出保持逐字节不变。切换方式：REPL `/language` 命令、`VULNCLAW_LANG=zh|en` 环境变量、`session.language` 配置。
- **修复 `/language` 命令输出** — 移除确认文本前的多余 ASCII 字母 `f`。
- **Agent 英文关键词支持** — finding parser、阶段检测、CTF 判定、输入分析、认证墙、技能分发与 MCP 路由等识别表补充英文等价信号词，英文提示下子 agent 的发现分类、阶段迁移与技能注入与中文模式一致。
- **知识库状态本地化** — KB 初始化/降级/禁用详情随当前语言输出。

</details>

<details open>
<summary><strong>Unreleased</strong> — 知识竞赛（理论题）支持</summary>

- **新增知识竞赛/理论题直答能力** — solve 引擎新增知识题识别（知识竞赛/理论题/选择题/判断题等关键词 + A./B./C./D. 选项模式），命中后注入 Knowledge Quiz Mode 指令：先抓题入证据、按平台格式作答、不确定用排除法、禁止对答题平台做扫描/注入/爆破。完成闸门为知识题目标走专属分支：不再强制 FINAL 携带 flag 或引用证据词（原闸门会让"答案：A"类最终答复永久拒绝死循环），仅要求题目先抓入证据、声称的 flag 仍需证据落地。
- **新增 `knowledge-quiz` 专项 Skill** — 识别信号、六步答题工作流、分题型对策 playbook（单选否定问法/多选策略/判断题绝对化表述/填空标准术语）与网络安全法律法规高频考点基线 `cn-cybersec-law-baseline.md`（四部核心法律时间线、网安法要点、等保 2.0、应急响应 PDCERF/事件四级、国密算法、刑法涉网罪名、常见端口）。dispatcher 路由新增知识竞赛/理论题/法规名/quiz 等中英文关键词。
- **新增超纲题人工兜底策略** — 超出模型知识的题目（当年时事、比赛主题/届数、训练截止后新发布文件）不猜测：以 `🔴 超纲题` 红标标记题号/题干/选项并附资料线索（可能出处文件、检索关键词、skill reference、平台公告页），继续做完其余题目；超纲题未答时扣卷不交，全场做完后 `ASK_USER:` 请用户作答，拿到答案合并后再做唯一一次最终提交。
- **知识题防误换靶与续跑保活（CLI）** — 新增 `_should_switch_target`：粘贴题目文本中引用的 IP/域名（如"192.168.1.1 属于哪类地址"）不再触发目标切换重置会话上下文；`_should_auto_pentest` 自动模式触发词补充"答题/知识竞赛"；Ctrl+C 中断后按回车续跑时恢复 prompt 附带任务类型标记，知识题指令与闸门豁免跨中断保留。
- **更新比赛模式策略** — competition-mode 明确知识竞赛环节最先做：零环境依赖、不受靶机过载影响、答完即锁定得分，是单位时间得分率最高的题型。
- **修复存量测试失败** — `test_solver.py` 的 `_Agent` mock 补齐 `runtime` 属性（solve playbook 机制引入的回归，修复后该文件测试时长从 ~113s 降至 ~2s）；`test_tool_parallel.py` 内联返回用例载荷从 5000 字符降至预览阈值（3500）以内，保留"小结果默认内联"的测试意图。
- **知识题门禁与护栏审计修复** — 完成闸门的 quiz 短路仅在 goal 未显式要求 flag/shell 时生效（"答题拿flag"类混合目标回落到 flag 落地校验，杜绝无 flag 提前判完成）；新增 `_quiz_questions_inline` 内联题目判定（≥3 个选项标记或"（ ）"填空），题目直接粘贴在任务文本时不再要求先抓取证据（原逻辑会指向不可能执行的动作并烧尽 max_steps）；`_should_switch_target` 按目标形态切分——quiz 文本中出现的完整 URL 视为真实换靶（"改打 http://x"），裸 IP/域名诱饵维持豁免；续跑任务类型后缀改走 i18n（`cli.resume_quiz_suffix`）。
- **工具裁剪与完成路径全量审计修复** — `_infer_allowed_tools` 为知识题目标保底 web 工具束：技术型题面（含 RSA/AES/端口等词）不再把 `fetch` 从工具 schema 裁掉（原 crypto bundle 首位命中会导致 quiz 指令要求的工具不存在）；`_implicit_flag_completion` 改为仅在 goal 显式要求 flag/shell 时触发，纯答题 goal 不再被页面证据中的 flag 形态字符串隐式判完成；premature-ASK_USER 守卫对 quiz 目标豁免——quiz 页面证据（表单/输入框）必触发 near-miss 启发，原守卫会把"超纲题转交用户"的既定流程随"资料/搜索"措辞永久拦截；`_quiz_questions_inline` 补判断题格式（对/错、正确/错误）与"无 URL 即内联"兜底。
- **quiz 启发式边界收紧（第三轮审计修复）** — 内联判定去掉过宽的"无 URL 即内联"兜底：改为要求实际题干内容（问句/选项/填空/对错格式），防止 `target` 命令给 URL、goal 仅"开始答题"时不读题即通过门禁；`_QUIZ_KEYWORDS` 移除裸"答题"（"对 XX 答题系统做渗透测试"是攻击任务，quiz 判定会同时翻转门禁豁免/ASK_USER 豁免/禁攻击指令三项行为；自动模式触发词表保留"答题"）；换靶守卫的 URL 分支需伴随"改打/切换到/换成"类显式换靶动词才重置会话（题干引用"判断题：https://x 是…"不再误清上下文）；`_infer_allowed_tools` 的 quiz 分支改为模块级导入并移除裸吞异常（当前无循环导入，回归会在导入期显式暴露）。
- **quiz 门禁第五轮审计修复(续)** — A2 提示判据与 URL 判据统一为 "://" 形态(HTTP 字样不再误指可抓取页面); 单行粘贴的编号卷子恢复内联识别(编号允许行中匹配, 问号共现条件保留, F1 规则列表防护不变)。
- **速查表脱敏** — benchmark-driving 的 TSecBench API 速查表内网 IP/预检地址替换为占位符(同 commit B1 红线自查)。
- **gitignore 补充** — DataCon 一次性解题产物(brute*/test_sha*/brute_flag/poll*/scan_full/disasm/out)不再有误提交风险。
- **quiz 内联判定第四轮审计修复** — 问号不再作为题干内联信号（"知识竞赛？开始答题"是指令不是题，原判定可让未读题的 FINAL 通过门禁）；无 URL 且无结构标记的内联题面，门禁拒绝消息改为指引"向用户要题面 URL 或粘贴题目"，不再指向不可能执行的 fetch（消除烧尽 max_steps 的死循环残余）。

</details>

<details open>
<summary><strong>v0.3.8</strong> — sub-agent fan-out + cold/hot memory + context budget</summary>

- **新增模型驱动的并行子 Agent 扇出** — 默认 solve 引擎新增 `spawn_subagents` 工具，主模型可在一轮内提交多个独立、自包含的攻击方向并发探索；子循环继承目标约束与已有证据，禁用递归扇出并采用单次/并发/每次 solve 生命周期预算。子证据合并回父状态时统一重分配 `eNNN`，同步修正 claim、pin、progress signal 和 tool-call 引用；CLI 新增 fan-out 生命周期事件展示。
- **新增 TUI 子代理实时监控面板** — Textual TUI 执行任务时通过带随机会话令牌的私有 JSON 行协议接收 `spawn/start/progress/finish/batch_done` 事件，按批次实时展示每个子代理的角色、状态、步数、目标或最新进展；每次执行使用独立 `run_id`、输出队列和事件 token，旧 worker 的迟到输出、结束哨兵及定时器不会污染或提前终止新任务。普通 CLI 日志保持不变，窄终端仍可从原始日志查看事件。
- **新增冷热记忆分离** — 会话历史超过 48 条消息或 32K token 时，旧消息自动归档到冷记忆 JSONL 分片（每 64MB 轮转，最多 8 分片），热上下文仅保留近期完整工具交换组；新增 `memory_search` 工具从冷记忆按关键词检索带上下文的片段。`ContextManager` 新增 `max_tokens`/`search_max_chars` 配置，大工具输出超预算时自动归档并替换为冷记忆指针+预览。`/compact` 改用 `group_tool_exchanges` 按工具交换组原子切分，不再拆散 assistant `tool_calls` 与对应 `tool` 消息。`_trim()` 改为 token+条数双重安全网，不再直接丢弃最早消息。
- **新增统一上下文预算与结构化压缩** — `context_budget.py` 提供 `prepare_context()` 唯一预算入口，覆盖所有 LLM 调用路径（`call_llm`/`call_llm_auto`/`call_llm_stream`/`call_llm_auto_stream`/`structured_call`/team planner/adviser/report summary）。预算公式：`usable = max_context_tokens - output_reserve`，trigger=usable×0.70，target=usable×0.55；工具 schema token 计入预算。压缩时按不可拆分工具组分组、保留最近 N 组、其余生成确定性 `[context digest v1]` 摘要（含 target/scope/verified_claims/pinned_facts/evidence 引用），原子回写 `ContextManager.replace_history_with_digest`。审计事件记录前后 token/原因/组数/evidence IDs，敏感字段（authorization/cookie/api_key）自动脱敏。新增 `ContextBudget`/`ContextCompactionResult`/`ContextDigest`/`ContextCompactionEvent` 类型。配置：`context_auto_compact=true`（默认启用）、`context_compact_trigger_ratio=0.70`、`context_compact_target_ratio=0.55`、`context_recent_message_groups=12`、`context_summary_max_tokens=3500`、`context_output_reserve_tokens=0`（自动取 min(max_tokens,8192)）、`context_compaction_mode=structured`、`context_compaction_audit_enabled=true`。旧 `solve_auto_compact`/`solve_compact_trigger_ratio` 标 deprecated，未显式设置新字段时自动迁移。
- **修复子 Agent 合并边界与审计完整性** — 父状态合并子 Agent 证据及辅助历史时继续遵守各项硬容量上限并清理淘汰引用；`spawn_subagents` 作为本地调度元工具不再被误判为 scan，子会话的约束违规消息与结构化事件会完整合并；所有子 Agent 预算/容量配置拒绝零值和负数。仅当子 Agent 在进入 `child_solve`（即启动 LLM/工具）之前的工厂/种子/setup 阶段失败时才退还其生命周期预算（确定零成本）；一旦进入 `child_solve` 即计入预算，避免昂贵的后期失败悄悄回收扇出广度。`max_concurrent` 文档提示：使用 chrome-devtools/burp 等外部 stdio MCP 时应设为 1，避免并发子 Agent 共享单条 stdio 会话交错。
- **加固子 Agent 扇出安全与子进程生命周期** — `SubagentConfig` 全部数值项补上界 `le=`（`max_depth` 硬顶为 2，防止逐层预算叠乘导致扇出指数爆炸），越界的 `VULNCLAW_SUBAGENT_*` 环境变量改为拒绝并告警而非静默丢弃；修复子证据合并后 `duplicate_of` 在源证据被容量截断丢弃时残留指向子侧 id 的悬挂引用（改为清空，避免后续随 `evidence_seq` 增长误解析到无关证据）；TUI 输出日志对来自子进程的不可信内容（子代理 `goal`/`NO_PATH` 复述等）先转义再写入 `markup=True` 面板，杜绝 `[/quote]` 等未闭合标签触发 `MarkupError` 击穿 TUI，或 `[link=]`/`[red]` 注入操作员终端；子进程中断/切换/退出改为 `terminate→wait→kill` 三段式并在退出时统一清理，子进程为 `SIGTERM` 注册与 `SIGINT` 一致的清理入口，避免遗留 MCP/nmap 孙进程被孤儿化。
- **重构工具循环上下文管理** — `call_llm_auto`/`call_llm_auto_stream` 不再每轮截断全部历史，而是构建稳定前缀（system prompt + 有界历史 + 任务指令）+ 可变工具循环尾部；仅在尾部超过高水位（默认 32K）时压缩至目标（26K），保留稳定前缀和近期完整工具交换组，减少不必要的上下文丢失。流式调用改为 `asyncio.to_thread` 包装同步 provider stream，避免子代理并发时阻塞事件循环。
- **Skill 参考资料化架构** — skill resolver 现在只向 prompt 注入可选参考索引（skill 名称、描述、reference 文件列表和路由原因），不再自动注入 primary skill 正文、默认 `pentest-flow` 剧本或 WAF 绕过知识。`load_skill_reference` 被定义为模型自主选择的参考资料读取工具，返回内容不再视为强制流程、阶段计划或工具调度。
- **纠偏层去命令化** — solve 系统提示和 correction layer 改为输出 diagnostic notes：只描述工具健康、重复调用、same-body、parser/filter、POP 链等证据状态，不再直接命令模型“必须使用某工具/某 payload/某验证顺序”。`NO_PATH`/`ASK_USER` 闸门只说明未解决的高信号证据，不替模型规划下一步。
- **架构调整 active context 证据工作集** — 大工具输出仍完整写入 `AgentState.evidence`，但默认不再把完整 HTML/body/stdout/stderr 重复塞进模型 active context；模型可见 tool transcript 使用 bounded high-signal preview，包含 raw size/hash、关键行、表单/参数、endpoint、源码 sink/filter、flag-like token 和请求面摘要。新增 `evidence_search` 用于在 raw evidence 中按关键词/正则查找精确片段；`evidence_view` 继续用于分页查看原始证据。相同 raw 输出再次出现时只注入 `same_as=eXXX` 引用，减少 context rot，同时不牺牲证据闸门、报告和按需回查的完整性。

- **修复 PHP5 反序列化差分误判** — `http_probe_batch` 现在会把响应头写入证据并默认关闭 TLS 校验，`runtime_diff_probe` 可从 `X-Powered-By: PHP/5.x` 推断目标运行时；遇到 `O:+n:` / `C:+n:` 这类 signed length 候选时，会明确标记为必须远程验证，防止模型把本地新版 PHP 的 `unserialize_ok=false` 误判成远程不可利用。
- **增强 PHP POP 链高信号记忆** — 看到 `unserialize`、魔术方法和 `eval/assert/system/exec` 等 sink 同时出现时，会固定“魔术方法入口对象 → sink 对象”的对象图提示，避免模型只序列化 sink 类而漏掉真正触发链。
- **强化 `fetch` HTTPS 兼容性** — 即使模型显式传入 `verify_tls=true`，证书链校验失败时也会自动以 `verify_tls=false` 重试一次，并在工具结果中标注，减少 CTF/lab 站点因本机 CA 问题浪费一次模型回合。
- **强化外部题解类 `ASK_USER` 闸门** — 当 flag/shell 目标仍有 parser/filter、源码 sink、请求面等高信号证据时，模型重复询问“是否查看公开题解/外部资料”会持续被拒绝；真正的授权、凭证、范围问题仍允许询问用户。
- **新增 `runtime_diff_probe` 运行时差分探测工具** — 模型在遇到“正则/字符串过滤器 → 运行时解析器/解释器”的边界时，可按需批量生成并验证 parser-accepted/filter-missed 候选；当前支持通用 regex 检查和 PHP serialize/unserialize 本地差分，并会提示目标/本地运行时版本不一致风险。
- **新增 `ASK_USER` 近成功防误停闸门** — 当目标仍要求 flag/shell 且已有源码 sink、parser/filter 边界、本地 proof、请求面等高信号证据时，不接受模型过早询问“是否查看外部题解/公开思路”，而是把拒绝原因反馈给模型继续做本地差分、精确编码或远程验证。
- **增强 parser/filter 纠偏记忆** — correction layer 会固定 `preg_match`/regex/blacklist 与 `unserialize`、模板、表达式、XML/JSON 等运行时解析器之间的边界事实，并提示优先用小规模差分实验代替大范围 payload 猜测。
- **重构默认 solve 引擎为模型主导模式** — 删除旧 `ResearchState` / 研究方向 / plan-action-observe 生命周期；solve 现在像 Claude Code/Codex 一样由模型自行决定下一步、工具调用、`FINAL:` 完成、`ASK_USER:` 询问或 `NO_PATH:` 终止。
- **新增 `AgentState` 证据记忆** — 工具结果统一写入 `AgentState.evidence` 并完整保留 raw；active context 默认使用高信号预览，新增 `evidence_list` / `evidence_search` / `evidence_view` 让模型按需回看历史证据。
- **改为 Codex-style 工具 transcript** — solve 工具调用后会把 assistant `tool_calls` 与 `role=tool` 结果追加进模型上下文，并继续采样；只有 provider 拒绝 tool transcript 时才降级为完整工具文本，避免旧的 `Summarizing...` 摘要污染上下文。
- **新增 `shell_command` 内置工具** — 模型可按需运行本地 `php -r`、`curl`、`rg`/`Select-String` 等命令做精确验证；默认完整返回 stdout/stderr，可用 `max_output_chars` 主动裁剪。
- **新增源码自动还原能力** — `fetch` / `http_probe_batch` 遇到 `highlight_file`、HTML 高亮源码和混杂 HTML/JS body 时，会自动在 raw body 前追加 clean source；`source_extract` 仍可按需重读历史 evidence 并提取危险 sink、服务器端源码线索、表单、input 与 endpoint 信号。修复高亮源码 `<span>` 被误当成换行导致源码 token 化、模型无法准确读代码的问题。
- **新增轻量纠偏层** — 记录工具耗时、失败降级、重复调用、请求面、same-body/响应差异和新发现信号，作为 AgentState prompt hint 提供给模型；纠偏层不做阶段规划、不主动安排工具。
- **新增高信号证据固定** — 从工具原始输出中提取源码 SQL、HTML 表单/input、PHP/API 链接和 JavaScript endpoint 构造，写入长期可见 pinned facts，避免后续 HTTP 试错把真实入口淹没；SQL 源码场景会提示模型优先从服务端表达式推导 payload，并在 comment 结尾失败时尝试 no-comment 小步变体。
- **新增 `http_probe_batch` 内置工具** — 一次比较多组 URL/参数/header/body/raw URL 变体，返回状态码、长度、hash、title、关键 body 信号、实际请求面、完整 body 和 same-body 分组；`max_body_chars` 只有显式设为正数时才裁剪。复杂 Cookie/精确编码 payload 推荐使用 `headers.Cookie`，输出会展示模型实际发送的 method/URL/params/headers/cookies/body/json。
- **新增 `NO_PATH` 近成功防误停闸门** — 当源码 sink、表单/参数、请求面、本地 proof、same-body/响应差异等高信号证据仍未耗尽时，solve 会拒绝模型因单次 payload 无回显或远端 same-body 就提前停止，并把“验证 method/URL/headers/cookies/body、编码、触发条件和替代回显通道”的纠偏提示反馈给模型继续行动。
- **增强 `fetch` 本地工具** — 默认 GET，支持 HTTP/HTTPS、自定义 method/headers/params/cookies/body/data/form/json、timeout/follow_redirects/verify_tls/max_body_chars；默认返回完整响应 body，CTF/靶场 HTTPS 默认不校验证书，减少模型退回 `python_execute` 手写请求的 token 消耗。
- **工具输出改为 raw evidence + active preview** — `python_execute` / `shell_command` / HTTP 工具默认完整保存 raw stdout/stderr/body 到 `AgentState.evidence`；大输出进入模型上下文时改为 bounded high-signal preview，显式配置正数上限时仍可在工具层主动裁剪 raw 输出。
- **修复终端 payload 渲染崩溃** — 工具输出、工具参数和 solve 观察摘要改为 Rich 纯文本渲染，避免 SQL payload 中的 `[/**/]`、`[xxx]` 被误解析为 Rich markup 标签。
- **修复证据查看空转问题** — `evidence_view` / `evidence_list` 现在会写入 AgentState 工具调用记录；重复读取同一 evidence 覆盖范围会被短路，连续多轮只有证据查看且没有新增 evidence 时触发 stall guard，避免模型把预算耗在反复翻同一批日志上。
- **保留 `python_execute` 原始证据** — `python_execute` 的完整 stdout/stderr 会写入 AgentState；小输出可直接进入 active context，大输出使用高信号预览，`python_execute_max_output_chars` 显式设为正数时才在工具层裁剪 raw 输出。
- **保留并强化证据闸门** — `FINAL:` 声称的 flag/结论必须由真实工具输出支撑或引用证据编号；不满足时不会假完成，而是把拒绝原因反馈给模型继续探索。
- **新增 solve 自动复盘报告** — 目标达成后基于 `AgentState` 确定性生成 Markdown 报告并默认打印，包含解题思路、关键证据、复现请求包、curl、响应片段和证据索引；新增 `session.solve_auto_report` / `session.solve_report_show` 配置。
- **上下文压缩改为显式/必要时触发** — solve 默认保留正常历史；仅在上下文接近上限、用户执行 `/compact` 或显式启用自动压缩时压缩。
- **工具改为可用能力清单** — 目录扫描、JS 收集、空间测绘、nmap、skill 读取等只作为工具暴露，框架不再按阶段模板主动安排。
- **工具失败不再打崩 solve** — MCP/browser 初始化失败、AnyIO cancel-scope 清理噪声等会作为工具失败证据返回给模型，模型可继续改用其他工具。
- **进度显示改为 Turn** — CLI 不再显示 `Step x/N`，`solve_max_steps` 明确为防失控安全预算，不作为模型工作流轮数；默认安全预算从 80 提高到 240，避免慢模型在接近答案时被过早截断。
- **导入授权红队 Skill** — 吸收 `codex-redteam-mode` 的授权红队 detail packs 到 `vulnclaw/skills/specialized/`；jailbreak、拒绝绕过、会话 patch 等破限内容未导入。
- **新增 SQL 注入实战知识条目** — 基于 fushuling《SQL注入一命通关!》二次整理 `web-sqli-fushuling-one-pass.md`，并接入 `secknowledge-skill` 路由和内置 KB seed。

</details>

---

<details>
<summary><strong>v0.4.1</strong> — 并行探索 + 记忆引擎 + 信息收集工具链 + MCP streamable-http</summary>

- **多方向并行探索** — solve 引擎支持同时探索多个方向（默认 max_parallel=3），单个方向异常不影响其他，每个方向有独立的证据缓冲区和工具调用记录。
- **agent 记忆引擎** — 共享研究状态新增工具调用日志（跨方向可见），reason 阶段显式列出已放弃方向并禁止重复提出，explore 上下文带"已执行工具"摘要；checkpoint 机制在图状态没变时跳过 reason 避免空转；已放弃方向做 Jaccard 去重兜底。
- **结论判定优化** — 放宽了"有进展"的标准（发现新接口、确认未授权都算推进），不再轻易丢弃有价值的发现；最后一步增加证据复核，防止误判丢弃实际有数据返回的探索。
- **完成判定否定闸门** — 模型在 complete 字段里写"未达到完成标准"等否定结论时不会再被误判为已完成；显式要求 complete=true 布尔值 + evidence fact 引用。
- **JS 信息收集（js_recon）** — 抓取页面及全部 JS 文件，提取 API 路径 / 关联域名 / 硬编码密钥；动态发现 PascalCase 实体名并与 base path + CRUD 动词排列组合推断隐藏接口；收集到的接口自动做 GET+POST 未授权探测。
- **未授权探测（unauth_test）** — 批量无凭据请求，按状态码/响应体/内容类型判定；支持有/无 token 差分对比确认未授权；自动跳过 delete/save/sms 等破坏性接口。
- **目录枚举（dir_enum）** — 并发字典爆破，带 404 基线与全局伪装 200 识别（随机路径返回 200 自动停止），状态码与响应长度过滤。
- **空间测绘（space_search）** — FOFA / Hunter / Quake / Shodan / ZoomEye / 0.zone 六引擎统一查询，engine=all 时并发查询所有已配置 key 的引擎。
- **子域名枚举（subdomain_enum）** — 空间测绘被动聚合 + 内置字典 DNS 爆破，自动去重。
- **MCP streamable-http 支持** — 支持 Chrome DevTools MCP 等 HTTP 传输的 MCP 服务器；惰性连接（启动时不占 session slot）；首次调用时自动建连 + 工具发现；连接失败降级为 service_unavailable 不影响 solve 循环。
- **Chrome MCP 工具名修正** — 占位工具改为真实 Chrome MCP 工具名（chrome_navigate / chrome_read_page / chrome_pentest_* 等）。
- 工具返回 undefined 标记为失败而非静默成功；事实序号 / 方向序号在 session 恢复后正确续接；新增 ReconConfig 配置区块与 solve_max_parallel 配置项。

</details>

<details>
<summary><strong>v0.4.0</strong> — 核心：自主引擎从「固定轮数工作流」重构为「目标驱动求解」</summary>

- **新增目标驱动求解引擎（默认）** — 基于已验证事实、研究方向与证据记录的计划/行动循环，以「目标达成 / 研究方向耗尽 / 安全预算」为终止条件，结构上杜绝"原地打转"；新增 `vulnclaw solve` 命令，`run`/REPL 自主模式默认改走该引擎（`session.engine=rounds` 可回退旧逻辑）。
- **新增证据级反幻觉闸门** — 录制所有真实工具输出作为唯一可信证据；声称的 flag/完成必须在真实输出里逐字符出现才被采信，否则判定幻觉并继续探索；拿到验证过的 flag 即时收敛。
- **新增结构化推理 + 自适应反思** — 已知事实（带置信度）/约束/攻击链结构化沉淀并注入提示词；失败自动归类并按 L0–L4 渐进升级 payload 绕过策略，persistent 模式跨周期保留失败记忆。
- **新增漏洞检测插件体系** — 低耦合插件运行时 + 内置只读 Web 插件（安全响应头 / JWT / JS 端点），结果可去重合并进 findings 与报告链路；新增 `vulnclaw plugins list/info/run` 命令。
- **修复 #45 工具被误约束** — 动作约束不再把 HTTP 方法（OPTIONS/POST）或使用 `requests` 误判为「利用」；只有实际攻击载荷（SQLi/RCE/路径穿越等）才算 exploit；`load_skill_reference`/`crypto_decode` 等纯本地工具豁免范围约束。
- 新增 `session.engine` / `solve_*` / `reflexion_*` / `plugin_*` 等配置项，均支持环境变量注入。

</details>
