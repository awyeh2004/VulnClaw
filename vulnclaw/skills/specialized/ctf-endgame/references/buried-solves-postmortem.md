# 被埋葬的解法：四个"差一步"完整复盘

来源：Crate-CTF 2026-11-22 + 强网杯 ezphp。每例包含"停在哪 / 官方钥匙 / 差距本质"。
复盘认知：**每一堵墙都是静态推演出来的，证伪实验都是一次工具调用的事。**

## 案例 1：ezphp（强网杯 PHP2shell）——平台拒值被封成封路径

- 事实：run 1 用 `/flag.php` 的未过滤 gopher scheme 8 分钟拿到值，平台判假旗。
- run 2 的 goal 写入："previously obtained flag{...} is a known decoy; never report or
  submit it. Do not spend time revalidating /flag.php gopher output."
- 结果：gopher 路径（唯一活路）被 goal 禁死，run 2 花 165 个工具调用构建无关的
  Nextcloud 加密攻击。
- 官方口径：平台拒绝的是**值**；同一路径可以产出不同的值。
- 规则：封**值**，不封**路径**；重跑同 vector 时只变收尾假设（编码/格式/目标文件）。
- 佐证：Crate-CTF Sidan Av Kanalen 同型——服务端返回的 flag 带 ä/å，手打丢失变音
  符被判错；16 位 PIN 而非 15 位。重跑同 vector 换收尾假设即中。

## 案例 2：ByteDB——长度拒绝被当成"无溢出"

- 服务端行为（黑盒实测）：hex 字节码 → SQL；映射表 18 个 token；含字节 0x11 的
  输入被 "You are not authorized to use 0x11" 拒绝；长度上限实测在 80-90 字节之间。
- 静态结论："长度检查干净拒绝 → 无溢出可能"。
- 官方解：查询字节**直接写进 bytecode_map**（缓冲区和映射表相邻），58 字节的
  合法 payload（11 查询字节 + 40×0x41 + 7 字节 `00 01 02 03 04 10 41`）溢出改写
  映射表前 7 项 → 0x41(knut) 重新映射为 admin_data → `00 23 01 41 FF`
  = `SELECT notes FROM admin_data;`。
- 差距本质：
  1. 长度检查看守的缓冲区和被溢出改写的结构**不是同一个**——"上限内"不等于
     "写不进相邻结构"。
  2. 溢出改写映射表**不崩溃、不报错**——唯一的可见信号是发完长输入后重新 dump
     映射表（选项 2）。上一轮从未做过这次 dump。
- 规则：发送过任何长输入/变异输入后，立刻重新 dump 全部状态（映射表/配置/全局
  结构/菜单）。静默腐坏只会在状态转储里现形。

## 案例 3：Celldelning——"没有代码调用堆指针"漏了间接分发表

- 二进制：PIE + Full RELRO + glibc 2.39；菜单式堆题（create/edit/delete/out），
  尺寸 0x410-0x510（刻意排除 tcache/fastbin），cells 上限 6（=6 次 malloc 上限）；
  win() 在 dlopen 的 libflag.so 里（getenv("FLAG")+puts），**从未被任何代码路径调用**。
- 已打通：libc 泄漏（delete+create 同尺寸 → 新 cell 拿到同一 chunk → out 打印
  残留的 fd=main_arena）；win 地址免费（菜单选项 5 printf %p）。
- 静态结论："largebin attack 写的是堆指针，没有代码调用堆指针 → 无用"。
- 官方解：heap feng shui + largebin attack + **House of Husk**——printf 的
  `__printf_function_table` / `__printf_arginfo_table` 是 libc 全局指针；largebin
  attack 把它们改写成堆地址、在堆上（edit 全控）伪造表项['p']=win 地址；
  程序下一次 printf("%p")（菜单选项 5！）即调 win → getenv → flag。
  3 次 sort（3 对 delete+create）恰好塞进 6 次 malloc 上限。
- 差距本质："没有代码调用 X" 只检查了**直接调用**。间接调用面：
  printf/strftime specifiers 表、C++ vtable、locale、atexit/__exit_funcs、
  宽字符表、dlsym 缓存。现代 glibc 去 hook 后，**堆写 + House of Husk 是标准答案**。
- 附注：largebin attack 在 2.39 官方可用（本次即用）；写原语的可达性先于泄漏。

## 案例 4：Owls and Dragons II——长宽比不匹配弃掉了蒙版

- 已打通：zTXt(SVG0-5 keyword 序)→cat.svg=刺猬 PNG+1199B AES 7z(pw YHSAFNBTE)→
  thing.png；SVG 结束标签后的 3.29MB blob=整幅 JPEG XOR 0x13（5333×4000 猫头鹰王
  飞行图）；图上旋转 ~17° 的 5 行字母格。
- 静态结论："thing.png 黑条 580×157 vs 字母格 720×500，长宽比不匹配 → 叠加不可行"。
- 官方解：把 thing.png（砖）**非等比缩放**叠加在字母格上，黑条盖住全部、孔中透出
  **TOYSFORTHEDRAGONS** → 作为 steghide 密码从 JPEG 抽出 flag.txt（PNG）→ 看图得 flag。
- 差距本质：蒙版/模板/贴纸类资产的缩放比**不需要保形**；坐标对不上先试旋转/平移/
  裁剪再放弃。附带：资产要逐一细读（Vandraren 的解在第 448 帧的地图里，run 翻过帧
 却没细看任何一帧）。

## 元教训：墙是静态推演出来的，证伪只要一次工具调用

三例共性：推演到"此路不通"后，没有执行那个**一次调用即可完成**的检验——
dump 状态 / 枚举分发表 / 试一次非等比叠加。框架侧的配套：blackboard MISS 响应
对静态断言措辞自动附加证伪提醒（`_static_closure_nudge`），技能 `ctf-endgame`
载入本检查单。
