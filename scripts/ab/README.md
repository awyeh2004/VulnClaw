# A/B 与冷热对照实验工装

这三个脚本是为"笔记复用链"的实测对照写的（背景见仓库根目录
`PLAYBOOK-REUSE-HANDOFF.md`）。原先它们放在 `.test-tmp/` 里，而那个目录会被
**pytest 的 conftest 清理掉超过 12 小时的顶层条目** —— 交接文档指向的脚本会凭空消失，
所以拷到这里留存。

## 脚本

| 文件 | 作用 |
|---|---|
| `cold_warm_pair.py` | 冷/热配对运行器：同一道题先跑 `cold`（配额目录笔记为空）再跑 `warm`（只放手工技术笔记），每臂各开一台新靶机，跑完即释放，结果写 `.test-tmp/rate-results.json` |
| `negative_control.py` | 反向对照：同框架但不同漏洞类的题（`[Weblogic]SSRF`），用来查"同框架被误注入"是否会带偏运行 |
| `parse_run_logs.py` | 解析运行日志：命中条目/分数/命中的键/是否 CLASS MISMATCH、步数、工具调用数、墙钟、逐组冷热差值 |

## 用法

这些是**实验工装**，不是产品代码，因此默认没有单测覆盖。开跑前按需修改文件顶部的常量：

- `PRACTICE`：CTF2 练习场 id
- `SIBLINGS` / `CHALLENGES`：题目 (name, challenge_id)
- `COLD` / `WARM`：两个隔离配置目录（脚本会重建 `COLD`，并按 `SEED` 给 `WARM` 播种子笔记）
- `MAX_STEPS` / `RUN_TIMEOUT_S`：预算

```powershell
$env:PYTHONIOENCODING="utf-8"
python -X utf8 scripts/ab/cold_warm_pair.py     # 跑配对
python -X utf8 scripts/ab/parse_run_logs.py     # 解析结果
```

## 先读这四条硬约束（都在交接文档 §4.3 有更详细的展开）

1. **并发靶机上限 3 台**；`start_environment` 是异步排队，要轮询 `get_target` 到 `running`；
   连开会被 429，脚本里有退避重试。
2. **每臂跑完必须 `stop_target` 释放**，收尾用 `get_target` 确认返回 `null`。
3. **平台提交被验证码挡着**（429 `risk_action='challenge'`），所以"提交成功"通常拿不到，
   不要当判据。
4. **同代码不同次运行的方差可达 33%-100%**（实测），n=1 的任何对比都不足以下结论；
   至少 3 组配对，并且逐组报告差值，不要只报聚合。
