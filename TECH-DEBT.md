# 技术债清单

> 只记录**仍未解决**的结构性问题；已修条目在提交时删除（git 历史可查）。
> 每条写清残余与先决条件，避免重复调查。

---

## A. 实例身份字段仍不完整

- `attachment_sha256[]`、`source_snapshot_id` 尚未作为身份字段存储；下载侧 sha256 已产出，待消费。
- 非 ctf2、且 goal 不含平台引用的手工题仍只有 token 身份。
- 已验证失败的两条路别再试：按正文稀有度拓宽（挑出的是 `ai`/`accepted` 这类散文词）；
  用平台元数据补键（ctf2 ref 已有 challenge uuid 后是死代码，手工 goal 又拿不到 hint）。

## B. stall guard 的收敛信号仍冻结

- `turn_metrics` 与 `scripts/replay_turn_metrics.py` 已就绪；首扫 73 个 run：
  **0 个含真实 telemetry、72 个 proxy-only**，proxy 的 reason 多为空、ratio 序列 0/1 二值。
- 在 telemetry replay 给出证据前，**printable-ratio/覆盖率不得接入任何 guard 决策**。
- `_path_progress_fingerprint` 不计新证据是刻意的防绕过设计；改前先读
  `tests/agent/test_path_stall_guard.py` 开头。

## C. 出站范围门残余

- shell 侧仍只有字符串扫描；OS 级 egress（代理/WFP）才是终局。
- ctypes/winsock 直连可绕过 CPython audit 事件。
- curl 多 URL 操作数时 `$URL` 混在干净字面 URL 旁边仍漏（取舍已注释）。
- `blocked_group_patterns` 的“不要测 <数字开头域>”仍会把 `8` 装进 blocked_ports
  （无害但同族；`allowed_ports` 的同类问题已用前瞻修掉）。
- 范围解析器把 shell 变量当 host 的一部分：
  `https://www.ys7.com/order/x.html?order_id=$i` 会被判成
  `Host www.ys7.com$i is outside allowed scope` 而误拒；修法=在 `$` / `{}` 处截断，
  或对含变量占位的 URL 明确报“需字面 URL”。
- MCP 通用 dispatch 的参数 scope 门已补；外部 MCP server 自身的范围门仍无仓库证据。

## D. 中文召回残余

- 模板词直接连写（`题目提交得到`）会产生 `目提/交得` 这类跨界 bigram，
  17 个停用词覆盖不到、也无法枚举全；彻底解是分词。
- IDF 乘法评分 2026-10-18 试过并撤回，不要重试。

## E. 真实题型命中仍为零

- F5 隐写、QR、OCR、`cve_lookup` 别名回退、`exploit_intel` 均有单测/闭环，
  但还没有真实比赛题命中。
- 机器可读矩阵在 `tests/fixtures/capabilities/manifest.yaml`；F5/OCR 的 fixture 仍缺
  （需 F5.jar/JDK 与外部 PNG，manifest 里如实标注）。
- 消除“未验证”列要靠真实题型，不是再补单测。

## F. 共享 TEMP 清理口径

- `E:\vulnclaw\tmp` 是共享 TEMP，不是 VulnClaw 专属目录；只能清确认属于 VulnClaw 的
  `*.events.ndjson` 和 run `.log`，**绝不按扩展名全局删**。
- 详见 `AGENTS.md` §一。

## G. 大附件预算阈值待实测校准

- `evidence_view` 32K/256K、附件 1GiB 都是工程值；需要在下一场大附件取证题上复测，
  确认不再触发 `token_budget_exceeded`，且不误伤正常取证。
